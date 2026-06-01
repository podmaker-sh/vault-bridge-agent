// Package poll runs the control-plane long-poll + dispatch loop.
//
// On every iteration the agent:
//
//  1. POSTs to /api/v1/vault-bridges/<id>/poll and blocks up to
//     `PollTimeout` for the next envelope (or 204 on timeout)
//  2. hands the envelope to the upstream dispatcher
//  3. POSTs the result to /respond
//  4. periodically POSTs to /heartbeat to keep status=online
//
// Failures retry with exponential backoff + jitter, capped at
// `MaxBackoff` (default 60s). A successful poll resets the
// backoff to `MinBackoff`.
package poll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"podmaker.sh/vault-bridge-agent/internal/metrics"
	"podmaker.sh/vault-bridge-agent/internal/upstream"
)

type Config struct {
	BridgeID       string
	Token          string
	ControlPlane   string
	PollTimeout    time.Duration
	HeartbeatEvery time.Duration

	// Stamped into every heartbeat so the CP can track the running
	// build per bridge. Empty string is fine — the CP keeps the
	// last-known value.
	AgentVersion string

	// Exponential backoff bounds. Starts at MinBackoff, doubles on
	// every consecutive failure, caps at MaxBackoff, resets on a
	// successful poll round-trip. Jitter is ±25%.
	MinBackoff time.Duration
	MaxBackoff time.Duration

	HTTP       *http.Client
	Dispatcher *upstream.Dispatcher
	Logger     *slog.Logger
}

type envelope struct {
	ID   string         `json:"id"`
	Op   string         `json:"op"`
	Path string         `json:"path"`
	Data map[string]any `json:"data,omitempty"`
}

// Run blocks until the context is cancelled. Returns the first
// error that bubbles past the retry loop.
func Run(ctx context.Context, cfg Config) error {
	if cfg.BridgeID == "" || cfg.Token == "" || cfg.ControlPlane == "" {
		return errors.New("poll: BridgeID + Token + ControlPlane required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: cfg.PollTimeout + 5*time.Second}
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = 25 * time.Second
	}
	if cfg.HeartbeatEvery == 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 60 * time.Second
	}

	go runHeartbeat(ctx, cfg)

	var inFlight atomic.Int64
	backoff := cfg.MinBackoff
	for {
		select {
		case <-ctx.Done():
			cfg.Logger.Info("poll: shutdown — waiting for in-flight envelopes", "count", inFlight.Load())
			return nil
		default:
		}

		env, err := pollOnce(ctx, cfg)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			metrics.PollErrorsTotal.Inc()
			cfg.Logger.Warn("poll: failed", "err", err, "backoff", backoff.String())
			sleep(ctx, jitter(backoff))
			backoff = nextBackoff(backoff, cfg.MaxBackoff)
			continue
		}
		// Successful round-trip — reset.
		backoff = cfg.MinBackoff
		metrics.PollsTotal.Inc()

		if env == nil {
			continue // 204 — long-poll timeout, just re-poll
		}

		inFlight.Add(1)
		go func(e envelope) {
			defer inFlight.Add(-1)
			handle(ctx, cfg, e)
		}(*env)
	}
}

func pollOnce(ctx context.Context, cfg Config) (*envelope, error) {
	url := strings.TrimRight(cfg.ControlPlane, "/") + "/api/v1/vault-bridges/" + cfg.BridgeID + "/poll"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url+"?timeout=25", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("poll HTTP %d: %s", resp.StatusCode, body)
	}
	var env envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("poll decode: %w", err)
	}
	if env.ID == "" {
		return nil, nil
	}
	return &env, nil
}

func handle(parent context.Context, cfg Config, env envelope) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	timer := metrics.RequestDuration.WithLabelValues(env.Op)
	start := time.Now()
	result := cfg.Dispatcher.Handle(ctx, env.Op, env.Path, env.Data)
	timer.Observe(time.Since(start).Seconds())

	outcome := "ok"
	switch {
	case !result.OK && result.Status == 404:
		outcome = "not_found" // missing key is a normal outcome, not a fault
	case !result.OK:
		outcome = "error"
		metrics.UpstreamErrorsTotal.WithLabelValues(cfg.Dispatcher.Driver.Slug()).Inc()
	}
	metrics.RequestsTotal.WithLabelValues(env.Op, outcome).Inc()

	body := map[string]any{
		"id":     env.ID,
		"ok":     result.OK,
		"data":   result.Data,
		"status": result.Status,
		"error":  result.Error,
	}
	payload, _ := json.Marshal(body)
	url := strings.TrimRight(cfg.ControlPlane, "/") + "/api/v1/vault-bridges/" + cfg.BridgeID + "/respond"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		cfg.Logger.Warn("respond: failed", "id", env.ID, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		cfg.Logger.Warn("respond: HTTP error", "id", env.ID, "status", resp.StatusCode, "body", string(body))
	}
}

func runHeartbeat(ctx context.Context, cfg Config) {
	ticker := time.NewTicker(cfg.HeartbeatEvery)
	defer ticker.Stop()
	url := strings.TrimRight(cfg.ControlPlane, "/") + "/api/v1/vault-bridges/" + cfg.BridgeID + "/heartbeat"
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			body := strings.NewReader(`{"agent_version":"` + cfg.AgentVersion + `"}`)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := cfg.HTTP.Do(req)
			metrics.HeartbeatsTotal.Inc()
			if err != nil {
				cfg.Logger.Warn("heartbeat: failed", "err", err)
				continue
			}
			resp.Body.Close()
		}
	}
}

// nextBackoff doubles d but never exceeds max.
func nextBackoff(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		return max
	}
	return d
}

// jitter adds ±25% randomness to d so a fleet of agents doesn't
// reconnect in lockstep after a control-plane outage.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	delta := float64(d) * 0.25
	return d + time.Duration((rand.Float64()*2-1)*delta)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
