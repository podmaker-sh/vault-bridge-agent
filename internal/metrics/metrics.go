// Package metrics exposes the agent's Prometheus surface. Metrics
// live on a dedicated local port so the operator can scrape them
// without poking holes in the firewall — the agent itself only
// dials outbound.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	PollsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podmaker_bridge_polls_total",
		Help: "Number of long-poll attempts (success + 204).",
	})
	PollErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podmaker_bridge_poll_errors_total",
		Help: "Number of poll attempts that failed before reaching the long-poll body.",
	})
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "podmaker_bridge_requests_total",
		Help: "Number of envelopes processed, labelled by op and outcome.",
	}, []string{"op", "outcome"})
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "podmaker_bridge_request_duration_seconds",
		Help:    "End-to-end time the agent took to handle an envelope.",
		Buckets: prometheus.DefBuckets,
	}, []string{"op"})
	UpstreamErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "podmaker_bridge_upstream_errors_total",
		Help: "Errors returned by the upstream vault driver.",
	}, []string{"driver"})
	HeartbeatsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podmaker_bridge_heartbeats_total",
		Help: "Number of heartbeat calls (success + failure).",
	})
	UpSince = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "podmaker_bridge_up_since_seconds",
		Help: "Agent start time as a unix timestamp.",
	})
	SelfUpdateChecksTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podmaker_bridge_selfupdate_checks_total",
		Help: "Number of manifest poll attempts.",
	})
	SelfUpdateOutcomeTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "podmaker_bridge_selfupdate_outcome_total",
		Help: "Number of self-update attempts grouped by outcome.",
	}, []string{"status"})
	SelfUpdateCurrentVersionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "podmaker_bridge_selfupdate_version_info",
		Help: "Static gauge with the current binary version as a label. Set to 1 at boot.",
	}, []string{"version"})
)

// MustRegister wires every metric into the default registry.
// Idempotent across re-registration via prometheus' own behaviour.
func init() {
	prometheus.MustRegister(
		PollsTotal, PollErrorsTotal,
		RequestsTotal, RequestDuration,
		UpstreamErrorsTotal,
		HeartbeatsTotal, UpSince,
		SelfUpdateChecksTotal, SelfUpdateOutcomeTotal, SelfUpdateCurrentVersionInfo,
	)
	UpSince.Set(float64(time.Now().Unix()))
}

// SetCurrentVersion seeds the version_info gauge. Called once from
// main after the build version is known.
func SetCurrentVersion(v string) {
	SelfUpdateCurrentVersionInfo.Reset()
	SelfUpdateCurrentVersionInfo.WithLabelValues(v).Set(1)
}

// Serve binds /metrics on the given address. Blocks until the
// context is cancelled. Errors after Shutdown are silently absorbed.
func Serve(ctx context.Context, addr string, logger *slog.Logger) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	logger.Info("metrics: listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Warn("metrics: serve", "err", err)
	}
}
