// Package crl polls the workspace CRL endpoint and exposes a
// concurrent-safe membership check the TLS layer consults before
// trusting the chain returned by the CP.
//
// Defense in depth — the fronting proxy already verifies the CRL
// on the inbound handshake. The agent re-verifies on the inverse
// direction: when the CP advertises a workspace-scoped CRL we
// refresh hourly, parse the standard X.509 CRL, and keep the
// serials in a hot cache. Calls to IsRevoked() take a single
// map lookup, so it's safe to wire into the TLS verify path
// without measurable latency.
package crl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Watcher struct {
	WorkspaceID  string
	ControlPlane string
	HTTP         *http.Client
	Logger       *slog.Logger

	mu      sync.RWMutex
	revoked map[string]struct{}
	updated time.Time
}

func New(workspaceID, cpURL string) *Watcher {
	return &Watcher{
		WorkspaceID:  workspaceID,
		ControlPlane: strings.TrimRight(cpURL, "/"),
		HTTP:         &http.Client{Timeout: 15 * time.Second},
		revoked:      map[string]struct{}{},
	}
}

// IsRevoked reports whether the given serial number appears in the
// most recent CRL fetch. Unknown serials default to "not revoked"
// — the caller still uses normal chain verification.
func (w *Watcher) IsRevoked(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, found := w.revoked[strings.ToLower(serial.Text(16))]
	return found
}

// LastUpdated reports when the cache was last refreshed. The
// metrics endpoint surfaces this for alerting on stale CRLs.
func (w *Watcher) LastUpdated() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.updated
}

// Run blocks until ctx is cancelled. Refresh hourly + one fetch
// at startup so the cache is hot before the first poll cycle.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	if w.WorkspaceID == "" || w.ControlPlane == "" {
		if w.Logger != nil {
			w.Logger.Info("crl: skipped — workspace_id / control plane not set")
		}
		return
	}
	if every == 0 {
		every = time.Hour
	}
	w.refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.refresh(ctx)
		}
	}
}

func (w *Watcher) refresh(ctx context.Context) {
	url := w.ControlPlane + "/api/v1/vault-bridges/workspaces/" + w.WorkspaceID + "/crl.pem"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := w.HTTP.Do(req)
	if err != nil {
		w.log("crl: fetch failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		w.log("crl: HTTP error", "status", resp.StatusCode)
		return
	}
	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		w.log("crl: read body", "err", err)
		return
	}
	revoked, err := parsePEM(pemBytes)
	if err != nil {
		w.log("crl: parse", "err", err)
		return
	}
	w.mu.Lock()
	w.revoked = revoked
	w.updated = time.Now()
	w.mu.Unlock()
	w.log("crl: refreshed", "revoked_count", len(revoked))
}

func parsePEM(pemBytes []byte) (map[string]struct{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("crl: not a PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil {
			out[strings.ToLower(entry.SerialNumber.Text(16))] = struct{}{}
		}
	}
	return out, nil
}

func (w *Watcher) log(msg string, fields ...any) {
	if w.Logger != nil {
		w.Logger.Info(msg, fields...)
	}
}
