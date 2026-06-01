// Package clientcert handles the agent's mTLS lifecycle.
//
// On first start the agent generates an ECDSA P-256 keypair, builds
// a CSR with CN=`bridge:<bridge_id>`, posts it to the control plane,
// and writes the signed cert + CA chain + private key to disk. On
// every subsequent start the agent reloads them; a background
// renewer re-signs ~6h before expiry.
//
// File layout (default `~/.podmaker-bridge/`):
//
//	key.pem    ECDSA P-256 private key (0600)
//	cert.pem   leaf certificate (0644)
//	ca.pem     issuer cert (0644)
package clientcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Config carries the knobs the agent passes to Provision + the
// renewer.
type Config struct {
	Dir           string // directory for key/cert/ca files
	BridgeID      string
	BearerToken   string // bootstrap auth + fallback during cert ops
	ControlPlane  string // CP base URL
	BootstrapHTTP *http.Client
	Logger        *slog.Logger
}

// Bundle is the in-memory tls keypair the agent loads on startup +
// hot-swaps on renewal.
type Bundle struct {
	cert        atomic.Pointer[tls.Certificate]
	caPool      atomic.Pointer[x509.CertPool]
	NotAfter    atomic.Int64 // unix seconds
	Fingerprint atomic.Pointer[string]
	WorkspaceID atomic.Pointer[string]
}

// Provision loads existing key/cert from Dir, or — if absent or
// expired — calls the control-plane sign endpoint to obtain a
// fresh pair. The returned Bundle is the live source of truth the
// HTTP transport reads on every request.
func Provision(ctx context.Context, cfg Config) (*Bundle, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("clientcert: mkdir %s: %w", cfg.Dir, err)
	}

	keyPEM, certPEM, caPEM, err := loadExisting(cfg.Dir)
	if err == nil && certUsable(certPEM, 60*time.Minute) {
		cfg.Logger.Info("clientcert: reusing on-disk cert", "dir", cfg.Dir)
		return mountBundle(keyPEM, certPEM, caPEM)
	}

	cfg.Logger.Info("clientcert: provisioning new cert via CP")
	keyPEM, csrPEM, err := newKeyAndCSR(cfg.BridgeID)
	if err != nil {
		return nil, err
	}
	certPEM, caPEM, err = signCSR(ctx, cfg, csrPEM)
	if err != nil {
		return nil, err
	}
	if err := writeFiles(cfg.Dir, keyPEM, certPEM, caPEM); err != nil {
		return nil, err
	}
	return mountBundle(keyPEM, certPEM, caPEM)
}

// RevocationChecker is the contract HTTPSTransport consults during
// the TLS handshake to reject peer certs whose serials appear on
// the latest CRL. The real implementation lives in
// `internal/crl` so this package stays free of the polling code.
type RevocationChecker interface {
	IsRevoked(serial *big.Int) bool
}

// HTTPSTransport returns an http.RoundTripper that presents the
// current cert on every dial. Hot-swap is automatic — Renew()
// updates the bundle and subsequent connections pick up the new
// keypair.
//
// When `revoker` is non-nil the TLS layer also runs a
// VerifyPeerCertificate callback that walks the verified chain
// and rejects the connection if any element's serial appears in
// the revoker. Defense in depth — the fronting proxy verifies
// the inbound handshake, and this checks the inverse direction
// so a stolen intermediate cannot impersonate the CP to the
// agent.
func (b *Bundle) HTTPSTransport(parent *http.Transport, revoker RevocationChecker) *http.Transport {
	if parent == nil {
		parent = http.DefaultTransport.(*http.Transport).Clone()
	}
	parent.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := b.cert.Load()
			if c == nil {
				return nil, errors.New("clientcert: bundle empty")
			}
			return c, nil
		},
		RootCAs: b.caPool.Load(),
		VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			if revoker == nil {
				return nil
			}
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					if cert.SerialNumber != nil && revoker.IsRevoked(cert.SerialNumber) {
						return fmt.Errorf("clientcert: peer cert serial %s is revoked", cert.SerialNumber.Text(16))
					}
				}
			}
			return nil
		},
	}
	return parent
}

// Renew loops in the background, re-issuing the cert ~6h before
// NotAfter. Failures retry every 30 minutes.
func (b *Bundle) Renew(ctx context.Context, cfg Config) {
	for {
		na := time.Unix(b.NotAfter.Load(), 0)
		// Renew 6h before expiry, but at least 1 minute from now.
		until := time.Until(na.Add(-6 * time.Hour))
		if until < time.Minute {
			until = time.Minute
		}
		t := time.NewTimer(until)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}

		cfg.Logger.Info("clientcert: rotating", "current_not_after", na)
		keyPEM, csrPEM, err := newKeyAndCSR(cfg.BridgeID)
		if err != nil {
			cfg.Logger.Warn("clientcert: csr build failed", "err", err)
			sleep(ctx, 30*time.Minute)
			continue
		}
		certPEM, caPEM, err := signCSR(ctx, cfg, csrPEM)
		if err != nil {
			cfg.Logger.Warn("clientcert: sign failed — will retry", "err", err)
			sleep(ctx, 30*time.Minute)
			continue
		}
		if err := writeFiles(cfg.Dir, keyPEM, certPEM, caPEM); err != nil {
			cfg.Logger.Warn("clientcert: write failed", "err", err)
			continue
		}
		nb, err := mountBundle(keyPEM, certPEM, caPEM)
		if err != nil {
			cfg.Logger.Warn("clientcert: remount failed", "err", err)
			continue
		}
		b.cert.Store(nb.cert.Load())
		b.caPool.Store(nb.caPool.Load())
		b.NotAfter.Store(nb.NotAfter.Load())
		b.Fingerprint.Store(nb.Fingerprint.Load())
	}
}

// --- internals ---------------------------------------------------

func loadExisting(dir string) (key, cert, ca []byte, err error) {
	key, err = os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err = os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err = os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, nil, nil, err
	}
	return
}

func certUsable(certPEM []byte, margin time.Duration) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Add(margin).Before(c.NotAfter)
}

func newKeyAndCSR(bridgeID string) (keyPEM, csrPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("clientcert: generate key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("clientcert: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bridge:" + bridgeID},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("clientcert: csr: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

func signCSR(ctx context.Context, cfg Config, csrPEM []byte) (certPEM, caPEM []byte, err error) {
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	url := strings.TrimRight(cfg.ControlPlane, "/") + "/api/v1/vault-bridges/" + cfg.BridgeID + "/cert"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := cfg.BootstrapHTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("clientcert: sign POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("clientcert: sign HTTP %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Cert        string `json:"cert"`
		Chain       string `json:"chain"`
		Root        string `json:"root"`
		WorkspaceID string `json:"workspace_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("clientcert: sign decode: %w", err)
	}
	if out.Cert == "" || out.Chain == "" {
		return nil, nil, errors.New("clientcert: sign returned empty cert/chain")
	}
	// cert.pem now holds the leaf + intermediate bundle so the
	// TLS handshake presents both to the proxy. ca.pem still
	// holds the trust anchor — root if the CP returned it, else
	// the intermediate as a graceful fallback.
	bundle := append([]byte(out.Cert), []byte("\n")...)
	bundle = append(bundle, []byte(out.Chain)...)
	root := []byte(out.Root)
	if len(root) == 0 {
		root = []byte(out.Chain)
	}
	// Persist the workspace ID so the CRL watcher can pick it up
	// on the next boot without re-asking the CP.
	if out.WorkspaceID != "" {
		_ = os.WriteFile(filepath.Join(cfg.Dir, "workspace_id"), []byte(out.WorkspaceID), 0o600)
	}
	return bundle, root, nil
}

// WorkspaceIDFromDisk returns the workspace_id the cert was issued
// against. Empty when the bridge has not yet provisioned a cert.
func WorkspaceIDFromDisk(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "workspace_id"))
	if err != nil {
		return ""
	}
	return string(b)
}

func writeFiles(dir string, key, cert, ca []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), key, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), cert, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ca.pem"), ca, 0o644)
}

func mountBundle(keyPEM, certPEM, caPEM []byte) (*Bundle, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("clientcert: x509 keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("clientcert: ca pem invalid")
	}

	parsed, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("clientcert: parse leaf: %w", err)
	}

	b := &Bundle{}
	b.cert.Store(&pair)
	b.caPool.Store(pool)
	b.NotAfter.Store(parsed.NotAfter.Unix())

	fp := formatFingerprint(parsed.Raw)
	b.Fingerprint.Store(&fp)
	return b, nil
}

func formatFingerprint(der []byte) string {
	sum := sha256(der)
	hex := make([]byte, len(sum)*2)
	const hexChars = "0123456789abcdef"
	for i, b := range sum {
		hex[i*2] = hexChars[b>>4]
		hex[i*2+1] = hexChars[b&0x0f]
	}
	return string(hex)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
