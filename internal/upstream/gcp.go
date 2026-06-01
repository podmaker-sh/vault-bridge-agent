package upstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GCPSecretManagerDriver — service-account JWT bearer flow against
// Secret Manager REST API. Names cannot contain `/` so paths are
// rewritten with `__` and inverted on read.
type GCPSecretManagerDriver struct {
	ProjectID          string
	ServiceAccountJSON string
	Client             *http.Client

	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time
}

func NewGCPSecretManager(projectID, serviceAccountJSON string) *GCPSecretManagerDriver {
	return &GCPSecretManagerDriver{
		ProjectID: projectID, ServiceAccountJSON: serviceAccountJSON,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GCPSecretManagerDriver) Slug() string { return "gcp-sm" }

func (g *GCPSecretManagerDriver) Ping(ctx context.Context) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?pageSize=1", g.ProjectID), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("gcp-sm ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (g *GCPSecretManagerDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	tok, err := g.token(ctx)
	if err != nil {
		return nil, false, err
	}
	name := gcpName(path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access", g.ProjectID, name), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("gcp-sm read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	raw, err := base64.StdEncoding.DecodeString(body.Payload.Data)
	if err != nil {
		return nil, false, fmt.Errorf("gcp-sm read %s: bad base64", path)
	}
	out := map[string]any{}
	if jerr := json.Unmarshal(raw, &out); jerr != nil {
		return map[string]any{"value": string(raw)}, true, nil
	}
	return out, true, nil
}

func (g *GCPSecretManagerDriver) Write(ctx context.Context, path string, data map[string]any) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	name := gcpName(path)

	// Ensure secret container — 409 means already exists.
	createBody, _ := json.Marshal(map[string]any{"replication": map[string]any{"automatic": map[string]any{}}})
	createReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?secretId=%s", g.ProjectID, name),
		bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+tok)
	createReq.Header.Set("Content-Type", "application/json")
	cresp, err := g.Client.Do(createReq)
	if err != nil {
		return err
	}
	cresp.Body.Close()
	if cresp.StatusCode >= 400 && cresp.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(cresp.Body)
		return fmt.Errorf("gcp-sm create %s HTTP %d: %s", path, cresp.StatusCode, raw)
	}

	payload, _ := json.Marshal(data)
	body, _ := json.Marshal(map[string]any{"payload": map[string]any{"data": base64.StdEncoding.EncodeToString(payload)}})
	addReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s:addVersion", g.ProjectID, name),
		bytes.NewReader(body))
	addReq.Header.Set("Authorization", "Bearer "+tok)
	addReq.Header.Set("Content-Type", "application/json")
	resp, err := g.Client.Do(addReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gcp-sm addVersion %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (g *GCPSecretManagerDriver) Delete(ctx context.Context, path string) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	name := gcpName(path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s", g.ProjectID, name), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gcp-sm delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func gcpName(path string) string {
	return strings.ReplaceAll(strings.TrimLeft(path, "/"), "/", "__")
}

// token mints a Google OAuth access token via JWT bearer flow and
// caches it in-memory.
func (g *GCPSecretManagerDriver) token(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cachedToken != "" && time.Now().Before(g.expiresAt) {
		return g.cachedToken, nil
	}
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(g.ServiceAccountJSON), &sa); err != nil {
		return "", fmt.Errorf("gcp-sm: parse service_account_json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", fmt.Errorf("gcp-sm: service_account_json missing client_email / private_key")
	}

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("gcp-sm: private_key not PEM")
	}
	key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if perr != nil {
		// Older keys ship PKCS1.
		k1, p1err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if p1err != nil {
			return "", fmt.Errorf("gcp-sm: parse private_key: %w", p1err)
		}
		key = k1
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("gcp-sm: private_key is not RSA")
	}

	now := time.Now().Unix()
	header := b64url(`{"alg":"RS256","typ":"JWT"}`)
	claimJSON, _ := json.Marshal(map[string]any{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   "https://oauth2.googleapis.com/token",
		"exp":   now + 3600,
		"iat":   now,
	})
	claim := b64url(string(claimJSON))
	signingInput := header + "." + claim

	hash := sha256.Sum256([]byte(signingInput))
	sig, signErr := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if signErr != nil {
		return "", fmt.Errorf("gcp-sm: sign JWT: %w", signErr)
	}
	jwt := signingInput + "." + b64urlBytes(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("gcp-sm token exchange HTTP %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	g.cachedToken = body.AccessToken
	g.expiresAt = time.Now().Add(time.Duration(body.ExpiresIn-60) * time.Second)
	return g.cachedToken, nil
}

func b64url(s string) string      { return b64urlBytes([]byte(s)) }
func b64urlBytes(b []byte) string { return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=") }
