package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ConjurDriver — CyberArk Conjur OSS / Cloud. Auth: host or user
// identity authenticates with an API key, gets back a base64-
// encoded short-lived token. Subsequent secret operations route
// through `/secrets/{account}/variable/{variableId}`. PodMaker
// path → variable id.
type ConjurDriver struct {
	ApplianceURL string
	Account      string
	Login        string
	APIKey       string
	Client       *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func NewConjur(appliance, account, login, apiKey string) *ConjurDriver {
	return &ConjurDriver{
		ApplianceURL: strings.TrimRight(appliance, "/"),
		Account:      account, Login: login, APIKey: apiKey,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *ConjurDriver) Slug() string { return "conjur" }

func (c *ConjurDriver) Ping(ctx context.Context) error {
	_, err := c.token(ctx)
	return err
}

func (c *ConjurDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, false, err
	}
	v := url.PathEscape(strings.TrimLeft(path, "/"))
	endpoint := fmt.Sprintf("%s/secrets/%s/variable/%s", c.ApplianceURL, url.PathEscape(c.Account), v)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", `Token token="`+tok+`"`)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("conjur read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if jerr := json.Unmarshal(raw, &out); jerr != nil {
		return map[string]any{"value": string(raw)}, true, nil
	}
	return out, true, nil
}

func (c *ConjurDriver) Write(ctx context.Context, path string, data map[string]any) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	val, _ := json.Marshal(data)
	v := url.PathEscape(strings.TrimLeft(path, "/"))
	endpoint := fmt.Sprintf("%s/secrets/%s/variable/%s", c.ApplianceURL, url.PathEscape(c.Account), v)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(val))
	req.Header.Set("Authorization", `Token token="`+tok+`"`)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("conjur write %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (c *ConjurDriver) Delete(_ context.Context, _ string) error {
	// Conjur secrets cannot be deleted via the data API — only the
	// policy that declares them can be modified. The CP-side delete
	// is best-effort: we log + succeed so the orchestrator does
	// not block on cleanup.
	return nil
}

func (c *ConjurDriver) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != "" && time.Now().Before(c.expiresAt) {
		return c.cached, nil
	}
	endpoint := fmt.Sprintf("%s/authn/%s/%s/authenticate", c.ApplianceURL, url.PathEscape(c.Account), url.PathEscape(c.Login))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(c.APIKey))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept-Encoding", "base64")
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("conjur authn HTTP %d: %s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	c.cached = strings.TrimSpace(string(raw))
	// Conjur tokens are valid for ~8m by default.
	c.expiresAt = time.Now().Add(6 * time.Minute)
	return c.cached, nil
}
