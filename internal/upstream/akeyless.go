package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AkeylessDriver — auth via access_id + access_key against the
// public API, exchange for a t-token, run set/get/delete-secret
// against `/secret`. Names are forward-slash separated paths
// inside the Akeyless namespace.
type AkeylessDriver struct {
	AccessID  string
	AccessKey string
	APIBase   string
	Client    *http.Client

	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time
}

func NewAkeyless(accessID, accessKey, apiBase string) *AkeylessDriver {
	if apiBase == "" {
		apiBase = "https://api.akeyless.io"
	}
	return &AkeylessDriver{
		AccessID: accessID, AccessKey: accessKey,
		APIBase: strings.TrimRight(apiBase, "/"),
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *AkeylessDriver) Slug() string { return "akeyless" }

func (a *AkeylessDriver) Ping(ctx context.Context) error {
	_, err := a.token(ctx)
	return err
}

func (a *AkeylessDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	tok, err := a.token(ctx)
	if err != nil {
		return nil, false, err
	}
	body, _ := json.Marshal(map[string]any{
		"token":  tok,
		"names":  []string{"/" + strings.TrimLeft(path, "/")},
	})
	resp, err := a.post(ctx, "/get-secret-value", body)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(raw), "not found") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("akeyless read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var decoded map[string]string
	if jerr := json.NewDecoder(resp.Body).Decode(&decoded); jerr != nil {
		return nil, false, jerr
	}
	raw, ok := decoded["/"+strings.TrimLeft(path, "/")]
	if !ok || raw == "" {
		return nil, false, nil
	}
	out := map[string]any{}
	if jerr := json.Unmarshal([]byte(raw), &out); jerr != nil {
		return map[string]any{"value": raw}, true, nil
	}
	return out, true, nil
}

func (a *AkeylessDriver) Write(ctx context.Context, path string, data map[string]any) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	val, _ := json.Marshal(data)
	body, _ := json.Marshal(map[string]any{
		"token": tok,
		"name":  "/" + strings.TrimLeft(path, "/"),
		"value": string(val),
	})
	// create-secret 409s if it exists; fall through to update-secret-val.
	resp, err := a.post(ctx, "/create-secret", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || (resp.StatusCode >= 400 && resp.StatusCode != http.StatusOK) {
		resp2, err := a.post(ctx, "/update-secret-val", body)
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode >= 400 {
			raw, _ := io.ReadAll(resp2.Body)
			return fmt.Errorf("akeyless update %s HTTP %d: %s", path, resp2.StatusCode, raw)
		}
	}
	return nil
}

func (a *AkeylessDriver) Delete(ctx context.Context, path string) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"token": tok,
		"name":  "/" + strings.TrimLeft(path, "/"),
	})
	resp, err := a.post(ctx, "/delete-item", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("akeyless delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (a *AkeylessDriver) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.APIBase+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return a.Client.Do(req)
}

func (a *AkeylessDriver) token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cachedToken != "" && time.Now().Before(a.expiresAt) {
		return a.cachedToken, nil
	}
	body, _ := json.Marshal(map[string]string{
		"access-id":   a.AccessID,
		"access-key":  a.AccessKey,
		"access-type": "api_key",
	})
	resp, err := a.post(ctx, "/auth", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("akeyless auth HTTP %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
	}
	if jerr := json.NewDecoder(resp.Body).Decode(&out); jerr != nil {
		return "", jerr
	}
	a.cachedToken = out.Token
	a.expiresAt = time.Now().Add(50 * time.Minute)
	return a.cachedToken, nil
}
