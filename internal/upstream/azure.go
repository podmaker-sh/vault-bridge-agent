package upstream

import (
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

// AzureKeyVaultDriver — client_credentials OAuth + Key Vault REST.
// PodMaker path → single Key Vault secret with JSON-encoded value.
// Name charset: ^[0-9a-zA-Z-]{1,127}$. We rewrite `/` → `--` and
// `_` → `-_-` on encode, invert on read.
type AzureKeyVaultDriver struct {
	VaultURL     string
	TenantID     string
	ClientID     string
	ClientSecret string
	Client       *http.Client

	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time
}

func NewAzureKeyVault(vaultURL, tenantID, clientID, clientSecret string) *AzureKeyVaultDriver {
	return &AzureKeyVaultDriver{
		VaultURL: strings.TrimRight(vaultURL, "/"),
		TenantID: tenantID, ClientID: clientID, ClientSecret: clientSecret,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *AzureKeyVaultDriver) Slug() string { return "azure-kv" }

func (a *AzureKeyVaultDriver) Ping(ctx context.Context) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.VaultURL+"/secrets?maxresults=1&api-version=7.4", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("azure-kv ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *AzureKeyVaultDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	tok, err := a.token(ctx)
	if err != nil {
		return nil, false, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.VaultURL+"/secrets/"+azureName(path)+"?api-version=7.4", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("azure-kv read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	if body.Value == "" {
		return nil, false, nil
	}
	out := map[string]any{}
	if jerr := json.Unmarshal([]byte(body.Value), &out); jerr != nil {
		return map[string]any{"value": body.Value}, true, nil
	}
	return out, true, nil
}

func (a *AzureKeyVaultDriver) Write(ctx context.Context, path string, data map[string]any) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	val, _ := json.Marshal(data)
	body, _ := json.Marshal(map[string]any{"value": string(val)})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, a.VaultURL+"/secrets/"+azureName(path)+"?api-version=7.4", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("azure-kv write %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (a *AzureKeyVaultDriver) Delete(ctx context.Context, path string) error {
	tok, err := a.token(ctx)
	if err != nil {
		return err
	}
	name := azureName(path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, a.VaultURL+"/secrets/"+name+"?api-version=7.4", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("azure-kv delete %s HTTP %d", path, resp.StatusCode)
	}
	// Purge soft-deleted entry so the same name is reusable immediately.
	purge, _ := http.NewRequestWithContext(ctx, http.MethodDelete, a.VaultURL+"/deletedsecrets/"+name+"?api-version=7.4", nil)
	purge.Header.Set("Authorization", "Bearer "+tok)
	if p, err := a.Client.Do(purge); err == nil {
		p.Body.Close()
	}
	return nil
}

func azureName(path string) string {
	s := strings.ReplaceAll(strings.TrimLeft(path, "/"), "_", "-_-")
	return strings.ReplaceAll(s, "/", "--")
}

func (a *AzureKeyVaultDriver) token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cachedToken != "" && time.Now().Before(a.expiresAt) {
		return a.cachedToken, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", a.ClientID)
	form.Set("client_secret", a.ClientSecret)
	form.Set("scope", "https://vault.azure.net/.default")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.microsoftonline.com/"+a.TenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("azure-kv token HTTP %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	a.cachedToken = body.AccessToken
	a.expiresAt = time.Now().Add(time.Duration(body.ExpiresIn-60) * time.Second)
	return a.cachedToken, nil
}
