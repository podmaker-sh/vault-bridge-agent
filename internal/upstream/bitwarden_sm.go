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

// BitwardenSMDriver — machine-account access tokens. Auth flow:
// POST `/connect/token` on identity → API token (1h); subsequent
// secret CRUD goes to /api/projects/<projectId>/secrets endpoints.
// PodMaker paths fold into the secret key.
type BitwardenSMDriver struct {
	AccessToken    string
	OrganizationID string
	ProjectID      string
	IdentityURL    string
	APIURL         string
	Client         *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func NewBitwardenSM(accessToken, orgID, projectID, identity, api string) *BitwardenSMDriver {
	if identity == "" {
		identity = "https://identity.bitwarden.com"
	}
	if api == "" {
		api = "https://api.bitwarden.com"
	}
	return &BitwardenSMDriver{
		AccessToken: accessToken, OrganizationID: orgID, ProjectID: projectID,
		IdentityURL: strings.TrimRight(identity, "/"),
		APIURL:      strings.TrimRight(api, "/"),
		Client:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (b *BitwardenSMDriver) Slug() string { return "bitwarden-sm" }

func (b *BitwardenSMDriver) Ping(ctx context.Context) error {
	_, err := b.bearer(ctx)
	return err
}

func (b *BitwardenSMDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	tok, err := b.bearer(ctx)
	if err != nil {
		return nil, false, err
	}
	id, ok, err := b.lookupID(ctx, tok, path)
	if err != nil || !ok {
		return nil, ok, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.APIURL+"/secrets/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("bitwarden-sm read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Value string `json:"value"`
	}
	if jerr := json.NewDecoder(resp.Body).Decode(&body); jerr != nil {
		return nil, false, jerr
	}
	out := map[string]any{}
	if jerr := json.Unmarshal([]byte(body.Value), &out); jerr != nil {
		return map[string]any{"value": body.Value}, true, nil
	}
	return out, true, nil
}

func (b *BitwardenSMDriver) Write(ctx context.Context, path string, data map[string]any) error {
	tok, err := b.bearer(ctx)
	if err != nil {
		return err
	}
	val, _ := json.Marshal(data)
	id, ok, err := b.lookupID(ctx, tok, path)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{
		"key":            path,
		"value":          string(val),
		"projectIds":     []string{b.ProjectID},
		"organizationId": b.OrganizationID,
	})
	method, u := http.MethodPost, b.APIURL+"/organizations/"+b.OrganizationID+"/secrets"
	if ok {
		method = http.MethodPut
		u = b.APIURL + "/secrets/" + id
	}
	req, _ := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := b.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bitwarden-sm write %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (b *BitwardenSMDriver) Delete(ctx context.Context, path string) error {
	tok, err := b.bearer(ctx)
	if err != nil {
		return err
	}
	id, ok, err := b.lookupID(ctx, tok, path)
	if err != nil || !ok {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, b.APIURL+"/secrets/delete", bytes.NewReader([]byte(`["`+id+`"]`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := b.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bitwarden-sm delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (b *BitwardenSMDriver) lookupID(ctx context.Context, tok, key string) (string, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.APIURL+"/organizations/"+b.OrganizationID+"/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := b.Client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", false, fmt.Errorf("bitwarden-sm list HTTP %d", resp.StatusCode)
	}
	var list struct {
		Data []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"data"`
	}
	if jerr := json.NewDecoder(resp.Body).Decode(&list); jerr != nil {
		return "", false, jerr
	}
	for _, item := range list.Data {
		if item.Key == key {
			return item.ID, true, nil
		}
	}
	return "", false, nil
}

func (b *BitwardenSMDriver) bearer(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cached != "" && time.Now().Before(b.expiresAt) {
		return b.cached, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "api.secrets")
	form.Set("client_id", b.AccessToken)
	form.Set("client_secret", b.AccessToken)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, b.IdentityURL+"/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bitwarden-sm identity HTTP %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if jerr := json.NewDecoder(resp.Body).Decode(&body); jerr != nil {
		return "", jerr
	}
	b.cached = body.AccessToken
	b.expiresAt = time.Now().Add(time.Duration(body.ExpiresIn-60) * time.Second)
	return b.cached, nil
}
