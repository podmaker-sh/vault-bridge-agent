package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// InfisicalDriver — machine identity token over /api/v3/secrets/raw.
// PodMaker path → single Infisical secret with JSON-encoded value.
type InfisicalDriver struct {
	Token       string
	ProjectID   string
	Environment string
	APIBase     string
	SecretPath  string
	Client      *http.Client
}

func NewInfisical(token, projectID, env, apiBase, secretPath string) *InfisicalDriver {
	if apiBase == "" {
		apiBase = "https://app.infisical.com"
	}
	if secretPath == "" {
		secretPath = "/podmaker"
	}
	return &InfisicalDriver{
		Token: token, ProjectID: projectID, Environment: env,
		APIBase: strings.TrimRight(apiBase, "/"), SecretPath: secretPath,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (i *InfisicalDriver) Slug() string { return "infisical" }

func (i *InfisicalDriver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.APIBase+"/api/v1/identity-access-token/me", nil)
	req.Header.Set("Authorization", "Bearer "+i.Token)
	resp, err := i.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("infisical ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (i *InfisicalDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	name := infisicalName(path)
	q := url.Values{}
	q.Set("workspaceId", i.ProjectID)
	q.Set("environment", i.Environment)
	q.Set("secretPath", i.SecretPath)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.APIBase+"/api/v3/secrets/raw/"+name+"?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+i.Token)
	resp, err := i.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("infisical read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	if body.Secret.SecretValue == "" {
		return nil, false, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(body.Secret.SecretValue), &out); err != nil {
		return map[string]any{"value": body.Secret.SecretValue}, true, nil
	}
	return out, true, nil
}

func (i *InfisicalDriver) Write(ctx context.Context, path string, data map[string]any) error {
	name := infisicalName(path)
	body, _ := json.Marshal(map[string]any{
		"workspaceId": i.ProjectID, "environment": i.Environment, "secretPath": i.SecretPath,
		"secretValue": mustJSON(data), "type": "shared",
	})
	urlStr := i.APIBase + "/api/v3/secrets/raw/" + name
	// PATCH upserts; 404 → POST creates.
	if err := i.send(ctx, http.MethodPatch, urlStr, body); err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return i.send(ctx, http.MethodPost, urlStr, body)
		}
		return err
	}
	return nil
}

func (i *InfisicalDriver) Delete(ctx context.Context, path string) error {
	name := infisicalName(path)
	q := url.Values{}
	q.Set("workspaceId", i.ProjectID)
	q.Set("environment", i.Environment)
	q.Set("secretPath", i.SecretPath)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, i.APIBase+"/api/v3/secrets/raw/"+name+"?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+i.Token)
	resp, err := i.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("infisical delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (i *InfisicalDriver) send(ctx context.Context, method, urlStr string, body []byte) error {
	req, _ := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+i.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("infisical %s %s HTTP %d: %s", method, urlStr, resp.StatusCode, raw)
	}
	return nil
}

var infisicalSanitise = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func infisicalName(path string) string {
	s := infisicalSanitise.ReplaceAllString(strings.TrimLeft(path, "/"), "_")
	return strings.Trim(strings.ToUpper(s), "_")
}
