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
	"time"
)

// PulumiESCDriver — Pulumi ESC (Environments, Secrets, and
// Configuration). One PodMaker path = one environment value
// inside the configured environment, written via the open API.
type PulumiESCDriver struct {
	Token        string
	Organization string
	Environment  string
	APIBase      string
	Client       *http.Client
}

func NewPulumiESC(token, org, env, apiBase string) *PulumiESCDriver {
	if apiBase == "" {
		apiBase = "https://api.pulumi.com"
	}
	return &PulumiESCDriver{
		Token: token, Organization: org, Environment: env,
		APIBase: strings.TrimRight(apiBase, "/"),
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (p *PulumiESCDriver) Slug() string { return "pulumi-esc" }

func (p *PulumiESCDriver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.APIBase+"/api/user", nil)
	req.Header.Set("Authorization", "token "+p.Token)
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pulumi-esc ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (p *PulumiESCDriver) endpoint(path string) string {
	return fmt.Sprintf("%s/api/esc/environments/%s/%s/values/%s",
		p.APIBase,
		url.PathEscape(p.Organization),
		url.PathEscape(p.Environment),
		url.PathEscape(strings.ReplaceAll(strings.TrimLeft(path, "/"), "/", ".")),
	)
}

func (p *PulumiESCDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint(path), nil)
	req.Header.Set("Authorization", "token "+p.Token)
	req.Header.Set("Accept", "application/vnd.pulumi+8")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("pulumi-esc read %s HTTP %d: %s", path, resp.StatusCode, raw)
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

func (p *PulumiESCDriver) Write(ctx context.Context, path string, data map[string]any) error {
	val, _ := json.Marshal(data)
	payload, _ := json.Marshal(map[string]any{"value": string(val), "secret": true})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint(path), bytes.NewReader(payload))
	req.Header.Set("Authorization", "token "+p.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pulumi-esc write %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (p *PulumiESCDriver) Delete(ctx context.Context, path string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, p.endpoint(path), nil)
	req.Header.Set("Authorization", "token "+p.Token)
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pulumi-esc delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

// PulumiESC tokens have no expiry; cache map placeholder kept off
// the driver since we always use the static token verbatim.
var _ = time.Now
