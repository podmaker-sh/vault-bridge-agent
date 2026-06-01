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

// DopplerDriver — Doppler API (https://api.doppler.com). One
// PodMaker path folds into a single Doppler secret per
// (project,config). The map value is JSON-encoded.
type DopplerDriver struct {
	Token   string
	Project string
	Config  string
	APIBase string
	Client  *http.Client
}

func NewDoppler(token, project, config, apiBase string) *DopplerDriver {
	if apiBase == "" {
		apiBase = "https://api.doppler.com"
	}
	return &DopplerDriver{
		Token: token, Project: project, Config: config, APIBase: strings.TrimRight(apiBase, "/"),
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (d *DopplerDriver) Slug() string { return "doppler" }

func (d *DopplerDriver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.APIBase+"/v3/me", nil)
	d.auth(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("doppler ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *DopplerDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	q := url.Values{}
	q.Set("project", d.Project)
	q.Set("config", d.Config)
	q.Set("name", dopplerName(path))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.APIBase+"/v3/configs/config/secret?"+q.Encode(), nil)
	d.auth(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("doppler read %s: HTTP %d: %s", path, resp.StatusCode, body)
	}
	var body struct {
		Value struct {
			Raw string `json:"raw"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	if body.Value.Raw == "" {
		return nil, false, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(body.Value.Raw), &out); err != nil {
		return map[string]any{"value": body.Value.Raw}, true, nil
	}
	return out, true, nil
}

func (d *DopplerDriver) Write(ctx context.Context, path string, data map[string]any) error {
	payload, _ := json.Marshal(map[string]any{
		"project": d.Project, "config": d.Config,
		"secrets": map[string]any{dopplerName(path): mustJSON(data)},
	})
	return d.post(ctx, d.APIBase+"/v3/configs/config/secrets", payload)
}

func (d *DopplerDriver) Delete(ctx context.Context, path string) error {
	// Doppler "delete" = upsert with null value.
	payload, _ := json.Marshal(map[string]any{
		"project": d.Project, "config": d.Config,
		"secrets": map[string]any{dopplerName(path): nil},
	})
	return d.post(ctx, d.APIBase+"/v3/configs/config/secrets", payload)
}

func (d *DopplerDriver) post(ctx context.Context, urlStr string, body []byte) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	d.auth(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("doppler %s HTTP %d: %s", urlStr, resp.StatusCode, raw)
	}
	return nil
}

func (d *DopplerDriver) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Accept", "application/json")
}

var dopplerSanitise = regexp.MustCompile(`[^A-Za-z0-9]`)

// Doppler secret names: ^[A-Z0-9_]+$.
func dopplerName(path string) string {
	s := dopplerSanitise.ReplaceAllString(strings.TrimLeft(path, "/"), "_")
	return strings.Trim(strings.ToUpper(s), "_")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
