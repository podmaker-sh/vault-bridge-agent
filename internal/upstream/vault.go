package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VaultDriver covers OpenBao + HashiCorp Vault (KV v2). The REST
// surface is the same: GET/PUT /v1/<mount>/data/<path>,
// DELETE /v1/<mount>/metadata/<path>, GET /v1/sys/health.
type VaultDriver struct {
	Endpoint  string
	Token     string
	KVMount   string
	Namespace string
	Client    *http.Client
	slug      string
}

func NewVault(slug, endpoint, token, kvMount, namespace string) *VaultDriver {
	if kvMount == "" {
		kvMount = "secret"
	}
	return &VaultDriver{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Token:     token,
		KVMount:   kvMount,
		Namespace: namespace,
		Client:    &http.Client{Timeout: 15 * time.Second},
		slug:      slug,
	}
}

func (d *VaultDriver) Slug() string { return d.slug }

func (d *VaultDriver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.Endpoint+"/v1/sys/health", nil)
	d.addHeaders(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Vault returns 200 / 429 / 472 / 473 to encode various active/
	// standby/dr states — every <500 is "alive".
	if resp.StatusCode >= 500 {
		return fmt.Errorf("vault ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *VaultDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.dataURI(path), nil)
	d.addHeaders(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("vault read %s: HTTP %d", path, resp.StatusCode)
	}
	var body struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("vault read %s: decode: %w", path, err)
	}
	return body.Data.Data, true, nil
}

func (d *VaultDriver) Write(ctx context.Context, path string, data map[string]any) error {
	payload, _ := json.Marshal(map[string]any{"data": data})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, d.dataURI(path), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	d.addHeaders(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("vault write %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

func (d *VaultDriver) Delete(ctx context.Context, path string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, d.metadataURI(path), nil)
	d.addHeaders(req)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("vault delete %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

func (d *VaultDriver) addHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Vault-Token", d.Token)
	if d.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.Namespace)
	}
}

func (d *VaultDriver) dataURI(path string) string {
	return d.Endpoint + "/v1/" + d.KVMount + "/data/" + strings.TrimLeft(path, "/")
}

func (d *VaultDriver) metadataURI(path string) string {
	return d.Endpoint + "/v1/" + d.KVMount + "/metadata/" + strings.TrimLeft(path, "/")
}
