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

// OnePasswordConnectDriver — items in a 1Password Connect vault.
// Each PodMaker path is one item; the map keys become CONCEALED
// fields on the item. Lookups go by title filter.
type OnePasswordConnectDriver struct {
	ConnectHost string
	Token       string
	VaultID     string
	Category    string
	Client      *http.Client
}

func New1PConnect(host, token, vaultID, category string) *OnePasswordConnectDriver {
	if category == "" {
		category = "SECURE_NOTE"
	}
	return &OnePasswordConnectDriver{
		ConnectHost: strings.TrimRight(host, "/"),
		Token:       token, VaultID: vaultID, Category: category,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (o *OnePasswordConnectDriver) Slug() string { return "1password-connect" }

func (o *OnePasswordConnectDriver) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.ConnectHost+"/v1/vaults", nil)
	o.auth(req)
	resp, err := o.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("1password ping HTTP %d", resp.StatusCode)
	}
	return nil
}

func (o *OnePasswordConnectDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	id, ok, err := o.lookupItemID(ctx, path)
	if err != nil || !ok {
		return nil, ok, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.ConnectHost+"/v1/vaults/"+o.VaultID+"/items/"+id, nil)
	o.auth(req)
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("1password read %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	var body struct {
		Fields []struct {
			Label string `json:"label"`
			Value any    `json:"value"`
		} `json:"fields"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, err
	}
	out := map[string]any{}
	for _, f := range body.Fields {
		if f.Label == "" || f.Label == "notesPlain" {
			continue
		}
		out[f.Label] = f.Value
	}
	return out, true, nil
}

func (o *OnePasswordConnectDriver) Write(ctx context.Context, path string, data map[string]any) error {
	fields := make([]map[string]any, 0, len(data))
	for k, v := range data {
		val := ""
		switch t := v.(type) {
		case string:
			val = t
		case nil:
		default:
			b, _ := json.Marshal(v)
			val = string(b)
		}
		fields = append(fields, map[string]any{
			"label": k, "type": "CONCEALED", "value": val,
		})
	}
	payload := map[string]any{
		"vault":    map[string]any{"id": o.VaultID},
		"category": o.Category,
		"title":    path,
		"fields":   fields,
	}
	body, _ := json.Marshal(payload)

	id, ok, err := o.lookupItemID(ctx, path)
	if err != nil {
		return err
	}
	method := http.MethodPost
	urlStr := o.ConnectHost + "/v1/vaults/" + o.VaultID + "/items"
	if ok {
		method = http.MethodPut
		urlStr += "/" + id
	}
	req, _ := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	o.auth(req)
	resp, err := o.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("1password write %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (o *OnePasswordConnectDriver) Delete(ctx context.Context, path string) error {
	id, ok, err := o.lookupItemID(ctx, path)
	if err != nil || !ok {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, o.ConnectHost+"/v1/vaults/"+o.VaultID+"/items/"+id, nil)
	o.auth(req)
	resp, err := o.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("1password delete %s HTTP %d: %s", path, resp.StatusCode, raw)
	}
	return nil
}

func (o *OnePasswordConnectDriver) lookupItemID(ctx context.Context, title string) (string, bool, error) {
	q := url.Values{}
	q.Set("filter", `title eq "`+strings.ReplaceAll(title, `"`, `\"`)+`"`)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.ConnectHost+"/v1/vaults/"+o.VaultID+"/items?"+q.Encode(), nil)
	o.auth(req)
	resp, err := o.Client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("1password lookup HTTP %d: %s", resp.StatusCode, raw)
	}
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return "", false, err
	}
	if len(items) == 0 {
		return "", false, nil
	}
	return items[0].ID, true, nil
}

func (o *OnePasswordConnectDriver) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+o.Token)
	req.Header.Set("Accept", "application/json")
}
