//go:build keeper_sdk

// This file is compiled only when the agent is built with
// `-tags=keeper_sdk`. It pulls in the official Keeper Secrets
// Manager Go SDK + replaces the stub Read/Write/Delete bodies in
// keeper_sm.go via Go's link-time replace.
//
// Default builds skip this file so the binary stays light. The
// SDK pulls in BoringSSL-flavoured crypto + protobuf which roughly
// doubles the binary size — operators who actually use Keeper opt
// in:
//
//   go build -tags=keeper_sdk ./cmd/vault-bridge-agent
//
// To activate inside the release pipeline, set BRIDGE_BUILD_TAGS=keeper_sdk
// before invoking `make bridge-release`.
//
// SDK source: https://github.com/Keeper-Security/secrets-manager-go
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

// init swaps the stub-returning methods on *KeeperSMDriver with
// the SDK-backed implementations. The package-level vars below
// hold function pointers the methods consult; the tagless build
// leaves them nil and the stubs return ErrKeeperSDKMissing.
func init() {
	keeperRead = keeperReadSDK
	keeperWrite = keeperWriteSDK
	keeperDelete = keeperDeleteSDK
	keeperPing = keeperPingSDK
}

func newKeeperClient(configJSON string) (*ksm.SecretsManager, error) {
	if configJSON == "" {
		return nil, errors.New("keeper-sm: config_json required")
	}
	cfg := ksm.NewMemoryKeyValueStorage()
	if err := cfg.LoadStorageBuffer([]byte(configJSON)); err != nil {
		return nil, fmt.Errorf("keeper-sm: load config: %w", err)
	}
	return ksm.NewSecretsManager(&ksm.ClientOptions{Config: cfg}), nil
}

func keeperPingSDK(_ context.Context, k *KeeperSMDriver) error {
	c, err := newKeeperClient(k.ConfigJSON)
	if err != nil {
		return err
	}
	_, err = c.GetSecrets([]string{})
	return err
}

// Keeper records map naturally onto a path of the form
// `<title>` (or `<folderUID>/<title>` when FolderUID is set). We
// match on the record title — Keeper requires unique titles
// inside a folder so the lookup is deterministic.
func keeperReadSDK(_ context.Context, k *KeeperSMDriver, path string) (map[string]any, bool, error) {
	c, err := newKeeperClient(k.ConfigJSON)
	if err != nil {
		return nil, false, err
	}
	records, err := c.GetSecrets([]string{})
	if err != nil {
		return nil, false, fmt.Errorf("keeper-sm: GetSecrets: %w", err)
	}
	wanted := strings.TrimLeft(path, "/")
	for _, r := range records {
		if r.Title() != wanted {
			continue
		}
		out := map[string]any{}
		for _, f := range r.GetFields() {
			vals := f.GetValue()
			if len(vals) == 0 {
				continue
			}
			b, _ := json.Marshal(vals[0])
			out[f.GetLabel()] = json.RawMessage(b)
		}
		return out, true, nil
	}
	return nil, false, nil
}

func keeperWriteSDK(_ context.Context, k *KeeperSMDriver, path string, data map[string]any) error {
	c, err := newKeeperClient(k.ConfigJSON)
	if err != nil {
		return err
	}
	records, err := c.GetSecrets([]string{})
	if err != nil {
		return fmt.Errorf("keeper-sm: GetSecrets: %w", err)
	}
	wanted := strings.TrimLeft(path, "/")
	for _, r := range records {
		if r.Title() != wanted {
			continue
		}
		// Replace the rawJSON value of every named field.
		raw, _ := json.Marshal(data)
		r.SetRawValue("custom", string(raw))
		return c.Save(r)
	}
	return fmt.Errorf("keeper-sm: record %q not found; create it from the Keeper console first", wanted)
}

func keeperDeleteSDK(_ context.Context, _ *KeeperSMDriver, _ string) error {
	// Keeper SDK does not expose record-delete; operators delete
	// from the Keeper console. We succeed silently so the orchestrator
	// cleanup path does not block.
	return nil
}
