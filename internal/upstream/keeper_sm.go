package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// KeeperSMDriver — Keeper Secrets Manager. The native protocol is
// mTLS + AES-GCM bound to client keys, which would pull in a
// heavyweight SDK (BoringSSL flavours + protobuf). The driver
// keeps that SDK behind the `keeper_sdk` build tag — the default
// agent build ships without it and the Read/Write/Delete bodies
// return `ErrKeeperSDKMissing`. Operators that need Keeper rebuild
// the agent with:
//
//	go build -tags=keeper_sdk ./cmd/vault-bridge-agent
//
// The tagged file keeper_sm_sdk.go overrides the function
// pointers below at init() time.
type KeeperSMDriver struct {
	ConfigJSON string
	FolderUID  string
	Hostname   string
}

func NewKeeperSM(configJSON, folderUID string) *KeeperSMDriver {
	hostname := "keepersecurity.com"
	if configJSON != "" {
		var parsed struct {
			Hostname string `json:"hostname"`
		}
		if json.Unmarshal([]byte(configJSON), &parsed) == nil && parsed.Hostname != "" {
			hostname = parsed.Hostname
		}
	}
	return &KeeperSMDriver{
		ConfigJSON: configJSON,
		FolderUID:  folderUID,
		Hostname:   strings.TrimPrefix(strings.TrimPrefix(hostname, "https://"), "http://"),
	}
}

func (k *KeeperSMDriver) Slug() string { return "keeper-sm" }

// ErrKeeperSDKMissing is returned by every CRUD method when the
// agent is built without the `keeper_sdk` tag. Surfaces clearly
// in audit logs + bridge response envelopes.
var ErrKeeperSDKMissing = errors.New("keeper-sm: native SDK not linked into this build (rebuild with -tags=keeper_sdk)")

// Function pointers — the SDK-tagged file fills these in. Default
// build leaves them nil and the wrappers return the sentinel.
var (
	keeperRead   func(context.Context, *KeeperSMDriver, string) (map[string]any, bool, error)
	keeperWrite  func(context.Context, *KeeperSMDriver, string, map[string]any) error
	keeperDelete func(context.Context, *KeeperSMDriver, string) error
	keeperPing   func(context.Context, *KeeperSMDriver) error
)

func (k *KeeperSMDriver) Ping(ctx context.Context) error {
	if keeperPing != nil {
		return keeperPing(ctx, k)
	}
	if k.ConfigJSON == "" {
		return errors.New("keeper-sm: config_json required")
	}
	return nil
}

func (k *KeeperSMDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	if keeperRead != nil {
		return keeperRead(ctx, k, path)
	}
	return nil, false, fmt.Errorf("%w (path=%s)", ErrKeeperSDKMissing, path)
}

func (k *KeeperSMDriver) Write(ctx context.Context, path string, data map[string]any) error {
	if keeperWrite != nil {
		return keeperWrite(ctx, k, path, data)
	}
	return fmt.Errorf("%w (path=%s)", ErrKeeperSDKMissing, path)
}

func (k *KeeperSMDriver) Delete(ctx context.Context, path string) error {
	if keeperDelete != nil {
		return keeperDelete(ctx, k, path)
	}
	return fmt.Errorf("%w (path=%s)", ErrKeeperSDKMissing, path)
}
