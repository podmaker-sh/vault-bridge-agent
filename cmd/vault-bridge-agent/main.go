// Command vault-bridge-agent proxies PodMaker control-plane vault
// calls to a vault that lives inside the customer's own network.
//
// The control plane never connects to the vault directly — it
// pushes a request envelope onto a per-bridge Redis queue, this
// agent long-polls the control plane, runs the call against the
// upstream vault, and posts the result back. Every envelope is
// scoped to a single workspace (bridge_id ULID), so a compromised
// bridge token cannot cross tenant boundaries.
//
// Required environment:
//
//	PODMAKER_BRIDGE_ID         ULID of the registered bridge row
//	PODMAKER_BRIDGE_TOKEN      bearer presented on every CP call
//	PODMAKER_CP_URL            control-plane base URL (https://app…)
//	PODMAKER_UPSTREAM_TYPE     one of: openbao, hashicorp-vault,
//	                            aws-sm, gcp-sm, azure-kv, doppler,
//	                            infisical, 1password-connect
//
// Per-upstream env vars (see buildDriver below for the full list).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"

	"podmaker.sh/vault-bridge-agent/internal/clientcert"
	"podmaker.sh/vault-bridge-agent/internal/crl"
	"podmaker.sh/vault-bridge-agent/internal/metrics"
	"podmaker.sh/vault-bridge-agent/internal/poll"
	"podmaker.sh/vault-bridge-agent/internal/selfupdate"
	"podmaker.sh/vault-bridge-agent/internal/upstream"
)

// Injected at build time via `-ldflags="-X main.version=..."`.
// Defaults to "dev" so a plain `go run` still works.
var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	logger.Info("vault-bridge-agent starting", "version", version)

	bridgeID := must("PODMAKER_BRIDGE_ID")
	token := must("PODMAKER_BRIDGE_TOKEN")
	cpURL := must("PODMAKER_CP_URL")
	upType := envOr("PODMAKER_UPSTREAM_TYPE", "openbao")

	driver, err := buildDriver(upType)
	if err != nil {
		logger.Error("upstream driver", "err", err)
		os.Exit(1)
	}
	logger.Info("upstream", "type", upType, "slug", driver.Slug())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	metricsAddr := envOr("PODMAKER_BRIDGE_METRICS_ADDR", "127.0.0.1:7768")
	metrics.SetCurrentVersion(version)
	go metrics.Serve(ctx, metricsAddr, logger)

	// Auto-update: poll the CP manifest hourly + replace the binary
	// when a newer build on the configured channel ships. Gated off
	// on Windows / containers / read-only installs (see package
	// docstring for the full skip matrix).
	if envOr("PODMAKER_BRIDGE_AUTO_UPDATE", "1") == "1" {
		binPath, _ := os.Executable()
		suCfg := selfupdate.Config{
			CurrentVersion: version,
			Channel:        envOr("PODMAKER_BRIDGE_CHANNEL", "stable"),
			BridgeID:       bridgeID,
			BearerToken:    token,
			ControlPlane:   cpURL,
			BinaryPath:     binPath,
			PollEvery:      time.Hour,
			Logger:         logger,
		}
		// Crash-loop guard. Fires inside the first 5 minutes of a
		// post-upgrade boot: if the marker is older than that, the
		// previous run died mid-flight and we revert.
		selfupdate.CheckPostUpgrade(ctx, suCfg)
		go selfupdate.Run(ctx, suCfg)
	}

	// mTLS: provision (or reload) a client cert and switch the
	// shared HTTP client over to the mTLS transport. The bearer
	// stays as the authn for the initial /cert call + as a
	// belt-and-braces second factor for poll/respond/heartbeat.
	certDir := envOr("PODMAKER_BRIDGE_CERT_DIR", defaultCertDir())
	bundle, err := clientcert.Provision(ctx, clientcert.Config{
		Dir:          certDir,
		BridgeID:     bridgeID,
		BearerToken:  token,
		ControlPlane: cpURL,
		Logger:       logger,
	})
	if err != nil {
		logger.Error("clientcert provision", "err", err)
		os.Exit(1)
	}
	if fp := bundle.Fingerprint.Load(); fp != nil {
		logger.Info("clientcert ready", "fingerprint", *fp, "not_after", bundle.NotAfter.Load())
	}
	go bundle.Renew(ctx, clientcert.Config{
		Dir:          certDir,
		BridgeID:     bridgeID,
		BearerToken:  token,
		ControlPlane: cpURL,
		Logger:       logger,
	})
	// Workspace-scoped CRL watcher. The TLS transport calls
	// watcher.IsRevoked() during the handshake, so a refresh has
	// to happen at least once before the first vault call. The
	// Run() goroutine refreshes hourly afterwards.
	//
	// Bootstrap order:
	//   1. Build CRL watcher (may be nil if no workspace_id on disk yet)
	//   2. Wire it into HTTPSTransport so handshakes reject revoked peers
	//   3. Spawn Run() to refresh in the background
	var revoker clientcert.RevocationChecker
	var watcher *crl.Watcher
	if workspaceID := clientcert.WorkspaceIDFromDisk(certDir); workspaceID != "" {
		watcher = crl.New(workspaceID, cpURL)
		watcher.Logger = logger
		revoker = watcher
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: bundle.HTTPSTransport(nil, revoker),
	}

	if watcher != nil {
		// Watcher reuses the now-built httpClient so its own poll
		// uses the same mTLS bundle.
		watcher.HTTP = httpClient
		go watcher.Run(ctx, time.Hour)
	}

	cfg := poll.Config{
		BridgeID:       bridgeID,
		Token:          token,
		AgentVersion:   version,
		ControlPlane:   cpURL,
		PollTimeout:    25 * time.Second,
		HeartbeatEvery: 30 * time.Second,
		MinBackoff:     time.Second,
		MaxBackoff:     60 * time.Second,
		HTTP:           httpClient,
		Dispatcher:     &upstream.Dispatcher{Driver: driver},
		Logger:         logger,
	}

	if err := poll.Run(ctx, cfg); err != nil {
		logger.Error("poll loop", "err", err)
		os.Exit(1)
	}
	logger.Info("vault-bridge-agent stopped")
}

func buildDriver(typ string) (upstream.Driver, error) {
	switch typ {
	case "openbao", "hashicorp-vault":
		return upstream.NewVault(
			typ,
			must("PODMAKER_UPSTREAM_ENDPOINT"),
			must("PODMAKER_UPSTREAM_TOKEN"),
			envOr("PODMAKER_UPSTREAM_KV_MOUNT", "secret"),
			os.Getenv("PODMAKER_UPSTREAM_NAMESPACE"),
		), nil

	case "doppler":
		return upstream.NewDoppler(
			must("PODMAKER_UPSTREAM_TOKEN"),
			must("PODMAKER_UPSTREAM_PROJECT"),
			must("PODMAKER_UPSTREAM_CONFIG"),
			envOr("PODMAKER_UPSTREAM_API_BASE", ""),
		), nil

	case "infisical":
		return upstream.NewInfisical(
			must("PODMAKER_UPSTREAM_TOKEN"),
			must("PODMAKER_UPSTREAM_PROJECT_ID"),
			envOr("PODMAKER_UPSTREAM_ENVIRONMENT", "prod"),
			envOr("PODMAKER_UPSTREAM_API_BASE", ""),
			envOr("PODMAKER_UPSTREAM_SECRET_PATH", ""),
		), nil

	case "1password-connect":
		return upstream.New1PConnect(
			must("PODMAKER_UPSTREAM_CONNECT_HOST"),
			must("PODMAKER_UPSTREAM_TOKEN"),
			must("PODMAKER_UPSTREAM_VAULT_ID"),
			envOr("PODMAKER_UPSTREAM_CATEGORY", "SECURE_NOTE"),
		), nil

	case "gcp-sm":
		return upstream.NewGCPSecretManager(
			must("PODMAKER_UPSTREAM_PROJECT_ID"),
			must("PODMAKER_UPSTREAM_SERVICE_ACCOUNT_JSON"),
		), nil

	case "azure-kv":
		return upstream.NewAzureKeyVault(
			must("PODMAKER_UPSTREAM_VAULT_URL"),
			must("PODMAKER_UPSTREAM_TENANT_ID"),
			must("PODMAKER_UPSTREAM_CLIENT_ID"),
			must("PODMAKER_UPSTREAM_CLIENT_SECRET"),
		), nil

	case "akeyless":
		return upstream.NewAkeyless(
			must("PODMAKER_UPSTREAM_ACCESS_ID"),
			must("PODMAKER_UPSTREAM_ACCESS_KEY"),
			envOr("PODMAKER_UPSTREAM_API_BASE", ""),
		), nil

	case "aws-ssm":
		region := envFirst("PODMAKER_UPSTREAM_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
		ak := envFirst("PODMAKER_UPSTREAM_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
		sk := envFirst("PODMAKER_UPSTREAM_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
		st := envFirst("PODMAKER_UPSTREAM_SESSION_TOKEN", "AWS_SESSION_TOKEN")
		if region == "" || ak == "" || sk == "" {
			return nil, fmt.Errorf("aws-ssm: region + access keys required")
		}
		return upstream.NewAWSSSM(region, ak, sk, st, os.Getenv("PODMAKER_UPSTREAM_PATH_PREFIX")), nil

	case "bitwarden-sm":
		return upstream.NewBitwardenSM(
			must("PODMAKER_UPSTREAM_ACCESS_TOKEN"),
			must("PODMAKER_UPSTREAM_ORGANIZATION_ID"),
			must("PODMAKER_UPSTREAM_PROJECT_ID"),
			envOr("PODMAKER_UPSTREAM_IDENTITY_URL", ""),
			envOr("PODMAKER_UPSTREAM_API_URL", ""),
		), nil

	case "conjur":
		return upstream.NewConjur(
			must("PODMAKER_UPSTREAM_APPLIANCE_URL"),
			must("PODMAKER_UPSTREAM_ACCOUNT"),
			must("PODMAKER_UPSTREAM_LOGIN"),
			must("PODMAKER_UPSTREAM_API_KEY"),
		), nil

	case "pulumi-esc":
		return upstream.NewPulumiESC(
			must("PODMAKER_UPSTREAM_TOKEN"),
			must("PODMAKER_UPSTREAM_ORGANIZATION"),
			must("PODMAKER_UPSTREAM_ENVIRONMENT"),
			envOr("PODMAKER_UPSTREAM_API_BASE", ""),
		), nil

	case "keeper-sm":
		return upstream.NewKeeperSM(
			must("PODMAKER_UPSTREAM_CONFIG_JSON"),
			os.Getenv("PODMAKER_UPSTREAM_FOLDER_UID"),
		), nil

	case "aws-sm":
		// Accept the prefixed env vars first, then fall back to
		// the standard AWS_* names that wrappers like
		// `aws-vault exec` set automatically. Lets the operator
		// pipe credentials in without re-exporting:
		//
		//   aws-vault exec prod -- podmaker-vault-bridge
		region := envFirst("PODMAKER_UPSTREAM_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
		ak := envFirst("PODMAKER_UPSTREAM_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
		sk := envFirst("PODMAKER_UPSTREAM_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
		st := envFirst("PODMAKER_UPSTREAM_SESSION_TOKEN", "AWS_SESSION_TOKEN")
		if region == "" {
			return nil, fmt.Errorf("aws-sm: region required (PODMAKER_UPSTREAM_REGION or AWS_REGION)")
		}
		if ak == "" || sk == "" {
			return nil, fmt.Errorf("aws-sm: credentials required (PODMAKER_UPSTREAM_ACCESS_KEY_ID/SECRET_ACCESS_KEY or AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY — `aws-vault exec PROFILE` sets these)")
		}
		return upstream.NewAWSSecretsManager(region, ak, sk, st), nil

	default:
		return nil, fmt.Errorf("unsupported PODMAKER_UPSTREAM_TYPE %q (supported: openbao, hashicorp-vault, aws-sm, aws-ssm, gcp-sm, azure-kv, doppler, infisical, 1password-connect, akeyless, bitwarden-sm, conjur, pulumi-esc, keeper-sm)", typ)
	}
}

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("env required", "key", k)
		os.Exit(1)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envFirst returns the first non-empty value among the listed env
// keys. Used so the agent can prefer its own PODMAKER_UPSTREAM_*
// vars while accepting the standard provider-side names (AWS_*,
// GCP_*, AZURE_*) when an outer wrapper has already set them.
func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func defaultCertDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home + "/.podmaker-bridge"
	}
	return "./.podmaker-bridge"
}
