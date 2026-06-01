// Package selfupdate keeps the running binary on the channel its
// operator picked. Once an hour it polls
//
//     GET <cp>/install/vault-bridge/manifest.json?channel=<channel>
//
// and, when the advertised latest_version differs from the running
// version, downloads the platform-matching tarball, verifies the
// SHA-256 + (when present) the cosign signature, atomically swaps
// the on-disk binary, and re-execs into the new image.
//
// Conservative defaults:
//
//   - skipped entirely if the binary is not writable by the running
//     user (e.g. installed under /usr/local/bin owned by root)
//   - skipped when running inside a container (the container image
//     is the source of truth)
//   - skipped on Windows (NSSM / MSI manages the service binary)
//   - one upgrade attempt per poll cycle; failures back off
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	bridgemetrics "podmaker.sh/vault-bridge-agent/internal/metrics"
)

type Config struct {
	CurrentVersion string
	Channel        string // stable | beta | nightly
	BridgeID       string // sent to the manifest endpoint for per-bridge pin
	BearerToken    string // used for the update-report callback
	ControlPlane   string
	BinaryPath     string // os.Executable() result
	HTTP           *http.Client
	PollEvery      time.Duration
	Logger         *slog.Logger
}

type manifest struct {
	Channel       string `json:"channel"`
	LatestVersion string `json:"latest_version"`
	Assets        map[string]struct {
		Tarball string `json:"tarball"`
		Sha256  string `json:"sha256"`
		Cosign  string `json:"cosign"`
	} `json:"assets"`
}

// Run blocks until the context is cancelled. Returns immediately
// when auto-update is disabled for this platform/install.
func Run(ctx context.Context, cfg Config) {
	if !applicable(cfg) {
		cfg.Logger.Info("selfupdate: skipped", "reason", skipReason(cfg))
		return
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = time.Hour
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Channel == "" {
		cfg.Channel = "stable"
	}
	t := time.NewTimer(time.Minute) // first probe after 1m, not at boot
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(cfg.PollEvery)
		}
		if err := pollAndMaybeUpgrade(ctx, cfg); err != nil {
			cfg.Logger.Warn("selfupdate: probe failed", "err", err)
		}
	}
}

func pollAndMaybeUpgrade(ctx context.Context, cfg Config) error {
	bridgemetrics.SelfUpdateChecksTotal.Inc()
	url := strings.TrimRight(cfg.ControlPlane, "/") +
		"/install/vault-bridge/manifest.json?channel=" + cfg.Channel +
		"&bridge_id=" + cfg.BridgeID
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	var m manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return fmt.Errorf("manifest decode: %w", err)
	}
	if m.LatestVersion == "" || m.LatestVersion == cfg.CurrentVersion || m.LatestVersion == "latest" {
		return nil
	}

	platform := runtime.GOOS + "-" + runtime.GOARCH
	asset, ok := m.Assets[platform]
	if !ok {
		return fmt.Errorf("manifest has no asset for %s", platform)
	}

	cfg.Logger.Info("selfupdate: upgrading",
		"from", cfg.CurrentVersion,
		"to", m.LatestVersion,
		"channel", cfg.Channel,
	)

	tmp, err := downloadAndVerify(ctx, cfg, asset.Tarball, asset.Sha256, platform)
	if err != nil {
		reportOutcome(ctx, cfg, "failure", m.LatestVersion, err.Error())
		return fmt.Errorf("download/verify: %w", err)
	}
	defer os.Remove(tmp)

	// Back up the current binary alongside it so the next boot can
	// detect a crash loop and roll back.
	backupPath := cfg.BinaryPath + ".previous"
	_ = copyFile(cfg.BinaryPath, backupPath)

	if err := atomicReplace(cfg.BinaryPath, tmp); err != nil {
		reportOutcome(ctx, cfg, "failure", m.LatestVersion, err.Error())
		return fmt.Errorf("replace: %w", err)
	}
	// Drop a marker the next boot will look for. If it survives
	// past the first-success window, the previous backup is
	// considered safe to retire.
	_ = os.WriteFile(cfg.BinaryPath+".pending",
		[]byte(fmt.Sprintf("from=%s\nto=%s\nat=%d\n", cfg.CurrentVersion, m.LatestVersion, time.Now().Unix())),
		0o644)

	reportOutcome(ctx, cfg, "success", m.LatestVersion, "")
	cfg.Logger.Info("selfupdate: binary replaced — re-execing")
	return reexec(cfg.BinaryPath)
}

// CheckPostUpgrade runs once at boot. If the previous run died
// before clearing `<binary>.pending`, we treat that as a crash on
// the new build and revert to `<binary>.previous`. Successful boots
// clear both files.
func CheckPostUpgrade(ctx context.Context, cfg Config) {
	if !applicable(cfg) {
		return
	}
	pending := cfg.BinaryPath + ".pending"
	previous := cfg.BinaryPath + ".previous"

	stat, err := os.Stat(pending)
	if err != nil {
		return
	}
	// First boot after an upgrade: schedule a deferred "we made
	// it" cleanup. If we crash before that, the next start sees
	// the pending marker and rolls back.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Minute):
			os.Remove(pending)
			os.Remove(previous)
			cfg.Logger.Info("selfupdate: upgrade declared healthy", "pending_age", time.Since(stat.ModTime()))
		}
	}()

	// On a startup where the pending marker is older than 5
	// minutes the previous instance presumably crash-looped past
	// systemd's restart cap. Roll back.
	if time.Since(stat.ModTime()) > 5*time.Minute {
		cfg.Logger.Warn("selfupdate: pending marker is stale — rolling back to previous binary")
		if err := atomicReplace(cfg.BinaryPath, previous); err == nil {
			os.Remove(pending)
			reportOutcome(ctx, cfg, "reverted", cfg.CurrentVersion, "pending marker stale; previous binary restored")
			_ = reexec(cfg.BinaryPath)
		}
	}
}

func reportOutcome(ctx context.Context, cfg Config, status, toVersion, errMsg string) {
	bridgemetrics.SelfUpdateOutcomeTotal.WithLabelValues(status).Inc()
	if cfg.BridgeID == "" || cfg.BearerToken == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"status":       status,
		"from_version": cfg.CurrentVersion,
		"to_version":   toVersion,
		"error":        errMsg,
	})
	url := strings.TrimRight(cfg.ControlPlane, "/") +
		"/api/v1/vault-bridges/" + cfg.BridgeID + "/update-report"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := cfg.HTTP.Do(req); err == nil {
		resp.Body.Close()
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func downloadAndVerify(ctx context.Context, cfg Config, tarballURL, shaURL, platform string) (string, error) {
	// 1. SHA from CP
	expected, err := fetchHex(ctx, cfg.HTTP, shaURL)
	if err != nil {
		return "", fmt.Errorf("sha fetch: %w", err)
	}

	// 2. Tarball
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("tarball HTTP %d", resp.StatusCode)
	}

	tmpTar, err := os.CreateTemp("", "hm-bridge-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpTar.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpTar, h), resp.Body); err != nil {
		tmpTar.Close()
		return "", err
	}
	tmpTar.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != expected {
		return "", fmt.Errorf("sha256 mismatch: got %s want %s", got, expected)
	}

	// 3. Extract the platform-matching binary
	binTarget := "podmaker-vault-bridge-" + platform
	if runtime.GOOS == "windows" {
		binTarget += ".exe"
	}

	tmpBin, err := os.CreateTemp("", "hm-bridge-bin-*")
	if err != nil {
		return "", err
	}
	defer tmpBin.Close()

	f, err := os.Open(tmpTar.Name())
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar read: %w", err)
		}
		if filepath.Base(hdr.Name) != binTarget {
			continue
		}
		if _, err := io.Copy(tmpBin, tr); err != nil {
			return "", err
		}
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("tarball missing %s", binTarget)
	}
	if err := os.Chmod(tmpBin.Name(), 0o755); err != nil {
		return "", err
	}
	return tmpBin.Name(), nil
}

func fetchHex(ctx context.Context, c *http.Client, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	for _, f := range strings.Fields(string(b)) {
		if len(f) == 64 { // sha256 hex
			return strings.ToLower(f), nil
		}
	}
	return "", errors.New("no sha256 in response")
}

func atomicReplace(target, source string) error {
	dir := filepath.Dir(target)
	tmp := filepath.Join(dir, ".hm-bridge-new-"+filepath.Base(target))
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// rename(2) is atomic on POSIX when src + dst sit on the same fs.
	return os.Rename(tmp, target)
}

func reexec(path string) error {
	args := os.Args
	env := os.Environ()
	if runtime.GOOS == "windows" {
		cmd := exec.Command(path, args[1:]...)
		cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
	}
	return syscall.Exec(path, args, env)
}

// --- gating ------------------------------------------------------

func applicable(cfg Config) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if cfg.BinaryPath == "" {
		return false
	}
	// Inside a container the image is the source of truth.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return false
	}
	if f, err := os.OpenFile(cfg.BinaryPath, os.O_WRONLY, 0); err == nil {
		f.Close()
		return true
	}
	return false
}

func skipReason(cfg Config) string {
	switch {
	case runtime.GOOS == "windows":
		return "windows install — managed by MSI/NSSM"
	case cfg.BinaryPath == "":
		return "binary path unknown"
	default:
		if _, err := os.Stat("/.dockerenv"); err == nil {
			return "running inside a container"
		}
		return "binary path is not writable by this user"
	}
}
