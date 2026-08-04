package image

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sblmnl/agentbox/internal/config"
)

func cfgWith(t *testing.T, toml string) *config.Config {
	t.Helper()
	tmp := t.TempDir()
	res, err := config.Load(config.LoadOptions{
		SystemPath:    tmp + "/none.toml",
		UserConfigDir: tmp,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := res.Config
	return cfg
}

func TestDigestDeterministicAndBackendIndependent(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Toolchains = map[string]string{"node": "24", "go": "none"}
	cfg.Image.Packages = []string{"graphviz", "postgresql-client"}

	d1 := FeaturesFrom(cfg).Digest()
	d2 := FeaturesFrom(cfg).Digest()
	if d1 != d2 {
		t.Error("digest must be deterministic")
	}
	cfg.Security.VM.GuestRoot = "deny"
	cfg.Security.Container.ReadOnlyRoot = false
	if FeaturesFrom(cfg).Digest() != d1 {
		t.Error("backend/security settings must not affect the feature digest")
	}
	// "none" toolchains are excluded.
	feats := FeaturesFrom(cfg)
	if _, ok := feats.Toolchains["go"]; ok {
		t.Error("toolchain \"none\" must be absent from features")
	}
	// Package order does not matter.
	cfg.Image.Packages = []string{"postgresql-client", "graphviz"}
	if FeaturesFrom(cfg).Digest() != d1 {
		t.Error("package order must not affect the digest")
	}
	if !strings.HasPrefix(feats.Tag(), "agentbox/dev:") || len(feats.Digest()) != 16 {
		t.Errorf("tag format: %s", feats.Tag())
	}
}

func TestRefVerbatim(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Image.Ref = "ghcr.io/me/box:2026-06"
	cfg.Toolchains = map[string]string{"node": "24"}
	res := Resolve(cfg)
	if res.Ref != "ghcr.io/me/box:2026-06" || res.Source != "config-ref" {
		t.Errorf("resolution: %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Error("toolchain mismatch with explicit ref must warn")
	}
}

func TestDefaultBaseIsUbuntu2604(t *testing.T) {
	cfg := cfgWith(t, "")
	if cfg.Image.Base != "ubuntu:26.04" {
		t.Errorf("default base = %q, want ubuntu:26.04", cfg.Image.Base)
	}
}

func TestDockerfileSourceBuildsUserFileByContent(t *testing.T) {
	cfg := cfgWith(t, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte("FROM ubuntu:26.04\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Image.Dockerfile = path
	cfg.Toolchains = map[string]string{"node": "24"}

	res := Resolve(cfg)
	if res.Source != "dockerfile" || !res.LocalBuild() {
		t.Errorf("resolution: %+v", res)
	}
	want := "agentbox/dev:" + DockerfileDigest([]byte("FROM ubuntu:26.04\n"))
	if res.Ref != want {
		t.Errorf("ref = %q, want %q (content-addressed)", res.Ref, want)
	}
	if len(res.Warnings) == 0 {
		t.Error("declared toolchains with a custom Dockerfile must warn they are ignored")
	}

	// Editing the file changes the tag so a rebuild is triggered.
	if err := os.WriteFile(path, []byte("FROM ubuntu:26.04\nRUN true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Resolve(cfg).Ref == want {
		t.Error("editing the Dockerfile must change the resolved tag")
	}
}

func TestDockerfileMissingWarnsButStaysStable(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Image.Dockerfile = filepath.Join(t.TempDir(), "nope.Dockerfile")
	res := Resolve(cfg)
	if res.Source != "dockerfile" || res.Ref == "" {
		t.Errorf("a missing Dockerfile must still yield a stable dockerfile resolution: %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Error("a missing Dockerfile must warn")
	}
	if Resolve(cfg).Ref != res.Ref {
		t.Error("the path-based fallback tag must be stable")
	}
}

func TestRefWinsOverDockerfile(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Image.Ref = "ghcr.io/me/box:1"
	cfg.Image.Dockerfile = "/tmp/whatever"
	res := Resolve(cfg)
	if res.Source != "config-ref" {
		t.Errorf("ref must take precedence: %+v", res)
	}
	var found bool
	for _, wmsg := range res.Warnings {
		if strings.Contains(wmsg, "dockerfile is ignored") {
			found = true
		}
	}
	if !found {
		t.Error("setting both ref and dockerfile must warn that the dockerfile is ignored")
	}
}

func TestClaudeCodeInstalledViaApt(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Agents.Install = []string{"claude-code"}
	df := Dockerfile(cfg, 1000, 1000)
	for _, want := range []string{
		"downloads.claude.ai/keys/claude-code.asc",          // official signing key
		"downloads.claude.ai/claude-code/apt/stable stable", // stable suite by default
		"31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE",          // verified fingerprint
		"apt-get install -y --no-install-recommends claude-code",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("claude-code apt install missing %q", want)
		}
	}
	if strings.Contains(df, "npm install -g @anthropic-ai/claude-code") {
		t.Error("claude-code must no longer be installed via npm")
	}
	// [agents].channel = latest selects the latest apt suite.
	cfg.Agents.Channel = "latest"
	if !strings.Contains(Dockerfile(cfg, 1000, 1000), "claude-code/apt/latest latest") {
		t.Error("channel = latest must select the latest apt suite")
	}
}

func TestDockerfileRequirements(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Toolchains = map[string]string{"node": "24"}
	cfg.Agents.Install = []string{"claude-code"}
	df := Dockerfile(cfg, 1000, 1000)

	for _, want := range []string{
		"useradd -m -u",                     // non-root user at invoking uid
		"userdel",                           // reclaiming an existing uid (ubuntu at 1000)
		"AGENTBOX_GUEST_ROOT=deny",          // sudo varies by build arg, not by image
		"apt-get purge -y sudo",             // no sudo under container
		"chmod a-s",                         // strip setuid/setgid
		"fingerprint mismatch",              // signing key verified against a constant
		"NPM_CONFIG_PREFIX=/home/agent",     // caches under home
		"safe.directory",                    // git safe.directory *
		"DOTNET_CLI_TELEMETRY_OPTOUT=1",     // telemetry opt-outs
		"CLAUDE_CODE_DISABLE_AUTOUPDATER=1", // self-updater disables
		"ripgrep",                           // baseline tooling
		"USER agent",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile missing %q", want)
		}
	}
	for _, forbid := range []string{"API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN"} {
		if strings.Contains(df, forbid) {
			t.Errorf("Dockerfile must not embed credentials (%s)", forbid)
		}
	}
	// Deterministic output.
	if Dockerfile(cfg, 1000, 1000) != df {
		t.Error("Dockerfile generation must be deterministic")
	}
	// strip_setuid off removes the chmod pass.
	cfg.Security.StripSetuid = false
	if strings.Contains(Dockerfile(cfg, 1000, 1000), "chmod a-s") {
		t.Error("strip_setuid = false must omit the setuid strip")
	}
}
