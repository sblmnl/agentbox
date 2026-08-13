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
	res, err := config.Load(config.LoadOptions{UserConfigDir: tmp})
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

// Every apt-repo step verifies a signing-key fingerprint with gpg, which the
// base images do not ship: gnupg must be installed before the first use, or
// the build dies with "gpg: not found" and the key goes unverified.
func TestGpgInstalledBeforeFirstUse(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Toolchains = map[string]string{"node": "24", "dotnet": "10", "python": "3.13", "go": "1.26.0", "rust": "stable"}
	cfg.Agents.Install = []string{"claude-code"}
	df := Dockerfile(cfg, 1000, 1000)

	install := strings.Index(df, "gnupg")
	if install < 0 {
		t.Fatal("gnupg is never installed, but the generated steps invoke gpg")
	}
	use := strings.Index(df, "gpg --")
	if use < 0 {
		t.Fatal("no gpg invocation found; this test no longer guards anything")
	}
	if use < install {
		t.Errorf("gpg is invoked at byte %d, before gnupg is installed at %d", use, install)
	}
}

// dotnet comes from the distro archive: packages.microsoft.com ships no .NET
// SDK for Ubuntu >= 22.04, so pointing apt at it added a third-party trust
// anchor and then failed to find the package.
func TestDotnetFromDistroArchive(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Toolchains = map[string]string{"dotnet": "10"}
	df := Dockerfile(cfg, 1000, 1000)

	if !strings.Contains(df, "apt-get install -y --no-install-recommends dotnet-sdk-10.0") {
		t.Error("dotnet toolchain must install dotnet-sdk-10.0")
	}
	if strings.Contains(df, "packages.microsoft.com") {
		t.Error("dotnet must not add the packages.microsoft.com repo: it carries no SDK for this release")
	}
	if strings.Contains(df, "sources.list.d/microsoft.list") {
		t.Error("dotnet must not add a microsoft apt source")
	}
}

// uv is the sole source of python. The build runs as root and the box runs as
// `agent` over a persistent /home/agent volume that shadows the image, so an
// interpreter under either home is unreachable; and a distro python installed
// beside it silently answers `python3` at a version nobody asked for.
func TestPythonIsSolelyUvManaged(t *testing.T) {
	cfg := cfgWith(t, "")
	cfg.Toolchains = map[string]string{"python": "3.13"}
	df := Dockerfile(cfg, 1000, 1000)

	if !strings.Contains(df, "UV_PYTHON_INSTALL_DIR=/opt/uv/python UV_PYTHON_BIN_DIR=/usr/local/bin") {
		t.Error("the managed interpreter must be installed under /opt, not a home directory")
	}
	if !strings.Contains(df, "uv python install --default 3.13") {
		t.Error("the pinned interpreter must be installed as the default python/python3")
	}
	if !strings.Contains(df, "ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python") {
		t.Error("UV_PYTHON_INSTALL_DIR must persist into the image so uv resolves it at runtime")
	}
	// No second interpreter, and no pipx: `uv tool install` covers it.
	for _, forbid := range []string{"install -y --no-install-recommends python3", "pipx", "PIPX_"} {
		if strings.Contains(df, forbid) {
			t.Errorf("python toolchain must not install %q alongside the uv interpreter", forbid)
		}
	}
	// The build asserts the interpreter on PATH is the requested one.
	if !strings.Contains(df, "python: wanted 3.13, got") {
		t.Error("the build must fail when the python on PATH is not the requested version")
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
