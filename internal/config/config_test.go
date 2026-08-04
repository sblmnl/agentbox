package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T, opts LoadOptions) (*Result, error) {
	t.Helper()
	if opts.SystemPath == "" {
		opts.SystemPath = filepath.Join(t.TempDir(), "nonexistent-system.toml")
	}
	if opts.UserConfigDir == "" {
		opts.UserConfigDir = t.TempDir()
	}
	return Load(opts)
}

func TestBuiltinDefaultsParse(t *testing.T) {
	res, err := load(t, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := res.Config
	if c.Network.Mode != "proxy" || c.Security.MinIsolation != "container" ||
		c.Security.Container.GuestRoot != "deny" || c.Workspace.TreeMode != "auto" {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestDockerfileRelativeToUserConfigDir(t *testing.T) {
	user := t.TempDir()
	ws := t.TempDir()
	// A baseline Dockerfile kept next to the user config in $XDG_CONFIG_HOME.
	writeFile(t, filepath.Join(user, "Dockerfile"), "FROM ubuntu:26.04\n")
	writeFile(t, filepath.Join(user, "config.toml"), "version = 1\n[image]\ndockerfile = \"Dockerfile\"\n")

	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(user, "Dockerfile")
	if res.Config.Image.Dockerfile != want {
		t.Errorf("dockerfile = %q, want %q (resolved next to the config that set it)", res.Config.Image.Dockerfile, want)
	}

	// A workspace config resolves its relative path against the workspace root.
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[image]\ndockerfile = \"my.Dockerfile\"\n")
	res2, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := res2.Config.Image.Dockerfile; got != filepath.Join(ws, "my.Dockerfile") {
		t.Errorf("workspace dockerfile = %q, want %q", got, filepath.Join(ws, "my.Dockerfile"))
	}
}

func TestDockerfileRelativeToExtendsBase(t *testing.T) {
	ws := t.TempDir()
	baseDir := filepath.Join(ws, "shared")
	// A relative [image].dockerfile set by an extends base resolves against
	// the base file's own directory, not the extending file's or the CWD.
	writeFile(t, filepath.Join(baseDir, "base.toml"), "version = 1\n[image]\ndockerfile = \"base.Dockerfile\"\n")
	writeFile(t, filepath.Join(baseDir, "base.Dockerfile"), "FROM ubuntu:26.04\n")
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\nextends = \"shared/base.toml\"\n")

	res, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(baseDir, "base.Dockerfile")
	if got := res.Config.Image.Dockerfile; got != want {
		t.Errorf("dockerfile = %q, want %q (resolved next to the extends base that set it)", got, want)
	}
}

func TestBackendScopeStatic(t *testing.T) {
	cases := []struct {
		toml    string
		wantSub string
	}{
		{"[security]\ncap_drop = [\"ALL\"]", "security.container"},
		{"[security]\nnested_docker = true", "security.vm"},
		{"[security]\nguest_root = \"allow\"", "security.container or security.vm"},
		{"[security]\nhypervisor = \"qemu\"", "security.vm"},
		{"[security]\nuserns = \"keep-id\"", "security.container"},
		// cap_drop has no meaning to a hypervisor: absent from vm scope,
		// and the error names where it belongs.
		{"[security.vm]\ncap_drop = [\"ALL\"]", "security.container"},
		// nested_docker is vm-only.
		{"[security.container]\nnested_docker = true", "security.vm"},
	}
	for _, c := range cases {
		ws := t.TempDir()
		writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n"+c.toml+"\n")
		_, err := load(t, LoadOptions{WorkspaceRoot: ws})
		if err == nil {
			t.Errorf("config %q: expected schema error, got none", c.toml)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("config %q: error %q does not mention %q", c.toml, err.Error(), c.wantSub)
		}
	}
}

func TestContainerGuestRootAllowRejected(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[security.container]\nguest_root = \"allow\"\n")
	_, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err == nil {
		t.Fatal("guest_root = \"allow\" under container must be a parse error")
	}
	if !strings.Contains(err.Error(), "guest_root") {
		t.Errorf("error should name the key: %v", err)
	}
	// And "allow" is fine under vm scope.
	ws2 := t.TempDir()
	writeFile(t, filepath.Join(ws2, "agentbox.toml"),
		"version = 1\n[security.vm]\nguest_root = \"allow\"\n")
	if _, err := load(t, LoadOptions{WorkspaceRoot: ws2}); err != nil {
		t.Errorf("guest_root = \"allow\" under vm should be legal: %v", err)
	}
}

func TestUnknownKeysHardError(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[securiy]\nmin_isolation = \"vm\"\n")
	_, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err == nil || !strings.Contains(err.Error(), "securiy") {
		t.Fatalf("misspelled table must fail naming the key, got: %v", err)
	}
}

func TestArrayMergeSemantics(t *testing.T) {
	user := t.TempDir()
	writeFile(t, filepath.Join(user, "config.toml"),
		"[network]\nbundles = [\"github\", \"npm\"]\n")
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[network]\nbundles = [\"pypi\", \"!npm\"]\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(res.Config.Network.Bundles, ",")
	if got != "github,pypi" {
		t.Errorf("append+remove: got %q want %q", got, "github,pypi")
	}

	ws2 := t.TempDir()
	writeFile(t, filepath.Join(ws2, "agentbox.toml"),
		"version = 1\n[network]\nbundles = [\"!reset\", \"crates\"]\n")
	res2, err := load(t, LoadOptions{WorkspaceRoot: ws2, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res2.Config.Network.Bundles, ","); got != "crates" {
		t.Errorf("!reset: got %q want %q", got, "crates")
	}
}

func TestOriginTracking(t *testing.T) {
	user := t.TempDir()
	writeFile(t, filepath.Join(user, "config.toml"), "[network]\nmode = \"open\"\n")
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[network]\nmode = \"none\"\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	origin := res.Merged.Origin["network.mode"]
	if !strings.HasPrefix(origin, LayerWorkspace) {
		t.Errorf("network.mode origin = %q, want workspace layer", origin)
	}
	if res.Config.Network.Mode != "none" {
		t.Errorf("mode = %q", res.Config.Network.Mode)
	}
}

func TestBothWorkspaceFilesError(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n")
	writeFile(t, filepath.Join(ws, ".agentbox.toml"), "version = 1\n")
	_, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err == nil {
		t.Fatal("expected error with both config files present")
	}
}

func TestExtendsAndCycle(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "base.toml"), "[toolchains]\nnode = \"24\"\n[network]\nbundles = [\"npm\"]\n")
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\nextends = \"base.toml\"\n[network]\nbundles = [\"github\"]\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Toolchains["node"] != "24" {
		t.Error("extends layer not applied")
	}
	if got := strings.Join(res.Config.Network.Bundles, ","); got != "npm,github" {
		t.Errorf("extends array append: %q", got)
	}

	ws2 := t.TempDir()
	writeFile(t, filepath.Join(ws2, "a.toml"), "extends = \"agentbox.toml\"\n")
	writeFile(t, filepath.Join(ws2, "agentbox.toml"), "version = 1\nextends = \"a.toml\"\n")
	if _, err := load(t, LoadOptions{WorkspaceRoot: ws2}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected extends cycle error, got %v", err)
	}
}

func TestProfileOverlay(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), `version = 1
[network]
mode = "proxy"
[profiles.airgapped]
[profiles.airgapped.network]
mode = "none"
`)
	res, err := load(t, LoadOptions{WorkspaceRoot: ws, ProfileName: "airgapped"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Network.Mode != "none" {
		t.Errorf("profile overlay not applied: mode = %q", res.Config.Network.Mode)
	}
	// Unknown profile errors rather than silently no-oping.
	if _, err := load(t, LoadOptions{WorkspaceRoot: ws, ProfileName: "nope"}); err == nil {
		t.Error("unknown profile must error")
	}
}

func TestEnvLayer(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[network]\nmode = \"proxy\"\n")
	res, err := load(t, LoadOptions{
		WorkspaceRoot: ws,
		Environ:       []string{"AGENTBOX_NETWORK__MODE=none"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.Network.Mode != "none" {
		t.Errorf("env layer not applied: %q", res.Config.Network.Mode)
	}
	// An invalid env value is a schema error like any other layer's.
	_, err = load(t, LoadOptions{
		WorkspaceRoot: ws,
		Environ:       []string{"AGENTBOX_NETWORK__MODE=bogus"},
	})
	if err == nil {
		t.Error("invalid env value must fail schema validation")
	}
}

// cap_add non-empty warns.
func TestCapAddWarns(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[security.container]\ncap_add = [\"NET_RAW\"]\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "cap_add") {
			found = true
		}
	}
	if !found {
		t.Error("non-empty cap_add must produce a warning")
	}
}

func TestEnumValidation(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[workspace]\ntree_mode = \"blended\"\n")
	if _, err := load(t, LoadOptions{WorkspaceRoot: ws}); err == nil {
		t.Fatal("invalid enum value must fail")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"8g": 8 << 30, "512m": 512 << 20, "1k": 1 << 10, "48G": 48 << 30,
	} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}
