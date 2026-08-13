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
		c.Security.MaskMode != "auto" || c.Workspace.Mount != "/workspace" {
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

func TestBackendScopeStatic(t *testing.T) {
	cases := []struct {
		toml    string
		wantSub string
	}{
		{"[security]\ncap_drop = [\"ALL\"]", "security.container"},
		{"[security]\nnested_docker = true", "security.vm"},
		{"[security]\nguest_root = \"allow\"", "security.vm"},
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

func TestUnknownKeysHardError(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[securiy]\nmin_isolation = \"vm\"\n")
	_, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err == nil || !strings.Contains(err.Error(), "securiy") {
		t.Fatalf("misspelled table must fail naming the key, got: %v", err)
	}
}

// The keys removed in the MVP scale-back must fail loudly rather than being
// ignored: a config that still carries them is asking for behavior agentbox
// no longer has, and silently dropping it would be the exact "silently
// ignored key" failure the schema exists to prevent.
func TestRemovedKeysAreHardErrors(t *testing.T) {
	for _, body := range []string{
		"extends = \"base.toml\"",
		"[box]\nprofile = \"x\"",
		"[project]\nmax_boxes = 2",
		"[workspace]\ntree_mode = \"worktree\"",
		"[[workspace.mounts]]\nsource = \"/a\"\ntarget = \"/b\"",
		"[hooks]\npre_up = [\"echo hi\"]",
		"[limits]\nmax_boxes = 3",
		"[security.vm]\nruntime = \"krun\"",
		"[security.vm]\nhypervisor = \"libkrun\"",
		"[security.container]\nguest_root = \"deny\"",
		"[profiles.x.network]\nmode = \"off\"",
	} {
		ws := t.TempDir()
		writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n"+body+"\n")
		if _, err := load(t, LoadOptions{WorkspaceRoot: ws}); err == nil {
			t.Errorf("removed key %q was accepted; it must be a hard error", body)
		}
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
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[network]\nmode = \"off\"\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	origin := res.Merged.Origin["network.mode"]
	if !strings.HasPrefix(origin, LayerWorkspace) {
		t.Errorf("network.mode origin = %q, want workspace layer", origin)
	}
	if res.Config.Network.Mode != "off" {
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

// The central invariant: a workspace config may win, but never quietly. A repo
// that drops the tier, opens egress, or turns off masking relative to what the
// user asked for must produce a warning naming the key and both values.
func TestWorkspaceWeakeningWarnsPerKey(t *testing.T) {
	cases := []struct {
		name       string
		userTOML   string
		wsTOML     string
		wantKey    string
		wantValues []string
	}{
		{
			name:       "isolation floor lowered",
			userTOML:   "[security]\nmin_isolation = \"vm\"\n",
			wsTOML:     "version = 1\n[security]\nmin_isolation = \"container\"\n",
			wantKey:    "security.min_isolation",
			wantValues: []string{`"vm"`, `"container"`},
		},
		{
			name:       "egress opened",
			userTOML:   "[network]\nmode = \"proxy\"\n",
			wsTOML:     "version = 1\n[network]\nmode = \"open\"\n",
			wantKey:    "network.mode",
			wantValues: []string{`"proxy"`, `"open"`},
		},
		{
			name:       "masking weakened",
			userTOML:   "[security]\nmask_mode = \"filter\"\n",
			wsTOML:     "version = 1\n[security]\nmask_mode = \"view\"\n",
			wantKey:    "security.mask_mode",
			wantValues: []string{`"filter"`, `"view"`},
		},
		{
			name:       "setuid stripping disabled",
			userTOML:   "[security]\nstrip_setuid = true\n",
			wsTOML:     "version = 1\n[security]\nstrip_setuid = false\n",
			wantKey:    "security.strip_setuid",
			wantValues: []string{"true", "false"},
		},
		{
			name:       "guest root allowed",
			userTOML:   "[security.vm]\nguest_root = \"deny\"\n",
			wsTOML:     "version = 1\n[security.vm]\nguest_root = \"allow\"\n",
			wantKey:    "security.vm.guest_root",
			wantValues: []string{`"deny"`, `"allow"`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := t.TempDir()
			writeFile(t, filepath.Join(user, "config.toml"), c.userTOML)
			ws := t.TempDir()
			writeFile(t, filepath.Join(ws, "agentbox.toml"), c.wsTOML)

			res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
			if err != nil {
				t.Fatal(err)
			}
			var warning string
			for _, w := range res.Warnings {
				if strings.Contains(w, c.wantKey) {
					warning = w
				}
			}
			if warning == "" {
				t.Fatalf("no warning naming %s; a workspace config weakened a security key silently.\nwarnings: %v",
					c.wantKey, res.Warnings)
			}
			for _, v := range c.wantValues {
				if !strings.Contains(warning, v) {
					t.Errorf("warning does not show value %s: %q", v, warning)
				}
			}
			// Naming the file is the actionable half: in a repo the user did
			// not write, "the workspace config" alone leaves them with
			// nothing to open.
			wsFile := filepath.Join(ws, "agentbox.toml")
			if !strings.Contains(warning, wsFile) {
				t.Errorf("warning does not name the file that weakened the key (%s): %q", wsFile, warning)
			}
			// A remediation clause naming a flag that cannot override the key
			// is worse than none: --config takes a path and replaces the
			// whole workspace layer.
			if strings.Contains(warning, "--config") {
				t.Errorf("warning advises --config, which cannot override a single key: %q", warning)
			}
		})
	}
}

// The mirror image: a workspace config that *tightens* is doing exactly what a
// project config is for, and must not be nagged about.
func TestWorkspaceTighteningIsQuiet(t *testing.T) {
	user := t.TempDir()
	writeFile(t, filepath.Join(user, "config.toml"), "[security]\nmin_isolation = \"container\"\n[network]\nmode = \"open\"\n")
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"),
		"version = 1\n[security]\nmin_isolation = \"vm\"\n[network]\nmode = \"proxy\"\n")

	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "lowered") {
			t.Errorf("tightening must not warn, got: %q", w)
		}
	}
}

// A flag is typed by the person at the prompt, so it is allowed to loosen
// anything -- and it also clears the complaint about the workspace, because
// the workspace value is no longer what is in effect.
func TestFlagLooseningIsNotWarnedAbout(t *testing.T) {
	user := t.TempDir()
	writeFile(t, filepath.Join(user, "config.toml"), "[network]\nmode = \"off\"\n")
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[network]\nmode = \"proxy\"\n")

	res, err := load(t, LoadOptions{WorkspaceRoot: ws, UserConfigDir: user})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.ApplyFlags(map[string]any{"network": map[string]any{"mode": "open"}}); err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "network.mode") {
			t.Errorf("an explicit flag must not be warned about as a workspace weakening: %q", w)
		}
	}
}

// A workspace weakening relative to the *built-in* default counts too: the
// user never chose the weaker value just because they never wrote a config.
func TestWorkspaceWeakeningAgainstBuiltinDefault(t *testing.T) {
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "agentbox.toml"), "version = 1\n[network]\nmode = \"open\"\n")
	res, err := load(t, LoadOptions{WorkspaceRoot: ws})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "network.mode") {
			found = true
		}
	}
	if !found {
		t.Errorf("a workspace opening egress against the proxy default must warn; warnings: %v", res.Warnings)
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
		"version = 1\n[network]\nmode = \"blended\"\n")
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
