package mask

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sblmnl/agentbox/internal/ignore"
)

func buildTree(t *testing.T, files map[string]string, symlinks map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range symlinks {
		full := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func matcherOf(t *testing.T, patterns string) *ignore.Matcher {
	t.Helper()
	m := &ignore.Matcher{}
	if err := m.AddFile(strings.NewReader(patterns), ".agentignore"); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestComputeMaskSet(t *testing.T) {
	root := buildTree(t, map[string]string{
		".env":               "SECRET=1",
		"server.pem":         "key",
		"src/main.go":        "package main",
		"secrets/api.txt":    "k",
		"secrets/deep/x.txt": "k",
		"node_modules/a/b":   "x",
	}, map[string]string{
		"link.pem": "/etc/passwd", // masked as file, never resolved
	})
	m := matcherOf(t, ".env\n*.pem\nsecrets/\nnode_modules/\n")
	set, err := Compute(root, m, "view", []string{".agentignore"})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Entry{}
	for _, e := range set.Entries {
		byPath[e.Path] = e
	}
	// Files masked with /dev/null binds.
	if e := byPath[".env"]; e.Kind != KindFile || e.Mechanism != MechDevNull {
		t.Errorf(".env: %+v", e)
	}
	if e := byPath["link.pem"]; e.Kind != KindSymlink || e.Mechanism != MechDevNull {
		t.Errorf("link.pem: %+v", e)
	}
	// Directories masked as a single tmpfs and not descended.
	if e := byPath["secrets"]; e.Kind != KindDir || e.Mechanism != MechTmpfs {
		t.Errorf("secrets: %+v", e)
	}
	if _, ok := byPath["secrets/api.txt"]; ok {
		t.Error("masked directory must not be descended")
	}
	// Unmatched files stay unmasked.
	if _, ok := byPath["src/main.go"]; ok {
		t.Error("src/main.go must not be masked")
	}
	// Every entry names the rule that matched (auditable: `mounts` shows
	// the reason).
	for _, e := range set.Entries {
		if e.Rule == "" || e.RuleSource == "" {
			t.Errorf("entry %s lacks rule attribution", e.Path)
		}
	}
}

func TestLayer0PlanOrdering(t *testing.T) {
	root := buildTree(t, map[string]string{
		"a/.env":     "x",
		".env":       "x",
		"a/b/c/.env": "x",
	}, nil)
	m := matcherOf(t, ".env\n")
	set, err := Compute(root, m, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	ops := set.Layer0Plan("/workspace", "1m", true)
	if len(ops) != 3 {
		t.Fatalf("want 3 ops, got %d", len(ops))
	}
	// Ordered by target depth so nested masks apply correctly.
	for i := 1; i < len(ops); i++ {
		if strings.Count(ops[i-1].Target, "/") > strings.Count(ops[i].Target, "/") {
			t.Errorf("ops out of depth order: %v", ops)
		}
	}
	if !ops[0].ReadOnly {
		t.Error("files_readonly must translate to read-only binds")
	}
}

func TestFilterFnCoversLateFiles(t *testing.T) {
	m := matcherOf(t, "*.pem\nsecrets/\n")
	filter := FilterFn(m)
	if !filter("created-later.pem", false) {
		t.Error("filter must mask a matching file that did not exist at box start")
	}
	if !filter("secrets/new.txt", false) {
		t.Error("filter must mask new files under a masked directory")
	}
	if filter("src/ok.go", false) {
		t.Error("filter must not mask unmatched paths")
	}
}

func TestLayer0RealMounts(t *testing.T) {
	if !CanApplyMounts() {
		t.Skip("requires root/CAP_SYS_ADMIN for real mount assertions")
	}
	if os.Getenv("AGENTBOX_L0_CHILD") == "1" {
		// Child: inside private namespace, apply and assert.
		root := os.Getenv("AGENTBOX_L0_ROOT")
		m := matcherOf(t, ".env\nsecrets/\n")
		set, err := Compute(root, m, "view", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := EnterPrivateNamespace(); err != nil {
			t.Fatal(err)
		}
		if err := ApplyLayer0(set.Layer0Plan(root, "1m", true)); err != nil {
			t.Fatal(err)
		}
		// Masked file reads empty.
		data, err := os.ReadFile(filepath.Join(root, ".env"))
		if err != nil || len(data) != 0 {
			t.Errorf("masked file: data=%q err=%v (want empty read)", data, err)
		}
		// Masked directory lists empty.
		ents, err := os.ReadDir(filepath.Join(root, "secrets"))
		if err != nil || len(ents) != 0 {
			t.Errorf("masked dir: %d entries, err=%v (want empty)", len(ents), err)
		}
		// Writes to masked paths do not reach the host: write into tmpfs...
		if err := os.WriteFile(filepath.Join(root, "secrets", "leak.txt"), []byte("x"), 0o644); err != nil {
			t.Errorf("tmpfs write should succeed in-memory: %v", err)
		}
		return
	}
	root := buildTree(t, map[string]string{
		".env":            "SECRET=1",
		"secrets/api.txt": "k",
	}, nil)
	cmd := exec.Command(os.Args[0], "-test.run", "TestLayer0RealMounts", "-test.v")
	cmd.Env = append(os.Environ(), "AGENTBOX_L0_CHILD=1", "AGENTBOX_L0_ROOT="+root)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	// ...and the write never reached the host tree.
	if _, err := os.Stat(filepath.Join(root, "secrets", "leak.txt")); !os.IsNotExist(err) {
		t.Error("write inside masked directory must not reach the host")
	}
	if data, _ := os.ReadFile(filepath.Join(root, ".env")); string(data) != "SECRET=1" {
		t.Error("host content must be untouched")
	}
}

func TestLoadMatcherPrecedence(t *testing.T) {
	userDir := t.TempDir()
	global := filepath.Join(userDir, "agentignore")
	if err := os.WriteFile(global, []byte("*.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := buildTree(t, map[string]string{
		"a.pem":        "1",
		"public.pem":   "1",
		".agentignore": "!public.pem\n",
	}, nil)
	m, sources, err := LoadMatcher(global, root, []string{".agentignore"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("sources: %v", sources)
	}
	if !m.IsIgnored("a.pem", false) {
		t.Error("global *.pem must apply")
	}
	if m.IsIgnored("public.pem", false) {
		t.Error("workspace negation must override the global rule")
	}
}

// An unprivileged teardown of a directory that is not a mountpoint must be a
// no-op, not an error: umount(2) checks CAP_SYS_ADMIN before it checks whether
// anything is mounted, so a plain directory returns EPERM rather than EINVAL.
// Getting this wrong made `rm` fail on every filter-mode box, whose share
// daemon has already retracted its own mount by the time teardown runs.
func TestTeardownViewOnPlainDirectoryIsNoOp(t *testing.T) {
	dir := t.TempDir()
	view := filepath.Join(dir, "view")
	if err := os.MkdirAll(view, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := TeardownView(view); err != nil {
		t.Fatalf("tearing down a non-mountpoint must succeed, got: %v", err)
	}
	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Errorf("view root should be removed, stat err = %v", err)
	}
	// And again, on a path that no longer exists.
	if err := TeardownView(view); err != nil {
		t.Errorf("teardown must be idempotent, got: %v", err)
	}
}
