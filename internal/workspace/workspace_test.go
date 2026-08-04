package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func mk(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, p)
		if filepath.Ext(p) == "" && !filepath.IsAbs(p) && p[len(p)-1] == '/' {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetectPrecedence(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "repo/agentbox.toml", "repo/sub/dir/keep.txt")
	if err := os.MkdirAll(filepath.Join(root, "repo/.git"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(filepath.Join(root, "repo/sub/dir"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root, "repo") {
		t.Errorf("got %s", got)
	}

	// VCS marker only.
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, "proj/.git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mk(t, root2, "proj/a/b/f.txt")
	got, err = Detect(filepath.Join(root2, "proj/a/b"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root2, "proj") {
		t.Errorf("vcs: got %s", got)
	}

	// Nothing: starting directory itself.
	root3 := t.TempDir()
	mk(t, root3, "plain/f.txt")
	got, err = Detect(filepath.Join(root3, "plain"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root3, "plain") {
		t.Errorf("plain: got %s", got)
	}
}

func TestDetectRefusesForbiddenRoots(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := Detect(home, ""); err == nil {
		t.Error("must refuse $HOME as workspace root")
	}
	// An explicit override of a normal dir is accepted.
	sub := filepath.Join(home, "proj")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(home, sub)
	if err != nil || got != sub {
		t.Errorf("override: %v %v", got, err)
	}
}

func TestSearchStopsAtHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(home, "src", "app")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(start, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != start {
		t.Errorf("search must stop at $HOME; got %s", got)
	}
}

func TestGuestWorkdir(t *testing.T) {
	if got := GuestWorkdir("/workspace", "/home/u/app", "/home/u/app/src/api"); got != "/workspace/src/api" {
		t.Errorf("got %s", got)
	}
	if got := GuestWorkdir("/workspace", "/home/u/app", "/home/u/app"); got != "/workspace" {
		t.Errorf("root: got %s", got)
	}
	// Outside the workspace: fall back to the mount point.
	if got := GuestWorkdir("/workspace", "/home/u/app", "/home/u/elsewhere"); got != "/workspace" {
		t.Errorf("outside: got %s", got)
	}
}
