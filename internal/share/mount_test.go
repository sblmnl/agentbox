//go:build linux

package share

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/sblmnl/agentbox/internal/ignore"
	"github.com/sblmnl/agentbox/internal/mask"
)

// TestFilterRealMount is the privileged half of the filter-mode suite: a
// real FUSE mount, exercised through ordinary syscalls the way virtiofsd
// will exercise it. Runs under `make test-privileged`; the CI job fails
// if this skips instead of running.
func TestFilterRealMount(t *testing.T) {
	if ok, reason := SeamAvailable(); !ok {
		t.Skipf("requires the Layer 3 seam: %s", reason)
	}

	root := t.TempDir()
	mnt := t.TempDir()
	files := map[string]string{
		"main.go":       "package main\n",
		".env":          "SECRET=1",
		"secrets/token": "tok",
		"docs/notes.md": "notes",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &ignore.Matcher{}
	if err := m.AddFile(strings.NewReader(".env\n*.pem\nsecrets/\n"), ".agentignore"); err != nil {
		t.Fatal(err)
	}
	fs, err := NewFS(root, Filter(mask.FilterFn(m)), m.HasAnchored())
	if err != nil {
		t.Fatal(err)
	}
	dev, err := mountFuse(mnt)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- NewConn(dev, fs).Serve() }()
	defer func() {
		if err := UnmountView(mnt); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
		dev.Close()
		fs.Close()
	}()

	// Masked paths do not exist: not stat-able, not listed.
	if _, err := os.Lstat(filepath.Join(mnt, ".env")); !os.IsNotExist(err) {
		t.Errorf("stat .env = %v, want ENOENT", err)
	}
	if _, err := os.Lstat(filepath.Join(mnt, "secrets")); !os.IsNotExist(err) {
		t.Errorf("stat secrets = %v, want ENOENT", err)
	}
	ents, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() == ".env" || e.Name() == "secrets" {
			t.Errorf("listing must omit %q", e.Name())
		}
	}

	// Unmasked paths read and write through.
	if data, err := os.ReadFile(filepath.Join(mnt, "main.go")); err != nil || string(data) != "package main\n" {
		t.Errorf("read main.go = %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(mnt, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write notes.txt: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "notes.txt")); err != nil || string(data) != "hi" {
		t.Errorf("host notes.txt = %q, %v", data, err)
	}

	// Writes to masked names are refused loudly and never reach the host.
	err = os.WriteFile(filepath.Join(mnt, ".env"), []byte("leak"), 0o644)
	if !errorIs(err, syscall.EPERM) {
		t.Errorf("write .env = %v, want EPERM", err)
	}
	if err := os.Mkdir(filepath.Join(mnt, "secrets"), 0o755); !errorIs(err, syscall.EPERM) {
		t.Errorf("mkdir secrets = %v, want EPERM", err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, ".env")); string(data) != "SECRET=1" {
		t.Errorf("host .env was altered: %q", data)
	}

	// The dynamic guarantee: a matching file created after mount is masked.
	if err := os.WriteFile(filepath.Join(root, "late-key.pem"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(mnt, "late-key.pem")); !os.IsNotExist(err) {
		t.Errorf("stat late-key.pem = %v, want ENOENT (created after mount)", err)
	}

	// A masked directory imposes no size cap: this tree has no tmpfs
	// anywhere — write a large unmasked file to prove the path is direct.
	big := make([]byte, 4<<20)
	if err := os.WriteFile(filepath.Join(mnt, "big.bin"), big, 0o644); err != nil {
		t.Errorf("write 4MiB: %v", err)
	}
}

func errorIs(err error, want syscall.Errno) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			return e == want
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestUserAllowOther pins the fuse.conf parse. The option is documented as
// appearing on a line by itself, so a commented or inline occurrence must
// not count: reading it as enabled would let the seam probe pass on a host
// where the helper will then refuse allow_other.
func TestUserAllowOther(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want bool
	}{
		{"absent", "# nothing here\n#mount_max = 1000\n", false},
		{"commented", "#user_allow_other\n", false},
		{"commented with space", "# user_allow_other\n", false},
		{"enabled", "user_allow_other\n", true},
		{"enabled among comments", "# preamble\nuser_allow_other\nmount_max = 1000\n", true},
		{"enabled with whitespace", "   user_allow_other\t\n", true},
		{"inline after option", "mount_max = 1000 user_allow_other\n", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "fuse.conf")
			if err := os.WriteFile(p, []byte(tc.conf), 0o644); err != nil {
				t.Fatal(err)
			}
			defer swapConfPath(p)()
			if got := userAllowOther(); got != tc.want {
				t.Errorf("userAllowOther() = %v, want %v (conf %q)", got, tc.want, tc.conf)
			}
		})
	}
}

// TestUserAllowOtherMissingFile: an absent fuse.conf is "not permitted",
// never an error that would be mistaken for permission.
func TestUserAllowOtherMissingFile(t *testing.T) {
	defer swapConfPath(filepath.Join(t.TempDir(), "does-not-exist"))()
	if userAllowOther() {
		t.Error("userAllowOther() = true with no fuse.conf, want false")
	}
}

// TestSeamAvailableUnprivileged covers the rootless route: the seam is
// deliverable through the setuid helper, and each way it can be
// undeliverable must refuse with a reason naming the fix — mask-mode
// resolution turns these strings into the user's only explanation for an
// explicit "filter" being rejected or "auto" degrading to "view".
func TestSeamAvailableUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root takes the direct mount route; this covers the helper route")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("/dev/fuse absent: the probe short-circuits before the helper checks")
	}

	conf := filepath.Join(t.TempDir(), "fuse.conf")
	if err := os.WriteFile(conf, []byte("user_allow_other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapConfPath(conf)()

	t.Run("helper and user_allow_other", func(t *testing.T) {
		defer swapHelper("/usr/bin/fusermount3")()
		ok, reason := SeamAvailable()
		if !ok {
			t.Errorf("SeamAvailable() = false (%s), want true", reason)
		}
	})

	t.Run("no helper", func(t *testing.T) {
		defer swapHelper("")()
		ok, reason := SeamAvailable()
		if ok {
			t.Fatal("SeamAvailable() = true with no helper, want false")
		}
		if !strings.Contains(reason, "fusermount3") {
			t.Errorf("reason %q must name the missing helper", reason)
		}
	})

	t.Run("no user_allow_other", func(t *testing.T) {
		defer swapHelper("/usr/bin/fusermount3")()
		bare := filepath.Join(t.TempDir(), "fuse.conf")
		if err := os.WriteFile(bare, []byte("#user_allow_other\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		defer swapConfPath(bare)()
		ok, reason := SeamAvailable()
		if ok {
			t.Fatal("SeamAvailable() = true without user_allow_other, want false")
		}
		if !strings.Contains(reason, "user_allow_other") || !strings.Contains(reason, bare) {
			t.Errorf("reason %q must name both the option and the file to edit", reason)
		}
	})
}

func swapConfPath(p string) func() {
	prev := fuseConfPath
	fuseConfPath = p
	return func() { fuseConfPath = prev }
}

func swapHelper(p string) func() {
	prev := findHelper
	findHelper = func() string { return p }
	return func() { findHelper = prev }
}
