//go:build linux

package share

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/sblmnl/agentbox/internal/mask"
)

// mountUnserved mounts a FUSE filesystem through the setuid helper and
// returns its device fd without ever serving it — the state left behind by
// a crashed fsd. allow_other is deliberately omitted so the fixture works
// on hosts that have not enabled user_allow_other; the option affects who
// may traverse the mount, not the teardown behavior under test.
func mountUnserved(t *testing.T, helper, mountpoint string) *os.File {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := fds[0]
	defer syscall.Close(local)
	child := os.NewFile(uintptr(fds[1]), "fusermount-comm")
	defer child.Close()

	cmd := exec.Command(helper, "-o", fmt.Sprintf("default_permissions,max_read=%d", maxWrite), "--", mountpoint)
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v: %s", helper, err, stderr.String())
	}
	child.Close()

	dev, err := recvFD(local)
	if err != nil {
		_ = unmountHelper(helper, mountpoint)
		t.Fatalf("recvFD: %v: %s", err, stderr.String())
	}
	return dev
}

// TestUnprivilegedMountRoundTrip covers the rootless seam end to end at the
// syscall level: the helper mounts, hands back the /dev/fuse descriptor
// over SCM_RIGHTS, and UnmountView retracts a mount that umount(2) would
// refuse this process. Needs only the helper, so it runs in ordinary CI.
func TestUnprivilegedMountRoundTrip(t *testing.T) {
	helper := findHelper()
	if helper == "" {
		t.Skip("no fusermount3 helper on PATH")
	}
	if os.Geteuid() == 0 {
		t.Skip("root takes the direct mount route; this covers the helper route")
	}
	// Not t.TempDir: its cleanup walks the tree, and walking into an
	// unserved FUSE mount blocks in the kernel.
	mnt, err := os.MkdirTemp("", "agentbox-fsd-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(mnt)

	dev := mountUnserved(t, helper, mnt)
	mounted := true
	defer func() {
		if mounted {
			_ = unmountHelper(helper, mnt)
		}
		dev.Close()
	}()

	if !mask.IsMountPoint(mnt) {
		t.Fatalf("%s is not a mountpoint after the helper mounted it", mnt)
	}
	if err := UnmountView(mnt); err != nil {
		t.Fatalf("UnmountView on an unprivileged mount: %v", err)
	}
	mounted = false
	if mask.IsMountPoint(mnt) {
		t.Errorf("%s still mounted after UnmountView", mnt)
	}
	// Idempotent: teardown paths call this unconditionally.
	if err := UnmountView(mnt); err != nil {
		t.Errorf("second UnmountView: %v", err)
	}
}

// TestIsMountPointDeadShare is the regression guard for the teardown
// deadlock: stat-ing the root of a FUSE mount whose daemon is gone blocks
// forever, so IsMountPoint must decide from the mount table alone. Without
// it every path that cleans up after a crashed fsd hangs instead.
func TestIsMountPointDeadShare(t *testing.T) {
	helper := findHelper()
	if helper == "" {
		t.Skip("no fusermount3 helper on PATH")
	}
	if os.Geteuid() == 0 {
		t.Skip("needs the unprivileged helper to build an unserved mount")
	}
	mnt, err := os.MkdirTemp("", "agentbox-fsd-dead")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(mnt)

	dev := mountUnserved(t, helper, mnt)
	// Close the device with nothing ever having served it: every request
	// the kernel forwards now has no reader.
	dev.Close()
	defer unmountHelper(helper, mnt)

	got := make(chan bool, 1)
	go func() { got <- mask.IsMountPoint(mnt) }()
	select {
	case ok := <-got:
		if !ok {
			t.Errorf("IsMountPoint(%s) = false, want true for a live-but-unserved mount", mnt)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("IsMountPoint(%s) blocked on a dead share: it must not stat the mountpoint", mnt)
	}

	done := make(chan error, 1)
	go func() { done <- UnmountView(mnt) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("UnmountView on a dead share: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UnmountView blocked on a dead share")
	}
}
