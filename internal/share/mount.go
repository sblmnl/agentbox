//go:build linux

package share

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sblmnl/agentbox/internal/mask"
)

// fuseConfPath is the system FUSE configuration consulted for
// user_allow_other. A variable so tests can point it at a fixture.
var fuseConfPath = "/etc/fuse.conf"

// helperNames are the unprivileged FUSE mount helpers, newest first. The
// helper is setuid root and performs the mount on our behalf, which is what
// lets the share daemon itself run entirely in the user's context.
var helperNames = []string{"fusermount3", "fusermount"}

// findHelper locates the unprivileged mount helper, "" when absent.
var findHelper = func() string {
	for _, n := range helperNames {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// userAllowOther reports whether the system FUSE configuration permits a
// non-root user to pass allow_other. fuse.conf documents the option as
// appearing on a line by itself, with no value.
func userAllowOther() bool {
	f, err := os.Open(fuseConfPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "user_allow_other" {
			return true
		}
	}
	return false
}

// SeamAvailable probes whether this host can deliver the Layer 3 filtered
// share. Two routes qualify: running as root, which mounts /dev/fuse
// directly, or the setuid fusermount3 helper, which mounts on behalf of an
// ordinary user and keeps the whole share daemon in the user's context.
//
// The unprivileged route additionally needs user_allow_other, because the
// mount is owned by this user while the runtime's virtiofs server may run
// as another (a root Docker daemon's does); without allow_other the kernel
// refuses it access and the guest would see an unusable share. Requiring it
// is deliberately conservative — a same-uid virtiofsd would not need it —
// because the alternative is a box that comes up and then fails opaquely.
//
// The result feeds mask-mode resolution; an unavailable seam must degrade
// loudly, never silently.
func SeamAvailable() (ok bool, reason string) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		return false, "/dev/fuse is not present (load the fuse kernel module)"
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		return false, "/proc is not mounted"
	}
	if os.Geteuid() == 0 {
		return true, ""
	}
	if findHelper() == "" {
		return false, "agentbox is not running as root and no fusermount3 helper is on PATH " +
			"(install the fuse3 package, or run agentbox as root)"
	}
	if !userAllowOther() {
		return false, fmt.Sprintf("agentbox is not running as root and %s does not enable user_allow_other, "+
			"which the runtime's virtiofs server needs in order to traverse a share owned by this user "+
			"(add a line reading exactly \"user_allow_other\" to %s, or run agentbox as root)",
			fuseConfPath, fuseConfPath)
	}
	return true, ""
}

// mountFuse mounts the filtered share and returns the device fd the daemon
// serves requests on, by whichever route this process is entitled to.
func mountFuse(mountpoint string) (*os.File, error) {
	if os.Geteuid() == 0 {
		return mountFuseDirect(mountpoint)
	}
	helper := findHelper()
	if helper == "" {
		return nil, fmt.Errorf("mounting filtered share at %s: not running as root and no fusermount3 helper on PATH", mountpoint)
	}
	return mountFuseHelper(helper, mountpoint)
}

// mountFuseDirect opens /dev/fuse and mounts it at mountpoint with mount(2),
// the route available when agentbox runs as root. default_permissions keeps
// permission checks in the kernel; allow_other lets the runtime's
// virtiofsd (and the guest behind it) traverse the mount.
func mountFuseDirect(mountpoint string) (*os.File, error) {
	dev, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /dev/fuse: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(mountpoint, &st); err != nil {
		dev.Close()
		return nil, fmt.Errorf("stat %s: %w", mountpoint, err)
	}
	data := fmt.Sprintf("fd=%d,rootmode=%o,user_id=0,group_id=0,default_permissions,allow_other,max_read=%d",
		dev.Fd(), st.Mode&syscall.S_IFMT, maxWrite)
	err = syscall.Mount("agentbox-fsd", mountpoint, "fuse.agentbox-fsd",
		syscall.MS_NOSUID|syscall.MS_NODEV, data)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("mounting filtered share at %s: %w (root or CAP_SYS_ADMIN required)", mountpoint, err)
	}
	return dev, nil
}

// mountFuseHelper mounts through the setuid helper, which performs the
// mount and hands the /dev/fuse descriptor back over a socketpair
// (SCM_RIGHTS). The helper supplies fd, rootmode, user_id and group_id
// itself and forces nosuid,nodev for unprivileged mounts — matching what
// the direct route asks for — so only the policy options are ours to pass.
func mountFuseHelper(helper, mountpoint string) (*os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair for %s: %w", helper, err)
	}
	local := fds[0]
	defer syscall.Close(local)
	child := os.NewFile(uintptr(fds[1]), "fusermount-comm")
	defer child.Close()

	opts := fmt.Sprintf("default_permissions,allow_other,max_read=%d", maxWrite)
	cmd := exec.Command(helper, "-o", opts, "--", mountpoint)
	cmd.ExtraFiles = []*os.File{child} // becomes fd 3 in the child
	cmd.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mounting filtered share at %s via %s: %w%s",
			mountpoint, helper, err, stderrSuffix(&stderr))
	}
	// Drop our copy of the child end before receiving: with it still open
	// a helper that exited without sending would leave the read blocking
	// on a descriptor nobody will ever write to.
	child.Close()

	dev, err := recvFD(local)
	if err != nil {
		_ = unmountHelper(helper, mountpoint)
		return nil, fmt.Errorf("receiving the /dev/fuse descriptor from %s: %w%s",
			helper, err, stderrSuffix(&stderr))
	}
	return dev, nil
}

// recvFD reads a single descriptor from a SCM_RIGHTS control message.
func recvFD(sock int) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := syscall.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 && oobn == 0 {
		return nil, fmt.Errorf("helper exited without sending a descriptor")
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, scm := range scms {
		rights, err := syscall.ParseUnixRights(&scm)
		if err != nil || len(rights) == 0 {
			continue
		}
		for _, extra := range rights[1:] {
			syscall.Close(extra)
		}
		syscall.CloseOnExec(rights[0])
		return os.NewFile(uintptr(rights[0]), "/dev/fuse"), nil
	}
	return nil, fmt.Errorf("no descriptor in the helper's control message")
}

// UnmountView lazily detaches the filtered share. Not a mountpoint or
// missing is not an error: teardown is idempotent. A share the helper
// mounted has to be retracted through the helper too, since umount(2) from
// an unprivileged caller fails with EPERM; the direct attempt comes first
// so the root path behaves exactly as it did before.
func UnmountView(mountpoint string) error {
	err := syscall.Unmount(mountpoint, syscall.MNT_DETACH)
	if err == nil || err == syscall.EINVAL || os.IsNotExist(err) {
		return nil
	}
	if err == syscall.EPERM {
		if !mask.IsMountPoint(mountpoint) {
			return nil
		}
		if helper := findHelper(); helper != "" {
			return unmountHelper(helper, mountpoint)
		}
	}
	return fmt.Errorf("unmounting filtered share %s: %w", mountpoint, err)
}

// unmountHelper retracts a share through the setuid helper. -z matches the
// MNT_DETACH semantics of the direct route.
func unmountHelper(helper, mountpoint string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(helper, "-u", "-z", "--", mountpoint)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// The helper reports a missing entry as failure; a share that is
		// already gone is the outcome teardown wanted either way.
		if !mask.IsMountPoint(mountpoint) {
			return nil
		}
		return fmt.Errorf("unmounting filtered share %s via %s: %w%s",
			mountpoint, helper, err, stderrSuffix(&stderr))
	}
	return nil
}

func stderrSuffix(b *bytes.Buffer) string {
	s := strings.TrimSpace(b.String())
	if s == "" {
		return ""
	}
	return ": " + s
}
