//go:build linux

package mask

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ApplyLayer0 applies the mount plan in the *current* mount namespace. The
// caller is responsible for having entered a private namespace first
// (unshare(CLONE_NEWNS) plus MS_PRIVATE remount of "/"): Layer 0 masks live
// in a host-side namespace that the guest cannot unmount, which is
// what makes them independent of guest privilege.
//
// Requires CAP_SYS_ADMIN in the active user namespace. The container
// backend can instead express the same plan as runtime mounts; the virtiofs
// share daemon serves the view for the vm backend.
func ApplyLayer0(ops []MountOp) error {
	for _, op := range ops {
		switch op.Mechanism {
		case MechDevNull:
			if err := syscall.Mount("/dev/null", op.Target, "", syscall.MS_BIND, ""); err != nil {
				return fmt.Errorf("bind /dev/null over %s: %w", op.Target, err)
			}
			if op.ReadOnly {
				if err := syscall.Mount("", op.Target, "",
					syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
					return fmt.Errorf("remounting %s read-only: %w", op.Target, err)
				}
			}
		case MechTmpfs:
			opts := ""
			if op.TmpfsSize != "" {
				opts = "size=" + op.TmpfsSize
			}
			// noexec: only /tmp needs exec (Appendix A); mask overlays never do.
			if err := syscall.Mount("tmpfs", op.Target, "tmpfs",
				syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV, opts); err != nil {
				return fmt.Errorf("tmpfs over %s: %w", op.Target, err)
			}
		}
	}
	return nil
}

// EnterPrivateNamespace unshares the mount namespace and makes every mount
// private so mask mounts do not propagate back to the host view.
func EnterPrivateNamespace() error {
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare(CLONE_NEWNS): %w (root or CAP_SYS_ADMIN required)", err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("remounting / private: %w", err)
	}
	return nil
}

// CanApplyMounts probes whether the current process could apply Layer 0
// mounts directly (effective uid 0; finer capability checks are the
// caller's concern).
func CanApplyMounts() bool { return os.Geteuid() == 0 }

// BuildView materializes a box's host-side mask view for the vm backend
// (Layer 2): bind the box's tree at viewRoot, make the bind private so
// mask mounts cannot propagate back into the real tree, then apply the
// Layer 0 plan over the view. The virtiofs share is pointed at viewRoot, so
// the enforcement point stays outside the guest even when the guest has
// root: unmounting inside the guest exposes the view, not the tree.
//
// ops must already be retargeted at viewRoot (RetargetOps).
func BuildView(treeRoot, viewRoot string, ops []MountOp) error {
	if err := os.MkdirAll(viewRoot, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount(treeRoot, viewRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w (root or CAP_SYS_ADMIN required)", treeRoot, viewRoot, err)
	}
	if err := syscall.Mount("", viewRoot, "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		_ = syscall.Unmount(viewRoot, syscall.MNT_DETACH)
		return fmt.Errorf("making view %s private: %w", viewRoot, err)
	}
	if err := ApplyLayer0(ops); err != nil {
		_ = syscall.Unmount(viewRoot, syscall.MNT_DETACH)
		return err
	}
	return nil
}

// TeardownView lazily detaches a view built by BuildView, including every
// mask mount stacked on it. Idempotent: a path that is not a mountpoint (or
// does not exist) is not an error, so recreate and remove paths can call it
// unconditionally.
func TeardownView(viewRoot string) error {
	err := syscall.Unmount(viewRoot, syscall.MNT_DETACH)
	if err != nil && err != syscall.EINVAL && !os.IsNotExist(err) {
		return fmt.Errorf("unmounting view %s: %w", viewRoot, err)
	}
	if err := os.Remove(viewRoot); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing view root %s: %w", viewRoot, err)
	}
	return nil
}

// IsMountPoint reports whether path appears as a mount point in this
// process's mount table. st_dev comparison is not usable here: a bind of a
// path on the same filesystem keeps the device number.
//
// Symlinks are resolved on the *parent* and the base name rejoined, never
// on path itself: path is frequently a FUSE mountpoint, and stat-ing the
// root of a share whose daemon has died blocks in the kernel forever. The
// callers that most need an answer — teardown, and the spawn-time check for
// a stale mount — are exactly the ones reached when the daemon is gone, so
// this must never touch the mount to decide.
func IsMountPoint(path string) bool {
	blob, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	clean := filepath.Clean(path)
	if parent, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		clean = filepath.Join(parent, filepath.Base(clean))
	}
	for _, line := range strings.Split(string(blob), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && unescapeMountPath(f[4]) == clean {
			return true
		}
	}
	return false
}

// unescapeMountPath decodes the octal escapes mountinfo uses for spaces,
// tabs, newlines, and backslashes in mount paths.
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
