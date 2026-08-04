//go:build linux

package share

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sblmnl/agentbox/internal/mask"
)

// DaemonSpec is one box's filtered share, serialized into the fsd spool as
// <resource>.json. Sources carry the pattern file *contents* captured
// host-side at spawn time: the daemon never opens pattern files from the
// tree it serves, because the tree is guest-writable and an agent that
// could edit its own mask patterns could unmask any path. Pattern changes
// take effect through the normal recreate path, where mask-digest drift
// is already detected and reported.
type DaemonSpec struct {
	Resource   string            `json:"resource"`
	TreeRoot   string            `json:"tree_root"`
	Mountpoint string            `json:"mountpoint"`
	Sources    []mask.SourceBlob `json:"sources"`
}

// Spool and pidfile layout under the agentbox state root, mirroring the
// netpol proxyd daemon.
func FsdDir(stateRoot string) string { return filepath.Join(stateRoot, "fsd") }
func specPath(stateRoot, resource string) string {
	return filepath.Join(FsdDir(stateRoot), resource+".json")
}
func pidPath(stateRoot, resource string) string {
	return filepath.Join(FsdDir(stateRoot), resource+".pid")
}

// LogPath is where a box's fsd daemon writes diagnostics.
func LogPath(stateRoot, resource string) string {
	return filepath.Join(FsdDir(stateRoot), resource+".log")
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func readPid(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(blob)))
	return pid
}

// EnsureDaemon declares a box's filtered share and makes it live: it
// writes the spec, spawns the fsd daemon when none is serving (or when the
// spec changed — the daemon's compiled filter is frozen at spawn), and
// waits for the mount to appear.
func EnsureDaemon(stateRoot, selfExe string, ds *DaemonSpec) error {
	if selfExe == "" {
		return fmt.Errorf("fsd: no agentbox binary path to spawn the share daemon from")
	}
	dir := FsdDir(stateRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	sp := specPath(stateRoot, ds.Resource)
	prev, _ := os.ReadFile(sp)
	pid := readPid(pidPath(stateRoot, ds.Resource))
	if pidAlive(pid) && mask.IsMountPoint(ds.Mountpoint) && bytes.Equal(prev, blob) {
		return nil // already serving this exact spec
	}
	// Spec changed or daemon dead: tear down before respawning so the
	// mount is never served by a daemon holding stale patterns.
	if err := Teardown(stateRoot, ds.Resource, ds.Mountpoint); err != nil {
		return err
	}

	tmp := sp + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, sp); err != nil {
		return err
	}
	if err := os.MkdirAll(ds.Mountpoint, 0o755); err != nil {
		return err
	}

	logf, err := os.OpenFile(LogPath(stateRoot, ds.Resource), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(selfExe, "fsd", "--spec", sp, "--pidfile", pidPath(stateRoot, ds.Resource))
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawning fsd: %w", err)
	}
	go cmd.Wait() // reap; lifetime is governed by the mount, not by us

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if mask.IsMountPoint(ds.Mountpoint) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("fsd did not mount %s within 10s\nfsd log: %s",
		ds.Mountpoint, LogPath(stateRoot, ds.Resource))
}

// Teardown retracts a box's filtered share: unmount, stop the daemon,
// remove its spool entries. A box that never had one is a no-op, so the
// backend can call this unconditionally on stop/remove.
func Teardown(stateRoot, resource, mountpoint string) error {
	sp := specPath(stateRoot, resource)
	pp := pidPath(stateRoot, resource)
	_, specErr := os.Stat(sp)
	pid := readPid(pp)
	if os.IsNotExist(specErr) && pid == 0 {
		return nil
	}
	if err := UnmountView(mountpoint); err != nil {
		return err
	}
	if pidAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 20 && pidAlive(pid); i++ {
			time.Sleep(50 * time.Millisecond)
		}
		if pidAlive(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	_ = os.Remove(pp)
	if err := os.Remove(sp); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SpecExists reports whether a filtered share is declared for resource —
// how the backend distinguishes a filter-mode view from a Layer 0 one.
func SpecExists(stateRoot, resource string) bool {
	_, err := os.Stat(specPath(stateRoot, resource))
	return err == nil
}

// RunDaemon is the hidden `fsd` subcommand: serve one box's filtered
// share until the mount goes away or the context is cancelled.
func RunDaemon(ctx context.Context, specFile, pidfile string, logw io.Writer) error {
	blob, err := os.ReadFile(specFile)
	if err != nil {
		return err
	}
	var ds DaemonSpec
	if err := json.Unmarshal(blob, &ds); err != nil {
		return fmt.Errorf("parsing %s: %w", specFile, err)
	}

	// Compile the filter from the frozen pattern contents — the same
	// parser, matcher, and predicate as every other masking layer.
	m, _, err := mask.MatcherFromSources(ds.Sources)
	if err != nil {
		return err
	}
	// Anchored patterns can be relocated out from under their match by
	// renaming an ancestor directory; the FS guards directory renames only
	// when they are present (unanchored patterns are rename-invariant).
	fs, err := NewFS(ds.TreeRoot, Filter(mask.FilterFn(m)), m.HasAnchored())
	if err != nil {
		return err
	}
	defer fs.Close()

	// Write the pidfile before mounting, not after: EnsureDaemon returns as
	// soon as the mount appears, and its "already serving" fast-path checks
	// the pidfile, so a mount observable before its pidfile would make a
	// concurrent EnsureDaemon tear down this healthy share and respawn.
	if pidfile != "" {
		if err := os.WriteFile(pidfile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			return err
		}
		defer os.Remove(pidfile)
	}

	// A stale mount from a previous daemon would shadow ours.
	if mask.IsMountPoint(ds.Mountpoint) {
		if err := UnmountView(ds.Mountpoint); err != nil {
			return err
		}
	}
	dev, err := mountFuse(ds.Mountpoint)
	if err != nil {
		return err
	}
	defer dev.Close()

	fmt.Fprintf(logw, "fsd: serving filtered share for %s: %s -> %s (%d pattern sources)\n",
		ds.Resource, ds.TreeRoot, ds.Mountpoint, len(ds.Sources))

	go func() {
		<-ctx.Done()
		// Unmounting makes Serve's device read return ENODEV.
		_ = UnmountView(ds.Mountpoint)
	}()

	err = NewConn(dev, fs).Serve()
	_ = UnmountView(ds.Mountpoint)
	if err != nil {
		return fmt.Errorf("serving %s: %w", ds.Mountpoint, err)
	}
	fmt.Fprintf(logw, "fsd: %s unmounted, exiting\n", ds.Mountpoint)
	return nil
}
