package backend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/mask"
	"github.com/sblmnl/agentbox/internal/netpol"
	"github.com/sblmnl/agentbox/internal/share"
)

// VMBackend provides the vm tier on an OCI-consuming VM runtime — Kata
// Containers — driven through a container engine CLI. The image pipeline, the
// configuration model, and the mask generator are exactly the ones the
// container backend uses; what changes is the runtime handed to the engine,
// the share construction, and the proxy topology.
//
// Nothing here is Kata-specific by design; krun is refused a tier up, at
// selection (see krunRefusal), because it cannot be entered at all.
type VMBackend struct {
	EngineBin string // "docker" or "podman"
	VMRuntime string // engine runtime name: "kata", "kata-qemu", "kata-clh"
	StateRoot string // agentbox state root: proxyd spool and share views live here
	SelfExe   string // binary spawned as the proxyd daemon (normally os.Executable)

	Runner func(args ...string) *exec.Cmd
	Warnf  func(format string, a ...any)

	// canMountView is a test seam over mask.CanApplyMounts.
	canMountView func() bool
	// waitReady is a test seam over netpol.WaitVsockReady: binding a vsock
	// socket depends on host kernel modules, which unit tests must not need.
	waitReady func(stateRoot string, timeout time.Duration) error
	// probeGrace is how long probeProxyReach keeps retrying a refused
	// connection while the in-guest forwarder binds. Zero disables the wait.
	probeGrace time.Duration
}

func NewVMBackend(engineBin, vmRuntime, stateRoot string) *VMBackend {
	v := &VMBackend{EngineBin: engineBin, VMRuntime: vmRuntime, StateRoot: stateRoot}
	v.Runner = func(args ...string) *exec.Cmd { return exec.Command(engineBin, args...) }
	v.Warnf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...) }
	v.canMountView = mask.CanApplyMounts
	v.waitReady = netpol.WaitVsockReady
	v.probeGrace = 15 * time.Second
	if exe, err := os.Executable(); err == nil {
		v.SelfExe = exe
	}
	return v
}

func (v *VMBackend) Name() string { return "vm" }
func (v *VMBackend) Tier() Tier   { return TierVM }

func (v *VMBackend) run(args ...string) error {
	return engineRun(v.EngineBin, v.Runner, args...)
}

// BuildImage and PullImage never involve the VM runtime: both backends MUST
// consume the same OCI images, and the runtime converts to a guest
// rootfs at create time.
func (v *VMBackend) BuildImage(dir, tag string, buildArgs map[string]string, noCache bool) error {
	return engineBuild(v.Runner, dir, tag, buildArgs, noCache)
}

func (v *VMBackend) PullImage(ref string) error {
	return v.run("pull", ref)
}

// PrepareRootfs is a no-op: choosing an OCI-consuming runtime is precisely
// what keeps agentbox out of the rootfs-building business. Derived
// artifacts the runtime caches are keyed by it, not by us.
func (v *VMBackend) PrepareRootfs(*BoxSpec) error { return nil }

// ViewsDir holds every box's host-side mask view, and ViewRoot is one box's,
// keyed by resource name so Remove can find it with nothing but the name.
// Both are exported because a view is also an artifact the inspection and
// prune paths have to locate, and a second copy of this path that drifted
// would leave a mounted view nobody could name.
func ViewsDir(stateRoot string) string { return filepath.Join(stateRoot, "views") }

func ViewRoot(stateRoot, resourceName string) string {
	return filepath.Join(ViewsDir(stateRoot), resourceName)
}

func (v *VMBackend) viewRoot(resourceName string) string {
	return ViewRoot(v.StateRoot, resourceName)
}

// SetupShare constructs the share layer the guest will see.
//
// Under mask_mode "filter" (Layer 3) the view root is agentbox's own
// share daemon: a filtering passthrough filesystem whose lookups evaluate
// the mask patterns live, served to the guest by the runtime's virtiofsd.
// Delivering it needs the same host privilege the Layer 0 view does;
// failing to deliver an explicitly resolved filter mode is an error here,
// never a silent downgrade — the daemon either mounts or the box does
// not come up.
//
// Under "view": a host-side view — the tree bind-mounted privately with
// the Layer 0 plan stacked on top — and the virtiofs share pointed at the
// view. The enforcement point is then outside the guest, which is what
// makes the masks independent of guest privilege and is a requirement
// once the guest may have root. Building the view needs CAP_SYS_ADMIN on
// the host; without it the plan is expressed as guest mounts instead,
// which a guest root process could unmount — that degradation is warned
// about, never silent.
func (v *VMBackend) SetupShare(spec *BoxSpec) error {
	spec.ShareRoot = spec.TreeRoot
	if spec.MaskMode == "filter" {
		if len(spec.MaskSources) == 0 {
			// No pattern sources exist (e.g. --no-mask): nothing can ever
			// match, share the tree directly.
			return nil
		}
		view := v.viewRoot(spec.ResourceName)
		err := share.EnsureDaemon(v.StateRoot, v.SelfExe, &share.DaemonSpec{
			Resource:   spec.ResourceName,
			TreeRoot:   spec.TreeRoot,
			Mountpoint: view,
			Sources:    spec.MaskSources,
		})
		if err != nil {
			return fmt.Errorf("mask_mode \"filter\": %w (refusing to fall back to \"view\" silently)", err)
		}
		spec.ShareRoot = view
		return nil
	}
	// A mode switch from filter to view leaves a share daemon owning the
	// view root; retract it before building Layer 0 mounts there.
	if share.SpecExists(v.StateRoot, spec.ResourceName) {
		if err := share.Teardown(v.StateRoot, spec.ResourceName, v.viewRoot(spec.ResourceName)); err != nil {
			return err
		}
	}
	if len(spec.MaskPlan) == 0 {
		return nil
	}
	if !v.canMountView() {
		spec.masksInGuest = true
		if spec.GuestRoot {
			v.Warnf("vm backend: agentbox lacks CAP_SYS_ADMIN, so mask mounts are expressed inside the guest, and security.vm.guest_root = \"allow\" means a root process in the guest can unmount them; run agentbox as root for a host-side view, or set guest_root = \"deny\"")
		} else {
			v.Warnf("vm backend: agentbox lacks CAP_SYS_ADMIN; mask mounts are expressed inside the guest rather than as a host-side view")
		}
		return nil
	}
	view := v.viewRoot(spec.ResourceName)
	if err := mask.TeardownView(view); err != nil {
		return err
	}
	ops, err := mask.RetargetOps(spec.MaskPlan, spec.Mount, view)
	if err != nil {
		return err
	}
	if err := mask.BuildView(spec.TreeRoot, view, ops); err != nil {
		return fmt.Errorf("building mask view: %w", err)
	}
	spec.ShareRoot = view
	return nil
}

// CreateNetwork creates the box's internal bridge. Under this tier the
// bridge carries no egress at all — that leaves over vsock — so its only job
// is separation: an --internal network per box means no route off the
// bridge and no box adjacent to another. There is no egress network and no
// sidecar.
//
// Egress deliberately does not run over the bridge. A VM guest's path to a
// host process crosses the host's INPUT policy and any VPN kill-switch that
// filters by source address, neither of which the container engine knows
// about; the observed failure is a healthy-looking box where every network
// call hangs. vsock has no address to filter (see netpol/vsock.go).
//
// The subnet and gateway are set explicitly, unlike the container tier,
// purely so a box never lands on a subnet the engine or another box already
// holds; 100.64.0.0/10 (RFC 6598) is carved for exactly this kind of
// second-layer use and steers clear of host LANs. Note that on an
// --internal network the engine blanks the *endpoint* gateway whatever
// --gateway says, so the guest has no default route — with egress on vsock
// and nothing to reach off the bridge, it needs none.
func (v *VMBackend) CreateNetwork(spec *BoxSpec) error {
	subnet, gateway, err := v.allocateSubnet()
	if err != nil {
		return err
	}
	return v.run("network", "create", "--internal",
		"--subnet", subnet, "--gateway", gateway, spec.ResourceName+"-int")
}

// subnetInspectFormat is the engine-specific template listing a network's
// configured subnets. The inspect schema differs between the engines.
func (v *VMBackend) subnetInspectFormat() string {
	if v.EngineBin == "podman" {
		return "{{range .Subnets}}{{.Subnet}} {{end}}"
	}
	return "{{range .IPAM.Config}}{{.Subnet}} {{end}}"
}

// usedSubnets collects every subnet already configured on an engine network,
// so an allocated box subnet never overlaps one the engine or another box
// holds. A network without IPAM config contributes nothing.
func (v *VMBackend) usedSubnets() ([]*net.IPNet, error) {
	ids, err := engineOutput(v.Runner, "network", "ls", "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("listing engine networks: %w", err)
	}
	var used []*net.IPNet
	for _, id := range strings.Fields(ids) {
		out, err := engineOutput(v.Runner, "network", "inspect", "--format", v.subnetInspectFormat(), id)
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(out) {
			if _, n, err := net.ParseCIDR(field); err == nil {
				used = append(used, n)
			}
		}
	}
	return used, nil
}

// allocateSubnet picks a free /24 for a box bridge and its .1 gateway — the
// address proxyd binds and the guest routes through. It carves from
// 100.64.0.0/10 (RFC 6598 shared address space): reserved for exactly this
// second-layer-of-NAT use, so it steers clear of both host LANs and the
// engine's own default pools, and of any subnet already in use.
func (v *VMBackend) allocateSubnet() (subnet, gateway string, err error) {
	used, err := v.usedSubnets()
	if err != nil {
		return "", "", err
	}
	for a := 64; a < 128; a++ {
		for b := 0; b < 256; b++ {
			base := fmt.Sprintf("100.%d.%d.0", a, b)
			_, cand, _ := net.ParseCIDR(base + "/24")
			if !overlapsAny(cand, used) {
				return base + "/24", fmt.Sprintf("100.%d.%d.1", a, b), nil
			}
		}
	}
	return "", "", fmt.Errorf("no free /24 in 100.64.0.0/10 for the box bridge; too many engine networks exist")
}

func overlapsAny(c *net.IPNet, used []*net.IPNet) bool {
	for _, u := range used {
		if u.Contains(c.IP) || c.Contains(u.IP) {
			return true
		}
	}
	return false
}

// guestHelperPath is where the agentbox binary is bind-mounted inside the
// box, to be run as the in-guest end of the vsock egress path. It is the
// same binary the host runs: the vm tier already requires host and guest to
// share an architecture, and one binary means the forwarder cannot drift
// from the daemon it speaks to.
const guestHelperPath = "/usr/local/lib/agentbox/agentbox"

// vsockToken returns the box's egress token, minting it on first use.
//
// The token is what tells the shared host listener which box a connection
// belongs to, so it must survive restarts: the value was baked into the
// box's environment at create time, and a fresh one would leave the guest
// announcing a token no listener claims. It lives in the box state
// directory at 0600 rather than in box metadata because it is a secret,
// not a descriptor — nothing should print it.
func (v *VMBackend) vsockToken(spec *BoxSpec) (string, error) {
	path := filepath.Join(spec.StateDir, "vsock-token")
	if blob, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(blob)); tok != "" {
			return tok, nil
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("minting vsock token: %w", err)
	}
	tok := hex.EncodeToString(buf)
	if err := os.MkdirAll(spec.StateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("storing vsock token: %w", err)
	}
	return tok, nil
}

// CreatePersistentState creates the box's persistent home, seeded
// from the image on first creation. It is engine-managed; under Kata the
// runtime attaches it to the guest, giving the disk-image-backed semantics
// this tier requires.
func (v *VMBackend) CreatePersistentState(spec *BoxSpec) error {
	return v.run("volume", "create", spec.ResourceName+"-home")
}

// Create constructs the guest. Container-tier hardening flags (cap_drop,
// no-new-privileges, read-only root, pids-limit) are deliberately absent:
// they are guest-local knobs under a hypervisor and are scoped out of
// this tier; the boundary is the KVM barrier, not capability arithmetic.
func (v *VMBackend) Create(spec *BoxSpec) error {
	args := []string{
		"create",
		"--name", spec.ResourceName,
		"--hostname", "agentbox",
		"--runtime", v.VMRuntime,
		"--network", spec.ResourceName + "-int",
		"--memory", spec.Memory,
		"--cpus", strconv.FormatFloat(spec.CPUs, 'f', -1, 64),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", spec.Nofile, spec.Nofile),
		// /tmp needs exec: single-file extractors run from it (App. A).
		"--tmpfs", "/tmp:exec,size=" + spec.TmpfsSize,
		"--tmpfs", "/run:noexec,size=16m",
		"--mount", "type=volume,src=" + spec.ResourceName + "-home,dst=/home/agent",
		"--workdir", spec.Workdir,
	}

	if spec.MemoryBacking == "prealloc" {
		// Kata annotation; balloon (the default) needs nothing.
		args = append(args, "--annotation", "io.katacontainers.config.hypervisor.enable_mem_prealloc=true")
	}
	if spec.NestedDocker {
		// a nested container engine is permitted at this tier because
		// it is guest-local. The engine flag is confined to the guest by the
		// VM runtime (Kata: privileged_without_host_devices).
		args = append(args, "--privileged")
	}

	wsMode := ""
	if spec.ReadOnly {
		wsMode = ",readonly"
	}
	// ShareRoot is the host-side mask view when SetupShare built one; the
	// runtime's virtiofsd is thereby pointed at the view (Layer 2).
	shareRoot := spec.ShareRoot
	if shareRoot == "" {
		shareRoot = spec.TreeRoot
	}
	args = append(args, "--mount", "type=bind,src="+shareRoot+",dst="+spec.Mount+wsMode)

	if spec.masksInGuest {
		for _, op := range spec.MaskPlan {
			switch op.Mechanism {
			case "tmpfs":
				args = append(args, "--tmpfs", op.Target+":noexec,size="+op.TmpfsSize)
			default:
				m := "type=bind,src=/dev/null,dst=" + op.Target
				if op.ReadOnly {
					m += ",readonly"
				}
				args = append(args, "--mount", m)
			}
		}
	}

	// Egress leaves the box over vsock, not over the bridge, so the proxy
	// variables point at loopback: the in-guest forwarder listens there and
	// carries the bytes to the host daemon. Loopback is also the only
	// address that cannot be reached from another box.
	command := []string{"sleep", "infinity"}
	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		token, err := v.vsockToken(spec)
		if err != nil {
			return err
		}
		if v.SelfExe == "" {
			return fmt.Errorf("cannot locate the agentbox binary to run as the box's egress forwarder")
		}
		args = append(args,
			"--mount", "type=bind,src="+v.SelfExe+",dst="+guestHelperPath+",readonly",
			"-e", "AGENTBOX_VSOCK_TOKEN="+token)
		spec.ProxyEnv = netpol.ProxyEnv(fmt.Sprintf("http://127.0.0.1:%d", netpol.VsockPort))
		// The forwarder is supervised by the box's own init process: if it
		// dies the box keeps running with no egress, which would look like
		// a hung agent, so it is restarted rather than left down.
		command = []string{"sh", "-c",
			"while :; do " + guestHelperPath + " vsockfwd; sleep 1; done & exec sleep infinity"}
	}
	for k, val := range spec.Env {
		args = append(args, "-e", k+"="+val)
	}
	for k, val := range spec.ProxyEnv {
		args = append(args, "-e", k+"="+val)
	}

	args = append(args, spec.ImageRef)
	args = append(args, command...)
	return v.run(args...)
}

// Start brings the box up, proxy first: a running guest behind a
// dead proxy fails every network call in a way that reads like a bug in the
// user's code.
func (v *VMBackend) Start(spec *BoxSpec) error {
	// A view can be stale after a host reboot: the guest would then see an
	// empty tree (safe, but baffling). Rebuild it before starting. Under
	// filter mode SetupShare is always re-run: EnsureDaemon is a fast
	// no-op while the daemon is healthy and heals a dead daemon whose
	// mount lingers (which would otherwise serve ENOTCONN).
	if spec.MaskMode == "filter" {
		if err := v.SetupShare(spec); err != nil {
			return err
		}
	} else if spec.ShareRoot != "" && spec.ShareRoot != spec.TreeRoot && !mask.IsMountPoint(spec.ShareRoot) {
		if err := v.SetupShare(spec); err != nil {
			return err
		}
	}
	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		if err := v.ensureProxyListener(spec); err != nil {
			return err
		}
	}
	if err := v.run("start", spec.ResourceName); err != nil {
		return err
	}
	if err := v.confirmRunning(spec); err != nil {
		return err
	}
	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		return v.probeProxyReach(spec)
	}
	return nil
}

// confirmRunning checks that the guest is still up after `start` returned.
//
// Under this tier `start` exiting 0 proves only that the engine launched the
// runtime; a hypervisor that aborts while bringing the guest up — no KVM
// permission, an unsupported machine type, a rootfs the runtime cannot
// convert — does so a moment later and out of band. What the user sees then
// is the *next* command failing to enter a box the engine describes as
// exited, with the actual panic sitting unread in the engine's log. Reading
// the log here turns that into one named error at start.
func (v *VMBackend) confirmRunning(spec *BoxSpec) error {
	st, err := v.Inspect(spec.ResourceName)
	if err != nil {
		return fmt.Errorf("box %s: `start` reported success but the box cannot be inspected: %w", spec.ResourceName, err)
	}
	if st.Running {
		return nil
	}
	msg := fmt.Sprintf("box %s exited immediately after starting (status %q, exit code %d)",
		spec.ResourceName, st.Status, st.ExitCode)
	if tail := v.logTail(spec.ResourceName); tail != "" {
		msg += "\n\nlast lines of the guest log:\n" + tail
	}
	return fmt.Errorf("%s\n\nThe VM runtime launched but the guest did not stay up. `%s logs %s` has the\nfull output; a hypervisor that cannot open /dev/kvm and a rootfs the runtime\ncannot convert both fail this way.",
		msg, v.EngineBin, spec.ResourceName)
}

// logTail returns the last few lines of a box's engine log, best-effort: it is
// diagnostic detail attached to an error that stands without it.
func (v *VMBackend) logTail(name string) string {
	out, _ := v.Runner("logs", "--tail", "20", name).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// probeProxyReach checks, from inside the started guest, that the box can
// actually open a connection to its proxy.
//
// ensureProxyListener only proves the daemon bound its vsock socket on the
// *host*. What it cannot prove is that the in-guest forwarder came up and
// reached it: the binary mount could have failed, the guest could lack the
// vsock transport, or the forwarder could be crash-looping. In every one of
// those cases the engine reports a perfectly healthy box and every network
// call inside it hangs until it times out, which reads like a hung agent
// rather than a broken egress path. Turning that into one named error at
// start is the whole point of the probe.
//
// A probe that cannot run (no curl in a user-supplied image) is not evidence
// of a broken path and must not fail the box; only an actual connect failure
// is treated as one. That exemption is deliberately narrow: it covers a
// missing tool *inside* a guest the engine did enter, and nothing else. An
// engine that cannot run the probe at all — a box that died, an engine error,
// a runtime whose exec is not implemented — leaves the check that exists to
// catch silently-broken egress unable to run, and passing that off as success
// would be a fail-open. It warns on every invocation instead.
func (v *VMBackend) probeProxyReach(spec *BoxSpec) error {
	addr := fmt.Sprintf("127.0.0.1:%d", netpol.VsockPort)
	// The box has only just started; give its forwarder a moment to bind
	// before treating a refusal as the answer.
	deadline := time.Now().Add(v.probeGrace)
	var code string
	for {
		// Any HTTP status proves the path; only the connect must succeed.
		cmd := v.Runner("exec", spec.ResourceName, "sh", "-c",
			"command -v curl >/dev/null 2>&1 || exit 127; "+
				"curl -s -o /dev/null -m 5 --noproxy '*' http://"+addr+"/; echo $?")
		out, err := cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 127 {
				// The guest ran the script and it found no curl: the probe
				// could not run, which is not evidence of a broken path.
				return nil
			}
			v.probeUnrunnableWarning(spec, err)
			return nil
		}
		code = strings.TrimSpace(string(out))
		if code != "7" || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	switch code {
	case "7", "28": // connection refused / timed out
		return fmt.Errorf(
			"box %s cannot reach its egress proxy on %s\n"+
				"The host daemon bound its vsock socket, so what failed is inside the box:\n"+
				"the forwarder that carries loopback to the host is not accepting.\n"+
				"\n"+
				"  * `agentbox logs` shows the forwarder's own errors; it is restarted in a\n"+
				"    loop, so a persistent fault repeats there once a second.\n"+
				"  * An \"exec format error\" means the mounted agentbox binary does not run in\n"+
				"    the guest. Build it static — `CGO_ENABLED=0 go build ./cmd/agentbox` — as\n"+
				"    a binary dynamically linked against the host's libc will not run there.\n"+
				"  * A vsock connect failure means the runtime gave the box no vsock device.\n"+
				"    Check that the host has /dev/vhost-vsock and that the VM runtime is\n"+
				"    configured to attach one.\n"+
				"\n"+
				"proxyd log: %s",
			spec.ResourceName, addr, netpol.LogPath(v.StateRoot))
	}
	return nil
}

// probeUnrunnableWarning reports that the egress path could not be verified.
//
// It is a warning rather than an error because the box may well be fine and
// the probe is itself diagnostic: failing the box closed here would let a
// transient engine hiccup take down work that would otherwise have run. What
// it must not do is stay quiet — an unverified egress path is exactly the
// condition the probe exists to surface.
func (v *VMBackend) probeUnrunnableWarning(spec *BoxSpec, err error) {
	detail := err.Error()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if msg := strings.TrimSpace(string(ee.Stderr)); msg != "" {
			detail = msg
		}
	}
	v.Warnf("box %s: could not verify that the box can reach its egress proxy — the engine\n"+
		"could not run the probe in it. Egress policy is enforced by the host daemon, so\n"+
		"this is not a widened policy; what is unverified is whether the box has any\n"+
		"working egress at all, and a broken forwarder makes every network call inside\n"+
		"the box hang. `agentbox logs` shows the forwarder's errors.\n"+
		"engine: %s", spec.ResourceName, detail)
}

func (v *VMBackend) ensureProxyListener(spec *BoxSpec) error {
	token, err := v.vsockToken(spec)
	if err != nil {
		return err
	}
	ls := &netpol.ListenerSpec{
		BoxID:          spec.BoxID,
		Resource:       spec.ResourceName,
		Token:          token,
		Mode:           spec.Policy.Mode,
		Allow:          spec.Policy.Allow,
		Deny:           spec.Policy.Deny,
		Audit:          spec.Policy.Audit,
		AuditPath:      filepath.Join(spec.StateDir, "logs", "proxy-access.log"),
		ReadTimeout:    spec.ProxyReadTimeout,
		RequestTimeout: spec.ProxyRequestTimeout,
	}
	if err := netpol.WriteListenerSpec(v.StateRoot, ls); err != nil {
		return err
	}
	if err := netpol.EnsureDaemon(v.StateRoot, v.SelfExe); err != nil {
		return err
	}
	// The daemon publishes readiness as a file: a host process cannot dial
	// its own CID_ANY vsock socket to test it the way it dialed a bridge
	// gateway.
	if err := v.waitReady(v.StateRoot, 30*time.Second); err != nil {
		return fmt.Errorf("%w\nproxyd log: %s", err, netpol.LogPath(v.StateRoot))
	}
	return nil
}

// Stop halts the guest and retracts its proxy listener. Stopping a VM box
// returns its memory to the host; leaving the listener bound
// would hold a gateway address the engine may reuse.
func (v *VMBackend) Stop(name string) error {
	err := v.run("stop", "--time", "10", name)
	_ = netpol.RemoveListenerSpec(v.StateRoot, name)
	// Retract the box's share daemon; a no-op for view-mode boxes.
	_ = share.Teardown(v.StateRoot, name, v.viewRoot(name))
	return err
}

func (v *VMBackend) Remove(name string, keepState bool) error {
	_ = netpol.RemoveListenerSpec(v.StateRoot, name)
	if err := v.run("rm", "-f", name); err != nil {
		return err
	}
	_ = v.run("network", "rm", name+"-int")
	if err := share.Teardown(v.StateRoot, name, v.viewRoot(name)); err != nil {
		return err
	}
	if err := mask.TeardownView(v.viewRoot(name)); err != nil {
		return err
	}
	if !keepState {
		return v.run("volume", "rm", name+"-home")
	}
	return nil
}

func (v *VMBackend) Exec(name string, es ExecSpec) (int, error) {
	return engineExec(v.Runner, name, es)
}

func (v *VMBackend) Inspect(name string) (State, error) {
	return engineInspect(v.Runner, v.EngineBin, name)
}

// Logs streams guest logs from the engine. Proxy logs are not an engine
// artifact under this tier — they are the audit file the host daemon
// writes — and the caller (CmdLogs) reads that file directly, where it also
// works for a stopped box.
func (v *VMBackend) Logs(name string, proxy bool, follow bool) error {
	if proxy {
		return fmt.Errorf("vm proxy logs live in the box state directory (logs/proxy-access.log); use `agentbox logs --proxy`")
	}
	args := []string{"logs"}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, name)
	cmd := v.Runner(args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
