package backend

import (
	"bufio"
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

// VMBackend provides the vm tier: Kata Containers driven through Docker. The
// image pipeline, the configuration model, the mask generator and the egress
// policy are exactly the ones the container backend uses; what changes is the
// runtime handed to the engine and the construction of the share.
type VMBackend struct {
	EngineBin string // "docker"
	VMRuntime string // engine runtime name: "kata", "kata-qemu", "kata-clh"
	StateRoot string // agentbox state root: share views live here

	Runner func(args ...string) *exec.Cmd
	Warnf  func(format string, a ...any)

	// canMountView is a test seam over mask.CanApplyMounts.
	canMountView func() bool
	// hostResolvers is a test seam over the host's upstream nameservers.
	hostResolvers func() ([]string, error)
	// probeGrace is how long probeProxyReach keeps retrying while the sidecar
	// finishes binding. Zero disables the wait.
	probeGrace time.Duration
}

// NewVMBackend builds the vm backend from a probed "<engine>/<runtime>"
// record (see detectVMRuntime).
func NewVMBackend(probedRuntime, stateRoot string) *VMBackend {
	engineBin, runtimeName := SplitVMRuntime(probedRuntime)
	v := &VMBackend{EngineBin: engineBin, VMRuntime: runtimeName, StateRoot: stateRoot}
	v.Runner = func(args ...string) *exec.Cmd { return exec.Command(engineBin, args...) }
	v.Warnf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...) }
	v.canMountView = mask.CanApplyMounts
	v.hostResolvers = hostUpstreamResolvers
	v.probeGrace = 15 * time.Second
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
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locating the agentbox binary to run as the share daemon: %w", err)
		}
		err = share.EnsureDaemon(v.StateRoot, exe, &share.DaemonSpec{
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

// CreateNetwork builds the box's network topology, which is the container
// tier's: a per-box bridge the guest sits on, and -- in proxy mode -- an
// egress network only the proxy sidecar joins. The guest's only route out is
// therefore through a proxy enforcing the allowlist, and a tool that ignores
// HTTPS_PROXY fails closed rather than reaching the internet.
//
// A Kata guest talks to its sidecar over an ordinary bridge, which was worth
// establishing rather than assuming: it does work, but Docker's embedded DNS
// resolver does not. Docker publishes it at 127.0.0.11 inside the network
// namespace, and a VM guest's loopback is its own, so nothing in the box can
// reach it and container names do not resolve. Everything below follows from
// that: the sidecar is addressed by a pinned IP rather than by name, and open
// mode carries its own resolv.conf.
//
// The subnet is allocated explicitly so a box never lands on one the engine
// or another box already holds. 100.64.0.0/10 (RFC 6598) is carved for
// exactly this kind of second-layer use and steers clear of host LANs.
func (v *VMBackend) CreateNetwork(spec *BoxSpec) error {
	proxyMode := spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy
	openMode := spec.Policy != nil && spec.Policy.Mode == netpol.ModeOpen

	// Allocation reads the engine's network list and then creates a network,
	// which is a check-then-act against state agentbox does not own. Two boxes
	// coming up at the same moment -- different workspaces, so no shared
	// agentbox lock serializes them -- can survey the same free /24 and both
	// try to claim it. The engine rejects the loser, so retry: re-surveying
	// after a failure is what makes the winner visible.
	var subnet, gateway string
	var err error
	tried := map[string]bool{}
	for attempt := 0; ; attempt++ {
		subnet, gateway, err = v.allocateSubnet(tried)
		if err != nil {
			return err
		}
		tried[subnet] = true
		args := []string{"network", "create", "--subnet", subnet, "--gateway", gateway}
		if !openMode {
			// Only open mode gets a route off the bridge.
			args = append(args, "--internal")
		}
		err = v.run(append(args, spec.ResourceName+"-int")...)
		if err == nil {
			break
		}
		if attempt >= 4 {
			return fmt.Errorf("could not allocate a free subnet for the box bridge after %d attempts: %w", attempt+1, err)
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	// Pin the sidecar at .2 (the engine holds .1 as the gateway) so the proxy
	// address baked into the guest's environment at create time stays correct
	// across restarts, with no lookup and no DNS.
	addr, err := proxyAddrIn(subnet)
	if err != nil {
		return err
	}
	spec.ProxyAddr = addr
	if proxyMode {
		return v.run("network", "create", spec.ResourceName+"-egress")
	}
	return nil
}

// proxyAddrIn returns the address the sidecar is pinned to within a box
// bridge's subnet: host .2, because the engine holds .1 as the gateway.
//
// One implementation, shared by the path that allocates the subnet and the
// path that recovers it from an existing network. Two would be free to
// disagree, and a disagreement here is a box whose baked-in HTTPS_PROXY
// points at an address nothing is listening on.
func proxyAddrIn(cidr string) (string, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("box bridge subnet %q is not a CIDR: %w", cidr, err)
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return "", fmt.Errorf("box bridge subnet %q is not IPv4", cidr)
	}
	addr := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+2)
	if !n.Contains(addr) {
		return "", fmt.Errorf("box bridge subnet %q is too small to hold a pinned proxy address", cidr)
	}
	return addr.String(), nil
}

// resolveProxyAddr fills in spec.ProxyAddr when the caller did not create the
// network on this invocation.
//
// CreateNetwork is the only place the address is assigned, and ensureUp calls
// it only when the box is absent from the runtime. Every restart of an
// existing box therefore reaches Start with an empty ProxyAddr, and an empty
// one is silently destructive twice over: createProxySidecar omits --ip and
// lets the engine place the sidecar anywhere, while the guest's HTTPS_PROXY
// was baked at create time and still names <subnet>.2 -- a box with a running
// proxy it can never dial, whose every network call hangs with no error. The
// reachability probe, meanwhile, dials /dev/tcp//3128 and reports a healthy
// box as unreachable after burning the full probe grace.
//
// The bridge itself is the authority, so read it back rather than persisting
// a second copy that could drift from the network it describes.
func (v *VMBackend) resolveProxyAddr(spec *BoxSpec) error {
	if spec.ProxyAddr != "" {
		return nil
	}
	bridge := spec.ResourceName + "-int"
	out, err := engineOutput(v.Runner, "network", "inspect", "--format", v.subnetInspectFormat(), bridge)
	if err != nil {
		return fmt.Errorf("cannot determine the proxy address for box %s: its bridge %s could not be inspected: %w",
			spec.ResourceName, bridge, err)
	}
	for _, field := range strings.Fields(out) {
		if addr, err := proxyAddrIn(field); err == nil {
			spec.ProxyAddr = addr
			return nil
		}
	}
	return fmt.Errorf("cannot determine the proxy address for box %s: its bridge %s reports no usable IPv4 subnet",
		spec.ResourceName, bridge)
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

// allocateSubnet picks a free /24 for a box bridge and its .1 gateway.
//
// skip holds subnets this call already tried and lost. Excluding them is what
// makes the retry terminate: re-surveying is not enough on its own, because
// the survey can still be reporting the moment before the winner's network
// appeared, and we would pick the same address forever.
func (v *VMBackend) allocateSubnet(skip map[string]bool) (subnet, gateway string, err error) {
	used, err := v.usedSubnets()
	if err != nil {
		return "", "", err
	}
	for a := 64; a < 128; a++ {
		for b := 0; b < 256; b++ {
			base := fmt.Sprintf("100.%d.%d.0", a, b)
			cidr := base + "/24"
			if skip[cidr] {
				continue
			}
			_, cand, _ := net.ParseCIDR(cidr)
			if !overlapsAny(cand, used) {
				return cidr, fmt.Sprintf("100.%d.%d.1", a, b), nil
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

// hostUpstreamResolvers returns the host's real upstream nameservers.
//
// Loopback entries are skipped: a stub resolver like systemd-resolved's
// 127.0.0.53 is reachable only from the host's own network namespace, which
// is precisely what a VM guest does not share. systemd's own
// /run/systemd/resolve/resolv.conf records the real upstreams behind the
// stub, so it is consulted first where it exists.
func hostUpstreamResolvers() ([]string, error) {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var out []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			if ip := net.ParseIP(fields[1]); ip != nil && !ip.IsLoopback() {
				out = append(out, fields[1])
			}
		}
		f.Close()
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, errors.New("no non-loopback nameserver found in /run/systemd/resolve/resolv.conf or /etc/resolv.conf")
}

// writeGuestResolvConf generates the resolv.conf bind-mounted into an
// open-mode guest, because Docker's embedded resolver cannot be reached from
// a VM. Note that --dns does not help: on a user-defined network the engine
// still writes 127.0.0.11 into the container's resolv.conf and merely points
// the embedded resolver's upstream at the given address.
func (v *VMBackend) writeGuestResolvConf(spec *BoxSpec) (string, error) {
	servers, err := v.hostResolvers()
	if err != nil {
		return "", fmt.Errorf("network mode \"open\" under the vm tier needs the host's upstream nameservers, "+
			"because a VM guest cannot reach the engine's embedded resolver: %w", err)
	}
	var b strings.Builder
	b.WriteString("# generated by agentbox: the engine's embedded resolver is unreachable from a VM guest\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	if err := os.MkdirAll(spec.StateDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(spec.StateDir, "resolv.conf")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// CreatePersistentState creates the box's persistent home, seeded
// from the image on first creation.
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
		// A nested container engine is permitted at this tier because it is
		// guest-local. The engine flag is confined to the guest by the VM
		// runtime (Kata: privileged_without_host_devices).
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

	switch {
	case spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy:
		// The proxy is addressed by IP: container-name DNS does not resolve
		// from a VM guest. In proxy mode the guest needs no resolver at all --
		// squid resolves on its behalf, which also means the box has no DNS
		// channel of its own to leak through.
		spec.ProxyEnv = netpol.ProxyEnv(fmt.Sprintf("http://%s:3128", spec.ProxyAddr))
	case spec.Policy != nil && spec.Policy.Mode == netpol.ModeOpen:
		path, err := v.writeGuestResolvConf(spec)
		if err != nil {
			return err
		}
		args = append(args, "--mount", "type=bind,src="+path+",dst=/etc/resolv.conf,readonly")
	}

	for k, val := range spec.Env {
		args = append(args, "-e", k+"="+val)
	}
	for k, val := range spec.ProxyEnv {
		args = append(args, "-e", k+"="+val)
	}

	args = append(args, spec.ImageRef, "sleep", "infinity")
	if err := v.run(args...); err != nil {
		return err
	}

	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		return createProxySidecar(v.Runner, v.EngineBin, spec)
	}
	return nil
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
		// Before anything touches the sidecar: on a restart CreateNetwork did
		// not run, so the pinned address has to be recovered from the bridge.
		// Refusing here is deliberate -- proceeding would produce an
		// unreachable proxy that reports no error at all.
		if err := v.resolveProxyAddr(spec); err != nil {
			return err
		}
		if err := ensureSidecarExists(v.Runner, v.EngineBin, spec); err != nil {
			return err
		}
		if err := v.run("start", spec.ResourceName+"-proxy"); err != nil {
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
		v.probeProxyReach(spec)
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
// It warns rather than failing: the policy is enforced at the sidecar, so an
// unreachable proxy is a box with no egress, not a box with widened egress.
// Failing closed here would let a transient engine hiccup take down work that
// would otherwise have run. What it must not do is stay quiet — a box whose
// every network call hangs is the most confusing failure this tier has.
func (v *VMBackend) probeProxyReach(spec *BoxSpec) {
	// bash, not sh: /dev/tcp is a bash builtin, and the box's /bin/sh is dash
	// on a Debian-family base, where it is not a real path and the probe would
	// report every healthy box as unreachable.
	//
	// exit 127 is "bash is not in this image" -- a custom [image].ref need not
	// carry it. That is a probe we could not run, not a box that cannot reach
	// its proxy, and the two must not produce the same message.
	const probeMissing = 127
	deadline := time.Now().Add(v.probeGrace)
	for {
		code, err := engineExecQuiet(v.Runner, spec.ResourceName, []string{
			"bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/%s/3128", spec.ProxyAddr),
		})
		if err == nil && code == 0 {
			return
		}
		if time.Now().After(deadline) {
			switch {
			case err != nil || code == probeMissing:
				v.Warnf("box %s: could not verify that it can reach its egress proxy at %s — the probe\n"+
					"itself could not run (the image may have no bash). Egress policy is enforced at\n"+
					"the proxy, so this is not a widened policy; what is unverified is whether the box\n"+
					"has any working egress at all.", spec.ResourceName, spec.ProxyAddr)
			default:
				v.Warnf("box %s: cannot reach its egress proxy at %s:3128. The box is running but every\n"+
					"network call from it will hang. `%s logs %s-proxy` shows why the sidecar is not\n"+
					"answering.", spec.ResourceName, spec.ProxyAddr, v.EngineBin, spec.ResourceName)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Stop halts the guest and its proxy. Stopping a VM box returns its memory to
// the host.
func (v *VMBackend) Stop(name string) error {
	_ = v.run("stop", "--time", "10", name+"-proxy")
	err := v.run("stop", "--time", "10", name)
	// Retract the box's share daemon; a no-op for view-mode boxes.
	_ = share.Teardown(v.StateRoot, name, v.viewRoot(name))
	return err
}

func (v *VMBackend) Remove(name string, keepState bool) error {
	_ = v.run("rm", "-f", name+"-proxy")
	if err := v.run("rm", "-f", name); err != nil {
		return err
	}
	_ = v.run("network", "rm", name+"-int")
	_ = v.run("network", "rm", name+"-egress")
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

func (v *VMBackend) Logs(name string, proxy bool, follow bool) error {
	target := name
	if proxy {
		target = name + "-proxy"
	}
	args := []string{"logs"}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, target)
	cmd := v.Runner(args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (v *VMBackend) ProxyLogCmd(name string, follow bool) *exec.Cmd {
	return proxyLogCmd(v.Runner, name, follow)
}

func (v *VMBackend) RemoveImage(ref string) error {
	return v.run("image", "rm", ref)
}
