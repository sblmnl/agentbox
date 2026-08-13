package backend

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/sblmnl/agentbox/internal/netpol"
)

// ContainerBackend drives Docker or rootless Podman. Runner is
// injectable for tests.
type ContainerBackend struct {
	RuntimeBin string // "docker" or "podman"
	Runner     func(args ...string) *exec.Cmd
}

func NewContainerBackend(runtimeBin string) *ContainerBackend {
	cb := &ContainerBackend{RuntimeBin: runtimeBin}
	cb.Runner = func(args ...string) *exec.Cmd { return exec.Command(runtimeBin, args...) }
	return cb
}

func (c *ContainerBackend) Name() string { return "container" }
func (c *ContainerBackend) Tier() Tier   { return TierContainer }

func (c *ContainerBackend) run(args ...string) error {
	return engineRun(c.RuntimeBin, c.Runner, args...)
}

func (c *ContainerBackend) BuildImage(dir, tag string, buildArgs map[string]string, noCache bool) error {
	return engineBuild(c.Runner, dir, tag, buildArgs, noCache)
}

func (c *ContainerBackend) PullImage(ref string) error {
	return c.run("pull", ref)
}

// PrepareRootfs is a no-op for containers: the runtime consumes the OCI
// image directly.
func (c *ContainerBackend) PrepareRootfs(*BoxSpec) error { return nil }

// SetupShare is a no-op at the container tier: Layer 0 mask mounts are
// expressed on the container spec in Create.
func (c *ContainerBackend) SetupShare(*BoxSpec) error { return nil }

// CreateNetwork creates the box network and, in proxy mode, the egress
// network the proxy sidecar straddles.
//
// In proxy and off mode the box network is --internal: the guest has no route
// to any external address, so a tool that ignores HTTPS_PROXY fails closed
// rather than reaching the internet directly. Open mode is the one case where
// the box is meant to have an ordinary route, and it says so on every
// invocation.
func (c *ContainerBackend) CreateNetwork(spec *BoxSpec) error {
	args := []string{"network", "create"}
	if spec.Policy == nil || spec.Policy.Mode != netpol.ModeOpen {
		args = append(args, "--internal")
	}
	if err := c.run(append(args, spec.ResourceName+"-int")...); err != nil {
		return err
	}
	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		return c.run("network", "create", spec.ResourceName+"-egress")
	}
	return nil
}

func (c *ContainerBackend) CreatePersistentState(spec *BoxSpec) error {
	// The agent home persists across `down` as a named volume,
	// seeded from the image on first creation.
	return c.run("volume", "create", spec.ResourceName+"-home")
}

// Create constructs the box container and, in proxy mode, its sidecar.
func (c *ContainerBackend) Create(spec *BoxSpec) error {
	if spec.GuestRoot {
		// guest root under container converts every mask into a
		// suggestion; the schema already rejects it, this is defense in
		// depth.
		return fmt.Errorf("guest root is not available under the container tier")
	}

	args := []string{
		"create",
		"--name", spec.ResourceName,
		"--hostname", "agentbox",
		"--network", spec.ResourceName + "-int",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--pids-limit", strconv.Itoa(spec.Pids),
		"--memory", spec.Memory,
		"--cpus", strconv.FormatFloat(spec.CPUs, 'f', -1, 64),
		"--ulimit", fmt.Sprintf("nofile=%d:%d", spec.Nofile, spec.Nofile),
		// /tmp needs exec: single-file extractors run from it (App. A);
		// other tmpfs mounts stay noexec.
		"--tmpfs", "/tmp:exec,size=" + spec.TmpfsSize,
		"--tmpfs", "/run:noexec,size=16m",
		"--mount", "type=volume,src=" + spec.ResourceName + "-home,dst=/home/agent",
		"--workdir", spec.Workdir,
	}

	wsMode := ""
	if spec.ReadOnly {
		wsMode = ",readonly"
	}
	args = append(args, "--mount", "type=bind,src="+spec.TreeRoot+",dst="+spec.Mount+wsMode)

	// Layer 0 mask plan expressed as runtime mounts; the runtime sorts by
	// target depth so nested masks apply correctly (Appendix A).
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

	for k, v := range spec.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range spec.ProxyEnv {
		args = append(args, "-e", k+"="+v)
	}

	args = append(args, spec.ImageRef, "sleep", "infinity")
	if err := c.run(args...); err != nil {
		return err
	}

	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		if err := createProxySidecar(c.Runner, c.RuntimeBin, spec); err != nil {
			return err
		}
	}
	return nil
}

// createProxySidecar builds a box's squid sidecar. Both tiers share it: the
// policy engine, its configuration and its hardening must not be able to
// differ between them, or an allowlist would mean two things.
func createProxySidecar(runner func(...string) *exec.Cmd, engineBin string, spec *BoxSpec) error {
	proxyName := spec.ResourceName + "-proxy"
	// non-root, unprivileged port, all capabilities dropped,
	// read-only root. One sidecar per box keeps per-box process isolation
	// of the policy engine free.
	args := []string{
		"create",
		"--name", proxyName,
		"--network", spec.ResourceName + "-int",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", "31337:31337",
		// mode=1777 is load-bearing, not decoration. Docker only defaults a
		// tmpfs to 1777 when the mountpoint does not already exist in the
		// image; all three of these do exist in ubuntu/squid, so the mount
		// inherits the image directory's 0755 root:root and the sidecar --
		// which runs as 31337 with no capabilities -- cannot write its pid
		// file or its access log. Squid then exits FATAL before binding, and
		// every request from the box fails in a way that reads like a network
		// bug rather than a dead proxy.
		"--tmpfs", "/var/log/squid:size=64m,mode=1777",
		"--tmpfs", "/var/spool/squid:size=16m,mode=1777",
		"--tmpfs", "/run:size=4m,mode=1777",
		"--mount", "type=bind,src=" + spec.ProxyConfigPath() + ",dst=/etc/squid/squid.conf,readonly",
	}
	if spec.ProxyAddr != "" {
		// The vm tier pins the address because its guest cannot resolve
		// container names; see VMBackend.CreateNetwork.
		args = append(args, "--ip", spec.ProxyAddr)
	}
	args = append(args, "ubuntu/squid:latest")
	if err := engineRun(engineBin, runner, args...); err != nil {
		return err
	}
	// The sidecar also joins the egress network; the box container does
	// not, so the internal bridge is its only path.
	return engineRun(engineBin, runner, "network", "connect", spec.ResourceName+"-egress", proxyName)
}

// ProxyConfigPath is where the generated squid.conf for this box lives.
func (s *BoxSpec) ProxyConfigPath() string { return s.proxyConfigPath }

// SetProxyConfigPath is called by the orchestrator after generating the
// proxy config under the box state directory.
func (s *BoxSpec) SetProxyConfigPath(p string) { s.proxyConfigPath = p }

func (c *ContainerBackend) Start(spec *BoxSpec) error {
	if spec.Policy != nil && spec.Policy.Mode == netpol.ModeProxy {
		// The guest is not ready before its proxy is: a running
		// guest behind a dead proxy fails every network call in a way that
		// reads like a bug in the user's code.
		if err := ensureSidecarExists(c.Runner, c.RuntimeBin, spec); err != nil {
			return err
		}
		if err := c.run("start", spec.ResourceName+"-proxy"); err != nil {
			return err
		}
	}
	return c.run("start", spec.ResourceName)
}

// ensureSidecarExists recreates a missing proxy sidecar before start.
//
// A create interrupted between the guest and its sidecar leaves the guest
// present and the sidecar absent. Every later `up` then finds the guest, skips
// creation entirely, and fails starting a sidecar that was never made -- a
// box wedged permanently by one Ctrl-C. Recreating the missing half is what
// makes creation recoverable rather than a one-shot.
func ensureSidecarExists(runner func(...string) *exec.Cmd, engineBin string, spec *BoxSpec) error {
	if _, err := engineInspect(runner, engineBin, spec.ResourceName+"-proxy"); err == nil {
		return nil
	}
	return createProxySidecar(runner, engineBin, spec)
}

func (c *ContainerBackend) Stop(name string) error {
	_ = c.run("stop", "--time", "10", name+"-proxy")
	return c.run("stop", "--time", "10", name)
}

func (c *ContainerBackend) Remove(name string, keepState bool) error {
	_ = c.run("rm", "-f", name+"-proxy")
	if err := c.run("rm", "-f", name); err != nil {
		return err
	}
	_ = c.run("network", "rm", name+"-int")
	_ = c.run("network", "rm", name+"-egress")
	if !keepState {
		return c.run("volume", "rm", name+"-home")
	}
	return nil
}

// Exec runs a command in the box, forwarding signals and returning the
// command's exit code verbatim.
func (c *ContainerBackend) Exec(name string, es ExecSpec) (int, error) {
	return engineExec(c.Runner, name, es)
}

func (c *ContainerBackend) Inspect(name string) (State, error) {
	return engineInspect(c.Runner, c.RuntimeBin, name)
}

func (c *ContainerBackend) Logs(name string, proxy bool, follow bool) error {
	target := name
	if proxy {
		target = name + "-proxy"
	}
	args := []string{"logs"}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, target)
	cmd := c.Runner(args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *ContainerBackend) ProxyLogCmd(name string, follow bool) *exec.Cmd {
	return proxyLogCmd(c.Runner, name, follow)
}

func (c *ContainerBackend) RemoveImage(ref string) error {
	return c.run("image", "rm", ref)
}

// proxyLogCmd is shared by both tiers: the sidecar is an ordinary container
// under each, so its log is read the same way.
func proxyLogCmd(runner func(...string) *exec.Cmd, name string, follow bool) *exec.Cmd {
	args := []string{"logs"}
	if follow {
		args = append(args, "-f")
	}
	return runner(append(args, name+"-proxy")...)
}

// VerifyWorkspaceWritable checks the workspace mount from inside a started
// box: rootless Podman remaps uids, so host-uid matching does not
// transfer, and getting it wrong produces permission errors that look like
// a bug in the user's project.
func (c *ContainerBackend) VerifyWorkspaceWritable(name, mount string) error {
	code, err := c.Exec(name, ExecSpec{Argv: []string{"sh", "-c", "touch " + mount + "/.agentbox-writecheck && rm " + mount + "/.agentbox-writecheck"}})
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the workspace mount %s is not writable from inside the box; under rootless Podman this usually means the uid mapping is wrong (the backend should be using --userns=keep-id)", mount)
	}
	return nil
}
