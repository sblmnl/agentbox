package backend

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
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

// CreateNetwork creates the internal (no-gateway) box network and the
// egress network the proxy sidecar straddles: the guest has no route
// to any external address, so a tool ignoring HTTPS_PROXY fails closed.
func (c *ContainerBackend) CreateNetwork(spec *BoxSpec) error {
	if err := c.run("network", "create", "--internal", spec.ResourceName+"-int"); err != nil {
		return err
	}
	if spec.Policy != nil && spec.Policy.Mode == "proxy" {
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

	if spec.Policy != nil && spec.Policy.Mode == "proxy" {
		if err := c.createProxySidecar(spec); err != nil {
			return err
		}
	}
	return nil
}

func (c *ContainerBackend) createProxySidecar(spec *BoxSpec) error {
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
		"--tmpfs", "/var/log/squid:size=64m",
		"--tmpfs", "/var/spool/squid:size=16m",
		"--tmpfs", "/run:size=4m",
		"--mount", "type=bind,src=" + spec.ProxyConfigPath() + ",dst=/etc/squid/squid.conf,readonly",
		"ubuntu/squid:latest",
	}
	if err := c.run(args...); err != nil {
		return err
	}
	// The sidecar also joins the egress network; the box container does
	// not, so the internal bridge is its only path.
	return c.run("network", "connect", spec.ResourceName+"-egress", proxyName)
}

// ProxyConfigPath is where the generated squid.conf for this box lives.
func (s *BoxSpec) ProxyConfigPath() string { return s.proxyConfigPath }

// SetProxyConfigPath is called by the orchestrator after generating the
// proxy config under the box state directory.
func (s *BoxSpec) SetProxyConfigPath(p string) { s.proxyConfigPath = p }

func (c *ContainerBackend) Start(spec *BoxSpec) error {
	if spec.Policy != nil && spec.Policy.Mode == "proxy" {
		// The guest is not ready before its proxy is: a running
		// guest behind a dead proxy fails every network call in a way that
		// reads like a bug in the user's code.
		if err := c.run("start", spec.ResourceName+"-proxy"); err != nil {
			return err
		}
	}
	return c.run("start", spec.ResourceName)
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
