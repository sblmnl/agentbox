package backend

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sblmnl/agentbox/internal/mask"
	"github.com/sblmnl/agentbox/internal/netpol"
)

// fakeEngine records engine invocations and scripts their stdout.
type fakeEngine struct {
	calls   [][]string
	outputs map[string]string // args-prefix -> stdout
}

func (f *fakeEngine) runner(args ...string) *exec.Cmd {
	f.calls = append(f.calls, args)
	joined := strings.Join(args, " ")
	for prefix, out := range f.outputs {
		if strings.HasPrefix(joined, prefix) {
			return exec.Command("echo", out)
		}
	}
	return exec.Command("true")
}

func (f *fakeEngine) call(verb string) []string {
	for _, c := range f.calls {
		if len(c) > 0 && c[0] == verb {
			return c
		}
	}
	return nil
}

func testVM(t *testing.T, fake *fakeEngine, canMount bool) (*VMBackend, *[]string) {
	t.Helper()
	v := NewVMBackend("docker", "kata", t.TempDir())
	v.Runner = fake.runner
	v.canMountView = func() bool { return canMount }
	// Unit tests must not depend on the host's vsock modules, and must not
	// sit out the forwarder's start-up grace.
	v.waitReady = func(string, time.Duration) error { return nil }
	v.probeGrace = 0
	var warnings []string
	v.Warnf = func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	return v, &warnings
}

func proxySpec(t *testing.T, name string) *BoxSpec {
	t.Helper()
	return &BoxSpec{
		BoxID:        "box-" + name,
		ResourceName: "agentbox-" + name,
		ImageRef:     "agentbox/dev:abc",
		TreeRoot:     "/src/tree",
		Mount:        "/workspace",
		Workdir:      "/workspace",
		Policy:       &netpol.Policy{Mode: netpol.ModeProxy, Allow: []string{"api.anthropic.com"}, Audit: true},
		StateDir:     t.TempDir(), // the box's vsock token lands here
		Memory:       "8g",
		CPUs:         4,
		Pids:         4096,
		TmpfsSize:    "4g",
		Nofile:       65536,
	}
}

func TestVMCreateFlags(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{"network inspect": "10.89.4.1"}}
	v, _ := testVM(t, fake, false)

	spec := proxySpec(t, "t1")
	spec.GuestRoot = true
	spec.NestedDocker = true
	spec.MemoryBacking = "prealloc"
	spec.MaskPlan = []mask.MountOp{
		{Target: "/workspace/.env", Mechanism: mask.MechDevNull, ReadOnly: true},
		{Target: "/workspace/secrets", Mechanism: mask.MechTmpfs, TmpfsSize: "1m"},
	}
	if err := v.SetupShare(spec); err != nil {
		t.Fatal(err)
	}
	if err := v.Create(spec); err != nil {
		t.Fatal(err)
	}
	create := fake.call("create")
	if create == nil {
		t.Fatal("no engine create call")
	}
	joined := strings.Join(create, " ")

	for _, want := range []string{
		"--runtime kata",
		"--privileged", // nested_docker, guest-local under the vm runtime
		"--annotation io.katacontainers.config.hypervisor.enable_mem_prealloc=true",
		"--mount type=bind,src=/src/tree,dst=/workspace",
		"--mount type=bind,src=/dev/null,dst=/workspace/.env,readonly",
		"--tmpfs /workspace/secrets:noexec,size=1m",
		// Egress leaves over vsock, so the proxy is on loopback and the
		// forwarder binary is mounted in to carry it.
		"-e HTTPS_PROXY=http://127.0.0.1:3128",
		"dst=" + guestHelperPath + ",readonly",
		"-e AGENTBOX_VSOCK_TOKEN=",
		"vsockfwd",
		"sleep infinity",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("create args missing %q:\n%s", want, joined)
		}
	}
	// Container-tier hardening knobs are scoped away from this tier:
	// the boundary is the KVM barrier, not capability arithmetic.
	for _, absent := range []string{"--cap-drop", "--read-only", "--pids-limit", "--security-opt"} {
		if strings.Contains(joined, absent) {
			t.Errorf("create args must not carry container-tier flag %q:\n%s", absent, joined)
		}
	}
}

func TestVMGuestRootAccepted(t *testing.T) {
	// The container backend rejects GuestRoot; the vm tier is
	// exactly where root is safe with respect to masking.
	fake := &fakeEngine{outputs: map[string]string{"network inspect": "10.89.4.1"}}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "t2")
	spec.GuestRoot = true
	if err := v.Create(spec); err != nil {
		t.Fatalf("vm backend must accept guest root: %v", err)
	}
}

func TestVMSetupShareFallbackWarns(t *testing.T) {
	fake := &fakeEngine{}
	v, warnings := testVM(t, fake, false)
	spec := proxySpec(t, "t3")
	spec.GuestRoot = true
	spec.MaskPlan = []mask.MountOp{{Target: "/workspace/.env", Mechanism: mask.MechDevNull}}
	if err := v.SetupShare(spec); err != nil {
		t.Fatal(err)
	}
	if spec.ShareRoot != spec.TreeRoot || !spec.masksInGuest {
		t.Fatalf("fallback should share the tree with guest-expressed masks; got ShareRoot=%q masksInGuest=%v", spec.ShareRoot, spec.masksInGuest)
	}
	if len(*warnings) == 0 || !strings.Contains((*warnings)[0], "guest_root") {
		t.Fatalf("expected a guest-root degradation warning, got %v", *warnings)
	}
}

func TestVMSetupShareNoMasksIsQuiet(t *testing.T) {
	fake := &fakeEngine{}
	v, warnings := testVM(t, fake, false)
	spec := proxySpec(t, "t4")
	if err := v.SetupShare(spec); err != nil {
		t.Fatal(err)
	}
	if len(*warnings) != 0 {
		t.Fatalf("no masks, no warnings; got %v", *warnings)
	}
}

func TestVMStartBringsProxyUpFirst(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{"network inspect": "127.0.0.1"}}
	v, _ := testVM(t, fake, false)

	// An in-process proxyd serves the spool; the pidfile carries our own
	// pid so EnsureDaemon does not spawn anything.
	if err := os.MkdirAll(netpol.ProxydDir(v.StateRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netpol.PidfilePath(v.StateRoot), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &netpol.Proxyd{SpoolDir: netpol.SpoolDir(v.StateRoot), Logf: t.Logf, IdleExit: time.Hour}
	go p.Run(ctx)

	spec := proxySpec(t, "t5")
	spec.StateDir = filepath.Join(v.StateRoot, "boxdir")
	if err := v.Start(spec); err != nil {
		t.Fatal(err)
	}
	// Start returned, so WaitListener saw the listener accept — the guest
	// was started only after its proxy was reachable.
	if fake.call("start") == nil {
		t.Fatal("engine start was not invoked")
	}
	ls, err := netpol.ReadListenerSpec(v.StateRoot, spec.ResourceName)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Allow[0] != "api.anthropic.com" {
		t.Fatalf("listener spec carries wrong policy: %+v", ls)
	}
	// The vm tier attaches over vsock: the box is identified by a token,
	// and binds no address of its own.
	if ls.Token == "" || ls.Addr != "" {
		t.Fatalf("vm listener must be token-attached with no bound address: %+v", ls)
	}

	// Stop retracts the listener so the gateway address is not held.
	if err := v.Stop(spec.ResourceName); err != nil {
		t.Fatal(err)
	}
	if _, err := netpol.ReadListenerSpec(v.StateRoot, spec.ResourceName); !os.IsNotExist(err) {
		t.Fatalf("listener spec should be retracted on stop, got %v", err)
	}
}

// startWithLiveProxyd runs Start against an in-process proxyd, so the host-side
// listener genuinely comes up and only the guest-side probe is in question.
func startWithLiveProxyd(t *testing.T, fake *fakeEngine, name string) error {
	t.Helper()
	v, _ := testVM(t, fake, false)
	if err := os.MkdirAll(netpol.ProxydDir(v.StateRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netpol.PidfilePath(v.StateRoot), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &netpol.Proxyd{SpoolDir: netpol.SpoolDir(v.StateRoot), Logf: t.Logf, IdleExit: time.Hour}
	go p.Run(ctx)

	spec := proxySpec(t, name)
	spec.StateDir = filepath.Join(v.StateRoot, "boxdir")
	return v.Start(spec)
}

// A guest that cannot open a connection to its proxy must fail the box at
// start, naming the blocked path. Letting it come up means every network call
// in the guest hangs until it times out, with nothing on the host to show why.
func TestVMStartRefusesUnreachableProxy(t *testing.T) {
	for _, code := range []string{"7", "28"} { // refused, timed out
		t.Run("curl"+code, func(t *testing.T) {
			fake := &fakeEngine{outputs: map[string]string{
				"network inspect": "127.0.0.1",
				"exec":            code,
			}}
			err := startWithLiveProxyd(t, fake, "unreach"+code)
			if err == nil {
				t.Fatal("Start accepted a box whose guest cannot reach its proxy")
			}
			for _, want := range []string{"cannot reach its egress proxy", "forwarder", "CGO_ENABLED=0"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// A probe that cannot run is not evidence of a blocked path: a user-supplied
// image without curl must not be refused on the strength of a missing tool.
func TestVMStartProbeUnavailableIsNotRefusal(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{
		"network inspect": "127.0.0.1",
		"exec":            "127", // command -v curl failed
	}}
	if err := startWithLiveProxyd(t, fake, "noprobe"); err != nil {
		t.Fatalf("missing probe tool must not fail the box: %v", err)
	}
}

func TestVMCreateNetworkGatewayedSubnet(t *testing.T) {
	// One existing engine network already holds 100.64.0.0/24 (plus an
	// out-of-pool Docker default), so allocation must skip to the next /24.
	fake := &fakeEngine{outputs: map[string]string{
		"network ls":      "netA",
		"network inspect": "100.64.0.0/24 172.20.0.0/16",
	}}
	v, _ := testVM(t, fake, false)

	if err := v.CreateNetwork(proxySpec(t, "t6")); err != nil {
		t.Fatal(err)
	}
	var create []string
	for _, c := range fake.calls {
		if len(c) >= 2 && c[0] == "network" && c[1] == "create" {
			create = c
		}
	}
	if create == nil {
		t.Fatal("no `network create` call")
	}
	joined := strings.Join(create, " ")
	for _, want := range []string{
		"--internal",
		"--subnet 100.64.1.0/24", // 100.64.0.0/24 was taken
		"--gateway 100.64.1.1",   // the .1 proxyd binds and the guest routes through
		"agentbox-t6-int",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("network create missing %q:\n%s", want, joined)
		}
	}
}

func TestVMAllocateSubnetExhausted(t *testing.T) {
	// A single network covering the whole 100.64.0.0/10 pool leaves nothing
	// to allocate: the failure must be loud, not a silent unnumbered bridge.
	fake := &fakeEngine{outputs: map[string]string{
		"network ls":      "netA",
		"network inspect": "100.64.0.0/10",
	}}
	v, _ := testVM(t, fake, false)

	err := v.CreateNetwork(proxySpec(t, "t7"))
	if err == nil {
		t.Fatal("expected allocation to fail when the pool is exhausted")
	}
	if !strings.Contains(err.Error(), "no free /24") {
		t.Errorf("error should name the exhausted pool, got: %v", err)
	}
}

func TestResolveVMRuntime(t *testing.T) {
	prev := listEngineRuntimes
	listEngineRuntimes = func(string) []string { return nil }
	defer func() { listEngineRuntimes = prev }()
	cases := []struct {
		probed, runtime, hypervisor string
		wantEngine, wantRuntime     string
		wantErr                     bool
	}{
		{"docker/kata", "auto", "auto", "docker", "kata", false},
		{"podman/krun", "", "", "podman", "krun", false},
		{"podman/krun", "krun", "libkrun", "podman", "krun", false},
		{"podman/krun", "kata", "libkrun", "", "", true}, // contradictory
		{"podman/krun", "kata", "auto", "", "", true},    // kata not configured
		{"docker/kata", "auto", "cloud-hypervisor", "", "", true},
		{"garbage", "auto", "auto", "", "", true},
	}
	for _, c := range cases {
		engine, runtime, err := ResolveVMRuntime(c.probed, c.runtime, c.hypervisor)
		if c.wantErr != (err != nil) {
			t.Errorf("ResolveVMRuntime(%q,%q,%q): err = %v, wantErr %v", c.probed, c.runtime, c.hypervisor, err, c.wantErr)
			continue
		}
		if engine != c.wantEngine || runtime != c.wantRuntime {
			t.Errorf("ResolveVMRuntime(%q,%q,%q) = %q,%q; want %q,%q", c.probed, c.runtime, c.hypervisor, engine, runtime, c.wantEngine, c.wantRuntime)
		}
	}
}

func TestPickVMRuntimeExcludesFirecracker(t *testing.T) {
	// Appendix B: Firecracker MUST NOT be used — it has no virtiofs, and
	// the share layer hard-requires it.
	if got := pickVMRuntime([]string{"runc", "kata-fc"}); got != "" {
		t.Fatalf("kata-fc must never be selected, got %q", got)
	}
	if got := pickVMRuntime([]string{"runc", "kata-fc", "kata-clh"}); got != "kata-clh" {
		t.Fatalf("want kata-clh, got %q", got)
	}
}
