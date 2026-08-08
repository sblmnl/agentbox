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

// fakeResult scripts one engine invocation. An engine command is not just a
// stdout string: the paths that distinguish a missing in-guest tool from an
// engine that could not run the command at all read the exit code and stderr,
// so the fake has to be able to produce both.
type fakeResult struct {
	stdout string
	stderr string
	code   int
}

// fakeEngine records engine invocations and scripts their results.
type fakeEngine struct {
	calls   [][]string
	outputs map[string]string     // args-prefix -> stdout, exit 0
	results map[string]fakeResult // args-prefix -> full result; consulted first
}

func (f *fakeEngine) runner(args ...string) *exec.Cmd {
	f.calls = append(f.calls, args)
	joined := strings.Join(args, " ")
	for prefix, r := range f.results {
		if strings.HasPrefix(joined, prefix) {
			return exec.Command("sh", "-c",
				"printf '%s\\n' "+shQuote(r.stdout)+"; "+
					"printf '%s\\n' "+shQuote(r.stderr)+" >&2; "+
					"exit "+strconv.Itoa(r.code))
		}
	}
	for prefix, out := range f.outputs {
		if strings.HasPrefix(joined, prefix) {
			return exec.Command("echo", out)
		}
	}
	return exec.Command("true")
}

// shQuote renders s as a single-quoted shell word.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

// runningBox is what `inspect` reports for a guest that came up and stayed up;
// Start checks it before going anywhere near the guest.
const runningBox = "true 4242 running 0"

func TestVMStartBringsProxyUpFirst(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{
		"network inspect": "127.0.0.1",
		"inspect":         runningBox,
	}}
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
// It returns the backend's warnings, which are the observable half of every
// path that declines to fail the box.
func startWithLiveProxyd(t *testing.T, fake *fakeEngine, name string) (*[]string, error) {
	t.Helper()
	v, warnings := testVM(t, fake, false)
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
	return warnings, v.Start(spec)
}

// A guest that cannot open a connection to its proxy must fail the box at
// start, naming the blocked path. Letting it come up means every network call
// in the guest hangs until it times out, with nothing on the host to show why.
func TestVMStartRefusesUnreachableProxy(t *testing.T) {
	for _, code := range []string{"7", "28"} { // refused, timed out
		t.Run("curl"+code, func(t *testing.T) {
			// The engine entered the box and the probe ran: the curl exit
			// code arrives on stdout of an exec that itself succeeded.
			fake := &fakeEngine{
				outputs: map[string]string{"network inspect": "127.0.0.1", "inspect": runningBox},
				results: map[string]fakeResult{"exec": {stdout: code}},
			}
			_, err := startWithLiveProxyd(t, fake, "unreach"+code)
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
// The engine entered the box and the script said so, both when the exit code
// reaches us through stdout and when the guest shell exits 127 directly.
func TestVMStartProbeUnavailableIsNotRefusal(t *testing.T) {
	t.Run("reported", func(t *testing.T) {
		fake := &fakeEngine{outputs: map[string]string{
			"network inspect": "127.0.0.1",
			"inspect":         runningBox,
			"exec":            "127", // command -v curl failed
		}}
		warnings, err := startWithLiveProxyd(t, fake, "noprobe")
		if err != nil {
			t.Fatalf("missing probe tool must not fail the box: %v", err)
		}
		if len(*warnings) != 0 {
			t.Errorf("a missing probe tool is not worth warning about; got %v", *warnings)
		}
	})
	t.Run("exit127", func(t *testing.T) {
		fake := &fakeEngine{
			outputs: map[string]string{"network inspect": "127.0.0.1", "inspect": runningBox},
			results: map[string]fakeResult{"exec": {code: 127}},
		}
		warnings, err := startWithLiveProxyd(t, fake, "noprobe127")
		if err != nil {
			t.Fatalf("missing probe tool must not fail the box: %v", err)
		}
		if len(*warnings) != 0 {
			t.Errorf("a missing probe tool is not worth warning about; got %v", *warnings)
		}
	})
}

// An engine that cannot run the probe at all is a different thing from a guest
// with no curl: the check that exists to catch silently-broken egress did not
// run. That must not pass as success — the box comes up, loudly.
func TestVMStartProbeEngineFailureWarns(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{"network inspect": "127.0.0.1", "inspect": runningBox},
		results: map[string]fakeResult{"exec": {
			code:   125,
			stderr: "Error: the handler does not support exec",
		}},
	}
	warnings, err := startWithLiveProxyd(t, fake, "execfail")
	if err != nil {
		t.Fatalf("an unrunnable probe is diagnostic and must not fail the box: %v", err)
	}
	if len(*warnings) != 1 {
		t.Fatalf("an unverified egress path must warn exactly once; got %v", *warnings)
	}
	for _, want := range []string{"could not verify", "egress proxy", "the handler does not support exec"} {
		if !strings.Contains((*warnings)[0], want) {
			t.Errorf("warning does not mention %q: %s", want, (*warnings)[0])
		}
	}
}

// `start` exiting 0 proves the runtime launched, not that the guest stayed up.
// A guest that aborts while booting must be named here, with its log, rather
// than surfacing later as an exec error against a box the engine calls exited.
func TestVMStartRefusesDeadGuest(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{
		"network inspect": "127.0.0.1",
		"inspect":         "false 0 exited 139",
		"logs":            "thread 'main' panicked at vstate.rs:447: Error creating the Kvm object",
	}}
	_, err := startWithLiveProxyd(t, fake, "deadguest")
	if err == nil {
		t.Fatal("Start accepted a box that exited immediately")
	}
	for _, want := range []string{"exited immediately", "139", "vstate.rs:447"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	// The guest is gone: probing it would only produce a second, misleading
	// failure about the egress path.
	if fake.call("exec") != nil {
		t.Error("the egress probe must not run against a box that already exited")
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
		probed                  []string
		runtime, hypervisor     string
		wantEngine, wantRuntime string
		wantErr                 bool
	}{
		{[]string{"docker/kata"}, "auto", "auto", "docker", "kata", false},
		{[]string{"docker/kata"}, "", "", "docker", "kata", false},
		{[]string{"docker/kata"}, "kata", "auto", "docker", "kata", false},
		{[]string{"docker/kata-clh"}, "auto", "cloud-hypervisor", "docker", "kata-clh", false},
		{[]string{"docker/kata"}, "auto", "cloud-hypervisor", "", "", true},
		{[]string{"garbage"}, "auto", "auto", "", "", true},
		{nil, "auto", "auto", "", "", true},

		// krun is refused by name, and the refusal cannot depend on the host:
		// it holds whether or not the probe found something to run it with.
		{[]string{"docker/kata"}, "krun", "auto", "", "", true},
		{[]string{"docker/kata"}, "auto", "libkrun", "", "", true},
		{[]string{"podman/krun"}, "krun", "libkrun", "", "", true},
		{[]string{"podman/krun"}, "kata", "libkrun", "", "", true}, // contradictory
		{nil, "krun", "auto", "", "", true},

		// A host with a VM runtime under each engine must be able to name
		// either: preferring the first at probe time must not make the second
		// unreachable to an explicit request.
		{[]string{"docker/kata", "podman/kata-clh"}, "auto", "cloud-hypervisor", "podman", "kata-clh", false},
		{[]string{"docker/kata", "podman/kata-clh"}, "kata", "auto", "docker", "kata", false},
		{[]string{"docker/kata", "podman/kata-clh"}, "auto", "auto", "docker", "kata", false},
		{[]string{"podman/kata-clh", "docker/kata"}, "auto", "auto", "podman", "kata-clh", false},
		{[]string{"docker/kata-clh", "podman/kata-clh"}, "auto", "qemu", "", "", true},
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

// The refusal has to say what is wrong and what to do instead. The generic
// "not configured on this host" message sends the user off to install a
// runtime that cannot work here however they change the host.
func TestResolveVMRuntimeRefusesKrunByName(t *testing.T) {
	prev := listEngineRuntimes
	listEngineRuntimes = func(string) []string { return nil }
	defer func() { listEngineRuntimes = prev }()

	for _, c := range []struct{ runtime, hypervisor string }{
		{"krun", "auto"},
		{"auto", "libkrun"},
		{"krun", "libkrun"},
	} {
		// Named on a host that has krun to run it with, so the refusal is
		// visibly a property of the runtime and not of this machine.
		_, _, err := ResolveVMRuntime([]string{"podman/krun", "docker/kata"}, c.runtime, c.hypervisor)
		if err == nil {
			t.Fatalf("runtime=%q hypervisor=%q was accepted; krun cannot serve the vm tier", c.runtime, c.hypervisor)
		}
		for _, want := range []string{"exec", "crun#2090", "kata"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("runtime=%q hypervisor=%q: refusal does not mention %q: %v", c.runtime, c.hypervisor, want, err)
			}
		}
	}
}

// A request that no engine can satisfy must name every runtime it did find,
// across engines — the message is the only thing telling the user what to
// install, and a truncated one sends them after the wrong engine.
func TestResolveVMRuntimeErrorNamesAllEngines(t *testing.T) {
	prev := listEngineRuntimes
	listEngineRuntimes = func(engine string) []string {
		if engine == "docker" {
			return []string{"runc", "kata"}
		}
		return nil
	}
	defer func() { listEngineRuntimes = prev }()

	_, _, err := ResolveVMRuntime([]string{"docker/kata", "podman/kata-qemu"}, "auto", "cloud-hypervisor")
	if err == nil {
		t.Fatal("expected an error: no engine provides kata-clh")
	}
	for _, want := range []string{"kata-clh", "docker/kata", "docker/runc", "podman/kata-qemu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestAvailabilityVMRuntimes(t *testing.T) {
	// Availability records built before Runtimes existed (and the container
	// tier, which has no runtime list) must still resolve through Runtime.
	if got := (Availability{Runtime: "docker/kata"}).VMRuntimes(); len(got) != 1 || got[0] != "docker/kata" {
		t.Errorf("VMRuntimes() = %q; want [docker/kata]", got)
	}
	av := Availability{Runtime: "docker/kata", Runtimes: []string{"docker/kata", "podman/kata-clh"}}
	if got := av.VMRuntimes(); len(got) != 2 || got[1] != "podman/kata-clh" {
		t.Errorf("VMRuntimes() = %q; want both candidates", got)
	}
	if got := (Availability{}).VMRuntimes(); got != nil {
		t.Errorf("VMRuntimes() = %q; want nil", got)
	}
}

// Two runtimes are excluded from selection for the same category of reason —
// the runtime cannot deliver something this tier is built on — and neither
// may be reached by `auto` on a daemon that happens to have it registered.
func TestPickVMRuntimeExcludesUnusableRuntimes(t *testing.T) {
	// Appendix B: Firecracker MUST NOT be used — it has no virtiofs, and
	// the share layer hard-requires it.
	if got := pickVMRuntime([]string{"runc", "kata-fc"}); got != "" {
		t.Fatalf("kata-fc must never be selected, got %q", got)
	}
	if got := pickVMRuntime([]string{"runc", "kata-fc", "kata-clh"}); got != "kata-clh" {
		t.Fatalf("want kata-clh, got %q", got)
	}
	// krun: nothing can enter a box it created (containers/crun#2090).
	if got := pickVMRuntime([]string{"runc", "krun"}); got != "" {
		t.Fatalf("krun must never be selected, got %q", got)
	}
	if got := pickVMRuntime([]string{"runc", "krun", "kata"}); got != "kata" {
		t.Fatalf("want kata, got %q", got)
	}
}

// stubHostProbe replaces the host-probe seams for one test: present names the
// binaries on PATH, runtimes the runtime names each reachable engine reports
// (an engine absent from the map is installed but not answering).
func stubHostProbe(t *testing.T, present []string, runtimes map[string][]string) {
	t.Helper()
	oldLook, oldNames, oldReach := lookPath, engineRuntimeNames, engineReachable
	t.Cleanup(func() { lookPath, engineRuntimeNames, engineReachable = oldLook, oldNames, oldReach })

	have := map[string]bool{}
	for _, name := range present {
		have[name] = true
	}
	lookPath = func(name string) (string, error) {
		if have[name] {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	engineRuntimeNames = func(bin string) ([]string, error) {
		names, ok := runtimes[filepath.Base(bin)]
		if !ok {
			return nil, fmt.Errorf("daemon not reachable")
		}
		return names, nil
	}
	engineReachable = func(bin string) bool {
		_, ok := runtimes[filepath.Base(bin)]
		return ok
	}
}

// An installed krun is not a candidate — but it is not passed over in silence
// either: `doctor` and `backends` are where the user goes to find out why the
// tier is unavailable, and "no VM runtime" would send them to install the one
// they already have.
func TestDetectVMRuntimesRefusesKrun(t *testing.T) {
	stubHostProbe(t, []string{"podman", "krun"}, map[string][]string{"podman": nil})

	candidates, detail := detectVMRuntimes()
	if len(candidates) != 0 {
		t.Fatalf("krun must not be a candidate, got %q", candidates)
	}
	for _, want := range []string{"krun found but unusable", "exec", "crun#2090", "Kata"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail does not mention %q: %s", want, detail)
		}
	}
}

// Not installed and installed-but-unusable are different situations, and the
// message must not tell someone to install what would not help.
func TestDetectVMRuntimesKrunNotInstalled(t *testing.T) {
	stubHostProbe(t, []string{"podman"}, map[string][]string{"podman": nil})

	candidates, detail := detectVMRuntimes()
	if len(candidates) != 0 {
		t.Fatalf("no runtime is installed; got candidates %q", candidates)
	}
	if !strings.Contains(detail, "no krun binary on PATH") || !strings.Contains(detail, "crun#2090") {
		t.Errorf("detail should name both the absence and the refusal: %s", detail)
	}
}

func TestDetectVMRuntimesDocker(t *testing.T) {
	// A daemon with krun registered alongside kata: kata is the candidate.
	stubHostProbe(t, []string{"docker"}, map[string][]string{"docker": {"runc", "krun", "kata"}})
	if candidates, detail := detectVMRuntimes(); len(candidates) != 1 || candidates[0] != "docker/kata" {
		t.Errorf("detectVMRuntimes() = %q (%s); want [docker/kata]", candidates, detail)
	}

	// krun alone is no candidate whichever engine registers it.
	stubHostProbe(t, []string{"docker"}, map[string][]string{"docker": {"runc", "krun"}})
	candidates, detail := detectVMRuntimes()
	if len(candidates) != 0 {
		t.Errorf("krun must not be a candidate under docker either, got %q", candidates)
	}
	if !strings.Contains(detail, "no kata runtime configured") {
		t.Errorf("detail should name what the daemon is missing: %s", detail)
	}
}

// On a host whose only VM runtime is krun the tier is unavailable, with a
// reason that says why. `min_isolation = "vm"` then exits 69 naming it, which
// is the correct treatment of an unsatisfiable floor — the alternative is a
// box that comes up and cannot be entered.
func TestProbeVMKrunOnlyHostIsUnavailable(t *testing.T) {
	stubHostProbe(t, []string{"podman", "krun"}, map[string][]string{"podman": nil})

	av := probeVM()
	if av.Available {
		t.Fatal("the vm tier must not be available on a krun-only host")
	}
	for _, want := range []string{"exec", "crun#2090"} {
		if !strings.Contains(av.Reason, want) {
			t.Errorf("reason does not mention %q: %s", want, av.Reason)
		}
	}
}
