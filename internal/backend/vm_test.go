package backend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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

// callMatching returns the first recorded call whose joined form contains sub.
func (f *fakeEngine) callMatching(sub string) []string {
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			return c
		}
	}
	return nil
}

func testVM(t *testing.T, fake *fakeEngine, canMount bool) (*VMBackend, *[]string) {
	t.Helper()
	v := NewVMBackend("docker/kata", t.TempDir())
	v.Runner = fake.runner
	v.canMountView = func() bool { return canMount }
	v.hostResolvers = func() ([]string, error) { return []string{"192.0.2.53"}, nil }
	v.probeGrace = 0
	var warnings []string
	v.Warnf = func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }
	return v, &warnings
}

func proxySpec(t *testing.T, name string) *BoxSpec {
	t.Helper()
	s := &BoxSpec{
		BoxID:        "box-" + name,
		ResourceName: "agentbox-" + name,
		ImageRef:     "agentbox/dev:abc",
		TreeRoot:     "/src/tree",
		Mount:        "/workspace",
		Workdir:      "/workspace",
		Policy:       &netpol.Policy{Mode: netpol.ModeProxy, Allow: []string{"api.anthropic.com"}, Audit: true},
		StateDir:     t.TempDir(),
		Memory:       "8g",
		CPUs:         4,
		Pids:         4096,
		TmpfsSize:    "4g",
		Nofile:       65536,
		ProxyAddr:    "100.64.1.2",
	}
	s.SetProxyConfigPath(filepath.Join(t.TempDir(), "squid.conf"))
	return s
}

func TestVMCreateFlags(t *testing.T) {
	fake := &fakeEngine{}
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
		// The proxy is addressed by IP: container-name DNS does not resolve
		// from inside a VM guest.
		"-e HTTPS_PROXY=http://100.64.1.2:3128",
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

// The guest must never be handed a proxy URL naming the sidecar container.
// Docker publishes its embedded resolver at 127.0.0.11 inside the network
// namespace, and a VM guest's loopback is its own, so a name would simply
// fail to resolve and every request would die at DNS.
func TestVMProxyIsAddressedByIPNotName(t *testing.T) {
	fake := &fakeEngine{}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "byip")
	if err := v.Create(spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.call("create"), " ")
	if strings.Contains(joined, spec.ResourceName+"-proxy:3128") {
		t.Errorf("proxy addressed by container name; a VM guest cannot resolve it:\n%s", joined)
	}
	if !strings.Contains(joined, "http://"+spec.ProxyAddr+":3128") {
		t.Errorf("proxy not addressed by pinned IP:\n%s", joined)
	}
}

// The sidecar must be pinned to the address baked into the guest's
// environment, or a restart would renumber it and the box would lose egress.
func TestVMSidecarPinnedToProxyAddr(t *testing.T) {
	fake := &fakeEngine{}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "pin")
	if err := v.Create(spec); err != nil {
		t.Fatal(err)
	}
	sidecar := fake.callMatching(spec.ResourceName + "-proxy")
	if sidecar == nil {
		t.Fatal("proxy mode created no sidecar")
	}
	joined := strings.Join(sidecar, " ")
	if !strings.Contains(joined, "--ip "+spec.ProxyAddr) {
		t.Errorf("sidecar is not pinned to %s:\n%s", spec.ProxyAddr, joined)
	}
}

// Open mode is the one mode where the guest resolves names itself, and it
// cannot use the engine's embedded resolver. Note that --dns does not fix
// this: on a user-defined network the engine still writes 127.0.0.11 into the
// container's resolv.conf and only redirects the embedded resolver's upstream.
func TestVMOpenModeCarriesItsOwnResolvConf(t *testing.T) {
	fake := &fakeEngine{}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "open")
	spec.Policy = &netpol.Policy{Mode: netpol.ModeOpen}
	if err := v.Create(spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.call("create"), " ")
	if !strings.Contains(joined, "dst=/etc/resolv.conf,readonly") {
		t.Fatalf("open mode must bind-mount a generated resolv.conf:\n%s", joined)
	}
	blob, err := os.ReadFile(filepath.Join(spec.StateDir, "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "nameserver 192.0.2.53") {
		t.Errorf("generated resolv.conf should carry the host's upstream: %q", blob)
	}
	// Open mode has no proxy, so nothing should be pointed at one.
	if strings.Contains(joined, "HTTPS_PROXY") {
		t.Errorf("open mode must not set proxy variables:\n%s", joined)
	}
}

// A host whose only resolver is a loopback stub cannot serve open mode, and
// saying so beats a box that starts and then resolves nothing.
func TestVMOpenModeWithoutUsableResolverFails(t *testing.T) {
	fake := &fakeEngine{}
	v, _ := testVM(t, fake, false)
	v.hostResolvers = func() ([]string, error) { return nil, fmt.Errorf("only 127.0.0.53") }
	spec := proxySpec(t, "nores")
	spec.Policy = &netpol.Policy{Mode: netpol.ModeOpen}
	err := v.Create(spec)
	if err == nil {
		t.Fatal("open mode with no usable resolver must fail rather than start a box that cannot resolve")
	}
	if !strings.Contains(err.Error(), "nameserver") {
		t.Errorf("error should explain the resolver problem: %v", err)
	}
}

// Off mode gets no proxy and no route: nothing to configure, nothing to leak.
func TestVMOffModeHasNoProxyAndNoResolver(t *testing.T) {
	fake := &fakeEngine{}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "off")
	spec.Policy = &netpol.Policy{Mode: netpol.ModeOff}
	if err := v.Create(spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.call("create"), " ")
	if strings.Contains(joined, "HTTPS_PROXY") || strings.Contains(joined, "resolv.conf") {
		t.Errorf("off mode must configure neither proxy nor resolver:\n%s", joined)
	}
	if fake.callMatching(spec.ResourceName+"-proxy") != nil {
		t.Error("off mode must not create a proxy sidecar")
	}
}

func TestVMGuestRootAccepted(t *testing.T) {
	// The container backend rejects GuestRoot; the vm tier is
	// exactly where root is safe with respect to masking.
	fake := &fakeEngine{}
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

// The guest must not be started before its proxy: a running guest behind a
// dead proxy fails every network call in a way that reads like a bug in the
// user's own code.
func TestVMStartBringsProxyUpFirst(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{"inspect": runningBox}}
	v, _ := testVM(t, fake, false)

	spec := proxySpec(t, "t5")
	if err := v.Start(spec); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, c := range fake.calls {
		if len(c) == 2 && c[0] == "start" {
			order = append(order, c[1])
		}
	}
	if len(order) < 2 {
		t.Fatalf("expected the proxy and the guest to be started, got %v", order)
	}
	if order[0] != spec.ResourceName+"-proxy" || order[1] != spec.ResourceName {
		t.Errorf("proxy must start before the guest, got %v", order)
	}
}

// An unreachable proxy is a box with no egress, not a box with widened
// egress, so it warns rather than failing -- but it must never be silent.
func TestVMStartWarnsOnUnreachableProxy(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{"inspect": runningBox},
		results: map[string]fakeResult{"exec": {code: 1}},
	}
	v, warnings := testVM(t, fake, false)
	if err := v.Start(proxySpec(t, "unreach")); err != nil {
		t.Fatalf("an unreachable proxy must not fail the box: %v", err)
	}
	joined := strings.Join(*warnings, "\n")
	if !strings.Contains(joined, "cannot reach its egress proxy") {
		t.Errorf("expected a warning about the unreachable proxy, got: %v", *warnings)
	}
}

// A probe that could not run at all (no bash in a custom image) is a
// different fact from a proxy that is not answering, and saying the second
// when the first is true sends the user debugging a healthy sidecar.
func TestVMStartDistinguishesUnrunnableProbe(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{"inspect": runningBox},
		results: map[string]fakeResult{"exec": {code: 127}},
	}
	v, warnings := testVM(t, fake, false)
	if err := v.Start(proxySpec(t, "noprobe")); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*warnings, "\n")
	if !strings.Contains(joined, "could not verify") {
		t.Errorf("an unrunnable probe must say so, got: %v", *warnings)
	}
	if strings.Contains(joined, "cannot reach its egress proxy") {
		t.Errorf("an unrunnable probe must not be reported as an unreachable proxy: %v", *warnings)
	}
}

// The probe must use bash: /dev/tcp is a bash builtin, and /bin/sh on a
// Debian-family base is dash, where the path does not exist and every healthy
// box would be reported unreachable.
func TestVMProxyProbeUsesBash(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{"inspect": runningBox}}
	v, _ := testVM(t, fake, false)
	if err := v.Start(proxySpec(t, "probesh")); err != nil {
		t.Fatal(err)
	}
	probe := fake.callMatching("/dev/tcp/")
	if probe == nil {
		t.Fatal("no proxy reachability probe was run")
	}
	if !strings.Contains(strings.Join(probe, " "), "bash") {
		t.Errorf("probe must run under bash, got: %v", probe)
	}
}

func TestVMStartQuietWhenProxyReachable(t *testing.T) {
	fake := &fakeEngine{outputs: map[string]string{"inspect": runningBox}}
	v, warnings := testVM(t, fake, false)
	if err := v.Start(proxySpec(t, "reach")); err != nil {
		t.Fatal(err)
	}
	if len(*warnings) != 0 {
		t.Errorf("a reachable proxy should produce no warnings, got %v", *warnings)
	}
}

// inspectPrefix is the engine `inspect` invocation engineInspect issues, up to
// but not including the resource name. Scripting one resource's inspect to
// fail while another's succeeds needs the whole prefix.
const inspectPrefix = "inspect --format {{.State.Running}} {{.State.Pid}} {{.State.Status}} {{.State.ExitCode}} "

// A restart does not run CreateNetwork, so Start arrives with an empty
// ProxyAddr and has to recover it from the bridge. Getting this wrong is
// silent: an unpinned sidecar lands on an arbitrary address while the guest's
// baked-in HTTPS_PROXY still names <subnet>.2, so every network call inside
// the box hangs forever with nothing logged anywhere.
func TestVMStartPinsSidecarAfterRestart(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{
			"inspect":         runningBox,
			"network inspect": "100.64.7.0/24",
		},
		// The sidecar is absent -- the interrupted-create case
		// ensureSidecarExists exists to recover from.
		results: map[string]fakeResult{
			inspectPrefix + "agentbox-restart-proxy": {code: 1, stderr: "No such object"},
		},
	}
	v, warnings := testVM(t, fake, false)

	spec := proxySpec(t, "restart")
	spec.ProxyAddr = ""
	if err := v.Start(spec); err != nil {
		t.Fatal(err)
	}

	sidecar := fake.callMatching("--name " + spec.ResourceName + "-proxy")
	if sidecar == nil {
		t.Fatal("the missing sidecar was not recreated")
	}
	if joined := strings.Join(sidecar, " "); !strings.Contains(joined, "--ip 100.64.7.2") {
		t.Errorf("recreated sidecar is not pinned to the bridge's .2:\n%s", joined)
	}
	probe := fake.callMatching("/dev/tcp/")
	if probe == nil {
		t.Fatal("no proxy reachability probe was run")
	}
	if joined := strings.Join(probe, " "); !strings.Contains(joined, "/dev/tcp/100.64.7.2/3128") {
		t.Errorf("probe dialled the wrong address:\n%s", joined)
	}
	if len(*warnings) != 0 {
		t.Errorf("a recovered, reachable proxy should produce no warnings, got %v", *warnings)
	}
}

// If the address cannot be recovered, Start must refuse. Carrying on would
// hand the user a box that looks healthy and can reach nothing, which is the
// hardest failure this tier has to diagnose.
func TestVMStartRefusesUnresolvableProxyAddr(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{"inspect": runningBox},
		results: map[string]fakeResult{"network inspect": {code: 1, stderr: "No such network"}},
	}
	v, _ := testVM(t, fake, false)

	spec := proxySpec(t, "noaddr")
	spec.ProxyAddr = ""
	err := v.Start(spec)
	if err == nil {
		t.Fatal("Start accepted a proxy-mode box whose proxy address could not be resolved")
	}
	if !strings.Contains(err.Error(), spec.ResourceName+"-int") {
		t.Errorf("error should name the bridge it could not inspect: %v", err)
	}
	if c := fake.call("create"); c != nil {
		t.Errorf("no container should be created once the address is unresolvable, got %v", c)
	}
}

func TestVMStartRefusesDeadGuest(t *testing.T) {
	// `start` exits 0 but the guest aborted a moment later: the engine
	// reports it exited, and the failure must be named here rather than
	// surfacing as the next command failing to enter the box.
	fake := &fakeEngine{outputs: map[string]string{"inspect": "false 0 exited 1"}}
	v, _ := testVM(t, fake, false)
	err := v.Start(proxySpec(t, "dead"))
	if err == nil {
		t.Fatal("Start accepted a guest that exited immediately")
	}
	if !strings.Contains(err.Error(), "exited immediately") {
		t.Errorf("error should name the dead guest: %v", err)
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

	spec := proxySpec(t, "t6")
	if err := v.CreateNetwork(spec); err != nil {
		t.Fatal(err)
	}
	create := fake.callMatching("-int")
	if create == nil {
		t.Fatal("no `network create` call for the box network")
	}
	joined := strings.Join(create, " ")
	for _, want := range []string{
		"--internal",
		"--subnet 100.64.1.0/24", // 100.64.0.0/24 was taken
		"--gateway 100.64.1.1",
		"agentbox-t6-int",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("network create missing %q:\n%s", want, joined)
		}
	}
	// The sidecar address must land inside the allocated subnet.
	if spec.ProxyAddr != "100.64.1.2" {
		t.Errorf("ProxyAddr = %q, want 100.64.1.2 (inside the allocated subnet)", spec.ProxyAddr)
	}
	// Proxy mode also needs the egress network the sidecar straddles.
	if fake.callMatching("-egress") == nil {
		t.Error("proxy mode created no egress network")
	}
}

// Open mode is the only mode where the box network is not --internal; in
// proxy and off mode a tool that ignores HTTPS_PROXY must fail closed.
func TestVMNetworkInternalExceptOpenMode(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantInternal bool
	}{
		{netpol.ModeProxy, true},
		{netpol.ModeOff, true},
		{netpol.ModeOpen, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			fake := &fakeEngine{outputs: map[string]string{"network ls": ""}}
			v, _ := testVM(t, fake, false)
			spec := proxySpec(t, "net-"+tc.mode)
			spec.Policy = &netpol.Policy{Mode: tc.mode}
			if err := v.CreateNetwork(spec); err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(fake.callMatching("-int"), " ")
			if got := strings.Contains(joined, "--internal"); got != tc.wantInternal {
				t.Errorf("mode %q: --internal = %v, want %v:\n%s", tc.mode, got, tc.wantInternal, joined)
			}
		})
	}
}

// Subnet allocation surveys the engine's networks and then creates one, which
// is check-then-act against state agentbox does not own: two boxes starting at
// once can pick the same free /24 and the engine rejects the loser. The loser
// must re-survey and take the next one, not fail the box.
func TestVMCreateNetworkRetriesOnSubnetCollision(t *testing.T) {
	fake := &fakeEngine{
		outputs: map[string]string{"network ls": ""},
		// The first create loses the race; later ones succeed.
		results: map[string]fakeResult{
			"network create --subnet 100.64.0.0/24": {
				code: 1, stderr: "Pool overlaps with other one on this address space",
			},
		},
	}
	v, _ := testVM(t, fake, false)
	spec := proxySpec(t, "race")
	if err := v.CreateNetwork(spec); err != nil {
		t.Fatalf("a lost subnet race must be retried, not fatal: %v", err)
	}
	// It must have moved on to a different subnet rather than retrying the
	// same one forever.
	var attempted []string
	for _, c := range fake.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "network create --subnet") {
			attempted = append(attempted, joined)
		}
	}
	if len(attempted) < 2 {
		t.Fatalf("expected a retry after the collision, got %v", attempted)
	}
	if spec.ProxyAddr == "100.64.0.2" {
		t.Errorf("ProxyAddr still points into the subnet that lost the race: %s", spec.ProxyAddr)
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

func TestSplitVMRuntime(t *testing.T) {
	for in, want := range map[string][2]string{
		"docker/kata":      {"docker", "kata"},
		"docker/kata-qemu": {"docker", "kata-qemu"},
		"":                 {"docker", "kata"}, // defensive default
	} {
		engine, runtime := SplitVMRuntime(in)
		if engine != want[0] || runtime != want[1] {
			t.Errorf("SplitVMRuntime(%q) = %q, %q; want %q, %q", in, engine, runtime, want[0], want[1])
		}
	}
}

func TestPickVMRuntimePrefersKata(t *testing.T) {
	// kata-fc is deliberately absent from the preference list: Firecracker
	// has no virtiofs, which the share layer hard-requires.
	if got := pickVMRuntime([]string{"runc", "kata-fc"}); got != "" {
		t.Errorf("kata-fc must not be selected, got %q", got)
	}
	if got := pickVMRuntime([]string{"runc", "kata-clh", "kata"}); got != "kata" {
		t.Errorf("preference order not honored, got %q", got)
	}
}

// A podman-only host must be reported as unavailable with the reason, not
// quietly passed over: podman's VM path is libkrun, which implements no exec
// callback, so a box created under it could never be entered.
func TestDetectVMRuntimePodmanOnlyIsUnavailableWithReason(t *testing.T) {
	prevLook := lookPath
	t.Cleanup(func() { lookPath = prevLook })
	lookPath = func(bin string) (string, error) {
		if bin == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", exec.ErrNotFound
	}
	runtime, detail := detectVMRuntime()
	if runtime != "" {
		t.Fatalf("podman must not yield a vm runtime, got %q", runtime)
	}
	if !strings.Contains(detail, "podman") || !strings.Contains(detail, "Docker + Kata") {
		t.Errorf("reason should name podman and what is required instead: %q", detail)
	}
}

func TestDetectVMRuntimeDocker(t *testing.T) {
	prevLook, prevNames := lookPath, engineRuntimeNames
	t.Cleanup(func() { lookPath, engineRuntimeNames = prevLook, prevNames })
	lookPath = func(bin string) (string, error) {
		if bin == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", exec.ErrNotFound
	}
	engineRuntimeNames = func(string) ([]string, error) { return []string{"runc", "kata"}, nil }

	runtime, _ := detectVMRuntime()
	if runtime != "docker/kata" {
		t.Errorf("runtime = %q, want docker/kata", runtime)
	}
}

func TestDetectVMRuntimeDockerWithoutKata(t *testing.T) {
	prevLook, prevNames := lookPath, engineRuntimeNames
	t.Cleanup(func() { lookPath, engineRuntimeNames = prevLook, prevNames })
	lookPath = func(bin string) (string, error) {
		if bin == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", exec.ErrNotFound
	}
	engineRuntimeNames = func(string) ([]string, error) { return []string{"runc"}, nil }

	runtime, detail := detectVMRuntime()
	if runtime != "" {
		t.Fatalf("no kata runtime configured, got %q", runtime)
	}
	if !strings.Contains(detail, "daemon.json") {
		t.Errorf("reason should say how to fix it: %q", detail)
	}
}
