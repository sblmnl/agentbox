// Package backend defines the isolation contract both backends implement
// and the selection algorithm. The interface is defined in
// terms of the contract, not either implementation: no Compose YAML and no
// hypervisor configuration appears here.
package backend

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sblmnl/agentbox/internal/mask"
	"github.com/sblmnl/agentbox/internal/netpol"
)

// Tier is the guarantee class a backend provides.
type Tier string

const (
	TierContainer Tier = "container"
	TierVM        Tier = "vm"
)

// tierRank orders tiers for floor comparison.
func tierRank(t Tier) int {
	if t == TierVM {
		return 2
	}
	return 1
}

// Meets reports whether t satisfies floor.
func Meets(t, floor Tier) bool { return tierRank(t) >= tierRank(floor) }

// BoxSpec is the backend-neutral description of one box to construct.
type BoxSpec struct {
	BoxID        string
	ResourceName string // derived, within backend naming limits
	ImageRef     string
	TreeRoot     string // host path the guest sees at Mount
	Mount        string // guest mount point
	Workdir      string // guest working directory
	ReadOnly     bool
	MaskPlan     []mask.MountOp
	// MaskMode is the resolved mask mode ("view" or "filter"). Under
	// "filter" the vm backend serves the tree through the Layer 3 share
	// daemon compiled from MaskSources instead of building Layer 0 mounts.
	MaskMode    string
	MaskSources []mask.SourceBlob
	Policy      *netpol.Policy
	ProxyEnv    map[string]string
	Env         map[string]string
	Memory      string
	CPUs        float64
	Pids        int
	TmpfsSize   string
	Nofile      int
	GuestRoot   bool // vm tier only; container backend rejects true

	// vm-tier inputs ([security.vm]); the container backend never
	// reads them, mirroring the config scoping.
	NestedDocker  bool
	MemoryBacking string

	// StateDir is this box's state directory: the vm backend's
	// proxy audit log lands under it.
	StateDir string
	// Proxy listener budgets ([network.proxy]), carried to the host daemon.
	ProxyReadTimeout    string
	ProxyRequestTimeout string

	// ShareRoot is the host path actually shared as the workspace: the
	// tree itself, or the host-side mask view SetupShare built over it.
	ShareRoot string

	proxyConfigPath string
	// masksInGuest records that SetupShare could not build a host-side
	// view and the Layer 0 plan is expressed as guest mounts instead.
	masksInGuest bool
}

// ExecSpec describes a command to run in a started box.
type ExecSpec struct {
	Argv    []string
	TTY     bool
	Root    bool // --root
	Workdir string
	Env     map[string]string
}

// Backend is the isolation contract.
type Backend interface {
	Name() string
	Tier() Tier

	BuildImage(dockerfileDir, tag string, buildArgs map[string]string, noCache bool) error
	PullImage(ref string) error
	PrepareRootfs(spec *BoxSpec) error
	SetupShare(spec *BoxSpec) error
	CreateNetwork(spec *BoxSpec) error
	CreatePersistentState(spec *BoxSpec) error
	Create(spec *BoxSpec) error
	Start(spec *BoxSpec) error
	Stop(name string) error
	Remove(name string, keepState bool) error
	Exec(name string, es ExecSpec) (int, error)
	Inspect(name string) (State, error)
	Logs(name string, proxy bool, follow bool) error
}

// State is a backend-reported box runtime state. ExitCode is meaningful only
// once the box has stopped: a guest that aborts at boot leaves it as the only
// evidence the engine kept of why.
type State struct {
	Running  bool
	Pid      int
	Status   string
	ExitCode int
}

// Availability is one probed backend: availability is probed,
// never assumed.
type Availability struct {
	Name      string `json:"name"`
	Tier      Tier   `json:"tier"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // why unavailable, and what would fix it
	Runtime   string `json:"runtime,omitempty"`
	// Runtimes lists every engine/runtime pair probed for this backend, in
	// preference order (vm tier only; Runtime is the first). A host can have
	// more than one, and [security.vm] may name any of them, so all of them
	// must survive the probe rather than only the preferred one.
	Runtimes []string `json:"runtimes,omitempty"`
}

// VMRuntimes returns the probed engine/runtime candidates, tolerating an
// Availability that carries only the single preferred Runtime.
func (a Availability) VMRuntimes() []string {
	if len(a.Runtimes) > 0 {
		return a.Runtimes
	}
	if a.Runtime == "" {
		return nil
	}
	return []string{a.Runtime}
}

// Probe enumerates backends and their availability on this host.
func Probe() []Availability {
	return []Availability{probeContainer(), probeVM()}
}

func probeContainer() Availability {
	av := Availability{Name: "container", Tier: TierContainer}
	if p, err := exec.LookPath("docker"); err == nil {
		if exec.Command(p, "info", "--format", "{{.ServerVersion}}").Run() == nil {
			av.Available = true
			av.Runtime = "docker"
			return av
		}
		av.Reason = "docker binary present but the daemon is not reachable; start the Docker daemon or install rootless Podman"
	}
	if p, err := exec.LookPath("podman"); err == nil {
		if exec.Command(p, "info").Run() == nil {
			av.Available = true
			av.Runtime = "podman"
			return av
		}
		if av.Reason == "" {
			av.Reason = "podman binary present but `podman info` failed; check the user session (rootless podman needs subuid/subgid ranges)"
		}
	}
	if av.Reason == "" {
		av.Reason = "no container runtime found; install Docker (Compose v2) or rootless Podman"
	}
	return av
}

func probeVM() Availability {
	av := Availability{Name: "vm", Tier: TierVM}
	kvm := false
	if fi, err := os.Stat("/dev/kvm"); err == nil && fi.Mode()&os.ModeDevice != 0 {
		kvm = true
	}
	candidates, detail := detectVMRuntimes()
	switch {
	case !kvm && len(candidates) == 0:
		av.Reason = "no /dev/kvm (hypervisor isolation requires KVM on bare metal or nested virtualization) and no OCI VM runtime (" + detail + ")"
	case !kvm:
		av.Reason = "no /dev/kvm: hypervisor isolation requires KVM on bare metal or nested virtualization"
	case len(candidates) == 0:
		av.Reason = "KVM is available but no OCI-consuming VM runtime is usable: " + detail
	default:
		av.Available = true
		av.Runtimes = candidates
		av.Runtime = candidates[0]
	}
	return av
}

// vmRuntimePreference orders engine runtime names worth selecting.
//
// Two runtimes are deliberately absent, for the same category of reason — the
// runtime cannot deliver something this tier is built on:
//   - Firecracker (kata-fc) lacks virtiofs, which the share layer hard-requires
//     (Appendix B).
//   - krun (libkrun) cannot be entered: see krunRefusal.
var vmRuntimePreference = []string{"kata", "kata-qemu", "kata-clh"}

// krunRefusal explains why the krun runtime cannot serve the vm tier.
//
// Every agentbox operation on a box is an engine `exec`: the box is created
// running `sleep infinity` and `up`, `run` and `shell` all enter it. crun's
// libkrun handler implements no exec callback — libkrun boots a microVM whose
// init *is* the entrypoint, and there is no in-guest agent to spawn further
// processes — so the failure is not one command but the whole tier. Kata
// works because kata-agent and its shim implement exec over vsock.
//
// This is a property of the runtime at every current version, not of this
// host, so it is a static refusal rather than a probe result.
const krunRefusal = "the krun runtime (libkrun) cannot serve the vm tier: crun's libkrun handler " +
	"implements no exec callback, so no agentbox command can enter the box " +
	"(containers/crun#2090); use Kata via docker instead"

// Test seams over the host. detectVMRuntimes is otherwise a pure function of
// what happens to be installed on the machine running the tests, which is not
// something a unit test can arrange.
var (
	lookPath = exec.LookPath

	// engineRuntimeNames lists an engine's configured runtime names.
	engineRuntimeNames = func(engineBin string) ([]string, error) {
		out, err := engineOutput(func(args ...string) *exec.Cmd { return exec.Command(engineBin, args...) },
			"info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}")
		if err != nil {
			return nil, err
		}
		return strings.Fields(out), nil
	}

	// engineReachable reports whether an engine answers at all.
	engineReachable = func(engineBin string) bool {
		return exec.Command(engineBin, "info").Run() == nil
	}
)

// detectVMRuntimes enumerates every engine able to drive an OCI VM runtime,
// in preference order. Availability is probed, never assumed — and probing
// does not stop at the first hit: a host with a VM runtime under each engine
// must offer both, or [security.vm].runtime could never name the second.
//
// A runtime that is installed but unusable contributes a detail saying so
// rather than going quiet, because `doctor` and `backends` are where the user
// looks to find out why the tier is unavailable.
func detectVMRuntimes() (candidates []string, detail string) {
	details := []string{}
	if p, err := lookPath("docker"); err == nil {
		if names, err := engineRuntimeNames(p); err == nil {
			if name := pickVMRuntime(names); name != "" {
				candidates = append(candidates, "docker/"+name)
			} else {
				details = append(details, "docker: no kata runtime configured in the daemon (add one under \"runtimes\" in daemon.json)")
			}
		} else {
			details = append(details, "docker: daemon not reachable")
		}
	} else {
		details = append(details, "docker: not installed")
	}
	if p, err := lookPath("podman"); err == nil {
		if engineReachable(p) {
			// podman drives libkrun through the krun OCI runtime binary;
			// Kata's shim-v2 architecture is containerd-shaped and is not
			// probed here. krun is found and then declined — a candidate
			// nothing could enter is worse than no candidate.
			if _, err := lookPath("krun"); err == nil {
				details = append(details, "podman: krun found but unusable — "+krunRefusal)
			} else {
				details = append(details, "podman: no krun binary on PATH, and krun could not serve this tier anyway — "+krunRefusal)
			}
		} else {
			details = append(details, "podman: `podman info` failed")
		}
	} else {
		details = append(details, "podman: not installed")
	}
	if len(candidates) > 0 {
		return candidates, ""
	}
	return nil, strings.Join(details, "; ")
}

func pickVMRuntime(configured []string) string {
	have := map[string]bool{}
	for _, name := range configured {
		have[name] = true
	}
	for _, want := range vmRuntimePreference {
		if have[want] {
			return want
		}
	}
	return ""
}

// listEngineRuntimes queries an engine's configured runtime names (empty
// where the engine has no such registry, e.g. podman). Injectable for tests.
var listEngineRuntimes = func(engineBin string) []string {
	if engineBin != "docker" {
		return nil
	}
	names, err := engineRuntimeNames(engineBin)
	if err != nil {
		return nil
	}
	return names
}

// ResolveVMRuntime maps [security.vm].runtime and .hypervisor onto an engine
// runtime recorded at probe time. Every probed engine is considered, so a
// request naming a runtime the *second* engine provides still resolves. A
// requested combination that is configured on no engine is an error naming
// what is missing — never a silent substitute.
//
// A request for krun is refused by name before any of that. The generic
// "not configured on this host" message would otherwise send the user off to
// install a runtime that cannot work here whatever they do to the host.
func ResolveVMRuntime(probed []string, wantRuntime, wantHypervisor string) (engineBin, runtimeName string, err error) {
	if wantRuntime == "krun" || wantHypervisor == "libkrun" {
		if wantRuntime == "kata" {
			return "", "", fmt.Errorf("security.vm: runtime \"kata\" cannot use hypervisor \"libkrun\"")
		}
		return "", "", fmt.Errorf("security.vm: %s (set runtime = \"kata\", or drop the key for \"auto\")", krunRefusal)
	}
	type candidate struct {
		engine   string
		detected string
	}
	var candidates []candidate
	for _, p := range probed {
		if i := strings.IndexByte(p, '/'); i > 0 && i < len(p)-1 {
			candidates = append(candidates, candidate{p[:i], p[i+1:]})
		}
	}
	if len(candidates) == 0 {
		return "", "", fmt.Errorf("malformed vm runtime record %q", strings.Join(probed, ", "))
	}
	if (wantRuntime == "" || wantRuntime == "auto") && (wantHypervisor == "" || wantHypervisor == "auto") {
		return candidates[0].engine, candidates[0].detected, nil
	}

	var acceptable []string
	switch {
	case wantHypervisor == "qemu":
		acceptable = []string{"kata-qemu", "kata"}
	case wantHypervisor == "cloud-hypervisor":
		acceptable = []string{"kata-clh"}
	default: // runtime == "kata", hypervisor auto
		acceptable = []string{"kata", "kata-qemu", "kata-clh"}
	}

	var found []string
	for _, c := range candidates {
		// The probe records one preferred runtime per engine; engines with a
		// runtime registry are re-queried so a non-preferred one can be named.
		configured := listEngineRuntimes(c.engine)
		if len(configured) == 0 {
			configured = []string{c.detected}
		}
		have := map[string]bool{}
		for _, name := range configured {
			have[name] = true
			found = append(found, c.engine+"/"+name)
		}
		for _, name := range acceptable {
			if have[name] {
				return c.engine, name, nil
			}
		}
	}
	return "", "", fmt.Errorf(
		"security.vm requests runtime %q / hypervisor %q, but none of the matching engine runtimes (%s) are configured on this host (found: %s)",
		orAuto(wantRuntime), orAuto(wantHypervisor), strings.Join(acceptable, ", "), strings.Join(found, ", "))
}

func orAuto(s string) string {
	if s == "" {
		return "auto"
	}
	return s
}

// SelectionInput carries the backend-selection inputs.
type SelectionInput struct {
	Floor          Tier   // from min_isolation and --min-isolation
	ForcedTier     Tier   // --force-isolation; empty if unset
	RequestedName  string // --backend or [security].backend; empty = auto
	Availabilities []Availability
}

// ErrNoBackend is the exit-69 condition: no available backend satisfies the
// isolation floor.
type ErrNoBackend struct {
	Floor   Tier
	Details []string
}

func (e *ErrNoBackend) Error() string {
	msg := fmt.Sprintf("no available backend satisfies the isolation floor %q", e.Floor)
	for _, d := range e.Details {
		msg += "\n  " + d
	}
	return msg
}

// Select chooses the backend. It runs per box at creation time; the result is
// frozen into that box's meta.json.
func Select(in SelectionInput) (Availability, error) {
	floor := in.Floor
	if in.ForcedTier != "" {
		// --force-isolation lowers the floor deliberately; the caller
		// records the override and warns on every invocation.
		floor = in.ForcedTier
	}

	var survivors []Availability
	var details []string
	for _, av := range in.Availabilities {
		if !av.Available {
			details = append(details, fmt.Sprintf("%s (%s): %s", av.Name, av.Tier, av.Reason))
			continue
		}
		if !Meets(av.Tier, floor) {
			details = append(details, fmt.Sprintf("%s (%s): available but below the floor", av.Name, av.Tier))
			continue
		}
		survivors = append(survivors, av)
	}
	if len(survivors) == 0 {
		return Availability{}, &ErrNoBackend{Floor: floor, Details: details}
	}
	if in.RequestedName != "" {
		for _, av := range survivors {
			if av.Name == in.RequestedName {
				return av, nil
			}
		}
		// A requested backend below the floor MUST NOT be selected.
		return Availability{}, &ErrNoBackend{Floor: floor, Details: append(details,
			fmt.Sprintf("requested backend %q is not among the backends satisfying the floor", in.RequestedName))}
	}
	best := survivors[0]
	for _, av := range survivors[1:] {
		if tierRank(av.Tier) > tierRank(best.Tier) {
			best = av
		}
	}
	return best, nil
}
