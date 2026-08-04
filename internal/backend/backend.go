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

// State is a backend-reported box runtime state.
type State struct {
	Running bool
	Pid     int
	Status  string
}

// Availability is one probed backend: availability is probed,
// never assumed.
type Availability struct {
	Name      string `json:"name"`
	Tier      Tier   `json:"tier"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"` // why unavailable, and what would fix it
	Runtime   string `json:"runtime,omitempty"`
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
	engine, runtime, detail := detectVMRuntime()
	switch {
	case !kvm && runtime == "":
		av.Reason = "no /dev/kvm (hypervisor isolation requires KVM on bare metal or nested virtualization) and no OCI VM runtime (" + detail + ")"
	case !kvm:
		av.Reason = "no /dev/kvm: hypervisor isolation requires KVM on bare metal or nested virtualization"
	case runtime == "":
		av.Reason = "KVM is available but no OCI-consuming VM runtime is usable: " + detail
	default:
		av.Available = true
		av.Runtime = engine + "/" + runtime
	}
	return av
}

// vmRuntimePreference orders engine runtime names worth selecting.
// Firecracker (kata-fc) is deliberately absent: it lacks virtiofs, which
// the share layer hard-requires (Appendix B).
var vmRuntimePreference = []string{"kata", "kata-qemu", "kata-clh", "krun"}

// detectVMRuntime finds an engine able to drive an OCI VM runtime.
// Availability is probed, never assumed.
func detectVMRuntime() (engine, runtime, detail string) {
	details := []string{}
	if p, err := exec.LookPath("docker"); err == nil {
		if out, err := engineOutput(func(args ...string) *exec.Cmd { return exec.Command(p, args...) },
			"info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"); err == nil {
			if name := pickVMRuntime(strings.Fields(out)); name != "" {
				return "docker", name, ""
			}
			details = append(details, "docker: no kata or krun runtime configured in the daemon (add one under \"runtimes\" in daemon.json)")
		} else {
			details = append(details, "docker: daemon not reachable")
		}
	} else {
		details = append(details, "docker: not installed")
	}
	if p, err := exec.LookPath("podman"); err == nil {
		if exec.Command(p, "info").Run() == nil {
			// podman drives libkrun through the krun OCI runtime binary;
			// Kata's shim-v2 architecture is containerd-shaped and is not
			// probed here.
			if _, err := exec.LookPath("krun"); err == nil {
				return "podman", "krun", ""
			}
			details = append(details, "podman: no krun binary on PATH (install libkrun/crun-krun)")
		} else {
			details = append(details, "podman: `podman info` failed")
		}
	} else {
		details = append(details, "podman: not installed")
	}
	return "", "", strings.Join(details, "; ")
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
	out, err := engineOutput(func(args ...string) *exec.Cmd { return exec.Command(engineBin, args...) },
		"info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}")
	if err != nil {
		return nil
	}
	return strings.Fields(out)
}

// ResolveVMRuntime maps [security.vm].runtime and .hypervisor onto the
// engine runtime recorded at probe time. A requested combination that is
// not configured on this host is an error naming what is missing — never a
// silent substitute.
func ResolveVMRuntime(probed string, wantRuntime, wantHypervisor string) (engineBin, runtimeName string, err error) {
	i := strings.IndexByte(probed, '/')
	if i <= 0 {
		return "", "", fmt.Errorf("malformed vm runtime record %q", probed)
	}
	engineBin, detected := probed[:i], probed[i+1:]
	if (wantRuntime == "" || wantRuntime == "auto") && (wantHypervisor == "" || wantHypervisor == "auto") {
		return engineBin, detected, nil
	}

	var acceptable []string
	switch {
	case wantRuntime == "krun" || wantHypervisor == "libkrun":
		if wantRuntime == "kata" {
			return "", "", fmt.Errorf("security.vm: runtime \"kata\" cannot use hypervisor \"libkrun\"")
		}
		acceptable = []string{"krun"}
	case wantHypervisor == "qemu":
		acceptable = []string{"kata-qemu", "kata"}
	case wantHypervisor == "cloud-hypervisor":
		acceptable = []string{"kata-clh"}
	default: // runtime == "kata", hypervisor auto
		acceptable = []string{"kata", "kata-qemu", "kata-clh"}
	}

	configured := listEngineRuntimes(engineBin)
	if len(configured) == 0 {
		configured = []string{detected}
	}
	have := map[string]bool{}
	for _, name := range configured {
		have[name] = true
	}
	for _, name := range acceptable {
		if have[name] {
			return engineBin, name, nil
		}
	}
	return "", "", fmt.Errorf(
		"security.vm requests runtime %q / hypervisor %q, but none of the matching engine runtimes (%s) are configured on this host (found: %s)",
		orAuto(wantRuntime), orAuto(wantHypervisor), strings.Join(acceptable, ", "), strings.Join(configured, ", "))
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
