package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/config"
	"github.com/sblmnl/agentbox/internal/identity"
	"github.com/sblmnl/agentbox/internal/image"
	"github.com/sblmnl/agentbox/internal/mask"
	"github.com/sblmnl/agentbox/internal/netpol"
	"github.com/sblmnl/agentbox/internal/share"
	"github.com/sblmnl/agentbox/internal/workspace"
)

// Plan is the full "what would this do" for the workspace's box. Building a
// plan never creates or starts anything, which is what lets --dry-run answer
// the question honestly: the plan printed is the plan enacted.
type Plan struct {
	Key          string                  `json:"key"`
	ResourceName string                  `json:"resource_name"` // see ResourceNameFor
	TreeRoot     string                  `json:"tree_root"`
	Backend      backend.Availability    `json:"backend"`
	Floor        string                  `json:"isolation_floor"`
	Forced       string                  `json:"force_isolation,omitempty"`
	Image        image.Resolution        `json:"image"`
	MaskMode     string                  `json:"mask_mode"`
	Masks        *mask.Set               `json:"masks"`
	Policy       *netpol.Policy          `json:"policy"`
	GuestWorkdir string                  `json:"guest_workdir"`
	Env          map[string]string       `json:"env"`
	Warnings     []string                `json:"warnings,omitempty"`
	Spec         *backend.BoxSpec        `json:"-"`
	Matcher      func(string, bool) bool `json:"-"`
	MaskSources  []mask.SourceBlob       `json:"-"`
}

// seamProbe is a test seam over share.SeamAvailable: whether this host
// can deliver the Layer 3 filtered share.
var seamProbe = share.SeamAvailable

// resolveMaskMode maps "auto" per tier: filter where available, else
// view. Requesting filter where it cannot be delivered is an error, not a
// downgrade; auto degrading to view returns a warning so the fallback is
// always visible, never silent.
func resolveMaskMode(mode string, tier backend.Tier) (resolved, warning string, err error) {
	switch mode {
	case "view":
		return "view", "", nil
	case "filter":
		if tier != backend.TierVM {
			return "", "", Configf("security.mask_mode = \"filter\" requires the vm tier; the container backend cannot filter at lookup time (forbids downgrading this silently)")
		}
		if ok, reason := seamProbe(); !ok {
			return "", "", Configf("security.mask_mode = \"filter\": %s; use \"view\" or \"auto\"", reason)
		}
		return "filter", "", nil
	default: // auto
		if tier == backend.TierVM {
			ok, reason := seamProbe()
			if ok {
				return "filter", "", nil
			}
			return "view", "mask_mode \"auto\" resolved to \"view\": " + reason, nil
		}
		return "view", "", nil
	}
}

// ResourceNameFor derives the engine resource name for a box. It is the
// single derivation: teardown decides what the engine holds for this box by
// matching against it, and a second copy that drifted would let it miss a
// live container or claim someone else's.
func ResourceNameFor(slug, key string) string {
	digest := key[strings.LastIndex(key, "-")+1:]
	return backend.ResourcePrefix + identity.TruncateForLimit(slug, digest, 63)
}

// BuildPlan computes everything needed to create or inspect the box without
// touching runtime state.
func (c *Ctx) BuildPlan() (*Plan, error) { return c.buildPlan(false) }

// BuildPlanLenient is for the inspection paths (`config`, `--dry-run`), which
// answer "what would this do" and must work before any backend exists.
// Selection failure degrades to a hypothetical backend at the floor tier
// instead of exit 69; creation paths stay strict.
func (c *Ctx) BuildPlanLenient() (*Plan, error) { return c.buildPlan(true) }

// planFor picks the strictness a command needs: lenient under --dry-run,
// strict otherwise.
//
// A dry run changes nothing, so refusing to produce one is refusing to answer
// a question. The box whose backend has since gone missing -- Docker stopped
// after the box was created -- is exactly when "what would this do" is worth
// asking, and exiting 69 with no plan there hides the answer behind the
// problem the user is trying to diagnose. The refusal is not lost: the plan
// reports the unsatisfiable floor as a warning of its own.
func (c *Ctx) planFor() (*Plan, error) {
	if c.Opts.DryRun {
		return c.BuildPlanLenient()
	}
	return c.BuildPlan()
}

func (c *Ctx) buildPlan(lenient bool) (*Plan, error) {
	cfg := c.Cfg.Config
	p := &Plan{Floor: cfg.Security.MinIsolation}

	// Backend selection.
	forced := backend.Tier("")
	if c.Opts.ForceIsolation != "" {
		forced = backend.Tier(c.Opts.ForceIsolation)
		p.Forced = c.Opts.ForceIsolation
	}
	av, err := backend.Select(backend.SelectionInput{
		Floor:          backend.Tier(cfg.Security.MinIsolation),
		ForcedTier:     forced,
		RequestedName:  cfg.Security.Backend,
		Availabilities: c.Availabilities(),
	})
	if err != nil {
		nb, isNB := err.(*backend.ErrNoBackend)
		if !isNB {
			return nil, Softwaref("%v", err)
		}
		if !lenient {
			return nil, Unavailablef("%s", nb.Error())
		}
		av = backend.Availability{
			Name: "none", Tier: backend.Tier(cfg.Security.MinIsolation),
			Available: false, Reason: nb.Error(),
		}
		p.Warnings = append(p.Warnings, "no backend satisfies the isolation floor on this host; the plan below assumes the floor tier ("+nb.Error()+")")
	}
	p.Backend = av

	// The box mounts the workspace itself. There is no separate tree to
	// materialize: a second box on the same project is a second workspace
	// root (`git worktree add`), which agentbox sees as a different project
	// entirely and gives its own box, branch and all.
	p.TreeRoot = c.Workspace
	p.Key = c.Key
	p.ResourceName = ResourceNameFor(c.Slug, c.Key)

	// Mask mode and mask set.
	maskMode, maskWarn, err := resolveMaskMode(cfg.Security.MaskMode, av.Tier)
	if err != nil {
		return nil, err
	}
	p.MaskMode = maskMode
	if maskWarn != "" {
		p.Warnings = append(p.Warnings, maskWarn)
	}
	if c.Opts.NoMask {
		p.Masks = &mask.Set{TreeRoot: p.TreeRoot, Mode: maskMode}
		p.Warnings = append(p.Warnings, "--no-mask: the mask set is empty by explicit request")
	} else {
		userGlobal := filepath.Join(config.UserConfigDir(), "agentignore")
		// One read serves every layer: the matcher compiled here and the
		// pattern contents frozen into the share daemon spec under filter
		// mode come from the same bytes, so they cannot diverge.
		blobs, err := mask.ReadSources(userGlobal, p.TreeRoot, cfg.Masking.IgnoreFiles)
		if err != nil {
			return nil, Configf("%v", err)
		}
		matcher, sources, err := mask.MatcherFromSources(blobs)
		if err != nil {
			return nil, Configf("%v", err)
		}
		p.MaskSources = blobs
		set, err := mask.Compute(p.TreeRoot, matcher, maskMode, sources)
		if err != nil {
			return nil, Softwaref("computing mask set: %v", err)
		}
		set.TreeRoot = p.TreeRoot
		p.Masks = set
		p.Matcher = mask.FilterFn(matcher)
	}

	// Egress policy.
	pol, err := netpol.Resolve(cfg.Network.Mode, cfg.Network.Bundles, cfg.Network.Allow, cfg.Network.Deny)
	if err != nil {
		return nil, Configf("%v", err)
	}
	pol.Audit = cfg.Network.Audit
	p.Policy = pol

	// Image.
	p.Image = image.Resolve(cfg)
	p.Warnings = append(p.Warnings, p.Image.Warnings...)
	p.Warnings = append(p.Warnings, agentBundleWithoutInstall(cfg, p.Image)...)

	// Environment: [variables], telemetry silencing, passthrough,
	// proxy variables in both casings.
	env := map[string]string{}
	for k, v := range cfg.Variables {
		env[k] = v
	}
	includedTelemetry := map[string]bool{}
	for _, b := range cfg.Network.Bundles {
		includedTelemetry[b] = true
	}
	for agentBundle, vars := range netpol.TelemetryDisableVars {
		if includedTelemetry[agentBundle] && !includedTelemetry[agentBundle+":telemetry"] {
			for k, v := range vars {
				env[k] = v
			}
		}
	}
	for _, k := range append(append([]string{}, cfg.Passthrough...), c.Opts.EnvPassthrough...) {
		if v, ok := lookupEnviron(k); ok {
			env[k] = v
		}
	}
	p.Env = env
	p.GuestWorkdir = workspace.GuestWorkdir(cfg.Workspace.Mount, c.Workspace, c.StartDir)

	// Backend-neutral box spec.
	spec := &backend.BoxSpec{
		BoxID:        p.Key,
		ResourceName: p.ResourceName,
		ImageRef:     p.Image.Ref,
		TreeRoot:     p.TreeRoot,
		Mount:        cfg.Workspace.Mount,
		Workdir:      p.GuestWorkdir,
		ReadOnly:     cfg.Workspace.ReadOnly,
		Policy:       pol,
		Env:          env,
		Memory:       cfg.Resources.Memory,
		CPUs:         cfg.Resources.CPUs,
		Pids:         cfg.Resources.Pids,
		TmpfsSize:    cfg.Resources.TmpfsSize,
		Nofile:       cfg.Resources.Nofile,
		GuestRoot:    av.Tier == backend.TierVM && cfg.Security.VM.GuestRoot == "allow",

		StateDir: c.Store.BoxDir(c.Key),

		ProxyReadTimeout:    cfg.Network.Proxy.ReadTimeout,
		ProxyRequestTimeout: cfg.Network.Proxy.RequestTimeout,
	}
	if av.Tier == backend.TierVM {
		spec.NestedDocker = cfg.Security.VM.NestedDocker
		spec.MemoryBacking = cfg.Security.VM.MemoryBacking
	}
	spec.MaskMode = p.MaskMode
	spec.MaskSources = p.MaskSources
	if p.Masks != nil {
		spec.MaskPlan = p.Masks.Layer0Plan(cfg.Workspace.Mount, cfg.Masking.TmpfsSize, cfg.Masking.FilesReadonly)
	}
	if pol.Mode == netpol.ModeProxy {
		// The generated squid.conf lives at a path derived from the box key,
		// so it is set here rather than when the file happens to be written.
		// A plan built for `up` or `run` is not the plan that created the box,
		// and a spec that only knew its own proxy config on the creating plan
		// would hand the engine an empty --mount source on every later start.
		spec.SetProxyConfigPath(filepath.Join(c.Store.BoxDir(c.Key), "proxy", "squid.conf"))
		if av.Tier == backend.TierContainer {
			// The container tier reaches its sidecar by container DNS name.
			// The vm tier cannot -- the engine's embedded resolver is
			// unreachable from a VM guest -- so its backend sets ProxyEnv from
			// the pinned sidecar IP once the box subnet is allocated.
			spec.ProxyEnv = netpol.ProxyEnv("http://" + p.ResourceName + "-proxy:3128")
		}
	}
	p.Spec = spec
	return p, nil
}

// agentBundleWithoutInstall catches a half-configured agent: egress opened for
// a tool that was never installed.
//
// The two settings are a character apart in the places people copy them from
// -- `[network].bundles = ["agent:claude-code"]` and
// `[agents].install = ["claude-code"]` -- and dropping one while keeping the
// other produces no failure until the agent is actually run, at which point
// the runtime reports a missing file against a container id. Catching it while
// building the plan puts the diagnosis before the symptom.
//
// It fires only when agentbox generates the image. A pinned [image].ref or a
// user's own Dockerfile may perfectly well already contain the agent, and
// nagging about a correct configuration is how warnings get ignored.
func agentBundleWithoutInstall(cfg *config.Config, img image.Resolution) []string {
	if img.Source != "build" {
		return nil
	}
	installed := map[string]bool{}
	for _, a := range cfg.Agents.Install {
		installed[a] = true
	}
	var out []string
	for _, b := range cfg.Network.Bundles {
		name, ok := strings.CutPrefix(b, "agent:")
		if !ok {
			continue
		}
		// "agent:claude-code:telemetry" is an add-on to the same agent.
		name, _, _ = strings.Cut(name, ":")
		if installed[name] {
			continue
		}
		out = append(out, fmt.Sprintf(
			"[network].bundles allows egress for %q but [agents].install does not include %q, "+
				"so the agent is not in the image; add it, or drop the bundle if the agent comes from elsewhere",
			b, name))
		installed[name] = true // one warning per agent, not per bundle entry
	}
	return out
}

// MaskDigest hashes what is frozen for drift comparison. Under view mode
// that is the computed entry list — the mounts are fixed at creation.
// Under filter mode entries come and go live by design (a new .env is
// masked the moment it appears), so the frozen input is the pattern
// sources the daemon compiled; only a pattern change is drift.
func (p *Plan) MaskDigest() string {
	var blob []byte
	if p.MaskMode == "filter" {
		blob, _ = json.Marshal(p.MaskSources)
	} else {
		blob, _ = json.Marshal(p.Masks.Entries)
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

func lookupEnviron(key string) (string, bool) { return os.LookupEnv(key) }
