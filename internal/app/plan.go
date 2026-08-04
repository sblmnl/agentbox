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
	"github.com/sblmnl/agentbox/internal/tree"
	"github.com/sblmnl/agentbox/internal/workspace"
)

// Plan is the full "what would this do" for one box (--dry-run and the
// inspection commands). Building a plan never creates or starts anything.
type Plan struct {
	BoxID        string                  `json:"box_id"`
	Instance     string                  `json:"instance"`
	ResourceName string                  `json:"resource_name"` // see ResourceNameFor
	TreeMode     string                  `json:"tree_mode"`
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

// BuildPlan computes everything needed to create or inspect a box without
// touching runtime state. instance may be "" for "the box that would be
// created"; existingTreeRoot overrides tree resolution for an existing box.
// ResourceNameFor derives the engine resource name for a box. It is the
// single derivation: prune decides what the engine holds that no box claims
// by matching against this, and a second copy that drifted would let it
// treat a live box's container as an orphan.
func ResourceNameFor(slug, key, instance string) string {
	digest := key[strings.LastIndex(key, "-")+1:]
	return backend.ResourcePrefix + identity.TruncateForLimit(slug, digest, instance, 63)
}

func (c *Ctx) BuildPlan(instance, treeMode, existingTreeRoot string) (*Plan, error) {
	return c.buildPlan(instance, treeMode, existingTreeRoot, false)
}

// BuildPlanLenient is for the inspection commands (config, mounts,
// masks, doctor answer "what would this do" and must work before any
// backend exists). Selection failure degrades to a hypothetical backend at
// the floor tier instead of exit 69; creation paths stay strict.
func (c *Ctx) BuildPlanLenient(instance, treeMode, existingTreeRoot string) (*Plan, error) {
	return c.buildPlan(instance, treeMode, existingTreeRoot, true)
}

func (c *Ctx) buildPlan(instance, treeMode, existingTreeRoot string, lenient bool) (*Plan, error) {
	cfg := c.Cfg.Config
	p := &Plan{Instance: instance, Floor: cfg.Security.MinIsolation}

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

	// Tree resolution.
	boxes, _ := c.Store.ListBoxes(c.Key)
	isGit := tree.IsGitRepo(c.Workspace)
	mode := treeMode
	if mode == "" {
		mode = cfg.Workspace.TreeMode
	}
	mode = tree.ResolveAuto(mode, len(boxes), isGit)
	p.TreeMode = mode
	if existingTreeRoot != "" {
		p.TreeRoot = existingTreeRoot
	} else if mode == tree.ModeShared {
		p.TreeRoot = c.Workspace
	} else {
		p.TreeRoot = c.Store.TreeDir(c.Key, orPlaceholder(instance))
	}
	if mode == tree.ModeShared {
		var others []string
		for _, b := range boxes {
			if b.TreeMode == tree.ModeShared && b.Instance != instance {
				others = append(others, b.Instance)
			}
		}
		if len(others) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"this box shares its working tree with box(es) %s; two agents editing one tree will overwrite each other's work unless supervised",
				strings.Join(others, ", ")))
		}
	}

	// Instance naming if not yet decided.
	if p.Instance == "" {
		taken := map[string]bool{}
		for _, b := range boxes {
			taken[b.Instance] = true
		}
		switch {
		case c.Opts.Name != "" && !identity.IsBareInteger(c.Opts.Name):
			p.Instance = c.Opts.Name
		case mode == tree.ModeWorktree && isGit && tree.CurrentBranch(c.Workspace) != "":
			cand := identity.SanitizeSlug(tree.CurrentBranch(c.Workspace))
			if identity.ValidInstanceName(cand) && !taken[cand] && !identity.IsBareInteger(cand) {
				p.Instance = cand
			}
		}
		if p.Instance == "" {
			p.Instance = identity.GenerateName(taken, nil)
		}
		if p.TreeRoot == c.Store.TreeDir(c.Key, "__pending__") {
			p.TreeRoot = c.Store.TreeDir(c.Key, p.Instance)
		}
	}
	p.BoxID = identity.BoxID(c.Key, p.Instance)
	p.ResourceName = ResourceNameFor(c.Slug, c.Key, p.Instance)

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
		maskTree := p.TreeRoot
		if _, err := filepath.EvalSymlinks(maskTree); err != nil {
			// The tree does not exist yet (worktree/copy not materialized):
			// compute the preview against the workspace; the definitive set
			// is recomputed at creation against the box's own tree.
			maskTree = c.Workspace
		}
		set, err := mask.Compute(maskTree, matcher, maskMode, sources)
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
		BoxID:        p.BoxID,
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

		StateDir:            c.Store.BoxDir(c.Key, p.Instance),
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
	if pol.Mode == netpol.ModeProxy && av.Tier == backend.TierContainer {
		// Sidecar topology: the proxy is resolvable by container DNS name.
		// Under vm the backend computes ProxyEnv at create time, once the
		// box's bridge gateway — where the host daemon listens — is known.
		proxyURL := "http://" + p.ResourceName + "-proxy:3128"
		spec.ProxyEnv = netpol.ProxyEnv(proxyURL)
	}
	p.Spec = spec
	return p, nil
}

func orPlaceholder(instance string) string {
	if instance == "" {
		return "__pending__"
	}
	return instance
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
