package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/config"
	"github.com/sblmnl/agentbox/internal/identity"
	"github.com/sblmnl/agentbox/internal/state"
	"github.com/sblmnl/agentbox/internal/tree"
)

// selectBox resolves which box a command addresses. createIfMissing
// applies only to bare invocations in an empty project.
func (c *Ctx) selectBox(createIfMissing bool) (*state.BoxMeta, error) {
	name, err := c.ResolveBoxName()
	if err != nil {
		return nil, err
	}
	boxes, err := c.Store.ListBoxes(c.Key)
	if err != nil {
		return nil, Softwaref("%v", err)
	}

	if c.Opts.New {
		return c.createBox(name)
	}
	if name != "" {
		for _, b := range boxes {
			if b.Instance == name {
				return b, nil
			}
		}
		return nil, Usagef("no box named %q in this project; --new creates it (existing: %s)", name, boxNames(boxes))
	}
	if len(boxes) == 0 {
		if !createIfMissing {
			return nil, Usagef("this project has no boxes; run `agentbox` or `agentbox new` to create one")
		}
		return c.createBox("")
	}
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil {
		return nil, Softwaref("project metadata: %v", err)
	}
	for _, b := range boxes {
		if b.Instance == pm.DefaultBox {
			return b, nil
		}
	}
	// The default names no surviving box (or none is set). `rm` repoints it,
	// so reaching here means state written by an older agentbox or edited by
	// hand. A single surviving box is adopted — with one candidate there is
	// nothing to guess between — but it is said out loud, because the box
	// being used is not the one recorded. Several candidates are ambiguous
	// and refused: guessing attaches the agent to the wrong box silently.
	if len(boxes) == 1 {
		c.Notef("default box %q no longer exists; using %s, the only box in this project (make it stick with `agentbox default %s`)",
			pm.DefaultBox, boxes[0].Instance, boxes[0].Instance)
		return boxes[0], nil
	}
	if pm.DefaultBox == "" {
		return nil, Usagef("this project has no default box; pick one with -n (available: %s) or set one with `agentbox default NAME`",
			boxNames(boxes))
	}
	return nil, Usagef("the default box %q no longer exists; pick one with -n (available: %s) or set a new default with `agentbox default NAME`",
		pm.DefaultBox, boxNames(boxes))
}

func boxNames(boxes []*state.BoxMeta) string {
	var names []string
	for _, b := range boxes {
		names = append(names, b.Instance)
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// createBox creates a new box under the project lock: name
// allocation, default-box selection, and max_boxes enforcement serialize
// here.
func (c *Ctx) createBox(name string) (*state.BoxMeta, error) {
	if name != "" && !identity.ValidInstanceName(name) {
		return nil, Usagef("invalid instance name %q", name)
	}
	if name != "" && identity.IsBareInteger(name) {
		return nil, Usagef("instance name %q is a bare integer, which is reserved for ordinal aliases", name)
	}

	pl, err := c.Store.LockProject(c.Key)
	if err != nil {
		return nil, Softwaref("%v", err)
	}
	defer pl.Release()

	boxes, err := c.Store.ListBoxes(c.Key)
	if err != nil {
		return nil, Softwaref("%v", err)
	}
	for _, b := range boxes {
		if b.Instance == name {
			return nil, Usagef("box %q already exists in this project", name)
		}
	}
	if err := c.enforceLimits(boxes); err != nil {
		return nil, err
	}

	prevOptName := c.Opts.Name
	c.Opts.Name = name
	var plan *Plan
	if c.Opts.DryRun {
		// A dry run must print the plan even where creation would refuse
		// (change nothing); the refusal itself is visible in the
		// plan's backend availability.
		plan, err = c.BuildPlanLenient("", c.Opts.TreeMode, "")
	} else {
		plan, err = c.BuildPlan("", c.Opts.TreeMode, "")
	}
	c.Opts.Name = prevOptName
	if err != nil {
		return nil, err
	}
	for _, w := range plan.Warnings {
		fmt.Fprintln(c.Stderr, "warning: "+w)
	}
	if plan.Forced != "" {
		fmt.Fprintf(c.Stderr, "warning: --force-isolation %s: this box runs BELOW the project's declared isolation floor (%s); this is recorded and will be warned about on every invocation\n",
			plan.Forced, c.Cfg.Config.Security.MinIsolation)
	}

	if c.Opts.DryRun {
		return nil, c.printPlan(plan)
	}

	// Materialize the tree.
	var branch string
	if plan.TreeMode != tree.ModeShared {
		res, err := tree.Create(plan.TreeMode, c.Workspace, c.Store.TreeDir(c.Key, plan.Instance), plan.Instance)
		if err != nil {
			return nil, Softwaref("%v", err)
		}
		branch = res.Branch
		// Recompute the mask set against the box's own tree.
		plan, err = c.BuildPlanForInstance(plan.Instance, plan.TreeMode, res.Root)
		if err != nil {
			return nil, err
		}
	}

	meta := &state.BoxMeta{
		Instance:       plan.Instance,
		ProjectKey:     c.Key,
		Backend:        plan.Backend.Name,
		Tier:           string(plan.Backend.Tier),
		TreeMode:       plan.TreeMode,
		TreeRoot:       plan.TreeRoot,
		Branch:         branch,
		ConfigDigest:   c.ConfigDigest(),
		ImageRef:       plan.Image.Ref,
		MaskDigest:     plan.MaskDigest(),
		MaskMode:       plan.MaskMode,
		ForceIsolation: plan.Forced,
		MemoryLimit:    c.Cfg.Config.Resources.Memory,
		CreatedAt:      time.Now().UTC(),
	}
	if err := c.Store.SaveBox(meta); err != nil {
		return nil, Softwaref("%v", err)
	}
	if err := c.writeGeneratedArtifacts(plan); err != nil {
		return nil, err
	}

	// First box becomes the project default; --new never changes an
	// existing default implicitly.
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil {
		pm = &state.ProjectMeta{WorkspaceRealpath: c.Workspace, Slug: c.Slug, CreatedAt: time.Now().UTC()}
	}
	if pm.DefaultBox == "" {
		pm.DefaultBox = meta.Instance
	}
	// auto-selecting a higher tier silently changes boot time and
	// filesystem behavior; say so once per workspace, then stay quiet.
	autoSelected := c.Cfg.Config.Security.Backend == "" && c.Opts.Backend == ""
	if meta.Tier == string(backend.TierVM) && autoSelected && !pm.VMTierNoticed {
		pm.VMTierNoticed = true
		fmt.Fprintln(c.Stderr, "notice: selected the vm backend (highest available isolation tier) for this box; boots take seconds and the workspace is shared via virtiofs. Pin the previous behavior with `-b container` or [security].backend = \"container\".")
	}
	if err := c.Store.SaveProject(c.Key, pm); err != nil {
		return nil, Softwaref("%v", err)
	}
	c.Notef("created box %s (backend %s, tier %s, tree mode %s)", meta.Instance, meta.Backend, meta.Tier, meta.TreeMode)
	return meta, nil
}

// BuildPlanForInstance rebuilds a plan for a known instance and tree root.
func (c *Ctx) BuildPlanForInstance(instance, treeMode, treeRoot string) (*Plan, error) {
	return c.BuildPlan(instance, treeMode, treeRoot)
}

// enforceLimits applies [project].max_boxes and user-level [limits] before
// creating a box, naming what would have to stop in the refusal.
func (c *Ctx) enforceLimits(projectBoxes []*state.BoxMeta) error {
	cfg := c.Cfg.Config
	if cfg.Project.MaxBoxes > 0 && len(projectBoxes) >= cfg.Project.MaxBoxes {
		return Usagef("project.max_boxes = %d reached; stop or remove one of: %s",
			cfg.Project.MaxBoxes, boxNames(projectBoxes))
	}
	keys, err := c.Store.ListProjects()
	if err != nil {
		return Softwaref("%v", err)
	}
	total := 0
	var totalMem int64
	var all []string
	for _, k := range keys {
		boxes, _ := c.Store.ListBoxes(k)
		total += len(boxes)
		for _, b := range boxes {
			if sz, err := config.ParseSize(b.MemoryLimit); err == nil {
				totalMem += sz
			}
			all = append(all, k+"/"+b.Instance)
		}
	}
	if cfg.Limits.MaxBoxes > 0 && total >= cfg.Limits.MaxBoxes {
		return Usagef("limits.max_boxes = %d reached across all projects; stop or remove one of: %s",
			cfg.Limits.MaxBoxes, strings.Join(all, ", "))
	}
	if lim, err := config.ParseSize(cfg.Limits.MaxTotalMemory); err == nil && lim > 0 {
		if want, err := config.ParseSize(cfg.Resources.Memory); err == nil && totalMem+want > lim {
			return Usagef("limits.max_total_memory = %s would be exceeded (current boxes reserve %d MiB); stop one of: %s",
				cfg.Limits.MaxTotalMemory, totalMem>>20, strings.Join(all, ", "))
		}
	}
	return nil
}

// writeGeneratedArtifacts persists masks.json, spec.json, and the proxy
// config under the box state dir. All are reconstructible.
func (c *Ctx) writeGeneratedArtifacts(plan *Plan) error {
	dir := c.Store.BoxDir(c.Key, plan.Instance)
	if err := os.MkdirAll(filepath.Join(dir, "proxy"), 0o700); err != nil {
		return Softwaref("%v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		return Softwaref("%v", err)
	}
	if err := state.WriteJSONFile(filepath.Join(dir, "masks.json"), plan.Masks); err != nil {
		return Softwaref("%v", err)
	}
	if err := state.WriteJSONFile(filepath.Join(dir, "spec.json"), plan.Spec); err != nil {
		return Softwaref("%v", err)
	}
	if plan.Policy.Mode == "proxy" && plan.Backend.Tier == backend.TierContainer {
		// Sidecar configuration; under vm the policy travels to the host
		// daemon as a listener spec the backend writes at Start.
		cfg := c.Cfg.Config
		sc := state.GeneratedFileHeader(ToolVersion, "agentbox.toml") +
			plan.Policy.SquidConfig(3128, cfg.Network.Proxy.ReadTimeout, cfg.Network.Proxy.RequestTimeout)
		p := filepath.Join(dir, "proxy", "squid.conf")
		if err := os.WriteFile(p, []byte(sc), 0o600); err != nil {
			return Softwaref("%v", err)
		}
		plan.Spec.SetProxyConfigPath(p)
	}
	return nil
}

// activeBackend instantiates the recorded backend for a box, honestly
// failing when it is not available on this host.
func (c *Ctx) activeBackend(meta *state.BoxMeta) (backend.Backend, error) {
	for _, av := range c.Availabilities() {
		if av.Name == meta.Backend {
			if !av.Available {
				return nil, Unavailablef("box %s was created on backend %q, which is unavailable here: %s", meta.Instance, meta.Backend, av.Reason)
			}
			switch av.Name {
			case "container":
				return backend.NewContainerBackend(av.Runtime), nil
			case "vm":
				vmCfg := c.Cfg.Config.Security.VM
				engine, runtime, err := backend.ResolveVMRuntime(av.Runtime, vmCfg.Runtime, vmCfg.Hypervisor)
				if err != nil {
					return nil, Configf("%v", err)
				}
				return backend.NewVMBackend(engine, runtime, c.Store.Root), nil
			}
			return nil, Unavailablef("backend %q is not implemented in this build", av.Name)
		}
	}
	return nil, Unavailablef("box %s records unknown backend %q", meta.Instance, meta.Backend)
}

// warnDrift warns about configuration drift for a resolved box.
func (c *Ctx) warnDrift(meta *state.BoxMeta, plan *Plan) {
	var drifted []string
	if meta.ConfigDigest != c.ConfigDigest() {
		drifted = append(drifted, "configuration")
	}
	if meta.ImageRef != plan.Image.Ref {
		drifted = append(drifted, fmt.Sprintf("image (%s -> %s)", meta.ImageRef, plan.Image.Ref))
	}
	if meta.MaskDigest != plan.MaskDigest() {
		drifted = append(drifted, "mask set")
	}
	if meta.Backend != plan.Backend.Name {
		drifted = append(drifted, fmt.Sprintf("backend (%s -> %s); `--recreate` rebuilds this box on the new backend, but prefer `--new` and keep both", meta.Backend, plan.Backend.Name))
	}
	if len(drifted) > 0 {
		fmt.Fprintf(c.Stderr, "warning: box %s drifts from current configuration: %s\n", meta.Instance, strings.Join(drifted, "; "))
	}
	if meta.ForceIsolation != "" {
		fmt.Fprintf(c.Stderr, "warning: box %s was created with --force-isolation %s and runs below the project's declared isolation floor\n", meta.Instance, meta.ForceIsolation)
	}
}

// ensureUp creates backend resources and starts the box.
func (c *Ctx) ensureUp(meta *state.BoxMeta, plan *Plan) error {
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	c.runHooks("pre_up", c.Cfg.Config.Hooks.PreUp)

	st, ierr := be.Inspect(plan.ResourceName)
	if ierr != nil {
		// Not created yet in the runtime.
		if plan.Image.LocalBuild() || c.Opts.Rebuild {
			if err := c.buildImage(be, plan, c.Opts.Rebuild); err != nil {
				return err
			}
		}
		for _, step := range []func(*backend.BoxSpec) error{
			be.PrepareRootfs, be.SetupShare, be.CreateNetwork, be.CreatePersistentState, be.Create,
		} {
			if err := step(plan.Spec); err != nil {
				return Softwaref("%v", err)
			}
		}
	} else if st.Running {
		return nil
	}
	if err := be.Start(plan.Spec); err != nil {
		return Softwaref("%v", err)
	}
	if cb, ok := be.(*backend.ContainerBackend); ok {
		if err := cb.VerifyWorkspaceWritable(plan.ResourceName, plan.Spec.Mount); err != nil && !c.Cfg.Config.Workspace.ReadOnly {
			return Softwaref("%v", err)
		}
	}
	c.runHooks("post_up", c.Cfg.Config.Hooks.PostUp)
	return nil
}

func (c *Ctx) buildImage(be backend.Backend, plan *Plan, noCache bool) error {
	dir, err := c.WriteBuildContext()
	if err != nil {
		return err
	}
	// uid/gid are passed as build args so a user-supplied [image].dockerfile can
	// create the agent user at the invoking identity; the generated Dockerfile
	// bakes the same defaults and is unaffected by passing them again.
	args := map[string]string{
		"AGENTBOX_UID": strconv.Itoa(os.Getuid()),
		"AGENTBOX_GID": strconv.Itoa(os.Getgid()),
	}
	if plan.Spec.GuestRoot {
		args["AGENTBOX_GUEST_ROOT"] = "allow"
	}
	for k, v := range c.Cfg.Config.Image.BuildArgs {
		args[k] = v
	}
	c.Notef("building image %s", plan.Image.Ref)
	if err := be.BuildImage(dir, plan.Image.Ref, args, noCache); err != nil {
		return Softwaref("image build failed: %v", err)
	}
	return nil
}

// runHooks executes host-side hooks. They
// run only on explicit configuration.
func (c *Ctx) runHooks(name string, cmds []string) {
	for _, h := range cmds {
		c.Verbosef("hook %s: %s", name, h)
		cmd := exec.Command("sh", "-c", h)
		cmd.Dir = c.Workspace
		cmd.Stdout = c.Stderr
		cmd.Stderr = c.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(c.Stderr, "warning: hook %s (%q) failed: %v\n", name, h, err)
		}
	}
}

// touchLastExec records activity for idle reaping.
func (c *Ctx) touchLastExec(meta *state.BoxMeta) {
	meta.LastExecAt = time.Now().UTC()
	_ = c.Store.SaveBox(meta)
}
