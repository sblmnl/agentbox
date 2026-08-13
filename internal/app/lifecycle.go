package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/state"
)

// selectBox resolves the workspace's box. There is exactly one, keyed by the
// workspace root, so there is nothing to choose between and no default to
// keep pointing somewhere: standing in the directory is the selection.
// createIfMissing distinguishes the commands that may bring a box into being
// from the ones that may only address an existing one.
func (c *Ctx) selectBox(createIfMissing bool) (*state.BoxMeta, error) {
	if c.Store.BoxExists(c.Key) {
		meta, err := c.Store.LoadBox(c.Key)
		if err != nil {
			return nil, Softwaref("reading box metadata: %v", err)
		}
		return meta, nil
	}
	if !createIfMissing {
		return nil, Usagef("no box for this workspace yet; run `agentbox` or `agentbox up` to create one")
	}
	return c.createBox()
}

// createBox creates this workspace's box under its exclusive lock.
func (c *Ctx) createBox() (*state.BoxMeta, error) {
	lock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return nil, Softwaref("%v", err)
	}
	defer lock.Release()

	// A concurrent invocation may have created it while we waited.
	if c.Store.BoxExists(c.Key) {
		return c.Store.LoadBox(c.Key)
	}

	// A dry run must print the plan even where creation would refuse (it
	// changes nothing); the refusal itself is visible in the plan's backend
	// availability.
	plan, err := c.planFor()
	if err != nil {
		return nil, err
	}
	c.emitPlanWarnings(plan)
	if plan.Forced != "" {
		fmt.Fprintf(c.Stderr, "warning: --force-isolation %s: this box runs BELOW the project's declared isolation floor (%s); this is recorded and will be warned about on every invocation\n",
			plan.Forced, c.Cfg.Config.Security.MinIsolation)
	}

	if c.Opts.DryRun {
		return nil, c.printPlan(plan)
	}

	meta := &state.BoxMeta{
		Key:               c.Key,
		WorkspaceRealpath: c.Workspace,
		Slug:              c.Slug,
		Backend:           plan.Backend.Name,
		Tier:              string(plan.Backend.Tier),
		ConfigDigest:      c.ConfigDigest(),
		ImageRef:          plan.Image.Ref,
		ImageBuilt:        plan.Image.LocalBuild(),
		MaskDigest:        plan.MaskDigest(),
		MaskMode:          plan.MaskMode,
		ForceIsolation:    plan.Forced,
		MemoryLimit:       c.Cfg.Config.Resources.Memory,
		CreatedAt:         time.Now().UTC(),
	}
	// Auto-selecting a higher tier silently changes boot time and filesystem
	// behavior; say so once per workspace, then stay quiet.
	autoSelected := c.Cfg.Config.Security.Backend == "" && c.Opts.Backend == ""
	if meta.Tier == string(backend.TierVM) && autoSelected {
		meta.VMTierNoticed = true
		fmt.Fprintln(c.Stderr, "notice: selected the vm backend (highest available isolation tier) for this box; boots take seconds and the workspace is shared via virtiofs. Pin the previous behavior with `-b container` or [security].backend = \"container\".")
	}
	if err := c.Store.SaveBox(meta); err != nil {
		return nil, Softwaref("%v", err)
	}
	if err := c.writeGeneratedArtifacts(plan); err != nil {
		return nil, err
	}
	c.Notef("created box for %s (backend %s, tier %s)", c.Workspace, meta.Backend, meta.Tier)
	return meta, nil
}

// writeGeneratedArtifacts persists masks.json, spec.json, and the proxy
// config under the box state dir. All are reconstructible.
func (c *Ctx) writeGeneratedArtifacts(plan *Plan) error {
	dir := c.Store.BoxDir(c.Key)
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
	if plan.Policy.Mode == "proxy" {
		// Both tiers run the same squid sidecar against the same generated
		// configuration; the tiers differ only in how the box addresses it.
		cfg := c.Cfg.Config
		sc := state.GeneratedFileHeader(ToolVersion, "agentbox.toml") +
			plan.Policy.SquidConfig(3128, cfg.Network.Proxy.ReadTimeout, cfg.Network.Proxy.RequestTimeout)
		// The path is fixed by BuildPlan; this only fills it in. The sidecar
		// bind-mounts it read-only, so it must be readable by the sidecar's
		// unprivileged uid rather than 0600 like the rest of the box state.
		if err := os.WriteFile(plan.Spec.ProxyConfigPath(), []byte(sc), 0o644); err != nil {
			return Softwaref("%v", err)
		}
	}
	return nil
}

// activeBackend instantiates the recorded backend for a box, honestly
// failing when it is not available on this host.
func (c *Ctx) activeBackend(meta *state.BoxMeta) (backend.Backend, error) {
	for _, av := range c.Availabilities() {
		if av.Name == meta.Backend {
			if !av.Available {
				return nil, Unavailablef("this box was created on backend %q, which is unavailable here: %s\n"+
					"Restore that backend, or rebuild the box on one that is available here with `--recreate` (the box's persistent home is kept).",
					meta.Backend, av.Reason)
			}
			switch av.Name {
			case "container":
				return backend.NewContainerBackend(av.Runtime), nil
			case "vm":
				return backend.NewVMBackend(av.Runtime, c.Store.Root), nil
			}
			return nil, Unavailablef("backend %q is not implemented in this build", av.Name)
		}
	}
	return nil, Unavailablef("this box records unknown backend %q", meta.Backend)
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
		drifted = append(drifted, fmt.Sprintf("backend (%s -> %s)", meta.Backend, plan.Backend.Name))
	}
	if len(drifted) > 0 {
		// Naming the remedy is the point. A box is deliberately not rebuilt
		// out from under a running agent, so drift is a warning -- but a
		// warning that only reports a mismatch leaves the user re-running the
		// same command and getting the same stale box.
		fmt.Fprintf(c.Stderr, "warning: this box drifts from current configuration: %s\n"+
			"  the box keeps running as built; `agentbox --recreate` rebuilds it from current configuration\n",
			strings.Join(drifted, "; "))
	}
	if meta.ForceIsolation != "" {
		fmt.Fprintf(c.Stderr, "warning: this box was created with --force-isolation %s and runs below the project's declared isolation floor\n", meta.ForceIsolation)
	}
}

// ensureUp creates backend resources and starts the box.
func (c *Ctx) ensureUp(meta *state.BoxMeta, plan *Plan) error {
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}

	st, ierr := be.Inspect(plan.ResourceName)
	if ierr != nil {
		// Not created yet in the runtime. Regenerate the derived artifacts
		// first: they are reconstructible by design and the box cannot be
		// created without them, so rebuilding beats failing on a state
		// directory someone cleaned out.
		if err := c.writeGeneratedArtifacts(plan); err != nil {
			return err
		}
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

// touchLastExec records activity for idle reaping.
func (c *Ctx) touchLastExec(meta *state.BoxMeta) {
	meta.LastExecAt = time.Now().UTC()
	_ = c.Store.SaveBox(meta)
}
