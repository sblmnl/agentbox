package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/image"
	"github.com/sblmnl/agentbox/internal/netpol"
	"github.com/sblmnl/agentbox/internal/state"
	"github.com/sblmnl/agentbox/internal/tree"
)

// ErrHandled signals "output already produced; exit 0".
var ErrHandled = &ExitError{Code: 0}

func (c *Ctx) printPlan(plan *Plan) error {
	blob, _ := json.MarshalIndent(plan, "", "  ")
	fmt.Println(string(blob))
	return ErrHandled
}

// CmdAttach attaches to an existing box: unlike bare `agentbox`, it
// never creates one.
func (c *Ctx) CmdAttach() (int, error) {
	if _, err := c.selectBox(false); err != nil {
		return 0, err
	}
	return c.CmdRun(nil, true)
}

// CmdRun implements bare `agentbox`, `run CMD...`, and `shell`.
func (c *Ctx) CmdRun(argv []string, interactiveShell bool) (int, error) {
	meta, err := c.selectBox(true)
	if err != nil {
		return 0, err
	}
	if meta == nil {
		return 0, ErrHandled // dry-run path
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		return 0, err
	}
	c.warnDrift(meta, plan)
	if c.Opts.DryRun {
		return 0, c.printPlan(plan)
	}
	if c.Opts.Recreate {
		if err := c.recreate(meta, plan); err != nil {
			return 0, err
		}
	}

	// run/attach hold the shared box lock; lifecycle transitions
	// take the exclusive one internally before this point.
	lock, err := c.Store.LockBoxShared(c.Key, meta.Instance)
	if err != nil {
		return 0, Softwaref("%v", err)
	}
	defer lock.Release()

	if err := c.ensureUp(meta, plan); err != nil {
		return 0, err
	}
	c.touchLastExec(meta)
	c.runHooks("pre_exec", c.Cfg.Config.Hooks.PreExec)

	if len(argv) == 0 {
		argv = c.Cfg.Config.Box.DefaultCommand
		if interactiveShell || len(argv) == 0 {
			argv = []string{"bash", "-l"}
		}
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return 0, err
	}
	es := backend.ExecSpec{
		Argv:    argv,
		TTY:     stdinIsTTY() && stdoutIsTTY(), // only when both are terminals
		Root:    c.Opts.Root,
		Workdir: plan.GuestWorkdir,
		Env:     plan.Env,
	}
	if c.Opts.Root && meta.Tier == "container" {
		// uid 0 in a container guest is not the same claim as vm
		// guest root; the runtime still confines it, but caps are dropped.
		fmt.Fprintln(c.Stderr, "warning: --root under the container tier runs uid 0 with all capabilities dropped; masking relies on the guest lacking CAP_SYS_ADMIN")
	}
	code, err := be.Exec(plan.ResourceName, es)
	if err != nil {
		return 0, Softwaref("%v", err)
	}
	return code, nil // in-box exit code returned verbatim
}

func (c *Ctx) recreate(meta *state.BoxMeta, plan *Plan) error {
	pl, err := c.Store.LockProject(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer pl.Release()
	bl, err := c.Store.LockBoxExclusive(pl, c.Key, meta.Instance)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer bl.Release()

	be, err := c.activeBackend(meta)
	if err == nil {
		_ = be.Remove(plan.ResourceName, true)
	}
	meta.ConfigDigest = c.ConfigDigest()
	meta.ImageRef = plan.Image.Ref
	meta.MaskDigest = plan.MaskDigest()
	meta.Backend = plan.Backend.Name
	meta.Tier = string(plan.Backend.Tier)
	if err := c.Store.SaveBox(meta); err != nil {
		return Softwaref("%v", err)
	}
	return c.writeGeneratedArtifacts(plan)
}

// CmdNew implements `new [--name N]`: create without attaching.
func (c *Ctx) CmdNew() error {
	name, err := c.ResolveBoxName()
	if err != nil {
		return err
	}
	meta, err := c.createBox(name)
	if err != nil {
		return err
	}
	if meta != nil {
		fmt.Println(meta.Instance)
	}
	return nil
}

// CmdDefault implements `default NAME` under the project lock.
func (c *Ctx) CmdDefault(name string) error {
	pl, err := c.Store.LockProject(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer pl.Release()
	boxes, _ := c.Store.ListBoxes(c.Key)
	found := false
	for _, b := range boxes {
		if b.Instance == name {
			found = true
		}
	}
	if !found {
		return Usagef("no box named %q (available: %s)", name, boxNames(boxes))
	}
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	pm.DefaultBox = name
	return c.Store.SaveProject(c.Key, pm)
}

// CmdUp creates and starts without exec.
func (c *Ctx) CmdUp() error {
	meta, err := c.selectBox(true)
	if err != nil {
		return err
	}
	if meta == nil {
		return ErrHandled
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		return err
	}
	c.warnDrift(meta, plan)
	if c.Opts.DryRun {
		return c.printPlan(plan)
	}
	pl, err := c.Store.LockProject(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	bl, err := c.Store.LockBoxExclusive(pl, c.Key, meta.Instance)
	pl.Release()
	if err != nil {
		return Softwaref("%v", err)
	}
	defer bl.Release()
	return c.ensureUp(meta, plan)
}

func (c *Ctx) forEachTarget(fn func(*state.BoxMeta) error) error {
	if c.Opts.All {
		boxes, err := c.Store.ListBoxes(c.Key)
		if err != nil {
			return Softwaref("%v", err)
		}
		for _, b := range boxes {
			if err := fn(b); err != nil {
				return err
			}
		}
		return nil
	}
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	return fn(meta)
}

// CmdStop stops a box, retaining state and tree (stopping
// frees guest memory while preserving everything unreviewed).
func (c *Ctx) CmdStop() error {
	return c.forEachTarget(func(meta *state.BoxMeta) error {
		be, err := c.activeBackend(meta)
		if err != nil {
			return err
		}
		plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
		if err != nil {
			return err
		}
		if err := be.Stop(plan.ResourceName); err != nil {
			c.Notef("box %s was not running", meta.Instance)
		}
		return nil
	})
}

// CmdDown stops and removes guest and networks; persistent state stays.
func (c *Ctx) CmdDown() error {
	return c.forEachTarget(func(meta *state.BoxMeta) error {
		be, err := c.activeBackend(meta)
		if err != nil {
			return err
		}
		plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
		if err != nil {
			return err
		}
		return be.Remove(plan.ResourceName, true)
	})
}

// CmdRestart recreates the box applying current configuration.
func (c *Ctx) CmdRestart() error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		return err
	}
	if err := c.recreate(meta, plan); err != nil {
		return err
	}
	return c.ensureUp(meta, plan)
}

// CmdRm removes a box and its worktree; the branch survives unless
// --delete-branch; --state also discards the persistent home.
func (c *Ctx) CmdRm(id string, removeState, deleteBranch bool) error {
	instance := id
	if instance == "" {
		meta, err := c.selectBox(false)
		if err != nil {
			return err
		}
		instance = meta.Instance
	} else if strings.Contains(id, "/") {
		parts := strings.SplitN(id, "/", 2)
		if parts[0] != c.Key {
			return Usagef("box id %q does not belong to this project (%s)", id, c.Key)
		}
		instance = parts[1]
	}

	pl, err := c.Store.LockProject(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer pl.Release()

	meta, err := c.Store.LoadBox(c.Key, instance)
	if err != nil {
		return Usagef("no box named %q in this project", instance)
	}
	if err := c.removeBox(&claim{
		Key: c.Key, Instance: instance, Slug: c.Slug, Workspace: c.Workspace,
		Resource: ResourceNameFor(c.Slug, c.Key, instance), Meta: meta,
	}, removeState, deleteBranch); err != nil {
		return err
	}
	c.Notef("removed box %s", instance)
	return nil
}

// removeBox tears one box down wherever it lives: its guest and networks
// through its own backend, then the tree, the state directory, and the
// project's default pointer. `rm` and `prune --boxes` share it so the two can
// never come to disagree about what removing a box means.
//
// The resource name is taken off the claim rather than rebuilt from a plan:
// a plan built here would name the resource after the *current* project, and
// prune reaches boxes in other projects. The branch is deleted only when the
// caller asks; prune never asks. The caller holds the project lock.
func (c *Ctx) removeBox(cl *claim, removeState, deleteBranch bool) error {
	if be, err := c.activeBackend(cl.Meta); err == nil {
		_ = be.Remove(cl.Resource, !removeState)
	}
	if err := tree.Remove(cl.Meta.TreeMode, cl.Workspace, cl.Meta.TreeRoot, cl.Meta.Branch, deleteBranch); err != nil {
		return Softwaref("%v", err)
	}
	if cl.Meta.Branch != "" && !deleteBranch {
		c.Notef("branch %s preserved; delete it with `git branch -D %s`", cl.Meta.Branch, cl.Meta.Branch)
	}
	if err := c.Store.RemoveBox(cl.Key, cl.Instance); err != nil {
		return Softwaref("%v", err)
	}
	if err := c.repointDefault(cl.Key, cl.Instance); err != nil {
		return Softwaref("%v", err)
	}
	return nil
}

// repointDefault keeps the project's default box from dangling once the box
// it names is gone. Left alone, every later invocation resolves the default,
// finds nothing, and refuses to run at all — a dead end the user has to
// clear by hand, for a box they deliberately removed.
//
// Exactly one remaining box is adopted, because with a single candidate
// there is nothing to guess between. With several, the default is cleared
// rather than picked: choosing for the user is how you end up attached to
// the wrong box. The caller holds the project lock.
func (c *Ctx) repointDefault(key, removed string) error {
	pm, err := c.Store.LoadProject(key)
	if err != nil {
		return nil
	}
	// Also runs when the default is already empty: a removal can take an
	// ambiguous project down to a single box, which is the point at which
	// there is again an unambiguous default to adopt.
	if pm.DefaultBox != "" && pm.DefaultBox != removed {
		return nil
	}
	boxes, err := c.Store.ListBoxes(key)
	if err != nil {
		return err
	}
	pm.DefaultBox = ""
	if len(boxes) == 1 {
		pm.DefaultBox = boxes[0].Instance
	}
	if err := c.Store.SaveProject(key, pm); err != nil {
		return err
	}
	switch {
	case pm.DefaultBox != "":
		c.Notef("default box is now %s", pm.DefaultBox)
	case len(boxes) > 0:
		c.Notef("no default box now; pick one with `agentbox default NAME` (available: %s)", boxNames(boxes))
	}
	return nil
}

// CmdLs lists boxes grouped by project. ls MUST show each box's
// tier so a mixed project is visible at a glance.
//
// Without --artifacts it makes no engine calls at all, which is what keeps it
// usable with a stopped daemon and what the shell completions rely on when
// they parse its columns. --artifacts opts into the unified view: live state,
// everything each box is holding, and a closing list of what nothing holds.
func (c *Ctx) CmdLs(allProjects, artifacts bool) error {
	keys := []string{c.Key}
	if allProjects {
		var err error
		keys, err = c.Store.ListProjects()
		if err != nil {
			return Softwaref("%v", err)
		}
	}
	type row struct {
		Project   string     `json:"project"`
		Instance  string     `json:"instance"`
		Default   bool       `json:"default"`
		Backend   string     `json:"backend"`
		Tier      string     `json:"tier"`
		TreeMode  string     `json:"tree_mode"`
		Forced    string     `json:"force_isolation,omitempty"`
		Age       string     `json:"age"`
		Orphaned  bool       `json:"orphaned,omitempty"`
		Memory    string     `json:"memory"`
		State     string     `json:"state,omitempty"`
		Artifacts []Artifact `json:"artifacts,omitempty"`
	}

	// The claim scan spans every project even when the listing does not:
	// whether an artifact is unclaimed is only answerable globally.
	var snap *engineSnapshot
	var s *scan
	if artifacts {
		var err error
		if s, err = c.scanClaims(); err != nil {
			return err
		}
		snap = newEngineSnapshot()
	}

	var rows []row
	for _, k := range keys {
		pm, err := c.Store.LoadProject(k)
		orphaned := false
		defaultBox := ""
		if err == nil {
			defaultBox = pm.DefaultBox
			if _, serr := os.Stat(pm.WorkspaceRealpath); os.IsNotExist(serr) {
				orphaned = true // flagged; prune reaps these
			}
		}
		boxes, _ := c.Store.ListBoxes(k)
		for _, b := range boxes {
			r := row{
				Project: k, Instance: b.Instance, Default: b.Instance == defaultBox,
				Backend: b.Backend, Tier: b.Tier, TreeMode: b.TreeMode,
				Forced:   b.ForceIsolation,
				Age:      time.Since(b.CreatedAt).Round(time.Minute).String(),
				Orphaned: orphaned, Memory: b.MemoryLimit,
			}
			// A box whose project has vanished holds nothing agentbox still
			// claims, so its artifacts belong in the unclaimed section below
			// rather than under the box. Listing them in both places would
			// make the same resource look like two.
			if artifacts && err == nil && !orphaned {
				if cl := s.Claims[ResourceNameFor(pm.Slug, k, b.Instance)]; cl != nil {
					r.State = c.boxState(cl)
					r.Artifacts = c.boxArtifacts(snap, cl)
				}
			}
			rows = append(rows, r)
		}
	}

	if c.Opts.JSON {
		out := any(rows)
		if artifacts {
			out = struct {
				Boxes     []row      `json:"boxes"`
				Unclaimed []Artifact `json:"unclaimed"`
			}{rows, c.unclaimedArtifacts(snap, s)}
		}
		blob, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	if len(rows) == 0 && !artifacts {
		fmt.Println("no boxes")
		return nil
	}
	if len(rows) > 0 {
		if artifacts {
			fmt.Printf("%-30s %-16s %-10s %-10s %-9s %-13s %-7s %s\n", "PROJECT", "INSTANCE", "BACKEND", "TIER", "TREE", "STATE", "MEM", "AGE")
		} else {
			fmt.Printf("%-30s %-16s %-10s %-10s %-9s %-7s %s\n", "PROJECT", "INSTANCE", "BACKEND", "TIER", "TREE", "MEM", "AGE")
		}
	}
	for _, r := range rows {
		name := r.Instance
		if r.Default {
			name += "*"
		}
		flags := ""
		if r.Forced != "" {
			flags = " [FORCED:" + r.Forced + "]"
		}
		if r.Orphaned {
			flags += " [ORPHANED]"
		}
		if !artifacts {
			fmt.Printf("%-30s %-16s %-10s %-10s %-9s %-7s %s%s\n", r.Project, name, r.Backend, r.Tier, r.TreeMode, r.Memory, r.Age, flags)
			continue
		}
		fmt.Printf("%-30s %-16s %-10s %-10s %-9s %-13s %-7s %s%s\n", r.Project, name, r.Backend, r.Tier, r.TreeMode, r.State, r.Memory, r.Age, flags)
		if r.Orphaned {
			fmt.Println("  (workspace no longer resolves; this box's artifacts are listed as unclaimed below)")
		}
		printArtifacts(r.Artifacts, "  ")
		fmt.Println()
	}
	if !artifacts {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("no boxes")
		fmt.Println()
	}
	unclaimed := c.unclaimedArtifacts(snap, s)
	if len(unclaimed) == 0 {
		fmt.Println("nothing unclaimed: every agentbox artifact on this host belongs to a box above")
		return nil
	}
	fmt.Printf("unclaimed (no box in agentbox state names these, across every project):\n")
	printArtifacts(unclaimed, "  ")
	fmt.Printf("\n%d unclaimed artifact(s). Reclaim them with: agentbox prune --apply\n", len(unclaimed))
	return nil
}

// CmdBuild builds or rebuilds the image.
func (c *Ctx) CmdBuild(noCache bool) error {
	plan, err := c.BuildPlan("", "", c.Workspace)
	if err != nil {
		return err
	}
	avs := c.Availabilities()
	for _, av := range avs {
		if av.Available && av.Name == "container" {
			be := backend.NewContainerBackend(av.Runtime)
			return c.buildImage(be, plan, noCache)
		}
	}
	// A vm-only host builds through the same engine CLI; the VM runtime is
	// not involved in a build (the image is the same artifact).
	for _, av := range avs {
		if av.Available && av.Name == "vm" {
			vmCfg := c.Cfg.Config.Security.VM
			engine, runtime, err := backend.ResolveVMRuntime(av.VMRuntimes(), vmCfg.Runtime, vmCfg.Hypervisor)
			if err != nil {
				return Configf("%v", err)
			}
			return c.buildImage(backend.NewVMBackend(engine, runtime, c.Store.Root), plan, noCache)
		}
	}
	return Unavailablef("no available backend can build images on this host")
}

// WriteBuildContext lays down the Dockerfile under the cache dir and returns
// the build-context directory. A user-supplied [image].dockerfile is copied in
// verbatim (its 16-hex content digest names the dir, matching the resolved
// tag); otherwise agentbox generates the Dockerfile from features. The context
// contains only the Dockerfile, so a custom Dockerfile must be self-contained
// (install via RUN rather than COPY host files; use [image].ref for the latter).
func (c *Ctx) WriteBuildContext() (string, error) {
	cfg := c.Cfg.Config
	var df []byte
	var digest string
	if p := cfg.Image.Dockerfile; p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", Configf("reading [image].dockerfile %q: %v", p, err)
		}
		df, digest = data, image.DockerfileDigest(data)
	} else {
		df = []byte(image.Dockerfile(cfg, os.Getuid(), os.Getgid()))
		digest = image.FeaturesFrom(cfg).Digest()
	}
	dir := filepath.Join(state.CacheDir(), "build", digest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", Softwaref("%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o600); err != nil {
		return "", Softwaref("%v", err)
	}
	return dir, nil
}

// CmdLogs shows box or proxy logs; --denied filters the proxy log to
// refused requests.
func (c *Ctx) CmdLogs(proxy, denied, follow bool) error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		return err
	}
	if denied {
		proxy = true
	}
	if proxy && meta.Tier == "vm" {
		// The vm proxy is a host daemon; its audit trail is a file under
		// the box state dir, readable even when the box is stopped.
		path := filepath.Join(c.Store.BoxDir(c.Key, meta.Instance), "logs", "proxy-access.log")
		return tailAuditLog(path, denied, follow)
	}
	if !denied {
		return be.Logs(plan.ResourceName, proxy, follow)
	}
	// Denied filter: squid logs TCP_DENIED for refused requests.
	pr, pw, err := os.Pipe()
	if err != nil {
		return Softwaref("%v", err)
	}
	go func() {
		defer pw.Close()
		cb := be.(*backend.ContainerBackend)
		cmd := cb.Runner("logs", plan.ResourceName+"-proxy")
		cmd.Stdout = pw
		cmd.Stderr = pw
		_ = cmd.Run()
	}()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "DENIED") || strings.Contains(line, "/403") {
			fmt.Println(line)
		}
	}
	return nil
}

// tailAuditLog prints a host-side proxy audit log, optionally filtered to
// denials and optionally following appended lines.
func tailAuditLog(path string, deniedOnly, follow bool) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Usagef("no proxy audit log at %s (the box has not served any request, or audit is disabled)", path)
		}
		return Softwaref("%v", err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	pending := "" // hold partial lines so a mid-write read is not split
	for {
		chunk, err := r.ReadString('\n')
		pending += chunk
		if strings.HasSuffix(pending, "\n") {
			if !deniedOnly || strings.Contains(pending, "DENIED") {
				fmt.Print(pending)
			}
			pending = ""
		}
		if err != nil {
			if !follow {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// CmdPs lists processes in the box.
func (c *Ctx) CmdPs() error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		return err
	}
	code, err := be.Exec(plan.ResourceName, backend.ExecSpec{Argv: []string{"ps", "aux"}})
	if err != nil {
		return Softwaref("%v", err)
	}
	if code != 0 {
		return Softwaref("ps exited %d", code)
	}
	return nil
}

// CmdBundles implements `bundles [--list] [--show NAME]`: an opaque
// allowlist is not auditable.
func (c *Ctx) CmdBundles(show string) error {
	if show != "" {
		domains, ok := netpol.Bundles[show]
		if !ok {
			return Usagef("unknown bundle %q", show)
		}
		if c.Opts.JSON {
			blob, _ := json.MarshalIndent(map[string]any{"name": show, "domains": domains}, "", "  ")
			fmt.Println(string(blob))
			return nil
		}
		for _, d := range domains {
			fmt.Println(d)
		}
		return nil
	}
	names := netpol.BundleNames()
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(names, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	for _, n := range names {
		fmt.Printf("%-28s %d domain(s)\n", n, len(netpol.Bundles[n]))
	}
	return nil
}

// CmdVersion prints tool and backend versions.
func (c *Ctx) CmdVersion() error {
	info := map[string]any{
		"agentbox":     ToolVersion,
		"go_generator": image.GeneratorVersion,
		"backends":     c.Availabilities(),
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	fmt.Printf("agentbox %s\n", ToolVersion)
	for _, av := range c.Availabilities() {
		status := "available"
		if !av.Available {
			status = "unavailable"
		}
		fmt.Printf("backend %s (tier %s): %s %s\n", av.Name, av.Tier, status, strings.Join(av.VMRuntimes(), ", "))
	}
	return nil
}

// SortedEnvKeys helps deterministic env output.
func SortedEnvKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func stdinIsTTY() bool  { return isTTY(os.Stdin) }
func stdoutIsTTY() bool { return isTTY(os.Stdout) }

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
