package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/state"
)

// The inspection commands MUST NOT create or start anything: they
// are the supported way to answer "what would this do" before committing.

// CmdStatus prints, on every invocation, the box's instance name, tree
// mode, active backend, and isolation tier. --artifacts adds everything
// agentbox is holding for the box; `ls --artifacts` is the same view across
// projects, with the unclaimed set that status (being box-scoped) omits.
func (c *Ctx) CmdStatus(artifacts bool) error {
	boxes, err := c.Store.ListBoxes(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	targets := boxes
	if !c.Opts.All {
		meta, err := c.selectBox(false)
		if err != nil {
			if len(boxes) == 0 {
				fmt.Printf("project: %s\nboxes:   none (bare `agentbox` creates one)\n", c.Key)
				return nil
			}
			return err
		}
		targets = []*state.BoxMeta{meta}
	}

	pm, _ := c.Store.LoadProject(c.Key)
	type status struct {
		Box            string     `json:"box"`
		Project        string     `json:"project"`
		Default        bool       `json:"default"`
		Backend        string     `json:"backend"`
		Tier           string     `json:"tier"`
		TreeMode       string     `json:"tree_mode"`
		TreeRoot       string     `json:"tree_root"`
		Branch         string     `json:"branch,omitempty"`
		MaskMode       string     `json:"mask_mode"`
		MaskCount      int        `json:"mask_count"`
		NetworkMode    string     `json:"network_mode"`
		AllowedDomains int        `json:"allowed_domains"`
		State          string     `json:"state"`
		ForceIsolation string     `json:"force_isolation,omitempty"`
		Drift          []string   `json:"drift,omitempty"`
		Artifacts      []Artifact `json:"artifacts,omitempty"`
	}
	var snap *engineSnapshot
	if artifacts {
		snap = newEngineSnapshot()
	}
	var out []status
	for _, meta := range targets {
		plan, err := c.BuildPlanLenient(meta.Instance, meta.TreeMode, meta.TreeRoot)
		if err != nil {
			return err
		}
		st := status{
			Box: meta.Instance, Project: c.Key,
			Default: pm != nil && pm.DefaultBox == meta.Instance,
			Backend: meta.Backend, Tier: meta.Tier,
			TreeMode: meta.TreeMode, TreeRoot: meta.TreeRoot, Branch: meta.Branch,
			MaskMode: meta.MaskMode, MaskCount: len(plan.Masks.Entries),
			NetworkMode: plan.Policy.Mode, AllowedDomains: len(plan.Policy.Allow),
			ForceIsolation: meta.ForceIsolation,
		}
		if meta.ConfigDigest != c.ConfigDigest() {
			st.Drift = append(st.Drift, "configuration")
		}
		if meta.ImageRef != plan.Image.Ref {
			st.Drift = append(st.Drift, "image")
		}
		if meta.MaskDigest != plan.MaskDigest() {
			st.Drift = append(st.Drift, "mask set")
		}
		if meta.Backend != plan.Backend.Name {
			st.Drift = append(st.Drift, "backend")
		}
		cl := &claim{
			Key: c.Key, Instance: meta.Instance, Slug: c.Slug, Workspace: c.Workspace,
			Resource: plan.ResourceName, Meta: meta,
		}
		st.State = c.boxState(cl)
		if artifacts {
			st.Artifacts = c.boxArtifacts(snap, cl)
		}
		out = append(out, st)
	}

	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	for i, st := range out {
		if i > 0 {
			fmt.Println()
		}
		def := ""
		if st.Default {
			def = " (default)"
		}
		fmt.Printf("box:      %s%s\n", st.Box, def)
		fmt.Printf("project:  %s\n", st.Project)
		fmt.Printf("backend:  %s (isolation tier: %s)\n", st.Backend, st.Tier)
		fmt.Printf("tree:     %s at %s", st.TreeMode, st.TreeRoot)
		if st.Branch != "" {
			fmt.Printf(" (branch %s)", st.Branch)
		}
		fmt.Println()
		fmt.Printf("mask:     mode %s, %d mask(s) in force\n", st.MaskMode, st.MaskCount)
		fmt.Printf("network:  %s, %d allowed domain(s)\n", st.NetworkMode, st.AllowedDomains)
		fmt.Printf("state:    %s\n", st.State)
		if st.ForceIsolation != "" {
			fmt.Printf("WARNING:  created with --force-isolation %s — runs below the declared isolation floor\n", st.ForceIsolation)
		}
		if len(st.Drift) > 0 {
			fmt.Printf("drift:    %s (apply with --recreate)\n", strings.Join(st.Drift, ", "))
		}
		if artifacts {
			fmt.Println("artifacts:")
			printArtifacts(st.Artifacts, "  ")
		}
	}
	return nil
}

// CmdConfig prints the effective merged configuration; --origin annotates
// each key with the layer that set it.
func (c *Ctx) CmdConfig(origin bool) error {
	if c.Opts.JSON {
		out := map[string]any{"config": c.Cfg.Merged.Tree}
		if origin {
			out["origin"] = c.Cfg.Merged.Origin
		}
		blob, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	rows := flattenTree(c.Cfg.Merged.Tree, "")
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	for _, kv := range rows {
		if origin {
			layer := c.Cfg.Merged.Origin[kv[0]]
			fmt.Printf("%-45s = %-30s # %s\n", kv[0], kv[1], layer)
		} else {
			fmt.Printf("%-45s = %s\n", kv[0], kv[1])
		}
	}
	return nil
}

func flattenTree(tree map[string]any, prefix string) [][2]string {
	var rows [][2]string
	for k, v := range tree {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if path == "profiles" {
			continue
		}
		switch tv := v.(type) {
		case map[string]any:
			rows = append(rows, flattenTree(tv, path)...)
		default:
			blob, _ := json.Marshal(v)
			rows = append(rows, [2]string{path, string(blob)})
		}
	}
	return rows
}

// CmdMounts lists every path presented to the guest, every mask, and the
// reason for each.
func (c *Ctx) CmdMounts() error {
	plan, err := c.planForInspection()
	if err != nil {
		return err
	}
	type mountRow struct {
		Target string `json:"target"`
		Source string `json:"source"`
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	var rows []mountRow
	mode := "rw"
	if c.Cfg.Config.Workspace.ReadOnly {
		mode = "ro"
	}
	rows = append(rows, mountRow{
		Target: c.Cfg.Config.Workspace.Mount, Source: plan.TreeRoot, Mode: mode,
		Reason: fmt.Sprintf("workspace tree (%s mode)", plan.TreeMode),
	})
	rows = append(rows, mountRow{
		Target: "/home/agent", Source: plan.ResourceName + "-home", Mode: "rw",
		Reason: "persistent guest home; survives down, shadows the image after first creation",
	})
	for _, m := range c.Cfg.Config.Workspace.Mounts {
		rows = append(rows, mountRow{
			Target: m.Target, Source: m.Source, Mode: m.Mode,
			Reason: "[[workspace.mounts]] — bypasses masking unless separately matched",
		})
	}
	for _, e := range plan.Masks.Entries {
		rows = append(rows, mountRow{
			Target: filepath.Join(c.Cfg.Config.Workspace.Mount, e.Path),
			Source: string(e.Mechanism), Mode: "mask",
			Reason: fmt.Sprintf("masked by %q (%s:%d)", e.Rule, e.RuleSource, e.RuleLine),
		})
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	for _, r := range rows {
		fmt.Printf("%-50s %-5s %-30s %s\n", r.Target, r.Mode, r.Source, r.Reason)
	}
	return nil
}

// CmdMasks prints the effective mask set; --verify asserts each mask is in
// force in a running box.
func (c *Ctx) CmdMasks(verify bool) error {
	plan, err := c.planForInspection()
	if err != nil {
		return err
	}
	if c.Opts.JSON && !verify {
		blob, _ := json.MarshalIndent(plan.Masks, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	if !verify {
		fmt.Printf("mask mode: %s (tree: %s)\n", plan.MaskMode, plan.TreeRoot)
		for _, e := range plan.Masks.Entries {
			fmt.Printf("%-8s %-40s <- %q (%s:%d)\n", e.Kind, e.Path, e.Rule, e.RuleSource, e.RuleLine)
		}
		if len(plan.Masks.Entries) == 0 {
			fmt.Println("no masks (no ignore patterns matched the tree)")
		}
		return nil
	}

	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	st, err := be.Inspect(plan.ResourceName)
	if err != nil || !st.Running {
		return Softwaref("masks --verify needs a running box; `agentbox up` first")
	}
	failures := 0
	for _, e := range plan.Masks.Entries {
		guestPath := filepath.Join(c.Cfg.Config.Workspace.Mount, e.Path)
		var script string
		switch {
		case plan.MaskMode == "filter":
			// Layer 3: the path must not exist at all — not read empty,
			// not listed.
			script = fmt.Sprintf(`[ ! -e %q ] && [ ! -L %q ]`, guestPath, guestPath)
		case e.Kind == "dir":
			script = fmt.Sprintf(`[ -z "$(ls -A %q 2>/dev/null)" ]`, guestPath)
		default:
			script = fmt.Sprintf(`[ ! -s %q ]`, guestPath)
		}
		code, err := be.Exec(plan.ResourceName, backend.ExecSpec{Argv: []string{"sh", "-c", script}})
		ok := err == nil && code == 0
		mark := "ok"
		if !ok {
			mark = "FAIL"
			failures++
		}
		fmt.Printf("%-4s %s\n", mark, e.Path)
	}
	if failures > 0 {
		return Softwaref("%d mask(s) NOT in force", failures)
	}
	return nil
}

func (c *Ctx) planForInspection() (*Plan, error) {
	name, err := c.ResolveBoxName()
	if err != nil {
		return nil, err
	}
	if name != "" {
		if meta, err := c.Store.LoadBox(c.Key, name); err == nil {
			return c.BuildPlanLenient(meta.Instance, meta.TreeMode, meta.TreeRoot)
		}
	}
	boxes, _ := c.Store.ListBoxes(c.Key)
	if len(boxes) > 0 {
		if pm, err := c.Store.LoadProject(c.Key); err == nil {
			for _, b := range boxes {
				if b.Instance == pm.DefaultBox {
					return c.BuildPlanLenient(b.Instance, b.TreeMode, b.TreeRoot)
				}
			}
		}
	}
	return c.BuildPlanLenient("", "", "")
}

// CmdBackends lists available backends, their tiers, and why any are
// unavailable.
func (c *Ctx) CmdBackends() error {
	avs := c.Availabilities()
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(avs, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	for _, av := range avs {
		if av.Available {
			fmt.Printf("%-10s tier=%-10s available (runtime: %s)\n", av.Name, av.Tier, av.Runtime)
		} else {
			fmt.Printf("%-10s tier=%-10s UNAVAILABLE: %s\n", av.Name, av.Tier, av.Reason)
		}
	}
	return nil
}

// CmdDoctor preflights the host: backends, KVM, config validity,
// SSH remotes, .git masking.
func (c *Ctx) CmdDoctor() error {
	ok := true
	report := func(good bool, format string, a ...any) {
		mark := "ok  "
		if !good {
			mark = "warn"
			ok = false
		}
		fmt.Printf("%s %s\n", mark, fmt.Sprintf(format, a...))
	}

	report(true, "workspace: %s (project %s)", c.Workspace, c.Key)
	report(true, "configuration: valid (%d layer(s): %s)", len(c.Cfg.Layers), strings.Join(c.Cfg.Layers, " -> "))

	// hooks and host mounts are refused from an untrusted workspace
	// config; say so here rather than at the first refused `run`.
	if len(c.Cfg.Restricted) > 0 {
		if c.workspaceTrusted() {
			report(true, "trust: %s is trusted (%s)", c.Cfg.WorkspaceFile, strings.Join(c.Cfg.Restricted, ", "))
		} else {
			report(false, "trust: %s declares %s but is not trusted; review it, then `agentbox trust`", c.Cfg.WorkspaceFile, strings.Join(c.Cfg.Restricted, ", "))
		}
	}

	for _, av := range c.Availabilities() {
		if av.Available {
			report(true, "backend %s (tier %s): available via %s", av.Name, av.Tier, av.Runtime)
		} else {
			report(av.Name == "vm", "backend %s (tier %s): %s", av.Name, av.Tier, av.Reason)
		}
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		report(true, "kvm: /dev/kvm present")
	} else {
		report(true, "kvm: /dev/kvm absent (vm tier needs bare metal or nested virtualization)")
	}

	// Layer 3 seam: whether "auto" resolves to "filter" here. Two machines
	// resolving differently is exactly the divergence a user must be able
	// to see before it surprises them.
	if seamOK, reason := seamProbe(); seamOK {
		report(true, "mask seam: Layer 3 filtered share deliverable (vm tier resolves mask_mode \"auto\" to \"filter\")")
	} else {
		report(true, "mask seam: filtered share not deliverable — %s; \"auto\" under the vm tier resolves to \"view\"", reason)
	}

	// an HTTP CONNECT proxy cannot carry SSH; detect SSH remotes now
	// rather than mid-session.
	if out, err := exec.Command("git", "-C", c.Workspace, "remote", "-v").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "git@") || strings.Contains(line, "ssh://") {
				report(false, "git remote uses SSH (%s): in proxy mode git operations must use HTTPS remotes", strings.Fields(line)[0])
				break
			}
		}
	}

	// .git should not be masked.
	if plan, err := c.planForInspection(); err == nil {
		for _, e := range plan.Masks.Entries {
			if e.Path == ".git" || strings.HasPrefix(e.Path, ".git/") {
				report(false, ".git is masked by %q (%s:%d): this costs diff, commit, and history for almost no gain", e.Rule, e.RuleSource, e.RuleLine)
			}
		}
	}

	if pol := c.Cfg.Config.Network; pol.Mode == "proxy" {
		if len(pol.Bundles) == 0 && len(pol.Allow) == 0 {
			report(false, "network: proxy mode with an empty allowlist — every egress request will be denied")
		} else {
			report(true, "network: proxy mode, %d bundle(s) + %d allow entries", len(pol.Bundles), len(pol.Allow))
		}
	}
	if !ok {
		return &ExitError{Code: 1, Msg: "doctor found issues"}
	}
	return nil
}
