package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CmdStatus prints what this workspace's box is and what is in force for it:
// the backend and isolation tier, the mask mode and how much it hides, the
// egress mode and how much it allows, and any drift from current
// configuration. It never creates a box.
func (c *Ctx) CmdStatus() error {
	if !c.Store.BoxExists(c.Key) {
		if c.Opts.JSON {
			blob, _ := json.MarshalIndent(map[string]any{
				"workspace": c.Workspace, "key": c.Key, "exists": false,
			}, "", "  ")
			fmt.Println(string(blob))
			return nil
		}
		fmt.Printf("workspace: %s\nbox:       none yet (bare `agentbox` creates one)\n", c.Workspace)
		return nil
	}
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	plan, err := c.BuildPlanLenient()
	if err != nil {
		return err
	}

	var drift []string
	if meta.ConfigDigest != c.ConfigDigest() {
		drift = append(drift, "configuration")
	}
	if meta.ImageRef != plan.Image.Ref {
		drift = append(drift, "image")
	}
	if meta.MaskDigest != plan.MaskDigest() {
		drift = append(drift, "mask set")
	}
	if meta.Backend != plan.Backend.Name {
		drift = append(drift, "backend")
	}

	runState := "not created"
	if be, err := c.activeBackend(meta); err == nil {
		if st, err := be.Inspect(plan.ResourceName); err == nil {
			runState = "stopped"
			if st.Running {
				runState = "running"
			}
		}
	}

	maskCount := 0
	if plan.Masks != nil {
		maskCount = len(plan.Masks.Entries)
	}

	st := struct {
		Workspace      string   `json:"workspace"`
		Key            string   `json:"key"`
		Exists         bool     `json:"exists"`
		Resource       string   `json:"resource_name"`
		Backend        string   `json:"backend"`
		Tier           string   `json:"tier"`
		State          string   `json:"state"`
		Image          string   `json:"image"`
		MaskMode       string   `json:"mask_mode"`
		MaskCount      int      `json:"mask_count"`
		NetworkMode    string   `json:"network_mode"`
		AllowedDomains int      `json:"allowed_domains"`
		Memory         string   `json:"memory"`
		ForceIsolation string   `json:"force_isolation,omitempty"`
		Drift          []string `json:"drift,omitempty"`
	}{
		Workspace: c.Workspace, Key: c.Key, Exists: true,
		Resource: plan.ResourceName,
		Backend:  meta.Backend, Tier: meta.Tier, State: runState,
		Image:    meta.ImageRef,
		MaskMode: plan.MaskMode, MaskCount: maskCount,
		NetworkMode: plan.Policy.Mode, AllowedDomains: len(plan.Policy.Allow),
		Memory: meta.MemoryLimit, ForceIsolation: meta.ForceIsolation,
		Drift: drift,
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	fmt.Printf("workspace:   %s\n", st.Workspace)
	fmt.Printf("box:         %s\n", st.Resource)
	fmt.Printf("state:       %s\n", st.State)
	fmt.Printf("backend:     %s (tier %s)\n", st.Backend, st.Tier)
	fmt.Printf("image:       %s\n", st.Image)
	fmt.Printf("masking:     %s (%d path(s) hidden)\n", st.MaskMode, st.MaskCount)
	fmt.Printf("egress:      %s", st.NetworkMode)
	if st.NetworkMode == "proxy" {
		fmt.Printf(" (%d domain(s) allowed)", st.AllowedDomains)
	}
	fmt.Println()
	fmt.Printf("memory:      %s\n", st.Memory)
	if st.ForceIsolation != "" {
		fmt.Printf("FORCED:      created with --force-isolation %s; runs below the declared floor\n", st.ForceIsolation)
	}
	if len(st.Drift) > 0 {
		fmt.Printf("drift:       %s (recreate with `agentbox --recreate`)\n", strings.Join(st.Drift, ", "))
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
			fmt.Printf("%-45s = %-30s # %s\n", kv[0], kv[1], c.Cfg.Merged.Origin[kv[0]])
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
