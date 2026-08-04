package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/config"
	"github.com/sblmnl/agentbox/internal/state"
)

// `agentbox prune` — find what agentbox has left behind, then reclaim it.
//
// Artifacts outlive their box in ordinary use: an interrupted create, a
// state directory removed by hand, a workspace deleted, an image superseded
// the moment a toolchain version changes. None of that is visible through
// the per-box commands, and a user who suspects agentbox is holding disk has
// no way to ask.
//
// So prune reports by default and removes only when told to. That ordering
// is deliberate: the report is the feature, and reclaiming disk is not worth
// deleting something the user still wanted. Nothing is a candidate unless
// agentbox itself would have created it under that name.

// PruneOptions selects what prune considers and whether it acts.
//
// Boxes, Running and State are an escalation ladder rather than one switch:
// each names exactly what it widens, none is implied by another, and the
// destructive end of it has to be spelled out in full. Nothing here removes
// anything without Apply.
type PruneOptions struct {
	Idle    bool // include boxes past their idle timeout (stopped, not removed)
	Images  bool // include built images no box references
	Boxes   bool // include stopped boxes: guest, networks, tree
	Running bool // ... and boxes that are currently running (needs Boxes)
	State   bool // ... and each box's persistent home volume (needs Boxes)
	Apply   bool // actually reclaim; without it, prune only reports
}

type pruneItem struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Size   string `json:"size,omitempty"`
	remove func() error
}

// engineSuffixes are the resources agentbox derives from a box's name. A
// candidate is matched back to its box through these before being called an
// orphan.
var engineSuffixes = []string{"-int", "-egress", "-home", "-proxy"}

// claim is one surviving box, indexed in a scan by the resource base name it
// owns. The same join answers three questions: prune asks which names are
// absent from the index, the artifact view asks what one box's name covers,
// and teardown acts on the boxes themselves. One derivation, three readings —
// a second copy that drifted would let one of them call a live box's network
// an orphan.
type claim struct {
	Key       string
	Instance  string
	Slug      string
	Workspace string // the project's workspace realpath, for tree removal
	Resource  string // ResourceNameFor(Slug, Key, Instance)
	Meta      *state.BoxMeta
}

// ID is the cross-project box identifier used in reports.
func (cl *claim) ID() string { return cl.Key + "/" + cl.Instance }

// vanishedProject is a project whose workspace no longer resolves. Its boxes
// are not surviving, so the engine resources named for them become orphans.
type vanishedProject struct {
	Key      string
	Realpath string
	Boxes    int
}

// scan is one pass over agentbox state: every surviving box, the resource
// names it claims, the images it references, and the projects that no longer
// resolve.
type scan struct {
	Claims   map[string]*claim // resource base name -> owning box
	Images   map[string]*claim // image ref -> a box that runs it
	Boxes    []*claim          // surviving boxes, project order
	Vanished []vanishedProject
}

// scanClaims builds that pass. It reads state only: no engine is contacted
// and nothing is created.
func (c *Ctx) scanClaims() (*scan, error) {
	keys, err := c.Store.ListProjects()
	if err != nil {
		return nil, Softwaref("%v", err)
	}
	s := &scan{Claims: map[string]*claim{}, Images: map[string]*claim{}}
	for _, k := range keys {
		pm, perr := c.Store.LoadProject(k)
		if perr != nil {
			continue
		}
		boxes, _ := c.Store.ListBoxes(k)
		if _, serr := os.Stat(pm.WorkspaceRealpath); os.IsNotExist(serr) {
			s.Vanished = append(s.Vanished, vanishedProject{
				Key: k, Realpath: pm.WorkspaceRealpath, Boxes: len(boxes),
			})
			continue
		}
		for _, b := range boxes {
			cl := &claim{
				Key: k, Instance: b.Instance, Slug: pm.Slug,
				Workspace: pm.WorkspaceRealpath,
				Resource:  ResourceNameFor(pm.Slug, k, b.Instance),
				Meta:      b,
			}
			s.Claims[cl.Resource] = cl
			s.Boxes = append(s.Boxes, cl)
			if b.ImageRef != "" && s.Images[b.ImageRef] == nil {
				s.Images[b.ImageRef] = cl
			}
		}
	}
	return s, nil
}

// ownerOf returns the live box an engine resource belongs to, or nil. The
// exact name is checked before the derived one, so a box whose instance
// happens to end in a suffix ("-int") is not mistaken for another box's
// network and deleted out from under itself.
func ownerOf(claims map[string]*claim, name string) *claim {
	if cl := claims[name]; cl != nil {
		return cl
	}
	for _, s := range engineSuffixes {
		if strings.HasSuffix(name, s) {
			if cl := claims[strings.TrimSuffix(name, s)]; cl != nil {
				return cl
			}
		}
	}
	return nil
}

// engineBins returns the engine CLIs to interrogate. Both are tried when
// both are installed: a box may have been created under either, and an
// engine that does not answer contributes nothing rather than failing the
// report.
// A var so tests can exercise the candidate logic without interrogating
// whatever engine happens to be running on the machine.
var engineBins = func() []string {
	var bins []string
	for _, bin := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(bin); err == nil {
			bins = append(bins, bin)
		}
	}
	return bins
}

// CmdPrune reports reclaimable artifacts, and reclaims them under --apply.
func (c *Ctx) CmdPrune(o PruneOptions) error {
	// --running and --state only mean something against a set of boxes.
	// Accepting them alone would silently do nothing, which is worse than
	// refusing: the user asked for a wider teardown and would be told it
	// succeeded.
	if (o.Running || o.State) && !o.Boxes {
		return Usagef("--running and --state widen `prune --boxes`; add --boxes to say which boxes you mean")
	}
	items, skipped, err := c.pruneCandidates(o)
	if err != nil {
		return err
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(struct {
			Applied bool        `json:"applied"`
			Items   []pruneItem `json:"items"`
			Skipped []string    `json:"skipped,omitempty"`
		}{o.Apply, items, skipped}, "", "  ")
		fmt.Println(string(blob))
		if !o.Apply {
			return nil
		}
	}
	if !o.Apply {
		if !c.Opts.JSON {
			c.reportPrune(items, skipped, o)
		}
		return nil
	}
	defer c.reportSkipped(skipped)
	var failed int
	for _, it := range items {
		if err := it.remove(); err != nil {
			c.Notef("could not reclaim %s %s: %v", it.Kind, it.Name, err)
			failed++
			continue
		}
		if !c.Opts.JSON {
			fmt.Printf("reclaimed %-10s %s\n", it.Kind, it.Name)
		}
	}
	if failed > 0 {
		return Softwaref("%d of %d items could not be reclaimed", failed, len(items))
	}
	if len(items) == 0 && !c.Opts.JSON {
		fmt.Println("nothing to reclaim")
	}
	return nil
}

// reportPrune prints the candidate set grouped by kind, and says plainly
// how to act on it — a report that does not tell you the next command is
// only half a UI.
func (c *Ctx) reportPrune(items []pruneItem, skipped []string, o PruneOptions) {
	if len(items) == 0 {
		fmt.Println("nothing to reclaim")
		if !o.Images {
			fmt.Println("(built images are only considered with --images)")
		}
		if !o.Boxes {
			fmt.Println("(boxes are only considered with --boxes)")
		}
		c.reportSkipped(skipped)
		return
	}
	fmt.Printf("%-10s %-44s %s\n", "KIND", "NAME", "WHY")
	var lastKind string
	for _, it := range items {
		if lastKind != "" && it.Kind != lastKind {
			fmt.Println()
		}
		lastKind = it.Kind
		why := it.Reason
		if it.Size != "" {
			why = it.Size + ", " + why
		}
		fmt.Printf("%-10s %-44s %s\n", it.Kind, it.Name, why)
	}
	fmt.Printf("\n%d item(s) reclaimable. Nothing has been removed.\n", len(items))
	fmt.Println("Reclaim them with: agentbox prune --apply")
	if !o.Images {
		fmt.Println("Built images are not considered unless you add --images.")
	}
	if !o.Boxes {
		fmt.Println("Boxes are not considered unless you add --boxes.")
	} else {
		fmt.Println("Boxes listed above lose their working tree; their git branches are kept.")
		if !o.State {
			fmt.Println("Their persistent homes survive; add --state to reclaim those too.")
		}
	}
	c.reportSkipped(skipped)
}

// reportSkipped names the boxes --boxes deliberately left alone. It runs on
// both the report and the --apply path: "I removed everything except these"
// is the only honest summary, and omitting it would let a user believe a
// machine was clear when boxes are still up.
func (c *Ctx) reportSkipped(skipped []string) {
	if len(skipped) == 0 || c.Opts.JSON {
		return
	}
	fmt.Printf("\n%d box(es) left alone (add --running to include them):\n", len(skipped))
	for _, s := range skipped {
		fmt.Printf("  %s\n", s)
	}
}

// pruneCandidates builds the candidate set. Order matters for --apply:
// containers are torn down before the networks and volumes they hold open,
// and projects last, since their boxes name the resources above.
func (c *Ctx) pruneCandidates(o PruneOptions) ([]pruneItem, []string, error) {
	s, err := c.scanClaims()
	if err != nil {
		return nil, nil, err
	}

	var projects []pruneItem
	for _, vp := range s.Vanished {
		key := vp.Key
		projects = append(projects, pruneItem{
			Kind:   "project",
			Name:   key,
			Reason: fmt.Sprintf("workspace no longer resolves: %s (%d box(es))", vp.Realpath, vp.Boxes),
			remove: func() error { return c.Store.RemoveProject(key) },
		})
	}

	// Boxes torn down by --boxes are not also reported as idle: one box, one
	// disposition, and removal supersedes stopping.
	boxes, covered, skipped := c.boxCandidates(o, s)
	var idle []pruneItem
	if o.Idle {
		for _, cl := range s.Boxes {
			if covered[cl.ID()] {
				continue
			}
			if item, ok := c.idleCandidate(cl); ok {
				idle = append(idle, item)
			}
		}
	}

	var containers, networks, volumes, images []pruneItem
	for _, bin := range engineBins() {
		inv := backend.NewInventory(bin)
		buckets := []struct {
			kind backend.ResourceKind
			out  *[]pruneItem
		}{
			{backend.KindContainer, &containers},
			{backend.KindNetwork, &networks},
			{backend.KindVolume, &volumes},
		}
		for _, b := range buckets {
			for _, name := range inv.Names(b.kind) {
				if ownerOf(s.Claims, name) != nil {
					continue
				}
				n, kind, i := name, b.kind, inv
				*b.out = append(*b.out, pruneItem{
					Kind:   string(kind),
					Name:   name,
					Reason: "no box in agentbox state claims it",
					remove: func() error { return i.Remove(kind, n) },
				})
			}
		}
		if o.Images {
			for _, ref := range inv.Names(backend.KindImage) {
				if s.Images[ref] != nil {
					continue
				}
				r, i := ref, inv
				images = append(images, pruneItem{
					Kind:   string(backend.KindImage),
					Name:   ref,
					Reason: "no box runs this image",
					Size:   inv.ImageSize(ref),
					remove: func() error { return i.Remove(backend.KindImage, r) },
				})
			}
		}
	}

	views := c.staleViews(s)

	// Boxes first: tearing a box down through its backend takes its own
	// container, networks and (under --state) home volume with it. The
	// buckets below were computed from the same scan, so they hold only what
	// was already unclaimed and can never overlap.
	var all []pruneItem
	all = append(all, boxes...)
	all = append(all, idle...)
	all = append(all, containers...)
	all = append(all, networks...)
	all = append(all, volumes...)
	all = append(all, images...)
	all = append(all, views...)
	all = append(all, projects...)
	return all, skipped, nil
}

// staleViews finds mask views left under the state root with no box to
// serve. A stale view is a mounted or copied tree, so it can hold real disk
// and, under the vm tier, a mount the host still carries.
func (c *Ctx) staleViews(s *scan) []pruneItem {
	root := backend.ViewsDir(c.Store.Root)
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var items []pruneItem
	for _, e := range ents {
		if !e.IsDir() || ownerOf(s.Claims, e.Name()) != nil {
			continue
		}
		path := filepath.Join(root, e.Name())
		items = append(items, pruneItem{
			Kind:   "view",
			Name:   e.Name(),
			Reason: "mask view with no box in agentbox state",
			remove: func() error { return os.RemoveAll(path) },
		})
	}
	return items
}

// boxCandidates builds the removal items for --boxes. It returns the items,
// the set of boxes they cover (so the same box is not also reported as idle),
// and the boxes deliberately left alone.
//
// The skipped set is returned rather than dropped because silence here is the
// dangerous outcome: a user who runs `prune --apply --boxes` and is not told
// that three running boxes survived believes the machine is clear when it is
// not.
func (c *Ctx) boxCandidates(o PruneOptions, s *scan) (items []pruneItem, covered map[string]bool, skipped []string) {
	if !o.Boxes {
		return nil, nil, nil
	}
	covered = map[string]bool{}
	for _, cl := range s.Boxes {
		running, liveness := c.boxLiveness(cl)
		if running && !o.Running {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", cl.ID(), liveness))
			continue
		}
		what := "removes the guest, its networks and its tree"
		if o.State {
			what += " and its persistent home"
		} else {
			what += "; the persistent home survives"
		}
		if cl.Meta.Branch != "" {
			what += "; branch " + cl.Meta.Branch + " is preserved"
		}
		box := cl
		covered[cl.ID()] = true
		items = append(items, pruneItem{
			Kind:   "box",
			Name:   cl.ID(),
			Reason: liveness + "; " + what,
			remove: func() error {
				pl, err := c.Store.LockProject(box.Key)
				if err != nil {
					return err
				}
				defer pl.Release()
				// deleteBranch is never true here: prune has no flag for it,
				// and unreviewed work on a branch is the one thing a bulk
				// teardown must not be able to destroy.
				return c.removeBox(box, o.State, false)
			},
		})
	}
	return items, covered, skipped
}

// boxLiveness reports whether a box is running, and how that was determined.
// A backend that is unavailable on this host cannot answer, and a box whose
// state cannot be established is reported as running: for a destructive
// default, "I could not tell" has to fall on the side of leaving it alone.
func (c *Ctx) boxLiveness(cl *claim) (running bool, detail string) {
	if c.Opts.BoxLiveness != nil {
		return c.Opts.BoxLiveness(cl.Instance)
	}
	be, err := c.activeBackend(cl.Meta)
	if err != nil {
		return true, fmt.Sprintf("state unknown (backend %q unavailable here)", cl.Meta.Backend)
	}
	st, err := be.Inspect(cl.Resource)
	if err != nil {
		return false, "not created in the runtime"
	}
	if st.Running {
		return true, "RUNNING"
	}
	return false, "stopped"
}

// idleCandidate reports a box past its idle timeout. Idle boxes are stopped,
// never removed: the box, its home volume and its tree survive, so this
// reclaims memory rather than work.
func (c *Ctx) idleCandidate(cl *claim) (pruneItem, bool) {
	d, err := config.ParseDuration(c.Cfg.Config.Box.IdleTimeout)
	if err != nil || d == 0 {
		return pruneItem{}, false
	}
	last := cl.Meta.LastExecAt
	if last.IsZero() {
		last = cl.Meta.CreatedAt
	}
	if time.Since(last) <= d {
		return pruneItem{}, false
	}
	return pruneItem{
		Kind:   "idle-box",
		Name:   cl.ID(),
		Reason: fmt.Sprintf("idle since %s; will be stopped, not removed", last.Format(time.RFC3339)),
		remove: func() error {
			// The resource name comes off the claim, not off a plan: a plan
			// built here would name it after the *current* project, and this
			// box may belong to another one.
			be, err := c.activeBackend(cl.Meta)
			if err != nil {
				return err
			}
			return be.Stop(cl.Resource)
		},
	}, true
}
