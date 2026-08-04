package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/netpol"
	"github.com/sblmnl/agentbox/internal/tree"
)

// The unified view: one box, and everything agentbox is holding on its
// behalf.
//
// `prune` asks which artifacts no box claims. This asks the same question
// from the other end — what does *this* box own, and is it actually there? —
// over the same name↔box join (scanClaims/ownerOf), so the two answers can
// never contradict each other.
//
// A listing that only showed what exists would be a filtered `docker ps`.
// The value is in the comparison: what a box expects is derived from what it
// was created with, and anything expected-but-absent or claimed-but-
// unexpected is said out loud. A stopped proxy sidecar beside a running box,
// or an -egress network that outlived a switch to network.mode = "none", is
// exactly what this is for.

// Artifact statuses. MISSING is deliberately shouted: it is the one that
// means something is wrong.
const (
	artRunning    = "running"
	artPresent    = "present"
	artMissing    = "MISSING"
	artUnexpected = "unexpected"
)

// Artifact is one thing agentbox created for a box: an engine resource, or a
// directory or file under the state root.
type Artifact struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// engineSnapshot is one pass over every reachable engine: what exists now, by
// kind, and which containers are running. Taken once per command rather than
// once per box, so listing twenty boxes does not interrogate the engine
// twenty times.
type engineSnapshot struct {
	byKind  map[backend.ResourceKind]map[string]bool
	running map[string]bool
	invs    []*backend.Inventory
}

func newEngineSnapshot() *engineSnapshot {
	snap := &engineSnapshot{
		byKind:  map[backend.ResourceKind]map[string]bool{},
		running: map[string]bool{},
	}
	kinds := []backend.ResourceKind{
		backend.KindContainer, backend.KindNetwork, backend.KindVolume, backend.KindImage,
	}
	for _, k := range kinds {
		snap.byKind[k] = map[string]bool{}
	}
	for _, bin := range engineBins() {
		inv := backend.NewInventory(bin)
		snap.invs = append(snap.invs, inv)
		for _, k := range kinds {
			for _, name := range inv.Names(k) {
				snap.byKind[k][name] = true
			}
		}
		for name := range inv.Running() {
			snap.running[name] = true
		}
	}
	return snap
}

func (s *engineSnapshot) has(kind backend.ResourceKind, name string) bool {
	return s.byKind[kind][name]
}

// imageSize asks the first engine that admits to holding the image. The
// number is for a human deciding whether to reclaim it, so it is reported
// verbatim rather than parsed.
func (s *engineSnapshot) imageSize(ref string) string {
	for _, inv := range s.invs {
		if size := inv.ImageSize(ref); size != "" {
			return size
		}
	}
	return ""
}

// engineArtifact resolves one expected engine resource against the snapshot.
func (s *engineSnapshot) engineArtifact(kind backend.ResourceKind, name, detail string) Artifact {
	a := Artifact{Kind: string(kind), Name: name, Status: artMissing, Detail: detail}
	switch {
	case kind == backend.KindContainer && s.running[name]:
		a.Status = artRunning
	case s.has(kind, name):
		a.Status = artPresent
	}
	return a
}

// hostArtifact resolves one expected host-side path.
func hostArtifact(kind, path, detail string) Artifact {
	a := Artifact{Kind: kind, Name: path, Status: artMissing, Detail: detail}
	if _, err := os.Stat(path); err == nil {
		a.Status = artPresent
	}
	return a
}

// frozenPolicyMode reports the egress mode the box was *created* under,
// read from the spec.json frozen at creation.
//
// Current configuration is the wrong source here: a project that has since
// switched to network.mode = "proxy" has not thereby grown a sidecar in a box
// created before the change, and reporting one as MISSING would turn ordinary
// drift — which `status` already reports on its own line — into an alarm.
func (c *Ctx) frozenPolicyMode(cl *claim) (mode, detail string) {
	blob, err := os.ReadFile(filepath.Join(c.Store.BoxDir(cl.Key, cl.Instance), "spec.json"))
	if err == nil {
		var spec backend.BoxSpec
		if json.Unmarshal(blob, &spec) == nil && spec.Policy != nil {
			return spec.Policy.Mode, ""
		}
	}
	return c.Cfg.Config.Network.Mode, "assumed from current configuration: this box has no readable spec.json"
}

// boxArtifacts lists everything agentbox holds for one box: the artifacts it
// expects, each resolved against what is actually there, followed by anything
// the engines hold under this box's name that it does not expect.
//
// It contacts engines and reads state. It creates and starts nothing — this
// is an inspection path, and answering "what is this holding?" must never be
// the thing that brings a box up.
func (c *Ctx) boxArtifacts(snap *engineSnapshot, cl *claim) []Artifact {
	res := cl.Resource
	meta := cl.Meta
	polMode, polDetail := c.frozenPolicyMode(cl)

	var arts []Artifact
	add := func(a Artifact) { arts = append(arts, a) }

	add(snap.engineArtifact(backend.KindContainer, res, "the box itself"))
	add(snap.engineArtifact(backend.KindNetwork, res+"-int", "internal network (no gateway)"))
	add(snap.engineArtifact(backend.KindVolume, res+"-home", "persistent guest home; survives `down`"))

	// The sidecar topology is container-tier only: under the vm tier the
	// proxy is a host daemon listener, which is a state-root file, not an
	// engine resource.
	if meta.Tier == string(backend.TierContainer) && polMode == netpol.ModeProxy {
		add(snap.engineArtifact(backend.KindNetwork, res+"-egress", "egress network; only the proxy is on it"))
		add(snap.engineArtifact(backend.KindContainer, res+"-proxy", "egress policy proxy"+withDetail(polDetail)))
	}

	if meta.ImageRef != "" {
		img := snap.engineArtifact(backend.KindImage, meta.ImageRef, "toolchain image")
		if size := snap.imageSize(meta.ImageRef); size != "" {
			img.Detail = size + ", " + img.Detail
		}
		add(img)
	}

	if meta.Tier == string(backend.TierVM) {
		add(hostArtifact("view", backend.ViewRoot(c.Store.Root, res), "host-side mask view ("+meta.MaskMode+" mode)"))
		if polMode == netpol.ModeProxy {
			add(c.listenerArtifact(res, polDetail))
		}
	}

	if meta.TreeMode != tree.ModeShared {
		kind := "tree"
		detail := meta.TreeMode + " of the workspace"
		if meta.TreeMode == tree.ModeWorktree {
			kind = "worktree"
			detail = "git worktree"
			if meta.Branch != "" {
				detail += " on branch " + meta.Branch
			}
		}
		add(hostArtifact(kind, meta.TreeRoot, detail))
	}
	add(hostArtifact("state", c.Store.BoxDir(cl.Key, cl.Instance), "box metadata and generated artifacts"))

	// Anything else the engines hold under this box's name. This is where a
	// sidecar left behind by a config change surfaces: it is claimed, so
	// prune will never touch it, and nothing expects it, so without this it
	// would be invisible from both ends.
	expected := map[string]bool{}
	for _, a := range arts {
		expected[a.Name] = true
	}
	claims := map[string]*claim{res: cl}
	var extra []Artifact
	for _, kind := range []backend.ResourceKind{backend.KindContainer, backend.KindNetwork, backend.KindVolume} {
		for name := range snap.byKind[kind] {
			if expected[name] || ownerOf(claims, name) == nil {
				continue
			}
			a := snap.engineArtifact(kind, name, "claimed by this box, but not part of what it was created with")
			a.Status = artUnexpected
			extra = append(extra, a)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].Name < extra[j].Name })
	return append(arts, extra...)
}

// listenerArtifact resolves the vm tier's host proxy listener, declared as a
// spec file in the proxyd spool.
func (c *Ctx) listenerArtifact(resource, polDetail string) Artifact {
	a := Artifact{
		Kind: "listener", Status: artMissing,
		Name:   filepath.Join(netpol.SpoolDir(c.Store.Root), resource+".json"),
		Detail: "host proxy listener" + withDetail(polDetail),
	}
	ls, err := netpol.ReadListenerSpec(c.Store.Root, resource)
	if err != nil {
		return a
	}
	a.Status = artPresent
	where := ls.Addr
	if ls.Token != "" {
		where = fmt.Sprintf("vsock:%d", netpol.VsockPort)
	}
	a.Detail = fmt.Sprintf("host proxy listener on %s, %d allow / %d deny", where, len(ls.Allow), len(ls.Deny))
	return a
}

// unclaimedArtifacts is the same join with the predicate negated: what the
// engines and the state root hold that no box in agentbox state names. It is
// what makes the view total — every artifact is either under a box above or
// in this list — and it is always computed across every project, because
// "unclaimed" is only true when no project claims it.
func (c *Ctx) unclaimedArtifacts(snap *engineSnapshot, s *scan) []Artifact {
	var arts []Artifact
	for _, kind := range []backend.ResourceKind{backend.KindContainer, backend.KindNetwork, backend.KindVolume} {
		for name := range snap.byKind[kind] {
			if ownerOf(s.Claims, name) != nil {
				continue
			}
			arts = append(arts, snap.engineArtifact(kind, name, "no box in agentbox state claims it"))
		}
	}
	if ents, err := os.ReadDir(backend.ViewsDir(c.Store.Root)); err == nil {
		for _, e := range ents {
			if !e.IsDir() || ownerOf(s.Claims, e.Name()) != nil {
				continue
			}
			arts = append(arts, Artifact{
				Kind: "view", Name: e.Name(), Status: artPresent,
				Detail: "mask view with no box to serve",
			})
		}
	}
	sort.Slice(arts, func(i, j int) bool {
		if arts[i].Kind != arts[j].Kind {
			return arts[i].Kind < arts[j].Kind
		}
		return arts[i].Name < arts[j].Name
	})
	return arts
}

// boxState reports a box's runtime state in the vocabulary `status` uses. A
// backend that is unavailable here is said so rather than reported as
// stopped: "not running" and "I cannot see it from this host" are different
// answers, and only one of them means the box is idle.
func (c *Ctx) boxState(cl *claim) string {
	be, err := c.activeBackend(cl.Meta)
	if err != nil {
		return "backend-unavailable"
	}
	st, err := be.Inspect(cl.Resource)
	if err != nil {
		return "not-created"
	}
	if st.Running {
		return "running"
	}
	return "stopped"
}

// printArtifacts writes an indented artifact block, in the same
// kind/name/why shape prune's report uses. Names are padded to a width that
// fits engine resource names; host paths overrun it rather than being
// truncated, since a path you cannot copy is not much of a report.
func printArtifacts(arts []Artifact, indent string) {
	for _, a := range arts {
		line := fmt.Sprintf("%s%-9s %-10s %-46s %s", indent, a.Kind, a.Status, a.Name, a.Detail)
		fmt.Println(strings.TrimRight(line, " "))
	}
}

func withDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return " (" + detail + ")"
}
