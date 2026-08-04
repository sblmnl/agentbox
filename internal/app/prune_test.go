package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sblmnl/agentbox/internal/backend"
)

// noEngines runs the candidate logic without touching a real engine.
func noEngines(t *testing.T) {
	t.Helper()
	prev := engineBins
	engineBins = func() []string { return nil }
	t.Cleanup(func() { engineBins = prev })
}

// ownerOf decides whether an engine resource still belongs to a box, so a
// mistake here deletes a running box's network or home volume. The exact
// name must be tried before the derived one: an instance whose name ends in
// a derived suffix would otherwise be stripped down to a different box.
func TestPruneClaimedBy(t *testing.T) {
	live := map[string]*claim{
		"agentbox-proj-abc-quiet-fern": {Instance: "quiet-fern"},
		"agentbox-proj-abc-odd-int":    {Instance: "odd-int"}, // instance literally named "odd-int"
	}
	claimed := []string{
		"agentbox-proj-abc-quiet-fern",        // the box container
		"agentbox-proj-abc-quiet-fern-int",    // its network
		"agentbox-proj-abc-quiet-fern-egress", // its egress network
		"agentbox-proj-abc-quiet-fern-home",   // its home volume
		"agentbox-proj-abc-quiet-fern-proxy",  // its sidecar
		"agentbox-proj-abc-odd-int",           // exact match wins over stripping
		"agentbox-proj-abc-odd-int-home",      // and its derived volume
	}
	for _, name := range claimed {
		if ownerOf(live, name) == nil {
			t.Errorf("%q belongs to a live box but would be pruned", name)
		}
	}
	orphans := []string{
		"agentbox-proj-abc-gone-box",
		"agentbox-proj-abc-gone-box-int",
		"agentbox-proj-abc-gone-box-home",
		"agentbox-other-xyz-quiet-fern", // same instance, different project
	}
	for _, name := range orphans {
		if cl := ownerOf(live, name); cl != nil {
			t.Errorf("%q belongs to no live box but would be kept (matched %s)", name, cl.Instance)
		}
	}
}

// Reporting must not remove: the default invocation is a question, and a
// user asking what is reclaimable has not agreed to lose any of it.
func TestPruneReportsWithoutRemoving(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("keeper"); err != nil {
		t.Fatal(err)
	}
	// A project whose workspace no longer exists is the classic candidate.
	gone := filepath.Join(t.TempDir(), "vanished")
	if err := os.MkdirAll(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	pm.WorkspaceRealpath = gone
	if err := c.Store.SaveProject(c.Key, pm); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	items, _, err := c.pruneCandidates(PruneOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Kind != "project" {
		t.Fatalf("vanished workspace should be the one candidate, got %+v", items)
	}
	// Report only: the project must survive.
	if err := c.CmdPrune(PruneOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store.LoadProject(c.Key); err != nil {
		t.Fatalf("prune without --apply must not remove anything: %v", err)
	}
	// With --apply it goes.
	if err := c.CmdPrune(PruneOptions{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store.LoadProject(c.Key); err == nil {
		t.Fatal("prune --apply should have reclaimed the orphaned project")
	}
}

// A live project is never a candidate, whatever else is lying around.
func TestPruneKeepsLiveProject(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("keeper"); err != nil {
		t.Fatal(err)
	}
	items, _, err := c.pruneCandidates(PruneOptions{Images: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if strings.Contains(it.Name, c.Key) {
			t.Fatalf("live project artifact listed as reclaimable: %+v", it)
		}
	}
}

// --running and --state only mean something against a set of boxes. Taking
// them alone and doing nothing would report success for a teardown that never
// happened, so they are refused outright.
func TestPruneTeardownFlagsRequireBoxes(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []PruneOptions{{Running: true}, {State: true}, {Running: true, Apply: true}} {
		err := c.CmdPrune(o)
		ee, ok := err.(*ExitError)
		if !ok || ee.Code != ExUsage {
			t.Errorf("%+v: got %v, want a usage error (exit %d)", o, err, ExUsage)
		}
	}
}

// The report is still the default. --boxes widens what prune considers; it
// does not make prune act.
func TestPruneBoxesReportsWithoutRemoving(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	opts.BoxLiveness = func(string) (bool, string) { return false, "stopped" }
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("keeper"); err != nil {
		t.Fatal(err)
	}
	items, _, err := c.pruneCandidates(PruneOptions{Boxes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Kind != "box" {
		t.Fatalf("the stopped box should be the one candidate, got %+v", items)
	}
	if err := c.CmdPrune(PruneOptions{Boxes: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store.LoadBox(c.Key, "keeper"); err != nil {
		t.Fatalf("prune --boxes without --apply must not remove anything: %v", err)
	}
}

// A running box is not swept up by --boxes, and the fact that it was left
// alone is reported rather than dropped: "removed everything except these" is
// the only honest summary of a partial teardown.
func TestPruneBoxesSkipsRunningUnlessAsked(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	opts.BoxLiveness = func(string) (bool, string) { return true, "RUNNING" }
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("busy"); err != nil {
		t.Fatal(err)
	}

	items, skipped, err := c.pruneCandidates(PruneOptions{Boxes: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Kind == "box" {
			t.Errorf("a running box must not be a candidate under --boxes alone: %+v", it)
		}
	}
	if len(skipped) != 1 {
		t.Fatalf("the skipped box must be reported, got %v", skipped)
	}

	items, skipped, err = c.pruneCandidates(PruneOptions{Boxes: true, Running: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Errorf("--running includes running boxes; nothing should be skipped, got %v", skipped)
	}
	if len(items) != 1 || items[0].Kind != "box" {
		t.Fatalf("--boxes --running must offer the running box, got %+v", items)
	}
}

// A box whose backend is unavailable here cannot be inspected, and an
// unanswerable box is left alone: for a destructive default, "I could not
// tell" has to fall on the side of not touching it.
func TestPruneBoxesLeavesUninspectableBoxes(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("stranded"); err != nil {
		t.Fatal(err)
	}
	// Same state root, but the backend the box records is now unavailable.
	opts.Availabilties = []backend.Availability{
		{Name: "container", Tier: backend.TierContainer, Available: false, Reason: "daemon not reachable"},
		{Name: "vm", Tier: backend.TierVM, Available: true, Runtime: "docker/kata"},
	}
	c, err = Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	items, skipped, err := c.pruneCandidates(PruneOptions{Boxes: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Kind == "box" {
			t.Errorf("a box whose state cannot be established must not be removed: %+v", it)
		}
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "unknown") {
		t.Errorf("the reason must say the state could not be established, got %v", skipped)
	}
}

// One box, one disposition: --boxes removes it, so it is not also listed as
// something to stop.
func TestPruneBoxesSupersedesIdle(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[box]\nidle_timeout = \"1s\"\n",
	}, containerOnly())
	opts.BoxLiveness = func(string) (bool, string) { return false, "stopped" }
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox("old")
	if err != nil {
		t.Fatal(err)
	}
	meta.CreatedAt = time.Now().Add(-time.Hour)
	meta.LastExecAt = time.Now().Add(-time.Hour)
	if err := c.Store.SaveBox(meta); err != nil {
		t.Fatal(err)
	}
	items, _, err := c.pruneCandidates(PruneOptions{Boxes: true, Idle: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Kind != "box" {
		t.Fatalf("a box being removed must not also be listed as idle, got %+v", items)
	}
}

// The two things a bulk teardown must never destroy: the branch holding
// unreviewed agent work, and the user's own workspace.
func TestPruneBoxesPreservesBranchesAndWorkspace(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	noEngines(t)
	opts, ws := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n",
		"main.go":       "package main\n",
	}, containerOnly())
	opts.BoxLiveness = func(string) (bool, string) { return false, "stopped" }
	gitDo(t, ws, "init", "-q")
	gitDo(t, ws, "add", ".")
	gitDo(t, ws, "commit", "-qm", "init")

	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := c.createBox("primary") // auto -> shared: the workspace itself
	if err != nil {
		t.Fatal(err)
	}
	wt, err := c.createBox("exp") // auto -> worktree on its own branch
	if err != nil {
		t.Fatal(err)
	}
	if wt.Branch == "" {
		t.Fatal("expected a worktree box with a branch")
	}

	if err := c.CmdPrune(PruneOptions{Boxes: true, Apply: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gitDo(t, ws, "branch", "--list", wt.Branch), wt.Branch) {
		t.Error("prune must never delete a branch: unreviewed agent work is the one thing a bulk teardown cannot be allowed to destroy")
	}
	if _, err := os.Stat(filepath.Join(ws, "main.go")); err != nil {
		t.Errorf("the workspace of a shared-tree box must survive its box: %v", err)
	}
	if _, err := os.Stat(wt.TreeRoot); !os.IsNotExist(err) {
		t.Error("the worktree goes with the box")
	}
	for _, inst := range []string{shared.Instance, wt.Instance} {
		if _, err := c.Store.LoadBox(c.Key, inst); err == nil {
			t.Errorf("box %s should be gone from agentbox state", inst)
		}
	}
}

// --state is what escalates from "the box" to "the box and everything it
// remembers", and the report has to say which of the two is on offer.
func TestPruneBoxesStateIsExplicit(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	opts.BoxLiveness = func(string) (bool, string) { return false, "stopped" }
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	without, _, err := c.pruneCandidates(PruneOptions{Boxes: true})
	if err != nil {
		t.Fatal(err)
	}
	with, _, err := c.pruneCandidates(PruneOptions{Boxes: true, State: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(without[0].Reason, "persistent home survives") {
		t.Errorf("--boxes alone keeps the persistent home and must say so: %q", without[0].Reason)
	}
	if !strings.Contains(with[0].Reason, "and its persistent home") {
		t.Errorf("--state also takes the persistent home and must say so: %q", with[0].Reason)
	}
}

// A mask view whose box is gone is reclaimable; one still claimed is not.
func TestPruneStaleViews(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	viewRoot := filepath.Join(c.Store.Root, "views")
	for _, name := range []string{"agentbox-proj-abc-live", "agentbox-proj-abc-dead"} {
		if err := os.MkdirAll(filepath.Join(viewRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	items := c.staleViews(&scan{Claims: map[string]*claim{
		"agentbox-proj-abc-live": {Instance: "live"},
	}})
	if len(items) != 1 || items[0].Name != "agentbox-proj-abc-dead" {
		t.Fatalf("only the unclaimed view is reclaimable, got %+v", items)
	}
	if err := items[0].remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(viewRoot, "agentbox-proj-abc-dead")); !os.IsNotExist(err) {
		t.Fatal("stale view was not removed")
	}
	if _, err := os.Stat(filepath.Join(viewRoot, "agentbox-proj-abc-live")); err != nil {
		t.Fatalf("claimed view must survive: %v", err)
	}
}
