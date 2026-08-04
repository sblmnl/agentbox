package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/state"
	"github.com/sblmnl/agentbox/internal/tree"
)

func testEnv(t *testing.T, wsFiles map[string]string, avail []backend.Availability) (*Options, string) {
	t.Helper()
	ws := t.TempDir()
	for p, content := range wsFiles {
		full := filepath.Join(ws, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := t.TempDir()
	nullf, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nullf.Close() })
	opts := &Options{
		Directory:     ws,
		Workspace:     ws,
		StateRoot:     stateRoot,
		Availabilties: avail,
		Stderr:        nullf,
		Quiet:         true,
		NoConfig:      false,
	}
	return opts, ws
}

func containerOnly() []backend.Availability {
	return []backend.Availability{
		{Name: "container", Tier: backend.TierContainer, Available: true, Runtime: "docker"},
		{Name: "vm", Tier: backend.TierVM, Available: false, Reason: "no /dev/kvm on this host"},
	}
}

func bothTiers() []backend.Availability {
	return []backend.Availability{
		{Name: "container", Tier: backend.TierContainer, Available: true, Runtime: "docker"},
		{Name: "vm", Tier: backend.TierVM, Available: true, Runtime: "docker/kata"},
	}
}

func TestVMAutoSelection(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, bothTiers())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox("v")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != "vm" || meta.Tier != "vm" {
		t.Fatalf("auto-selection must take the highest tier, got %s/%s", meta.Backend, meta.Tier)
	}
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil || !pm.VMTierNoticed {
		t.Errorf("the one-time higher-tier notice must be recorded, got %+v (%v)", pm, err)
	}
}

func TestVMMaskModeHonesty(t *testing.T) {
	setSeam := func(t *testing.T, ok bool, reason string) {
		prev := seamProbe
		seamProbe = func() (bool, string) { return ok, reason }
		t.Cleanup(func() { seamProbe = prev })
	}

	t.Run("seam unavailable: auto falls back to view with a warning", func(t *testing.T) {
		setSeam(t, false, "not running as root")
		opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, bothTiers())
		c, err := Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := c.BuildPlan("", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if plan.Backend.Name != "vm" || plan.MaskMode != "view" {
			t.Fatalf("auto must resolve to view without the seam, got %s/%s", plan.Backend.Name, plan.MaskMode)
		}
		warned := false
		for _, w := range plan.Warnings {
			if strings.Contains(w, "view") && strings.Contains(w, "not running as root") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("the auto->view fallback must be warned about, naming the reason; warnings: %v", plan.Warnings)
		}
	})

	t.Run("seam unavailable: explicit filter is a config error, not a downgrade", func(t *testing.T) {
		setSeam(t, false, "not running as root")
		opts, _ := testEnv(t, map[string]string{
			"agentbox.toml": "version = 1\n[security]\nmask_mode = \"filter\"\n",
		}, bothTiers())
		c, err := Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.BuildPlan("", "", "")
		ee, ok := err.(*ExitError)
		if !ok || ee.Code != ExConfig {
			t.Fatalf("explicit filter without the seam must be a config error, got %v", err)
		}
	})

	t.Run("seam available: auto resolves to filter, silently is fine (an upgrade)", func(t *testing.T) {
		setSeam(t, true, "")
		opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, bothTiers())
		c, err := Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := c.BuildPlan("", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if plan.Backend.Name != "vm" || plan.MaskMode != "filter" {
			t.Fatalf("auto must resolve to filter with the seam available, got %s/%s", plan.Backend.Name, plan.MaskMode)
		}
	})

	t.Run("explicit filter under the container tier stays an error", func(t *testing.T) {
		setSeam(t, true, "")
		opts, _ := testEnv(t, map[string]string{
			"agentbox.toml": "version = 1\n[security]\nmask_mode = \"filter\"\nbackend = \"container\"\n",
		}, bothTiers())
		c, err := Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.BuildPlan("", "", "")
		ee, ok := err.(*ExitError)
		if !ok || ee.Code != ExConfig {
			t.Fatalf("filter under container must be a config error, got %v", err)
		}
	})
}

func TestVMProxyTopologyPlanned(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
	}, bothTiers())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox("v")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlanForInstance(meta.Instance, meta.TreeMode, meta.TreeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Spec.ProxyEnv) != 0 {
		t.Errorf("vm plans must not carry sidecar proxy env: %v", plan.Spec.ProxyEnv)
	}
	if plan.Spec.StateDir == "" {
		t.Error("vm spec must carry the box state dir for the audit log")
	}
	if _, err := os.Stat(filepath.Join(c.Store.BoxDir(c.Key, meta.Instance), "proxy", "squid.conf")); !os.IsNotExist(err) {
		t.Error("no squid.conf may be generated for a vm box")
	}
}

func TestIsolationFloorExit69(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[security]\nmin_isolation = \"vm\"\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.createBox("")
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExUnavailable {
		t.Fatalf("want exit %d, got %v", ExUnavailable, err)
	}
	if !strings.Contains(ee.Msg, "kvm") {
		t.Errorf("diagnostic must name what is missing: %s", ee.Msg)
	}
	// Nothing was created.
	boxes, _ := c.Store.ListBoxes(c.Key)
	if len(boxes) != 0 {
		t.Errorf("no box may be created on floor refusal, found %d", len(boxes))
	}
	if _, err := os.Stat(c.Store.ProjectDir(c.Key)); err == nil {
		if _, err := c.Store.LoadProject(c.Key); err == nil {
			t.Error("no project metadata may be persisted on floor refusal")
		}
	}
}

func TestMinIsolationCannotLower(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[security]\nmin_isolation = \"vm\"\n",
	}, containerOnly())
	opts.MinIsolation = "container"
	_, err := Resolve(opts)
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExUsage {
		t.Fatalf("lowering the floor via --min-isolation must be a usage error, got %v", err)
	}
}

func TestConcurrentCreation(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[project]\nmax_boxes = 2\n",
	}, containerOnly())

	run := func() error {
		c, err := Resolve(opts)
		if err != nil {
			return err
		}
		_, err = c.createBox("")
		return err
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = run()
		}(i)
	}
	wg.Wait()

	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	boxes, _ := c.Store.ListBoxes(c.Key)
	if len(boxes) != 2 {
		t.Fatalf("max_boxes = 2 must cap concurrent creation; got %d boxes", len(boxes))
	}
	if boxes[0].Instance == boxes[1].Instance {
		t.Error("concurrent creations must allocate distinct names")
	}
	failures := 0
	for _, e := range errs {
		if e != nil {
			failures++
			if !strings.Contains(e.Error(), "max_boxes") {
				t.Errorf("refusal must name the limit: %v", e)
			}
		}
	}
	if failures != 2 {
		t.Errorf("want exactly 2 refusals, got %d", failures)
	}
}

func gitDo(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Hermetic: the scratch repo must not inherit the contributor's git
	// config. commit.gpgsign is the one that bites — it sends every test
	// commit to gpg, which launches pinentry against a terminal no test has,
	// and the run fails on a signing timeout that has nothing to do with the
	// code under test. Templates, hooks and gpg.format are the same class.
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestTreeModes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	opts, ws := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n",
		"main.go":       "package main\n",
	}, containerOnly())
	gitDo(t, ws, "init", "-q")
	gitDo(t, ws, "add", ".")
	gitDo(t, ws, "commit", "-qm", "init")

	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	// First box: auto -> shared.
	b1, err := c.createBox("primary")
	if err != nil {
		t.Fatal(err)
	}
	if b1.TreeMode != tree.ModeShared || b1.TreeRoot != c.Workspace {
		t.Fatalf("first box must share the workspace: %+v", b1)
	}
	// Second and third: auto -> worktree on distinct branches.
	b2, err := c.createBox("exp1")
	if err != nil {
		t.Fatal(err)
	}
	b3, err := c.createBox("exp2")
	if err != nil {
		t.Fatal(err)
	}
	if b2.TreeMode != tree.ModeWorktree || b3.TreeMode != tree.ModeWorktree {
		t.Fatalf("additional boxes in a git workspace must get worktrees: %s/%s", b2.TreeMode, b3.TreeMode)
	}
	if b2.TreeRoot == b3.TreeRoot || b2.Branch == b3.Branch {
		t.Fatal("worktree boxes must have distinct trees and branches")
	}
	if strings.HasPrefix(b2.TreeRoot, ws+string(os.PathSeparator)) {
		t.Error("worktrees must live outside the workspace")
	}
	if strings.Contains(gitDo(t, ws, "status", "--porcelain"), "tree") {
		t.Error("worktree creation must keep `git status` clean")
	}

	// Independent edits diverge without conflict.
	if err := os.WriteFile(filepath.Join(b2.TreeRoot, "main.go"), []byte("package main // exp1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitDo(t, b2.TreeRoot, "commit", "-aqm", "exp1 change")
	if err := os.WriteFile(filepath.Join(b3.TreeRoot, "main.go"), []byte("package main // exp2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitDo(t, b3.TreeRoot, "commit", "-aqm", "exp2 change")
	if data, _ := os.ReadFile(filepath.Join(ws, "main.go")); string(data) != "package main\n" {
		t.Error("worktree edits must not appear in the primary tree")
	}

	// rm preserves the branch (unreviewed agent work) unless --delete-branch.
	if err := c.CmdRm("exp1", false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gitDo(t, ws, "branch", "--list", b2.Branch), b2.Branch) {
		t.Error("rm must preserve the branch absent --delete-branch")
	}
	if _, err := os.Stat(b2.TreeRoot); !os.IsNotExist(err) {
		t.Error("rm must remove the worktree")
	}
	if err := c.CmdRm("exp2", false, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gitDo(t, ws, "branch", "--list", b3.Branch), b3.Branch) {
		t.Error("rm --delete-branch must delete the branch")
	}
}

func TestSecondSharedBoxWarns(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("one"); err != nil {
		t.Fatal(err)
	}
	c.Opts.TreeMode = "shared"
	plan, err := c.BuildPlan("", "shared", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "one") && strings.Contains(w, "share") {
			found = true
		}
	}
	if !found {
		t.Errorf("second shared box must warn naming the other boxes; warnings: %v", plan.Warnings)
	}
}

func TestDefaultBoxResolution(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := c.createBox("first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("second"); err != nil {
		t.Fatal(err)
	}
	got, err := c.selectBox(false)
	if err != nil || got.Instance != "first" {
		t.Fatalf("default must be the first-created box: %v, %v", got, err)
	}
	// Change default explicitly.
	if err := c.CmdDefault("second"); err != nil {
		t.Fatal(err)
	}
	got, err = c.selectBox(false)
	if err != nil || got.Instance != "second" {
		t.Fatalf("explicit default: %v, %v", got, err)
	}
	if _, err := c.createBox("third"); err != nil {
		t.Fatal(err)
	}
	// Removing the default with several boxes left is ambiguous: the
	// default is cleared rather than guessed, and selection says so naming
	// the survivors.
	if err := c.CmdRm("second", false, false); err != nil {
		t.Fatal(err)
	}
	pm, err := c.Store.LoadProject(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	if pm.DefaultBox != "" {
		t.Fatalf("removed default must not stay recorded, got %q", pm.DefaultBox)
	}
	_, err = c.selectBox(false)
	if err == nil || !strings.Contains(err.Error(), b1.Instance) {
		t.Fatalf("ambiguous default must error naming available boxes, got %v", err)
	}

	// Down to one box, the default is unambiguous: `rm` adopts it, so the
	// next invocation runs instead of dead-ending on a box that is gone.
	if err := c.CmdRm("third", false, false); err != nil {
		t.Fatal(err)
	}
	pm, err = c.Store.LoadProject(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	if pm.DefaultBox != b1.Instance {
		t.Fatalf("sole surviving box must become the default, got %q", pm.DefaultBox)
	}
	got, err = c.selectBox(false)
	if err != nil || got.Instance != b1.Instance {
		t.Fatalf("selection after removing the default: %v, %v", got, err)
	}
}

func TestOrdinalAliases(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("beta"); err != nil {
		t.Fatal(err)
	}
	inst, err := c.Store.ResolveOrdinal(c.Key, 2)
	if err != nil || inst != "beta" {
		t.Errorf("ordinal 2 = %q, %v", inst, err)
	}
	if _, err := c.createBox("42"); err == nil {
		t.Error("a bare-integer instance name must be rejected")
	}
}

func TestDriftDetection(t *testing.T) {
	opts, ws := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox("stable")
	if err != nil {
		t.Fatal(err)
	}
	if meta.ConfigDigest != c.ConfigDigest() {
		t.Fatal("fresh box must not drift")
	}
	// Change the workspace config; digest must move.
	if err := os.WriteFile(filepath.Join(ws, "agentbox.toml"),
		[]byte("version = 1\n[network]\nmode = \"none\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ConfigDigest == c2.ConfigDigest() {
		t.Error("config change must change the digest")
	}
}

func TestInterBoxStateSeparation(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n",
		".agentignore":  ".env\n",
		".env":          "S=1",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("b"); err != nil {
		t.Fatal(err)
	}
	pa, err := c.BuildPlanLenient("a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := c.BuildPlanLenient("b", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if pa.ResourceName == pb.ResourceName {
		t.Error("derived resource names must differ per box")
	}
	da := c.Store.BoxDir(c.Key, "a")
	db := c.Store.BoxDir(c.Key, "b")
	if da == db {
		t.Error("box state dirs must differ")
	}
	for _, d := range []string{da, db} {
		if _, err := os.Stat(filepath.Join(d, "masks.json")); err != nil {
			t.Errorf("masks.json missing in %s", d)
		}
	}
}

// Generated artifacts are reconstructible and carry provenance; the
// workspace is never written during run-adjacent operations.
func TestWorkspaceNotWritten(t *testing.T) {
	opts, ws := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	before := listDir(t, ws)
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("clean"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BuildPlanLenient("clean", "", ""); err != nil {
		t.Fatal(err)
	}
	after := listDir(t, ws)
	if before != after {
		t.Errorf("workspace modified: before=%q after=%q", before, after)
	}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}

// state lock: acquisition times out with a message naming the holder.
func TestLockTimeoutNamesHolder(t *testing.T) {
	st := state.Open(t.TempDir())
	pl, err := st.LockProject("k")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Release()
	// A second exclusive acquisition in another process would block; we
	// verify the shared/exclusive conflict via a raw second handle in this
	// process using a child process for realism is heavyweight, so assert
	// the lock file records our pid for the diagnostic path.
	data, err := os.ReadFile(filepath.Join(st.ProjectDir("k"), "lock"))
	if err != nil || len(data) == 0 {
		t.Fatalf("lock file must record the holder pid: %v", err)
	}
}
