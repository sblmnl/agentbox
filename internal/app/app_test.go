package app

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/state"
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
	}
	return opts, ws
}

// captureStderr redirects a test context's diagnostics to a file and returns
// a reader for whatever landed there.
func captureStderr(t *testing.T, opts *Options) func() string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	opts.Stderr = f
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// seedBox writes box metadata directly, so a command takes the "box already
// exists" path without an engine anywhere in reach.
func seedBox(t *testing.T, c *Ctx) {
	t.Helper()
	if err := c.Store.SaveBox(&state.BoxMeta{
		Key:               c.Key,
		WorkspaceRealpath: c.Workspace,
		Slug:              c.Slug,
		Backend:           "container",
		Tier:              "container",
	}); err != nil {
		t.Fatal(err)
	}
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

// noBackends is a host where neither tier can be used -- the engine was
// stopped after the box was created.
func noBackends() []backend.Availability {
	return []backend.Availability{
		{Name: "container", Tier: backend.TierContainer, Available: false, Reason: "docker daemon is not running"},
		{Name: "vm", Tier: backend.TierVM, Available: false, Reason: "no /dev/kvm on this host"},
	}
}

func TestVMAutoSelection(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, bothTiers())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox()
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != "vm" || meta.Tier != "vm" {
		t.Fatalf("auto-selection must take the highest tier, got %s/%s", meta.Backend, meta.Tier)
	}
	if !meta.VMTierNoticed {
		t.Error("the one-time higher-tier notice must be recorded")
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
		plan, err := c.BuildPlan()
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
		_, err = c.BuildPlan()
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
		plan, err := c.BuildPlan()
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
		_, err = c.BuildPlan()
		ee, ok := err.(*ExitError)
		if !ok || ee.Code != ExConfig {
			t.Fatalf("filter under container must be a config error, got %v", err)
		}
	})
}

// Both tiers run the same squid sidecar against the same generated
// configuration. The vm tier used to reach a host daemon over vsock instead;
// what makes the sidecar workable is that a Kata guest can reach a sibling
// container by IP, which it can, so the two tiers no longer differ here.
func TestProxyTopologyIsSharedAcrossTiers(t *testing.T) {
	for _, avail := range []struct {
		name  string
		avail []backend.Availability
	}{
		{"container", containerOnly()},
		{"vm", bothTiers()},
	} {
		t.Run(avail.name, func(t *testing.T) {
			opts, _ := testEnv(t, map[string]string{
				"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
			}, avail.avail)
			c, err := Resolve(opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.createBox(); err != nil {
				t.Fatal(err)
			}
			// Every proxy-mode box gets a generated squid.conf, whatever the tier.
			conf := filepath.Join(c.Store.BoxDir(c.Key), "proxy", "squid.conf")
			blob, err := os.ReadFile(conf)
			if err != nil {
				t.Fatalf("proxy mode must generate a squid.conf: %v", err)
			}
			if !strings.Contains(string(blob), "http_access deny all") {
				t.Error("generated squid config must end in a terminal deny")
			}
		})
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
	_, err = c.createBox()
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExUnavailable {
		t.Fatalf("want exit %d, got %v", ExUnavailable, err)
	}
	if !strings.Contains(ee.Msg, "kvm") {
		t.Errorf("diagnostic must name what is missing: %s", ee.Msg)
	}
	// Nothing was created.
	if c.Store.BoxExists(c.Key) {
		t.Error("no box may be recorded on floor refusal")
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

// --force-isolation is the only way below the floor, and it must be recorded
// on the box so every later invocation can warn about it.
func TestForceIsolationIsRecorded(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[security]\nmin_isolation = \"vm\"\n",
	}, containerOnly())
	opts.ForceIsolation = "container"
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox()
	if err != nil {
		t.Fatal(err)
	}
	if meta.ForceIsolation != "container" {
		t.Errorf("force_isolation must be frozen into box metadata, got %q", meta.ForceIsolation)
	}
	if meta.Tier != "container" {
		t.Errorf("forced tier not applied, got %q", meta.Tier)
	}
}

// Two invocations racing to create the workspace's box must converge on one
// box, not two half-built ones.
func TestConcurrentCreation(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := Resolve(opts)
			if err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = c.createBox()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("creation %d failed: %v", i, err)
		}
	}
	st := state.Open(opts.StateRoot)
	boxes, err := st.ListBoxes()
	if err != nil {
		t.Fatal(err)
	}
	if len(boxes) != 1 {
		t.Errorf("concurrent creation produced %d boxes, want exactly 1", len(boxes))
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
	meta, err := c.createBox()
	if err != nil {
		t.Fatal(err)
	}
	if meta.ConfigDigest != c.ConfigDigest() {
		t.Fatal("fresh box must not drift")
	}
	// Change the workspace config; digest must move.
	if err := os.WriteFile(filepath.Join(ws, "agentbox.toml"),
		[]byte("version = 1\n[network]\nmode = \"off\"\n"), 0o644); err != nil {
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

// Two workspaces -- including a git worktree beside its main checkout, which
// is how a project gets a second box -- must never share a container name or
// a state directory.
func TestInterWorkspaceSeparation(t *testing.T) {
	files := map[string]string{
		"agentbox.toml": "version = 1\n",
		".agentignore":  ".env\n",
		".env":          "S=1",
	}
	optsA, _ := testEnv(t, files, containerOnly())
	optsB, _ := testEnv(t, files, containerOnly())
	// Share one state root, so a collision would actually collide.
	optsB.StateRoot = optsA.StateRoot

	ca, err := Resolve(optsA)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Resolve(optsB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.createBox(); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.createBox(); err != nil {
		t.Fatal(err)
	}
	pa, err := ca.BuildPlanLenient()
	if err != nil {
		t.Fatal(err)
	}
	pb, err := cb.BuildPlanLenient()
	if err != nil {
		t.Fatal(err)
	}
	if pa.ResourceName == pb.ResourceName {
		t.Error("derived resource names must differ per workspace")
	}
	if ca.Store.BoxDir(ca.Key) == cb.Store.BoxDir(cb.Key) {
		t.Error("box state dirs must differ per workspace")
	}
	for _, c := range []*Ctx{ca, cb} {
		if _, err := os.Stat(filepath.Join(c.Store.BoxDir(c.Key), "masks.json")); err != nil {
			t.Errorf("masks.json missing for %s", c.Key)
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
	if _, err := c.createBox(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BuildPlanLenient(); err != nil {
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

// The mask set must reflect the workspace the box actually mounts, and
// .agentignore matches must land in it. This is the plumbing that the whole
// masking story rests on, so it is asserted end to end at the plan level.
func TestMaskSetCoversIgnoredFiles(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml":   "version = 1\n",
		".agentignore":    ".env\nsecrets/\n",
		".env":            "TOKEN=1",
		"secrets/key.pem": "x",
		"src/main.go":     "package main",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	var masked []string
	for _, e := range plan.Masks.Entries {
		masked = append(masked, e.Path)
	}
	joined := strings.Join(masked, ",")
	if !strings.Contains(joined, ".env") {
		t.Errorf(".env must be masked, got %v", masked)
	}
	if !strings.Contains(joined, "secrets") {
		t.Errorf("secrets/ must be masked, got %v", masked)
	}
	if strings.Contains(joined, "main.go") {
		t.Errorf("ordinary source must not be masked, got %v", masked)
	}
}

// --no-mask empties the mask set, and must say so: it is the loudest
// weakening the tool offers.
func TestNoMaskIsEmptyAndWarns(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n",
		".agentignore":  ".env\n",
		".env":          "TOKEN=1",
	}, containerOnly())
	opts.NoMask = true
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Masks.Entries) != 0 {
		t.Errorf("--no-mask must empty the mask set, got %v", plan.Masks.Entries)
	}
	warned := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "no-mask") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("--no-mask must warn; warnings: %v", plan.Warnings)
	}
}

// state lock: the lock file records the holder pid for the timeout diagnostic.
func TestLockRecordsHolder(t *testing.T) {
	st := state.Open(t.TempDir())
	lock, err := st.LockBoxExclusive("k")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	data, err := os.ReadFile(filepath.Join(st.BoxDir("k"), "lock"))
	if err != nil || len(data) == 0 {
		t.Fatalf("lock file must record the holder pid: %v", err)
	}
}

// The most likely first-run mistake: a project that allows Claude's *egress*
// but never asked for the agent to be installed. The runtime answers "the file
// claude was not found" attached to a container id, which says nothing about
// either setting -- so agentbox has to.
func TestMissingAgentHintNamesTheInstallKey(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nbundles = [\"agent:claude-code\"]\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	hint := c.missingCommandHint([]string{"claude"}, "the file claude was not found")
	if hint == "" {
		t.Fatal("a missing agent binary must produce a hint")
	}
	for _, want := range []string{"[agents]", "claude-code", "--recreate", "bundles"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint should mention %q:\n%s", want, hint)
		}
	}
}

// When the agent *is* configured, the box's image simply predates the setting;
// telling the user to add a key they already have would be worse than useless.
func TestMissingAgentHintWhenAlreadyConfigured(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[agents]\ninstall = [\"claude-code\"]\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	hint := c.missingCommandHint([]string{"claude"}, "not found")
	if !strings.Contains(hint, "--rebuild") {
		t.Errorf("an already-configured agent should point at a rebuild:\n%s", hint)
	}
	if strings.Contains(hint, "[agents]\n    install") {
		t.Errorf("should not tell the user to add a key they already set:\n%s", hint)
	}
}

// An unrelated failure must not be dressed up as a missing binary.
func TestMissingCommandHintIgnoresUnrelatedErrors(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if hint := c.missingCommandHint([]string{"claude"}, "connection refused"); hint != "" {
		t.Errorf("unrelated engine errors must not produce a missing-binary hint: %s", hint)
	}
}

// A 126/127 with no engine error behind it came from a command that ran:
// `bash -c 'nosuchtool'`, or make propagating a recipe's exit code. Announcing
// that bash is missing from the box sends the user to rebuild an image over a
// typo in their own build.
func TestMissingCommandHintNeedsEngineEvidence(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if hint := c.missingCommandHint([]string{"bash"}, ""); hint != "" {
		t.Errorf("an in-box exit code is not evidence the binary is missing: %s", hint)
	}
}

// Egress opened for an agent that was never installed is a half-configured
// box, and it stays silent until the agent is actually run. The plan is where
// the diagnosis belongs, ahead of the symptom.
func TestAgentBundleWithoutInstallWarns(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nbundles = [\"agent:claude-code\", \"github\"]\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	found := ""
	for _, w := range plan.Warnings {
		if strings.Contains(w, "agents") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("expected a warning about the uninstalled agent; warnings: %v", plan.Warnings)
	}
	if !strings.Contains(found, "claude-code") {
		t.Errorf("warning must name the agent: %q", found)
	}
}

func TestAgentBundleWithInstallIsQuiet(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[agents]\ninstall = [\"claude-code\"]\n" +
			"[network]\nbundles = [\"agent:claude-code\", \"agent:claude-code:telemetry\"]\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(w, "agents") {
			t.Errorf("a correctly configured agent must not warn: %q", w)
		}
	}
}

// A pinned image or a user's own Dockerfile may already contain the agent.
// Nagging about a correct configuration is how warnings get ignored.
func TestAgentBundleWarningSuppressedForPinnedImage(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[image]\nref = \"ghcr.io/me/box:1\"\n" +
			"[network]\nbundles = [\"agent:claude-code\"]\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(w, "[agents].install") {
			t.Errorf("a pinned image may already carry the agent; must not warn: %q", w)
		}
	}
}

// What `init` writes must itself be a configuration that works: the scaffold
// commits to Claude in the egress bundles, so it must install it too.
func TestInitScaffoldIsInternallyConsistent(t *testing.T) {
	opts, ws := testEnv(t, nil, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CmdInit(); err != nil {
		t.Fatal(err)
	}
	// Re-resolve against the file init just wrote.
	c2, err := Resolve(opts)
	if err != nil {
		t.Fatalf("init wrote a config that does not load: %v", err)
	}
	plan, err := c2.BuildPlan()
	if err != nil {
		t.Fatalf("init wrote a config that does not plan: %v", err)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(w, "[agents].install") {
			t.Errorf("the scaffolded config warns about itself: %q", w)
		}
	}
	blob, err := os.ReadFile(filepath.Join(ws, "agentbox.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `install = ["claude-code"]`) {
		t.Errorf("scaffold opens egress for claude-code but does not install it:\n%s", blob)
	}
}

// A plan's warnings describe the box you are about to enter, so they must
// reach the user on every invocation -- not only the one that happened to
// create the box. Adding an agent bundle to a config is the ordinary case:
// the box already exists by then, and under the old plumbing the warning
// about the agent never being installed was computed and then dropped.
func TestPlanWarningsReachStderrOnANonCreatingInvocation(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nbundles = [\"agent:claude-code\"]\n",
	}, containerOnly())
	readErr := captureStderr(t, opts)
	opts.DryRun = true

	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	seedBox(t, c)
	if err := c.CmdUp(); err != ErrHandled {
		t.Fatalf("dry run on an existing box: %v", err)
	}
	if got := readErr(); !strings.Contains(got, "[agents].install") {
		t.Errorf("the uninstalled-agent warning never reached the user on an existing box; stderr:\n%s", got)
	}
}

// --dry-run --json is the documented inspection surface, and it changes
// nothing. A box whose engine has since stopped is precisely when "what would
// this do" is worth asking, so it must answer rather than exit 69 -- the
// unsatisfiable floor is reported inside the plan instead.
func TestDryRunAnswersWhenNoBackendIsAvailable(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, noBackends())
	opts.DryRun = true

	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	seedBox(t, c)

	plan, err := c.planFor()
	if err != nil {
		t.Fatalf("--dry-run must not refuse when no backend is available: %v", err)
	}
	found := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "isolation floor") {
			found = true
		}
	}
	if !found {
		t.Errorf("the unsatisfiable floor must be visible in the plan; warnings: %v", plan.Warnings)
	}
	if _, err := c.CmdRun(nil, false); err != ErrHandled {
		t.Errorf("dry run on an existing box with no backend: %v", err)
	}
}

// The run path takes the exclusive lock for ensureUp and the shared one for
// the exec that follows. The two-phase hold rests on two properties: the
// hand-off must not deadlock against itself, and the shared phase must still
// admit a second command, or an interactive shell would serialize the box.
func TestRunLockPhases(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	seedBox(t, c)

	up, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		t.Fatalf("ensureUp phase could not take the exclusive lock: %v", err)
	}
	up.Release()

	first, err := c.Store.LockBoxShared(c.Key)
	if err != nil {
		t.Fatalf("exec phase could not take the shared lock after the exclusive one: %v", err)
	}
	defer first.Release()
	second, err := c.Store.LockBoxShared(c.Key)
	if err != nil {
		t.Fatalf("a second command must be able to run in a box that already has one: %v", err)
	}
	second.Release()
}
