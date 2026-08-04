package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sblmnl/agentbox/internal/backend"
)

// snapshotOf builds an engine snapshot from literal names, so the artifact
// join is exercised without an engine on the machine. Containers listed in
// running are also present: an engine cannot run what it does not hold.
func snapshotOf(present map[backend.ResourceKind][]string, running ...string) *engineSnapshot {
	snap := &engineSnapshot{
		byKind:  map[backend.ResourceKind]map[string]bool{},
		running: map[string]bool{},
	}
	for _, k := range []backend.ResourceKind{
		backend.KindContainer, backend.KindNetwork, backend.KindVolume, backend.KindImage,
	} {
		snap.byKind[k] = map[string]bool{}
	}
	for kind, names := range present {
		for _, n := range names {
			snap.byKind[kind][n] = true
		}
	}
	for _, n := range running {
		snap.running[n] = true
		snap.byKind[backend.KindContainer][n] = true
	}
	return snap
}

// only claim in the scan, for a box created by the test helpers.
func soleClaim(t *testing.T, c *Ctx, instance string) *claim {
	t.Helper()
	s, err := c.scanClaims()
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range s.Boxes {
		if cl.Instance == instance {
			return cl
		}
	}
	t.Fatalf("box %q is not in the claim scan", instance)
	return nil
}

func find(arts []Artifact, kind, name string) *Artifact {
	for i := range arts {
		if arts[i].Kind == kind && arts[i].Name == name {
			return &arts[i]
		}
	}
	return nil
}

func names(arts []Artifact) []string {
	var out []string
	for _, a := range arts {
		out = append(out, a.Kind+" "+a.Name)
	}
	return out
}

// The expected set is what makes this more than a filtered `docker ps`: a
// container-tier box in proxy mode owns a sidecar and an egress network, and
// nothing that belongs only to the vm tier.
func TestArtifactsExpectedSetContainerTier(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	cl := soleClaim(t, c, "solo")
	arts := c.boxArtifacts(snapshotOf(nil), cl)

	res := cl.Resource
	for _, want := range [][2]string{
		{"container", res},
		{"network", res + "-int"},
		{"network", res + "-egress"},
		{"container", res + "-proxy"},
		{"volume", res + "-home"},
		{"state", c.Store.BoxDir(cl.Key, cl.Instance)},
	} {
		if find(arts, want[0], want[1]) == nil {
			t.Errorf("%s %s missing from the artifact set; got %v", want[0], want[1], names(arts))
		}
	}
	if find(arts, "view", backend.ViewRoot(c.Store.Root, res)) != nil {
		t.Error("the container tier has no host-side mask view; reporting one invents an artifact")
	}
	for _, a := range arts {
		if a.Kind == "listener" {
			t.Error("the container tier proxies through a sidecar, not a host listener")
		}
	}
	// The image is named, and named as the box records it rather than as
	// current configuration would resolve it.
	if a := find(arts, "image", cl.Meta.ImageRef); a == nil {
		t.Errorf("the box's image must be listed; got %v", names(arts))
	}
}

// Under the vm tier the proxy is a host daemon listener and the share is a
// host-side view. Neither is an engine resource, and the sidecar pair does
// not exist at all.
func TestArtifactsExpectedSetVMTier(t *testing.T) {
	noEngines(t)
	prev := seamProbe
	seamProbe = func() (bool, string) { return false, "not running as root" }
	t.Cleanup(func() { seamProbe = prev })

	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
	}, bothTiers())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := c.createBox("vmbox")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Tier != string(backend.TierVM) {
		t.Fatalf("expected the vm tier to be selected, got %q", meta.Tier)
	}
	cl := soleClaim(t, c, "vmbox")
	arts := c.boxArtifacts(snapshotOf(nil), cl)

	if find(arts, "view", backend.ViewRoot(c.Store.Root, cl.Resource)) == nil {
		t.Errorf("a vm-tier box owns a host-side mask view; got %v", names(arts))
	}
	found := false
	for _, a := range arts {
		if a.Kind == "listener" {
			found = true
		}
	}
	if !found {
		t.Errorf("a vm-tier box in proxy mode owns a host proxy listener; got %v", names(arts))
	}
	if find(arts, "container", cl.Resource+"-proxy") != nil {
		t.Error("the vm tier has no proxy sidecar; reporting one invents an artifact")
	}
	if find(arts, "network", cl.Resource+"-egress") != nil {
		t.Error("the vm tier has no egress network; reporting one invents an artifact")
	}
}

// Absence is the answer that matters. An artifact the box expects and the
// engine does not hold must be shouted, never quietly dropped from the list —
// a view that only showed what exists could not tell a healthy box from a
// half-destroyed one.
func TestArtifactsMissingIsLoud(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	cl := soleClaim(t, c, "solo")
	arts := c.boxArtifacts(snapshotOf(nil), cl) // engines hold nothing

	engineKinds := map[string]bool{"container": true, "network": true, "volume": true, "image": true}
	saw := 0
	for _, a := range arts {
		if !engineKinds[a.Kind] {
			continue
		}
		saw++
		if a.Status != artMissing {
			t.Errorf("%s %s: status %q, want %q — an absent artifact must be reported, not assumed fine",
				a.Kind, a.Name, a.Status, artMissing)
		}
	}
	if saw == 0 {
		t.Fatal("no engine artifacts were reported at all")
	}
	// The state directory is real and must not be swept up in the same brush.
	if a := find(arts, "state", c.Store.BoxDir(cl.Key, cl.Instance)); a == nil || a.Status != artPresent {
		t.Errorf("the box state directory exists and must report %q, got %+v", artPresent, a)
	}
}

// Present and running are different answers. A stopped sidecar beside a
// running box is a broken egress path, and a listing that collapsed the two
// would show it as healthy.
func TestArtifactsRunningIsDistinctFromPresent(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	cl := soleClaim(t, c, "solo")
	res := cl.Resource
	snap := snapshotOf(map[backend.ResourceKind][]string{
		backend.KindContainer: {res + "-proxy"}, // present but stopped
	}, res) // the box itself is up
	arts := c.boxArtifacts(snap, cl)

	if a := find(arts, "container", res); a == nil || a.Status != artRunning {
		t.Errorf("the box is running and must say so, got %+v", a)
	}
	if a := find(arts, "container", res+"-proxy"); a == nil || a.Status != artPresent {
		t.Errorf("a stopped sidecar must read %q, not %q or missing, got %+v", artPresent, artRunning, a)
	}
}

// A resource this box's name claims but that it was never created with is
// invisible from both ends otherwise: prune will not touch it, because it is
// claimed, and the expected set does not name it. It has to be surfaced here.
func TestArtifactsUnexpectedSurfaced(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"none\"\n",
	}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	cl := soleClaim(t, c, "solo")
	// A sidecar left behind by a switch away from proxy mode.
	stale := cl.Resource + "-proxy"
	arts := c.boxArtifacts(snapshotOf(map[backend.ResourceKind][]string{
		backend.KindContainer: {stale},
	}), cl)

	a := find(arts, "container", stale)
	if a == nil {
		t.Fatalf("a claimed resource the box does not expect must still be listed; got %v", names(arts))
	}
	if a.Status != artUnexpected {
		t.Errorf("status = %q, want %q", a.Status, artUnexpected)
	}
}

// The two directions of the same join must agree: an artifact under a box is
// never also unclaimed, and an unclaimed one never belongs to a box. If they
// disagreed, `prune` would offer to delete something the view says is in use.
func TestArtifactsAndUnclaimedAgree(t *testing.T) {
	noEngines(t)
	opts, _ := testEnv(t, map[string]string{"agentbox.toml": "version = 1\n"}, containerOnly())
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}
	cl := soleClaim(t, c, "solo")
	s, err := c.scanClaims()
	if err != nil {
		t.Fatal(err)
	}
	orphan := backend.ResourcePrefix + "someone-else-9f2a-gone-home"
	snap := snapshotOf(map[backend.ResourceKind][]string{
		backend.KindContainer: {cl.Resource},
		backend.KindNetwork:   {cl.Resource + "-int"},
		backend.KindVolume:    {cl.Resource + "-home", orphan},
	})

	mine := map[string]bool{}
	for _, a := range c.boxArtifacts(snap, cl) {
		mine[a.Name] = true
	}
	unclaimed := c.unclaimedArtifacts(snap, s)
	if len(unclaimed) == 0 {
		t.Fatal("the orphan volume must be reported as unclaimed")
	}
	sawOrphan := false
	for _, a := range unclaimed {
		if a.Name == orphan {
			sawOrphan = true
		}
		if mine[a.Name] {
			t.Errorf("%s is listed both under box %s and as unclaimed", a.Name, cl.Instance)
		}
	}
	if !sawOrphan {
		t.Errorf("orphan %s missing from the unclaimed set: %v", orphan, names(unclaimed))
	}
}

// The expected set follows what the box was created with, not what the config
// says now. Otherwise every ordinary drift would be reported as a missing
// artifact, and `status` already reports drift on its own line.
func TestArtifactsFollowTheFrozenSpec(t *testing.T) {
	noEngines(t)
	ws := t.TempDir()
	stateRoot := t.TempDir()
	nullf, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nullf.Close() })
	write := func(cfg string) {
		if err := os.WriteFile(filepath.Join(ws, "agentbox.toml"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	newCtx := func() *Ctx {
		c, err := Resolve(&Options{
			Directory: ws, Workspace: ws, StateRoot: stateRoot,
			Availabilties: containerOnly(), Stderr: nullf, Quiet: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Created without a proxy: no sidecar, no egress network.
	write("version = 1\n[network]\nmode = \"none\"\n")
	c := newCtx()
	if _, err := c.createBox("solo"); err != nil {
		t.Fatal(err)
	}

	// Configuration now asks for one. The box still does not have it.
	write("version = 1\n[network]\nmode = \"proxy\"\n")
	c = newCtx()
	cl := soleClaim(t, c, "solo")
	arts := c.boxArtifacts(snapshotOf(nil), cl)
	if a := find(arts, "container", cl.Resource+"-proxy"); a != nil {
		t.Errorf("a config change must not make the box look like it lost a sidecar it never had: %+v", a)
	}
}
