package backend

import (
	"strings"
	"testing"

	"github.com/sblmnl/agentbox/internal/netpol"
)

func testContainer(fake *fakeEngine) *ContainerBackend {
	c := NewContainerBackend("docker")
	c.Runner = fake.runner
	return c
}

func containerProxySpec(t *testing.T, name string) *BoxSpec {
	t.Helper()
	s := &BoxSpec{
		BoxID:        "box-" + name,
		ResourceName: "agentbox-" + name,
		ImageRef:     "agentbox/dev:abc",
		TreeRoot:     "/src/tree",
		Mount:        "/workspace",
		Workdir:      "/workspace",
		Policy:       &netpol.Policy{Mode: netpol.ModeProxy, Allow: []string{"api.anthropic.com"}, Audit: true},
		StateDir:     t.TempDir(),
		Memory:       "8g",
		CPUs:         4,
		Pids:         4096,
		TmpfsSize:    "4g",
		Nofile:       65536,
	}
	s.SetProxyConfigPath(t.TempDir() + "/squid.conf")
	return s
}

// The sidecar runs as uid 31337 with every capability dropped. Docker only
// defaults a tmpfs to 1777 when the mountpoint does not already exist in the
// image; /run, /var/log/squid and /var/spool/squid all exist in ubuntu/squid,
// so without an explicit mode the mount inherits 0755 root:root and squid
// exits FATAL before it ever binds -- taking the box's entire egress path
// with it while looking like a network fault. This is a regression test for
// exactly that: every tmpfs the sidecar writes to must carry a mode.
func TestProxySidecarTmpfsIsWritableByTheSidecarUser(t *testing.T) {
	fake := &fakeEngine{}
	c := testContainer(fake)

	if err := c.Create(containerProxySpec(t, "tmpfs")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var sidecar []string
	for _, call := range fake.calls {
		if len(call) > 2 && call[0] == "create" && strings.HasSuffix(call[2], "-proxy") {
			sidecar = call
		}
	}
	if sidecar == nil {
		t.Fatal("no proxy sidecar was created")
	}

	// Every path squid writes to at startup, in the order it touches them:
	// the pid file, then the access log, then the cache spool.
	for _, target := range []string{"/run", "/var/log/squid", "/var/spool/squid"} {
		var spec string
		for i, a := range sidecar {
			if a == "--tmpfs" && i+1 < len(sidecar) && strings.HasPrefix(sidecar[i+1], target+":") {
				spec = sidecar[i+1]
			}
		}
		if spec == "" {
			t.Errorf("sidecar has no tmpfs for %s", target)
			continue
		}
		if !strings.Contains(spec, "mode=") {
			t.Errorf("tmpfs %q sets no mode: it will inherit 0755 root:root from the image "+
				"and squid (uid 31337, no capabilities) cannot write there, so the sidecar "+
				"exits FATAL and the box has no egress path", spec)
		}
	}
}

// The box must never share a network with anything but its own proxy, and the
// internal network is what makes a tool that ignores HTTPS_PROXY fail closed
// rather than reach the internet directly.
func TestContainerBoxNetworkIsInternal(t *testing.T) {
	fake := &fakeEngine{}
	c := testContainer(fake)

	if err := c.CreateNetwork(containerProxySpec(t, "net")); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	var internal, egress []string
	for _, call := range fake.calls {
		if len(call) < 3 || call[0] != "network" || call[1] != "create" {
			continue
		}
		switch {
		case strings.HasSuffix(call[len(call)-1], "-int"):
			internal = call
		case strings.HasSuffix(call[len(call)-1], "-egress"):
			egress = call
		}
	}
	if internal == nil {
		t.Fatal("no -int network was created")
	}
	if !contains(internal, "--internal") {
		t.Errorf("box network is not --internal: %v; the guest would have a route off the bridge", internal)
	}
	if egress == nil {
		t.Fatal("proxy mode created no -egress network for the sidecar to straddle")
	}
	if contains(egress, "--internal") {
		t.Errorf("egress network is --internal: %v; the sidecar could not reach anything", egress)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
