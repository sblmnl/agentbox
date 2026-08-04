// Package vmconformance is the VM conformance suite. It drives the
// real CLI against a real OCI VM runtime, so it needs KVM, an engine with a
// kata/krun runtime configured, and root (the host-side mask view needs
// CAP_SYS_ADMIN). It is gated on AGENTBOX_VM_CONFORMANCE=1 and skips
// visibly otherwise; the CI job FAILS when this suite skips —
// a green build that silently omitted it is the failure mode these tests
// exist to prevent.
//
// The Layer 3 filtered share (mask_mode "filter") ships in this build;
// TestFilterModeGuarantees covers the filter-mode guarantees end-to-end through a
// real guest, including the two view mode cannot deliver: a file created
// after box start is masked, and a masked directory imposes no size cap.
package vmconformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var agentboxBin string

func TestMain(m *testing.M) {
	if os.Getenv("AGENTBOX_VM_CONFORMANCE") != "1" {
		// testing.M has no Skip; individual tests check the gate and skip.
		os.Exit(m.Run())
	}
	agentboxBin = os.Getenv("AGENTBOX_BIN")
	if agentboxBin == "" {
		bin := filepath.Join(os.TempDir(), fmt.Sprintf("agentbox-conf-%d", os.Getpid()))
		build := exec.Command("go", "build", "-o", bin, "github.com/sblmnl/agentbox/cmd/agentbox")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "building agentbox: %v\n", err)
			os.Exit(1)
		}
		agentboxBin = bin
		defer os.Remove(bin)
	}
	os.Exit(m.Run())
}

// gate skips (visibly) outside the conformance environment and verifies the
// vm backend really is available before any test claims coverage.
func gate(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTBOX_VM_CONFORMANCE") != "1" {
		t.Skip("vm conformance requires AGENTBOX_VM_CONFORMANCE=1 (KVM + kata/krun + root); CI must fail on this skip")
	}
	out, _, code := agentbox(t, t.TempDir(), "backends", "--json")
	if code != 0 {
		t.Fatalf("agentbox backends failed: %s", out)
	}
	var avs []struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(out), &avs); err != nil {
		t.Fatalf("backends --json: %v\n%s", err, out)
	}
	for _, av := range avs {
		if av.Name == "vm" {
			if !av.Available {
				t.Fatalf("AGENTBOX_VM_CONFORMANCE=1 but the vm backend is unavailable: %s", av.Reason)
			}
			return
		}
	}
	t.Fatal("no vm backend in probe output")
}

// ws creates a conformance workspace with its own state root, so guests and
// listeners cannot leak across tests, and registers teardown.
func ws(t *testing.T, config string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agentbox.toml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := t.TempDir()
	stateRoots[dir] = stateRoot
	t.Cleanup(func() {
		_, _, _ = agentbox(t, dir, "down", "--all")
		delete(stateRoots, dir)
	})
	return dir
}

var stateRoots = map[string]string{}

// agentbox runs the CLI against a workspace, returning stdout, stderr, and
// the exit code — which must be the in-guest code verbatim.
func agentbox(t *testing.T, workspace string, args ...string) (string, string, int) {
	t.Helper()
	full := append([]string{"-C", workspace}, args...)
	cmd := exec.Command(agentboxBin, full...)
	root := stateRoots[workspace]
	if root == "" {
		root = filepath.Join(os.TempDir(), "agentbox-conf-state")
	}
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+root, "XDG_CACHE_HOME="+root+"-cache")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("agentbox %v: %v", args, err)
	}
	t.Logf("agentbox %v -> %d\nstdout: %s\nstderr: %s", args, code, stdout.String(), stderr.String())
	return stdout.String(), stderr.String(), code
}

const baseConfig = `version = 1
[image]
ref = "ubuntu:24.04"
[security]
min_isolation = "vm"
[network]
mode = "none"
`

func TestExitCodeFidelity(t *testing.T) {
	gate(t)
	dir := ws(t, baseConfig, nil)
	_, _, code := agentbox(t, dir, "run", "sh", "-c", "exit 42")
	if code != 42 {
		t.Fatalf("in-guest exit 42 must surface verbatim, got %d", code)
	}
}

func TestMaskSurvivesGuestRoot(t *testing.T) {
	gate(t)
	dir := ws(t, baseConfig, map[string]string{
		".agentignore": ".env\n",
		".env":         "SECRET=exfiltrate-me\n",
	})
	out, _, code := agentbox(t, dir, "run", "--root", "sh", "-c", "cat /workspace/.env; true")
	if code != 0 {
		t.Fatalf("exec failed: %d", code)
	}
	if strings.Contains(out, "exfiltrate-me") {
		t.Fatal("masked file readable as guest root")
	}
	out, _, _ = agentbox(t, dir, "run", "--root", "sh", "-c",
		"umount /workspace/.env 2>&1; umount -l /workspace/.env 2>&1; cat /workspace/.env; ls /workspace")
	if strings.Contains(out, "exfiltrate-me") {
		t.Fatal("guest root reached masked content after unmount attempts")
	}
}

func TestEgressFailsClosed(t *testing.T) {
	gate(t)
	dir := ws(t, `version = 1
[image]
ref = "ubuntu:24.04"
[security]
min_isolation = "vm"
[network]
mode = "proxy"
allow = ["api.anthropic.com"]
`, nil)
	// Raw IP, no DNS involved: must have no route.
	out, _, _ := agentbox(t, dir, "run", "bash", "-c",
		"timeout 15 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null && echo REACHED || echo BLOCKED")
	if !strings.Contains(out, "BLOCKED") {
		t.Fatal("raw IP egress must be blocked by topology, not policy")
	}
	// Unset proxy variables: a tool ignoring HTTPS_PROXY must still fail.
	out, _, _ = agentbox(t, dir, "run", "bash", "-c",
		"unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy; timeout 15 bash -c 'exec 3<>/dev/tcp/api.anthropic.com/443' 2>/dev/null && echo REACHED || echo BLOCKED")
	if !strings.Contains(out, "BLOCKED") {
		t.Fatal("egress with proxy variables unset must fail closed")
	}
}

func TestConcurrentGuests(t *testing.T) {
	gate(t)
	dir := ws(t, baseConfig, nil)
	for _, name := range []string{"alpha", "beta"} {
		if _, errOut, code := agentbox(t, dir, "new", "--name", name); code != 0 {
			t.Fatalf("creating %s: %s", name, errOut)
		}
	}
	var wg sync.WaitGroup
	results := map[string]string{}
	var mu sync.Mutex
	for _, name := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			out, _, code := agentbox(t, dir, "-n", name, "run", "sh", "-c", "uname -r; hostname")
			mu.Lock()
			defer mu.Unlock()
			if code != 0 {
				results[name] = fmt.Sprintf("exit %d", code)
			} else {
				results[name] = out
			}
		}(name)
	}
	wg.Wait()
	for name, res := range results {
		if strings.HasPrefix(res, "exit ") {
			t.Fatalf("box %s failed under concurrency: %s", name, res)
		}
	}

	// Stop one; the other keeps serving.
	if _, errOut, code := agentbox(t, dir, "-n", "alpha", "stop"); code != 0 {
		t.Fatalf("stop alpha: %s", errOut)
	}
	time.Sleep(2 * time.Second)
	if out, _, code := agentbox(t, dir, "-n", "beta", "run", "echo", "still-alive"); code != 0 || !strings.Contains(out, "still-alive") {
		t.Fatalf("beta disturbed by stopping alpha: code %d, out %q", code, out)
	}
}

// TestFilterModeGuarantees drives the filter-mode guarantee table through a real
// guest behind the filtered share. The suite runs as root, so the seam is
// available and an explicit mask_mode = "filter" must be honored — a
// failure to deliver it must fail the box, never downgrade.
func TestFilterModeGuarantees(t *testing.T) {
	gate(t)
	filterConfig := `version = 1
[image]
ref = "ubuntu:24.04"
[security]
min_isolation = "vm"
mask_mode = "filter"
[network]
mode = "none"
`
	dir := ws(t, filterConfig, map[string]string{
		".agentignore":  ".env\n*.pem\nsecrets/\n",
		".env":          "SECRET=exfiltrate-me\n",
		"secrets/token": "tok\n",
		"main.go":       "package main\n",
	})
	if _, stderr, code := agentbox(t, dir, "up"); code != 0 {
		t.Fatalf("up with explicit filter mode failed: %d\n%s", code, stderr)
	}

	// Masked paths do not exist in the guest: not readable, not listed —
	// including for guest root, because enforcement is host-side.
	out, _, _ := agentbox(t, dir, "run", "--root", "sh", "-c",
		"ls -a /workspace; cat /workspace/.env 2>&1; cat /workspace/secrets/token 2>&1; true")
	if strings.Contains(out, "exfiltrate-me") || strings.Contains(out, "tok\n") {
		t.Fatal("masked content readable through the filtered share")
	}
	if strings.Contains(out, ".env") || strings.Contains(out, "secrets") {
		t.Fatalf("masked names must be absent from listings, got:\n%s", out)
	}

	// Guarantee: a matching file created after box start is masked. The
	// tree is shared, so a host-side write lands in the live tree.
	if err := os.WriteFile(filepath.Join(dir, "late-key.pem"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ = agentbox(t, dir, "run", "sh", "-c",
		"test -e /workspace/late-key.pem && echo VISIBLE || echo MASKED")
	if !strings.Contains(out, "MASKED") {
		t.Fatal("a file created after box start must be masked under filter mode")
	}

	// Writes to masked names fail loudly and never reach the host.
	out, _, _ = agentbox(t, dir, "run", "sh", "-c",
		"echo leak > /workspace/.env 2>&1 && echo WROTE || echo REFUSED")
	if !strings.Contains(out, "REFUSED") {
		t.Fatal("creating a masked name must be refused")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ".env")); string(data) != "SECRET=exfiltrate-me\n" {
		t.Fatalf("host .env was altered: %q", data)
	}

	// Guarantee: no tmpfs size cap anywhere in the masked view — a
	// large write to an unmasked path passes straight through.
	out, _, code := agentbox(t, dir, "run", "sh", "-c",
		"dd if=/dev/zero of=/workspace/big.bin bs=1M count=8 2>&1 && echo OK")
	if code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("large write through the filtered share failed:\n%s", out)
	}

	// `masks --verify` asserts absence (not emptiness) under filter mode.
	out, stderr, code := agentbox(t, dir, "masks", "--verify")
	if code != 0 {
		t.Fatalf("masks --verify failed: %d\n%s\n%s", code, out, stderr)
	}
}
