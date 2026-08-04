package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceTrustHooks(t *testing.T) {
	opts, ws := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[hooks]\npre_up = [\"echo pwned\"]\n",
	}, containerOnly())

	_, err := Resolve(opts)
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExNoPerm {
		t.Fatalf("untrusted config with hooks must be refused with exit %d, got %v", ExNoPerm, err)
	}
	if !strings.Contains(ee.Msg, "hooks.pre_up") || !strings.Contains(ee.Msg, "trust") {
		t.Errorf("refusal must name the restricted keys and the remedy: %s", ee.Msg)
	}

	// Inspection commands proceed with a warning.
	opts.TrustLenient = true
	c, err := Resolve(opts)
	if err != nil {
		t.Fatalf("lenient resolve must proceed: %v", err)
	}
	opts.TrustLenient = false

	// Trust it; enforcement lifts.
	if err := c.CmdTrust(false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("trusted config must resolve: %v", err)
	}

	// Any edit invalidates trust.
	if err := os.WriteFile(filepath.Join(ws, "agentbox.toml"),
		[]byte("version = 1\n[hooks]\npre_up = [\"echo changed\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(opts)
	ee, ok = err.(*ExitError)
	if !ok || ee.Code != ExNoPerm {
		t.Fatalf("edited config must be refused again, got %v", err)
	}
	if !strings.Contains(ee.Msg, "CHANGED") {
		t.Errorf("refusal after an edit should say the file changed: %s", ee.Msg)
	}

	// Revoke works.
	opts.TrustLenient = true
	c, err = Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CmdTrust(false, false); err != nil {
		t.Fatal(err)
	}
	if err := c.CmdTrust(false, true); err != nil {
		t.Fatal(err)
	}
	opts.TrustLenient = false
	if _, err := Resolve(opts); err == nil {
		t.Fatal("revoked trust must restore the refusal")
	}
}

func TestWorkspaceTrustMounts(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[[workspace.mounts]]\nsource = \"~/.ssh\"\ntarget = \"/home/agent/.ssh\"\n",
	}, containerOnly())
	_, err := Resolve(opts)
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExNoPerm {
		t.Fatalf("untrusted host mounts must be refused, got %v", err)
	}
	if !strings.Contains(ee.Msg, "workspace.mounts") {
		t.Errorf("refusal must name workspace.mounts: %s", ee.Msg)
	}
}

// A workspace config without hooks or mounts needs no trust at all.
func TestWorkspaceTrustNotRequired(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[network]\nmode = \"proxy\"\nallow = [\"example.com\"]\n",
	}, containerOnly())
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("config without restricted keys must not require trust: %v", err)
	}
}

// Hooks smuggled through a workspace-defined profile are restricted too.
func TestWorkspaceTrustProfileHooks(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[profiles.evil]\n[profiles.evil.hooks]\npre_up = [\"echo pwned\"]\n",
	}, containerOnly())
	// Profile inactive: nothing runs, nothing restricted.
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("inactive profile must not require trust: %v", err)
	}
	// Activating it makes the hooks live and therefore restricted.
	opts.Profile = "evil"
	_, err := Resolve(opts)
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExNoPerm {
		t.Fatalf("workspace-defined profile hooks must be refused, got %v", err)
	}
	if !strings.Contains(ee.Msg, "profiles.evil.hooks.pre_up") {
		t.Errorf("refusal must name the profile key: %s", ee.Msg)
	}
}

// An extends base pulled in by the workspace config is part of the trust
// digest: editing the base invalidates trust recorded on the chain.
func TestWorkspaceTrustExtendsChain(t *testing.T) {
	opts, ws := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\nextends = \"base.toml\"\n",
		"base.toml":     "[hooks]\npost_up = [\"echo base\"]\n",
	}, containerOnly())
	_, err := Resolve(opts)
	ee, ok := err.(*ExitError)
	if !ok || ee.Code != ExNoPerm {
		t.Fatalf("hooks from an extends base must be refused, got %v", err)
	}
	opts.TrustLenient = true
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CmdTrust(false, false); err != nil {
		t.Fatal(err)
	}
	opts.TrustLenient = false
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("trusted chain must resolve: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ws, "base.toml"),
		[]byte("[hooks]\npost_up = [\"echo tampered\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(opts); err == nil {
		t.Fatal("editing the extends base must invalidate trust")
	}
}

// `allow` rewrites the config on explicit invocation and must not invalidate
// recorded trust.
func TestAllowRefreshesTrust(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[hooks]\npre_up = [\"echo hi\"]\n",
	}, containerOnly())
	opts.TrustLenient = true
	c, err := Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CmdTrust(false, false); err != nil {
		t.Fatal(err)
	}
	opts.TrustLenient = false
	c, err = Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CmdAllow([]string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("allow must refresh trust after its own rewrite: %v", err)
	}
}

// --dry-run is an inspection path: it proceeds (with a warning) so `what
// would this do` stays answerable before trusting.
func TestDryRunLenientOnTrust(t *testing.T) {
	opts, _ := testEnv(t, map[string]string{
		"agentbox.toml": "version = 1\n[hooks]\npre_up = [\"echo hi\"]\n",
	}, containerOnly())
	opts.DryRun = true
	if _, err := Resolve(opts); err != nil {
		t.Fatalf("--dry-run must not be blocked by trust: %v", err)
	}
}
