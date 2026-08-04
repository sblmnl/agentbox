package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sblmnl/agentbox/internal/config"
	"github.com/sblmnl/agentbox/internal/state"
)

// Workspace-config trust. agentbox.toml is committed, so cloning a
// repository and running `agentbox` would execute configuration the user did
// not write — including [hooks], which run on the host, and
// [[workspace.mounts]], which can mount host paths like ~/.ssh. Those keys
// are therefore refused from a workspace config until the user has reviewed
// the file and recorded trust with `agentbox trust`, à la direnv. The trust
// record is a digest of the workspace config chain; any edit invalidates it.

// trustRecord is projects/<key>/trust.json.
type trustRecord struct {
	Path       string    `json:"path"`
	Digest     string    `json:"digest"`
	Restricted []string  `json:"restricted,omitempty"`
	TrustedAt  time.Time `json:"trusted_at"`
}

func (c *Ctx) trustPath() string {
	return filepath.Join(c.Store.ProjectDir(c.Key), "trust.json")
}

func (c *Ctx) loadTrust() *trustRecord {
	data, err := os.ReadFile(c.trustPath())
	if err != nil {
		return nil
	}
	var rec trustRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	return &rec
}

// workspaceTrusted reports whether the current workspace config chain
// matches the recorded trust digest.
func (c *Ctx) workspaceTrusted() bool {
	rec := c.loadTrust()
	return rec != nil && rec.Digest == config.DigestFiles(c.Cfg.WorkspaceChain)
}

// checkWorkspaceTrust runs at the end of Resolve. Inspection commands and
// --dry-run proceed with a warning — they are the supported way to review
// what an untrusted config would do — while anything that could run hooks or
// materialize mounts is refused.
func (c *Ctx) checkWorkspaceTrust() error {
	if len(c.Cfg.Restricted) == 0 {
		return nil
	}
	if c.workspaceTrusted() {
		return nil
	}
	keys := strings.Join(c.Cfg.Restricted, ", ")
	file := c.Cfg.WorkspaceFile
	if c.Opts.TrustLenient || c.Opts.DryRun {
		fmt.Fprintf(c.Stderr, "warning: %s declares %s but is not trusted; agentbox will refuse to run, create, or start boxes until you review the file and run `agentbox trust`\n", file, keys)
		return nil
	}
	changed := ""
	if c.loadTrust() != nil {
		changed = " The file has CHANGED since it was last trusted."
	}
	return &ExitError{Code: ExNoPerm, Msg: fmt.Sprintf(
		"refusing to honor %s from the untrusted workspace config %s.%s\nHooks execute commands on your host and mounts can expose host paths to the agent.\nReview the file (`agentbox config --origin` shows what it sets), then run `agentbox trust` to accept it — or run with --no-config to ignore it.",
		keys, file, changed)}
}

// CmdTrust implements `trust [--show] [--revoke]`.
func (c *Ctx) CmdTrust(show, revoke bool) error {
	if revoke {
		if err := os.Remove(c.trustPath()); err != nil && !os.IsNotExist(err) {
			return Softwaref("%v", err)
		}
		c.Notef("trust revoked for %s", c.Workspace)
		return nil
	}
	if show {
		return c.showTrust()
	}
	if c.Cfg.WorkspaceFile == "" {
		return Usagef("no workspace configuration found in %s; nothing to trust", c.Workspace)
	}
	rec := &trustRecord{
		Path:       c.Cfg.WorkspaceFile,
		Digest:     config.DigestFiles(c.Cfg.WorkspaceChain),
		Restricted: c.Cfg.Restricted,
		TrustedAt:  time.Now().UTC(),
	}
	if err := os.MkdirAll(c.Store.ProjectDir(c.Key), 0o700); err != nil {
		return Softwaref("%v", err)
	}
	if err := state.WriteJSONFile(c.trustPath(), rec); err != nil {
		return Softwaref("%v", err)
	}
	if len(c.Cfg.Restricted) > 0 {
		c.Notef("trusted %s: %s will now be honored; any edit to the file requires trusting it again", rec.Path, strings.Join(c.Cfg.Restricted, ", "))
	} else {
		c.Notef("trusted %s (it currently declares no hooks or host mounts; trust will apply if it gains them unchanged)", rec.Path)
	}
	return nil
}

func (c *Ctx) showTrust() error {
	rec := c.loadTrust()
	status := map[string]any{
		"workspace":   c.Workspace,
		"config_file": c.Cfg.WorkspaceFile,
		"restricted":  c.Cfg.Restricted,
		"trusted":     len(c.Cfg.Restricted) == 0 || c.workspaceTrusted(),
	}
	if rec != nil {
		status["trusted_at"] = rec.TrustedAt
		status["digest_matches"] = rec.Digest == config.DigestFiles(c.Cfg.WorkspaceChain)
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	if c.Cfg.WorkspaceFile == "" {
		fmt.Println("no workspace configuration")
		return nil
	}
	fmt.Printf("config:     %s\n", c.Cfg.WorkspaceFile)
	if len(c.Cfg.Restricted) == 0 {
		fmt.Println("restricted: none (no hooks or host mounts; trust not required)")
	} else {
		fmt.Printf("restricted: %s\n", strings.Join(c.Cfg.Restricted, ", "))
	}
	switch {
	case rec == nil && len(c.Cfg.Restricted) > 0:
		fmt.Println("trusted:    no — run `agentbox trust` after reviewing the file")
	case rec == nil:
		fmt.Println("trusted:    not recorded (not required)")
	case rec.Digest == config.DigestFiles(c.Cfg.WorkspaceChain):
		fmt.Printf("trusted:    yes (%s)\n", rec.TrustedAt.Format(time.RFC3339))
	default:
		fmt.Println("trusted:    no — the file has changed since it was trusted")
	}
	return nil
}

// refreshTrustAfterRewrite re-records trust when agentbox itself rewrites
// the workspace config on explicit invocation (`allow`): the user asked for
// the edit, so it does not invalidate their prior review.
func (c *Ctx) refreshTrustAfterRewrite() {
	if c.loadTrust() == nil {
		return
	}
	rec := &trustRecord{
		Path:       c.Cfg.WorkspaceFile,
		Digest:     config.DigestFiles(c.Cfg.WorkspaceChain),
		Restricted: c.Cfg.Restricted,
		TrustedAt:  time.Now().UTC(),
	}
	_ = state.WriteJSONFile(c.trustPath(), rec)
}
