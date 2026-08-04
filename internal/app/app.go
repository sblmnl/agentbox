// Package app wires the subsystems into the CLI commands.
package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/config"
	"github.com/sblmnl/agentbox/internal/identity"
	"github.com/sblmnl/agentbox/internal/state"
	"github.com/sblmnl/agentbox/internal/workspace"
)

// Version identifiers (`version`).
const (
	ToolVersion = "0.0.1-dev"
)

// sysexits.h codes used for agentbox's own failures.
const (
	ExUsage       = 64
	ExUnavailable = 69 // no backend satisfies the isolation floor
	ExSoftware    = 70
	ExNoPerm      = 77 // workspace config not trusted
	ExConfig      = 78 // configuration invalid, including backend-scope violations
)

// ExitError carries an agentbox-owned failure to main.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

func Usagef(format string, a ...any) *ExitError {
	return &ExitError{Code: ExUsage, Msg: fmt.Sprintf(format, a...)}
}
func Configf(format string, a ...any) *ExitError {
	return &ExitError{Code: ExConfig, Msg: fmt.Sprintf(format, a...)}
}
func Unavailablef(format string, a ...any) *ExitError {
	return &ExitError{Code: ExUnavailable, Msg: fmt.Sprintf(format, a...)}
}
func Softwaref(format string, a ...any) *ExitError {
	return &ExitError{Code: ExSoftware, Msg: fmt.Sprintf(format, a...)}
}

// Options mirrors the global flags.
type Options struct {
	Directory      string // -C
	Workspace      string // -w
	Name           string // -n
	New            bool
	All            bool
	TreeMode       string
	Profile        string // -p
	ConfigFile     string // -c
	NoConfig       bool
	Backend        string // -b
	MinIsolation   string
	ForceIsolation string
	Env            []string // -e KEY=VAL
	EnvPassthrough []string // -E KEY
	NetworkMode    string
	Offline        bool
	Rebuild        bool
	Recreate       bool
	Root           bool
	NoMask         bool
	DryRun         bool
	JSON           bool
	Quiet          bool
	Verbose        bool
	Timeout        int

	// TrustLenient downgrades the workspace-trust refusal to a
	// warning. Set by the CLI for inspection commands — reviewing an
	// untrusted config is exactly what they are for — never from config.
	TrustLenient bool

	// Test seams.
	StateRoot     string
	Availabilties []backend.Availability // nil = probe the host
	Stderr        *os.File
	// BoxLiveness overrides the per-box runtime probe prune's teardown uses
	// to decide what it may touch (nil = ask the backend).
	BoxLiveness func(instance string) (running bool, detail string)
}

// Ctx is everything resolved before a command runs.
type Ctx struct {
	Opts      *Options
	StartDir  string
	Workspace string // resolved workspace root (realpath)
	Key       string
	Slug      string
	Cfg       *config.Result
	Store     *state.Store
	Stderr    *os.File
}

// Resolve builds the context: workspace detection, configuration load, flag
// overlay.
func Resolve(opts *Options) (*Ctx, error) {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	startDir := opts.Directory
	if startDir == "" {
		var err error
		startDir, err = os.Getwd()
		if err != nil {
			return nil, Softwaref("getwd: %v", err)
		}
	}
	ws, err := workspace.Detect(startDir, opts.Workspace)
	if err != nil {
		return nil, Usagef("%v", err)
	}
	real, err := filepath.EvalSymlinks(ws)
	if err != nil {
		return nil, Softwaref("resolving %s: %v", ws, err)
	}

	res, err := config.Load(config.LoadOptions{
		WorkspaceRoot: real,
		ProfileName:   opts.Profile,
		ConfigFile:    opts.ConfigFile,
		NoConfig:      opts.NoConfig,
		Environ:       os.Environ(),
	})
	if err != nil {
		return nil, asConfigErr(err)
	}

	// Flag overlay.
	flags := map[string]any{}
	netMode := opts.NetworkMode
	if opts.Offline {
		netMode = "none"
	}
	if netMode != "" {
		setPath(flags, "network.mode", netMode)
	}
	if opts.TreeMode != "" {
		setPath(flags, "workspace.tree_mode", opts.TreeMode)
	}
	if opts.MinIsolation != "" {
		// MAY raise the floor, MUST NOT lower it.
		cur := res.Config.Security.MinIsolation
		if cur == "vm" && opts.MinIsolation == "container" {
			return nil, Usagef("--min-isolation may raise the isolation floor but not lower it (config declares %q); lowering requires --force-isolation", cur)
		}
		setPath(flags, "security.min_isolation", opts.MinIsolation)
	}
	if opts.Backend != "" {
		setPath(flags, "security.backend", opts.Backend)
	}
	for _, kv := range opts.Env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			return nil, Usagef("--env expects KEY=VAL, got %q", kv)
		}
		setPath(flags, "variables."+kv[:i], kv[i+1:])
	}
	if len(flags) > 0 {
		if err := res.ApplyFlags(flags); err != nil {
			return nil, asConfigErr(err)
		}
	}

	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning: "+w)
	}
	if opts.NoMask {
		fmt.Fprintln(stderr, "warning: --no-mask: secret masking is DISABLED for this invocation; every file in the tree is readable from the box")
	}
	if res.Config.Network.Mode == "open" {
		fmt.Fprintln(stderr, "warning: network mode \"open\": the box has ordinary network access; the egress allowlist and audit trail do not apply")
	}

	ctx := &Ctx{
		Opts:      opts,
		StartDir:  startDir,
		Workspace: real,
		Key:       identity.ProjectKey(real),
		Slug:      identity.SanitizeSlug(filepath.Base(real)),
		Cfg:       res,
		Store:     state.Open(opts.StateRoot),
		Stderr:    stderr,
	}
	if err := ctx.checkWorkspaceTrust(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func asConfigErr(err error) error {
	if se, ok := err.(*config.SchemaError); ok {
		return &ExitError{Code: ExConfig, Msg: se.Error()}
	}
	return &ExitError{Code: ExConfig, Msg: err.Error()}
}

func setPath(tree map[string]any, path string, val any) {
	parts := strings.Split(path, ".")
	cur := tree
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

// ConfigDigest hashes the effective merged tree for drift detection.
func (c *Ctx) ConfigDigest() string {
	blob, _ := json.Marshal(c.Cfg.Merged.Tree)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// Availabilities returns probe results (or the test seam).
func (c *Ctx) Availabilities() []backend.Availability {
	if c.Opts.Availabilties != nil {
		return c.Opts.Availabilties
	}
	return backend.Probe()
}

// ResolveBoxName maps -n (name or ordinal alias) to an instance name.
func (c *Ctx) ResolveBoxName() (string, error) {
	n := c.Opts.Name
	if n == "" {
		return "", nil
	}
	if ord, err := strconv.Atoi(n); err == nil {
		inst, err := c.Store.ResolveOrdinal(c.Key, ord)
		if err != nil {
			return "", Usagef("%v", err)
		}
		return inst, nil
	}
	if !identity.ValidInstanceName(n) {
		return "", Usagef("invalid instance name %q (must match [a-z0-9][a-z0-9_-]{0,31})", n)
	}
	return n, nil
}

// Verbosef prints a diagnostic when -v is set.
func (c *Ctx) Verbosef(format string, a ...any) {
	if c.Opts.Verbose {
		fmt.Fprintf(c.Stderr, format+"\n", a...)
	}
}

// Notef prints a diagnostic unless -q.
func (c *Ctx) Notef(format string, a ...any) {
	if !c.Opts.Quiet {
		fmt.Fprintf(c.Stderr, format+"\n", a...)
	}
}
