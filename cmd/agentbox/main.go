// agentbox runs an agentic coding tool inside an isolated environment built
// for the current project.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sblmnl/agentbox/internal/app"
	"github.com/sblmnl/agentbox/internal/share"
)

// Reserved subcommands are a closed, documented set; adding one that
// collides with a common binary name is a breaking change.
var reserved = map[string]bool{
	"run": true, "shell": true, "up": true, "down": true, "status": true,
	"logs": true, "build": true, "config": true, "init": true, "rm": true,
	"version": true, "help": true,
}

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		if ee, ok := err.(*app.ExitError); ok {
			if ee.Msg != "" {
				fmt.Fprintln(os.Stderr, "agentbox: "+ee.Msg)
			}
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, "agentbox: "+err.Error())
		os.Exit(app.ExSoftware)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	// `fsd` is the hidden share-daemon entry point for mask_mode "filter"
	// (the Layer 3 filtered share), spawned by agentbox itself. It is
	// intercepted before interpretation: it needs no workspace and is not
	// part of the documented, closed subcommand set.
	if len(args) > 0 && args[0] == "fsd" {
		return runFsd(args[1:])
	}

	opts := &app.Options{Timeout: 120}
	var rest []string
	forced := false // saw "--"

	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			forced = true
			rest = args[i+1:]
			break
		}
		if !strings.HasPrefix(a, "-") {
			rest = args[i:]
			break
		}
		take := func() (string, error) {
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				return a[eq+1:], nil
			}
			i++
			if i >= len(args) {
				return "", app.Usagef("flag %s requires a value", a)
			}
			return args[i], nil
		}
		flagName := a
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			flagName = a[:eq]
		}
		var err error
		var v string
		switch flagName {
		case "-C", "--directory":
			if v, err = take(); err == nil {
				opts.Directory = v
			}
		case "-w", "--workspace":
			if v, err = take(); err == nil {
				opts.Workspace = v
			}
		case "-c", "--config":
			if v, err = take(); err == nil {
				opts.ConfigFile = v
			}
		case "--no-config":
			opts.NoConfig = true
		case "-b", "--backend":
			if v, err = take(); err == nil {
				opts.Backend = v
			}
		case "--min-isolation":
			if v, err = take(); err == nil {
				opts.MinIsolation = v
			}
		case "--force-isolation":
			if v, err = take(); err == nil {
				opts.ForceIsolation = v
			}
		case "-e", "--env":
			if v, err = take(); err == nil {
				opts.Env = append(opts.Env, v)
			}
		case "-E", "--env-passthrough":
			if v, err = take(); err == nil {
				opts.EnvPassthrough = append(opts.EnvPassthrough, v)
			}
		case "--network":
			if v, err = take(); err == nil {
				opts.NetworkMode = v
			}
		case "--rebuild":
			opts.Rebuild = true
		case "--recreate":
			opts.Recreate = true
		case "--root":
			opts.Root = true
		case "--no-mask":
			opts.NoMask = true
		case "--dry-run":
			opts.DryRun = true
		case "--json":
			opts.JSON = true
		case "-q", "--quiet":
			opts.Quiet = true
		case "-v", "--verbose":
			opts.Verbose = true
		case "--timeout":
			if v, err = take(); err == nil {
				if opts.Timeout, err = strconv.Atoi(v); err != nil {
					err = app.Usagef("--timeout expects seconds, got %q", v)
				}
			}
		case "-h", "--help":
			usage(os.Stdout)
			return 0, nil
		default:
			return 0, app.Usagef("unknown flag %s (see `agentbox help`)", a)
		}
		if err != nil {
			return 0, err
		}
	}

	// Interpretation: first non-flag argument that is a reserved
	// subcommand dispatches; anything else is a command to run in the box.
	// `--` forces the in-box interpretation.
	if forced {
		if len(rest) == 0 {
			return 0, app.Usagef("`--` requires a command to run in the box")
		}
		return runInBox(opts, rest, false)
	}
	if len(rest) == 0 {
		return runInBox(opts, nil, false)
	}
	cmd, cmdArgs := rest[0], rest[1:]
	if !reserved[cmd] {
		for _, tok := range rest {
			if reserved[tok] {
				fmt.Fprintf(os.Stderr, "agentbox: note: %q matches a reserved subcommand; use `--` if you meant to run it in the box\n", tok)
				break
			}
		}
		return runInBox(opts, rest, false)
	}
	return dispatch(opts, cmd, cmdArgs)
}

func runFsd(args []string) (int, error) {
	spec, pidfile := "", ""
	for j := 0; j < len(args); j++ {
		switch {
		case args[j] == "--spec" && j+1 < len(args):
			spec = args[j+1]
			j++
		case args[j] == "--pidfile" && j+1 < len(args):
			pidfile = args[j+1]
			j++
		}
	}
	if spec == "" {
		return 0, app.Usagef("fsd: --spec is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := share.RunDaemon(ctx, spec, pidfile, os.Stdout); err != nil {
		return 0, app.Softwaref("fsd: %v", err)
	}
	return 0, nil
}

func runInBox(opts *app.Options, argv []string, shell bool) (int, error) {
	c, err := app.Resolve(opts)
	if err != nil {
		return 0, err
	}
	code, err := c.CmdRun(argv, shell)
	if err == app.ErrHandled {
		return 0, nil
	}
	return code, err
}

// takesInBoxArgs reports whether a subcommand's trailing arguments are a
// command line for the box rather than for agentbox.
func takesInBoxArgs(cmd string) bool { return cmd == "run" || cmd == "shell" }

// flagScanLimit returns how much of args agentbox may interpret as its own
// subcommand-local flags.
//
// After `run`, args *is* the command line for the box, and agentbox has no
// business rewriting it: scanning the whole slice means `agentbox run mytool
// --root` quietly drops the tool's own --root and runs the box as root
// instead. So for those subcommands only the leading run of flags counts,
// ending at the first bare word or at `--`. Every other subcommand takes no
// positional arguments, so its flags stay recognised anywhere.
func flagScanLimit(cmd string, args []string) int {
	if !takesInBoxArgs(cmd) {
		return len(args)
	}
	n := 0
	for n < len(args) && strings.HasPrefix(args[n], "-") && args[n] != "--" {
		n++
	}
	return n
}

// stripFlagTerminator drops the `--` that ended agentbox's flags, which is
// what gives a command whose own first argument looks like a flag a way
// through: `agentbox run -- mytool --root`.
func stripFlagTerminator(cmd string, args []string) []string {
	if takesInBoxArgs(cmd) && len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}

func dispatch(opts *app.Options, cmd string, args []string) (int, error) {
	scan := flagScanLimit(cmd, args)
	boolFlag := func(name string) bool {
		for j := 0; j < scan; j++ {
			if args[j] == name {
				args = append(args[:j:j], args[j+1:]...)
				scan--
				return true
			}
		}
		return false
	}
	if boolFlag("--json") {
		opts.JSON = true
	}
	// --root is accepted after `run`/`shell` as well as before, because
	// `agentbox run --root cmd` is how everyone writes it and silently
	// forwarding it to the guest as an argument is a baffling failure.
	if boolFlag("--root") {
		opts.Root = true
	}
	args = stripFlagTerminator(cmd, args)

	if cmd == "help" {
		usage(os.Stdout)
		return 0, nil
	}

	c, err := app.Resolve(opts)
	if err != nil {
		return 0, err
	}

	var cmdErr error
	switch cmd {
	case "run":
		if len(args) == 0 {
			return 0, app.Usagef("run requires a command")
		}
		return c.CmdRun(args, false)
	case "shell":
		return c.CmdRun(nil, true)
	case "up":
		cmdErr = c.CmdUp()
	case "down":
		cmdErr = c.CmdDown()
	case "status":
		cmdErr = c.CmdStatus()
	case "logs":
		cmdErr = c.CmdLogs(boolFlag("--proxy"), boolFlag("--denied"), boolFlag("-f") || boolFlag("--follow"))
	case "build":
		cmdErr = c.CmdBuild(boolFlag("--no-cache"))
	case "config":
		cmdErr = c.CmdConfig(boolFlag("--origin"))
	case "init":
		cmdErr = c.CmdInit()
	case "rm":
		cmdErr = c.CmdRm(boolFlag("--keep-image"))
	case "version":
		cmdErr = c.CmdVersion()
	default:
		return 0, app.Usagef("unknown subcommand %q", cmd)
	}
	if cmdErr == app.ErrHandled {
		return 0, nil
	}
	if cmdErr != nil {
		return 0, cmdErr
	}
	return 0, nil
}

func usage(w *os.File) {
	fmt.Fprint(w, `agentbox — run an agentic coding tool in an isolated per-project environment

usage:
  agentbox [flags] [COMMAND] [ARGS...]
  agentbox [flags] [--] COMMAND-IN-BOX [ARGS...]

There is one box per workspace root: cd into a project and you are in its box.
For a second box, make a second root — `+"`git worktree add ../feature`"+` gets its
own box, on its own branch, for free.

Commands not in the reserved set run inside the box. Reserved:
  run shell up down status logs build config init rm version help

  run CMD...      run a command in the box
  shell           interactive shell in the box
  up              create and start the box; run nothing
  down            stop and remove the box, keeping its home and identity
  rm              remove the box and everything it holds, image included
  status          backend, tier, egress, masking, and any config drift
  logs            box logs (--proxy for the egress proxy, --denied for refusals)
  build           build or rebuild the image (--no-cache)
  config          the effective merged configuration (--origin to attribute it)
  init            scaffold agentbox.toml and .agentignore
  version         agentbox and backend versions

Key flags:
  -C DIR          resolve the workspace as if from DIR
  -w DIR          override workspace-root detection
  -c FILE         use FILE as the workspace config layer
  --no-config     built-in defaults only
  -b NAME         select a backend (never below the isolation floor)
  --min-isolation T  raise the floor for this invocation
  --force-isolation T  lower it; recorded, and warned on every invocation
  --network MODE  off | proxy | open
  -e KEY=VAL      set a variable in the box
  -E KEY          pass a host variable through
  --rebuild       rebuild the image before starting
  --recreate      recreate the box from current configuration
  --root          run as uid 0 inside the box
  --no-mask       disable secret masking for this invocation (warns, loudly)
  --dry-run       print the full plan, including every mask; change nothing
  --json          machine-readable output where supported
  -q / -v         quieter / more verbose diagnostics

Configuration layers, lowest first: built-in, user
($XDG_CONFIG_HOME/agentbox/config.toml), workspace (agentbox.toml), flags.
`)
}
