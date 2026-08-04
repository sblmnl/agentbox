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
	"github.com/sblmnl/agentbox/internal/netpol"
	"github.com/sblmnl/agentbox/internal/share"
	"github.com/sblmnl/agentbox/internal/state"
)

// Reserved subcommands are a closed, documented set; adding one that
// collides with a common binary name is a breaking change.
var reserved = map[string]bool{
	"run": true, "shell": true, "new": true, "attach": true, "default": true,
	"up": true, "stop": true, "down": true, "restart": true, "status": true,
	"ps": true, "logs": true, "build": true, "config": true, "mounts": true,
	"masks": true, "backends": true, "allow": true, "bundles": true,
	"init": true, "ls": true, "rm": true, "prune": true, "doctor": true,
	"trust": true, "completion": true, "version": true, "help": true,
}

// trustLenient marks the read-only commands that proceed with a warning when
// the workspace config is untrusted — they are the supported way to
// review what an untrusted config would do. Everything else that could run
// hooks or materialize mounts is refused until `agentbox trust`.
var trustLenient = map[string]bool{
	"config": true, "mounts": true, "masks": true, "backends": true,
	"bundles": true, "doctor": true, "version": true, "ls": true,
	"status": true, "ps": true, "logs": true, "prune": true, "stop": true,
	"down": true, "rm": true, "trust": true, "completion": true,
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
	// `proxyd` is the hidden host-proxy daemon entry point for the vm
	// backend, spawned by agentbox itself. It is intercepted before
	// interpretation: it needs no workspace and is not part of the
	// documented, closed subcommand set.
	if len(args) > 0 && args[0] == "proxyd" {
		return runProxyd(args[1:])
	}
	// `fsd` is the hidden share-daemon entry point for mask_mode "filter"
	// (the Layer 3 filtered share), likewise spawned by agentbox itself
	// and intercepted before interpretation.
	if len(args) > 0 && args[0] == "fsd" {
		return runFsd(args[1:])
	}
	// `vsockfwd` is the hidden in-guest half of the vm tier's egress path:
	// the same binary, bind-mounted into the box and run there, forwarding
	// loopback to the host daemon over vsock. Intercepted for the same
	// reason as the others — it is not part of the documented subcommand
	// set and needs no workspace.
	if len(args) > 0 && args[0] == "vsockfwd" {
		return runVsockfwd(args[1:])
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
		case "-n", "--name":
			if v, err = take(); err == nil {
				opts.Name = v
			}
		case "--new":
			opts.New = true
		case "--all":
			opts.All = true
		case "--tree-mode":
			if v, err = take(); err == nil {
				opts.TreeMode = v
			}
		case "-p", "--profile":
			if v, err = take(); err == nil {
				opts.Profile = v
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
		case "--offline":
			opts.Offline = true
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

func runProxyd(args []string) (int, error) {
	root := ""
	for j := 0; j < len(args); j++ {
		if args[j] == "--state-root" && j+1 < len(args) {
			root = args[j+1]
			j++
		}
	}
	if root == "" {
		root = state.Dir()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := netpol.RunDaemon(ctx, root, os.Stdout); err != nil {
		return 0, app.Softwaref("proxyd: %v", err)
	}
	return 0, nil
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

// runVsockfwd reads its token from the environment rather than a flag: the
// box's own process table is readable by the agent, and a token on a command
// line is a capability on display.
func runVsockfwd(args []string) (int, error) {
	spec := &netpol.GuestForwarderSpec{
		Listen: "127.0.0.1:" + strconv.Itoa(netpol.VsockPort),
		Token:  os.Getenv("AGENTBOX_VSOCK_TOKEN"),
		Port:   netpol.VsockPort,
	}
	for j := 0; j < len(args); j++ {
		if args[j] == "--listen" && j+1 < len(args) {
			spec.Listen = args[j+1]
			j++
		}
	}
	if spec.Token == "" {
		return 0, app.Usagef("vsockfwd: AGENTBOX_VSOCK_TOKEN is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := netpol.RunGuestForwarder(ctx, spec, os.Stderr); err != nil {
		return 0, app.Softwaref("vsockfwd: %v", err)
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

func dispatch(opts *app.Options, cmd string, args []string) (int, error) {
	// Subcommand-local flags.
	var boolFlag = func(name string) bool {
		for j, a := range args {
			if a == name {
				args = append(args[:j:j], args[j+1:]...)
				return true
			}
		}
		return false
	}
	var stringFlag = func(name string) string {
		for j, a := range args {
			if a == name && j+1 < len(args) {
				v := args[j+1]
				args = append(args[:j:j], args[j+2:]...)
				return v
			}
			if strings.HasPrefix(a, name+"=") {
				args = append(args[:j:j], args[j+1:]...)
				return a[len(name)+1:]
			}
		}
		return ""
	}
	if boolFlag("--json") {
		opts.JSON = true
	}

	if cmd == "help" {
		usage(os.Stdout)
		return 0, nil
	}
	if cmd == "completion" {
		if len(args) != 1 {
			return 0, app.Usagef("completion requires a shell: bash, zsh, or fish")
		}
		return app.CmdCompletion(args[0])
	}
	if trustLenient[cmd] {
		opts.TrustLenient = true
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
	case "new":
		if n := stringFlag("--name"); n != "" {
			opts.Name = n
		}
		cmdErr = c.CmdNew()
	case "attach":
		return c.CmdAttach()
	case "default":
		if len(args) != 1 {
			return 0, app.Usagef("default requires exactly one box name")
		}
		cmdErr = c.CmdDefault(args[0])
	case "up":
		cmdErr = c.CmdUp()
	case "stop":
		cmdErr = c.CmdStop()
	case "down":
		cmdErr = c.CmdDown()
	case "restart":
		cmdErr = c.CmdRestart()
	case "status":
		cmdErr = c.CmdStatus(boolFlag("--artifacts"))
	case "ps":
		cmdErr = c.CmdPs()
	case "logs":
		cmdErr = c.CmdLogs(boolFlag("--proxy"), boolFlag("--denied"), boolFlag("-f") || boolFlag("--follow"))
	case "build":
		cmdErr = c.CmdBuild(boolFlag("--no-cache"))
	case "config":
		cmdErr = c.CmdConfig(boolFlag("--origin"))
	case "mounts":
		cmdErr = c.CmdMounts()
	case "masks":
		cmdErr = c.CmdMasks(boolFlag("--verify"))
	case "backends":
		cmdErr = c.CmdBackends()
	case "allow":
		cmdErr = c.CmdAllow(args)
	case "bundles":
		_ = boolFlag("--list")
		cmdErr = c.CmdBundles(stringFlag("--show"))
	case "init":
		cmdErr = c.CmdInit(stringFlag("--profile"))
	case "ls":
		all := boolFlag("--all")
		_ = boolFlag("--project") // current project is the default scope
		cmdErr = c.CmdLs(all, boolFlag("--artifacts"))
	case "rm":
		removeState := boolFlag("--state")
		deleteBranch := boolFlag("--delete-branch")
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		cmdErr = c.CmdRm(id, removeState, deleteBranch)
	case "prune":
		cmdErr = c.CmdPrune(app.PruneOptions{
			Idle:    boolFlag("--idle"),
			Images:  boolFlag("--images"),
			Boxes:   boolFlag("--boxes"),
			Running: boolFlag("--running"),
			State:   boolFlag("--state"),
			Apply:   boolFlag("--apply"),
		})
	case "doctor":
		cmdErr = c.CmdDoctor()
	case "trust":
		cmdErr = c.CmdTrust(boolFlag("--show"), boolFlag("--revoke"))
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

Commands not in the reserved set run inside the box. Reserved:
  run shell new attach default up stop down restart status ps logs build
  config mounts masks backends allow bundles init ls rm prune doctor trust
  completion version

Key flags:
  -C DIR          resolve the workspace as if from DIR
  -w DIR          override workspace-root detection
  -n NAME         address a box by name or ordinal alias
  --new           create an additional box
  --all           apply stop/down/status to every box in the project
  --tree-mode M   shared | worktree | copy (overrides [workspace].tree_mode)
  -p NAME         apply a profile overlay
  -b NAME         select a backend (never below the isolation floor)
  --min-isolation T  raise the floor for this invocation
  --network MODE  none | proxy | open
  --offline       same as --network none
  --dry-run       print the plan; change nothing
  --json          machine-readable output where supported

Seeing what is held:
  agentbox ls --artifacts        every box and what it is holding, plus what
                                 nothing holds (--all spans projects)
  agentbox status --artifacts    the same, for one box, in detail

Reclaiming disk:
  agentbox prune            report what agentbox can reclaim; removes nothing
  agentbox prune --apply    reclaim it (--images to include built images)

  Boxes are only candidates with --boxes, which widens in named steps:
    --boxes     stopped boxes: the guest, its networks, its tree
    --running   ... also boxes that are running
    --state     ... also each box's persistent home
  Branches are never deleted by prune, at any combination of flags.

`)
}
