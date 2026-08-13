package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sblmnl/agentbox/internal/backend"
	"github.com/sblmnl/agentbox/internal/image"
	"github.com/sblmnl/agentbox/internal/state"
)

// ErrHandled signals "output already produced; exit 0".
var ErrHandled = &ExitError{Code: 0}

func (c *Ctx) printPlan(plan *Plan) error {
	blob, _ := json.MarshalIndent(plan, "", "  ")
	fmt.Println(string(blob))
	return ErrHandled
}

// posture prints what is actually in force, on every invocation that starts a
// box. The workspace config wins over the user's when they disagree -- that is
// ordinary layering -- so the guard against a repo quietly weakening someone's
// setup is not to refuse the value but to state the result. Anything that
// reduced a property relative to the user's own configuration has already been
// warned about by name; this line is the summary that makes the warning make
// sense.
func (c *Ctx) posture(plan *Plan) {
	if c.Opts.Quiet {
		return
	}
	net := plan.Policy.Mode
	if net == "proxy" {
		net = fmt.Sprintf("proxy (%d domain(s) allowed)", len(plan.Policy.Allow))
	}
	masked := "off"
	if plan.Masks != nil && len(plan.Masks.Entries) > 0 {
		masked = fmt.Sprintf("%s, %d path(s) hidden", plan.MaskMode, len(plan.Masks.Entries))
	} else if plan.Masks != nil {
		masked = plan.MaskMode + ", nothing matched"
	}
	fmt.Fprintf(c.Stderr, "agentbox: backend %s (tier %s) | egress %s | masking %s\n",
		plan.Backend.Name, plan.Backend.Tier, net, masked)
}

// CmdRun implements bare `agentbox`, `run CMD...`, and `shell`.
func (c *Ctx) CmdRun(argv []string, interactiveShell bool) (int, error) {
	meta, err := c.selectBox(true)
	if err != nil {
		return 0, err
	}
	if meta == nil {
		return 0, ErrHandled // dry-run path
	}
	plan, err := c.planFor()
	if err != nil {
		return 0, err
	}
	c.emitPlanWarnings(plan)
	c.warnDrift(meta, plan)
	if c.Opts.DryRun {
		return 0, c.printPlan(plan)
	}
	if c.Opts.Recreate {
		if err := c.recreate(meta, plan); err != nil {
			return 0, err
		}
	}

	// Two phases, because bringing the box up and running in it want
	// different locks.
	//
	// ensureUp is a lifecycle transition -- it creates networks, containers
	// and persistent state -- so it needs the exclusive lock. Under the
	// shared one, two `agentbox` invocations in the same workspace both see
	// `Inspect` report the box absent and both try to create it, and the
	// loser gets the engine's "the container name is already in use" wrapped
	// as an internal error. Holding it exclusively turns the loser's
	// re-inspect into the no-op it should always have been.
	//
	// The exec that follows only needs the shared lock: concurrent commands
	// in one box are ordinary, and holding the exclusive lock for the
	// lifetime of an interactive shell would serialize them.
	upLock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return 0, Softwaref("%v", err)
	}
	err = c.ensureUp(meta, plan)
	upLock.Release()
	if err != nil {
		return 0, err
	}

	lock, err := c.Store.LockBoxShared(c.Key)
	if err != nil {
		return 0, Softwaref("%v", err)
	}
	defer lock.Release()

	c.posture(plan)
	c.touchLastExec(meta)

	if len(argv) == 0 {
		argv = c.Cfg.Config.Box.DefaultCommand
		if interactiveShell || len(argv) == 0 {
			argv = []string{"bash", "-l"}
		}
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return 0, err
	}
	es := backend.ExecSpec{
		Argv:    argv,
		TTY:     stdinIsTTY() && stdoutIsTTY(), // only when both are terminals
		Root:    c.Opts.Root,
		Workdir: plan.GuestWorkdir,
		Env:     plan.Env,
	}
	if c.Opts.Root && meta.Tier == "container" {
		// uid 0 in a container guest is not the same claim as vm guest root;
		// the runtime still confines it, but every capability is dropped.
		fmt.Fprintln(c.Stderr, "warning: --root under the container tier runs uid 0 with all capabilities dropped; masking relies on the guest lacking CAP_SYS_ADMIN")
	}
	code, err := be.Exec(plan.ResourceName, es)
	if err != nil {
		if hint := c.missingCommandHint(argv, err.Error()); hint != "" {
			return 0, Usagef("%s", hint)
		}
		return 0, Softwaref("%v", err)
	}
	// 126/127 is deliberately NOT hinted on. Those codes are indistinguishable
	// from the same codes produced by a command that ran perfectly well --
	// `bash -c 'nosuchtool'`, or make propagating a 127 out of a recipe --
	// and agentbox has no way to tell the two apart without the engine
	// saying so, which is what the err branch above reads. Guessing there
	// tells a user whose build is broken that bash is missing from the box.
	return code, nil // in-box exit code returned verbatim
}

// missingCommandHint explains an in-box command that could not be started.
//
// The failure that produces it is the most likely first-run mistake there is:
// `agentbox claude` in a project whose config allows Claude's *egress*
// (`[network].bundles = ["agent:claude-code"]`) but never asked for the agent
// to be installed (`[agents].install = ["claude-code"]`). Those two names are
// a character apart in the places people copy them from, and the runtime's own
// answer -- "the file claude was not found", attached to a container id -- says
// nothing about either.
func (c *Ctx) missingCommandHint(argv []string, engineErr string) string {
	if len(argv) == 0 {
		return ""
	}
	// The engine's own words are the only evidence that the *box* is what
	// failed. Without them the hint is a guess, and the guess is wrong for
	// every command that ran and exited 126/127 on its own account.
	if !strings.Contains(engineErr, "not found") &&
		!strings.Contains(engineErr, "no such file") &&
		!strings.Contains(engineErr, "executable file not found") {
		return ""
	}
	cmd := argv[0]
	if agent, ok := image.AgentForCommand(cmd); ok {
		installed := false
		for _, a := range c.Cfg.Config.Agents.Install {
			if a == agent {
				installed = true
			}
		}
		if !installed {
			return fmt.Sprintf("%q is not installed in this box.\n"+
				"Add it to the image and rebuild the box:\n\n"+
				"    [agents]\n    install = [%q]\n\n"+
				"then run `agentbox --recreate %s`. Note that [network].bundles = [\"agent:%s\"] only\n"+
				"opens egress to its endpoints; it does not install anything.",
				cmd, agent, cmd, agent)
		}
		return fmt.Sprintf("%q is configured in [agents].install but is not present in the box's image.\n"+
			"The image predates that setting; rebuild it with `agentbox --recreate --rebuild %s`.", cmd, cmd)
	}
	return fmt.Sprintf("%q was not found in the box.\n"+
		"Install it via [image].packages or a [toolchains] entry, then `agentbox --recreate`.", cmd)
}

func (c *Ctx) recreate(meta *state.BoxMeta, plan *Plan) error {
	lock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer lock.Release()

	be, err := c.activeBackend(meta)
	if err == nil {
		_ = be.Remove(plan.ResourceName, true)
	}
	meta.ConfigDigest = c.ConfigDigest()
	meta.ImageRef = plan.Image.Ref
	meta.MaskDigest = plan.MaskDigest()
	meta.Backend = plan.Backend.Name
	meta.Tier = string(plan.Backend.Tier)
	if err := c.Store.SaveBox(meta); err != nil {
		return Softwaref("%v", err)
	}
	return c.writeGeneratedArtifacts(plan)
}

// CmdUp creates and starts the box without running anything in it.
func (c *Ctx) CmdUp() error {
	meta, err := c.selectBox(true)
	if err != nil {
		return err
	}
	if meta == nil {
		return ErrHandled
	}
	plan, err := c.planFor()
	if err != nil {
		return err
	}
	c.emitPlanWarnings(plan)
	c.warnDrift(meta, plan)
	if c.Opts.DryRun {
		return c.printPlan(plan)
	}
	lock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer lock.Release()
	if err := c.ensureUp(meta, plan); err != nil {
		return err
	}
	c.posture(plan)
	return nil
}

// CmdDown stops the box and removes its guest and networks. The persistent
// home and the box's identity survive, so `agentbox` brings back the same box
// rather than a fresh one -- that is what separates `down` from `rm`.
func (c *Ctx) CmdDown() error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	lock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}
	defer lock.Release()

	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	if err := be.Remove(ResourceNameFor(c.Slug, c.Key), true); err != nil {
		return Softwaref("%v", err)
	}
	c.Notef("box stopped and removed; its home and configuration are kept (`agentbox rm` discards those too)")
	return nil
}

// CmdRm removes the box and everything it holds: guest, networks, persistent
// home volume, recorded state, and -- unless it is shared with another box --
// the image built for it.
func (c *Ctx) CmdRm(keepImage bool) error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	lock, err := c.Store.LockBoxExclusive(c.Key)
	if err != nil {
		return Softwaref("%v", err)
	}

	resource := ResourceNameFor(c.Slug, c.Key)
	be, beErr := c.activeBackend(meta)
	if beErr == nil {
		// keepState=false: the persistent home volume goes with the box.
		if err := be.Remove(resource, false); err != nil {
			lock.Release()
			return Softwaref("%v", err)
		}
	}

	switch {
	case keepImage || beErr != nil || meta.ImageRef == "":
	case !meta.ImageBuilt:
		// A pinned [image].ref is the user's image, not ours; agentbox only
		// reclaims what it built.
		c.Notef("image %s kept: agentbox did not build it ([image].ref)", meta.ImageRef)
	default:
		if shared, other := c.imageSharedWith(meta); shared {
			c.Notef("image %s kept: it is also used by the box for %s", meta.ImageRef, other)
		} else if err := be.RemoveImage(meta.ImageRef); err != nil {
			// A build cache or another tag can legitimately hold the image;
			// failing the whole removal over it would leave the box
			// half-removed, which is worse than a retained image.
			c.Notef("could not remove image %s: %v", meta.ImageRef, err)
		} else {
			c.Notef("removed image %s", meta.ImageRef)
		}
	}

	// Release before removing the directory the lock file lives in.
	lock.Release()
	if err := c.Store.RemoveBox(c.Key); err != nil {
		return Softwaref("%v", err)
	}
	c.Notef("removed the box for %s and everything it held", c.Workspace)
	return nil
}

// imageSharedWith reports whether another box references the same image, so
// `rm` never deletes an image out from under a box that is still using it.
func (c *Ctx) imageSharedWith(meta *state.BoxMeta) (bool, string) {
	boxes, err := c.Store.ListBoxes()
	if err != nil {
		// Unable to tell: assume shared. Keeping an image costs disk; removing
		// one another box needs costs that box its next start.
		return true, "another workspace (box list unreadable)"
	}
	for _, b := range boxes {
		if b.Key != meta.Key && b.ImageRef == meta.ImageRef {
			return true, b.WorkspaceRealpath
		}
	}
	return false, ""
}

// CmdBuild builds or rebuilds the image.
func (c *Ctx) CmdBuild(noCache bool) error {
	plan, err := c.BuildPlan()
	if err != nil {
		return err
	}
	avs := c.Availabilities()
	for _, av := range avs {
		if av.Available && av.Name == "container" {
			return c.buildImage(backend.NewContainerBackend(av.Runtime), plan, noCache)
		}
	}
	// A vm-only host builds through the same engine CLI; the VM runtime is
	// not involved in a build (the image is the same artifact).
	for _, av := range avs {
		if av.Available && av.Name == "vm" {
			return c.buildImage(backend.NewVMBackend(av.Runtime, c.Store.Root), plan, noCache)
		}
	}
	return Unavailablef("no available backend can build images on this host")
}

// WriteBuildContext lays down the Dockerfile under the cache dir and returns
// the build-context directory. A user-supplied [image].dockerfile is copied in
// verbatim (its 16-hex content digest names the dir, matching the resolved
// tag); otherwise agentbox generates the Dockerfile from features. The context
// contains only the Dockerfile, so a custom Dockerfile must be self-contained
// (install via RUN rather than COPY host files; use [image].ref for the latter).
func (c *Ctx) WriteBuildContext() (string, error) {
	cfg := c.Cfg.Config
	var df []byte
	var digest string
	if p := cfg.Image.Dockerfile; p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", Configf("reading [image].dockerfile %q: %v", p, err)
		}
		df, digest = data, image.DockerfileDigest(data)
	} else {
		df = []byte(image.Dockerfile(cfg, os.Getuid(), os.Getgid()))
		digest = image.FeaturesFrom(cfg).Digest()
	}
	dir := filepath.Join(state.CacheDir(), "build", digest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", Softwaref("%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o600); err != nil {
		return "", Softwaref("%v", err)
	}
	return dir, nil
}

// CmdLogs shows box or proxy logs; --denied filters the proxy log to
// refused requests.
func (c *Ctx) CmdLogs(proxy, denied, follow bool) error {
	meta, err := c.selectBox(false)
	if err != nil {
		return err
	}
	be, err := c.activeBackend(meta)
	if err != nil {
		return err
	}
	resource := ResourceNameFor(c.Slug, c.Key)
	if denied {
		proxy = true
	}
	if !denied {
		return be.Logs(resource, proxy, follow)
	}
	// Denied filter: squid logs TCP_DENIED for refused requests. Both tiers
	// run the sidecar as a container, so both read it the same way.
	pr, pw, err := os.Pipe()
	if err != nil {
		return Softwaref("%v", err)
	}
	// The engine's stderr gets its own buffer rather than the pipe. Routed
	// into the pipe it would be swallowed by the DENIED filter below, so
	// `logs --denied` against a box whose sidecar is gone -- the ordinary
	// state after `agentbox down` -- would print nothing and exit 0, which
	// reads as "no requests were ever denied".
	var engineErr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		defer pw.Close()
		cmd := be.ProxyLogCmd(resource, follow)
		cmd.Stdout = pw
		cmd.Stderr = &engineErr
		done <- cmd.Run()
	}()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "DENIED") || strings.Contains(line, "/403") {
			fmt.Println(line)
		}
	}
	if err := <-done; err != nil {
		return Usagef("no proxy audit log for box %s: %s",
			resource, strings.TrimSpace(engineErr.String()))
	}
	return nil
}

// CmdVersion prints tool and backend versions.
func (c *Ctx) CmdVersion() error {
	info := map[string]any{
		"agentbox":     ToolVersion,
		"go_generator": image.GeneratorVersion,
		"backends":     c.Availabilities(),
	}
	if c.Opts.JSON {
		blob, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(blob))
		return nil
	}
	fmt.Printf("agentbox %s\n", ToolVersion)
	for _, av := range c.Availabilities() {
		status := "available"
		if !av.Available {
			status = "unavailable: " + av.Reason
		}
		fmt.Printf("backend %s (tier %s): %s\n", av.Name, av.Tier, status)
	}
	return nil
}

// SortedEnvKeys helps deterministic env output.
func SortedEnvKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func stdinIsTTY() bool  { return isTTY(os.Stdin) }
func stdoutIsTTY() bool { return isTTY(os.Stdout) }

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
