package backend

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

// Both backends drive a container engine CLI (docker or podman): the
// container backend directly, the vm backend with the engine's OCI VM
// runtime. The command surface used here is identical across the
// two engines, so the plumbing is shared.

// engineRun executes one engine command, folding stderr into the error.
func engineRun(bin string, runner func(args ...string) *exec.Cmd, args ...string) error {
	cmd := runner(args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func engineOutput(runner func(args ...string) *exec.Cmd, args ...string) (string, error) {
	cmd := runner(args...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// engineExec runs `exec` in a started guest, forwarding signals and
// returning the in-guest exit code verbatim.
func engineExec(runner func(args ...string) *exec.Cmd, name string, es ExecSpec) (int, error) {
	args := []string{"exec", "-i"}
	if es.TTY {
		args = append(args, "-t")
	}
	if es.Root {
		args = append(args, "--user", "0:0")
	}
	if es.Workdir != "" {
		args = append(args, "--workdir", es.Workdir)
	}
	for k, v := range es.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, name)
	args = append(args, es.Argv...)

	cmd := runner(args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGWINCH)
	defer signal.Stop(sigc)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigc:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	return 0, err
}

// engineInspect reads a guest's runtime state.
func engineInspect(runner func(args ...string) *exec.Cmd, bin, name string) (State, error) {
	out, err := engineOutput(runner, "inspect", "--format", "{{.State.Running}} {{.State.Pid}} {{.State.Status}}", name)
	if err != nil {
		return State{}, fmt.Errorf("box %q does not exist in the %s runtime", name, bin)
	}
	parts := strings.Fields(out)
	st := State{}
	if len(parts) == 3 {
		st.Running = parts[0] == "true"
		st.Pid, _ = strconv.Atoi(parts[1])
		st.Status = parts[2]
	}
	return st, nil
}

// engineBuild runs an image build with progress on stderr; stdout stays
// clean. Building never involves the VM runtime: the image is the
// same artifact under both tiers.
func engineBuild(runner func(args ...string) *exec.Cmd, dir, tag string, buildArgs map[string]string, noCache bool) error {
	args := []string{"build", "-t", tag}
	if noCache {
		args = append(args, "--no-cache")
	}
	for k, v := range buildArgs {
		args = append(args, "--build-arg", k+"="+v)
	}
	args = append(args, dir)
	cmd := runner(args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
