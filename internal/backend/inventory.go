package backend

import (
	"os/exec"
	"strings"
)

// Engine-wide enumeration, for `agentbox prune`.
//
// The rest of this package addresses one box at a time, by name. Pruning is
// the one job that has to ask the opposite question — what does the engine
// hold that no box claims? — because the ways artifacts outlive their box
// (an interrupted create, a state directory removed by hand, a box removed
// by an older agentbox) all leave something behind with nothing left to
// name it.
//
// Everything here is scoped by agentbox's own naming. A resource is a
// candidate only if agentbox would have created it under that name; nothing
// else on the engine is ever a candidate, whatever it looks like.

// ResourceKind is a class of engine-managed artifact.
type ResourceKind string

const (
	KindContainer ResourceKind = "container"
	KindNetwork   ResourceKind = "network"
	KindVolume    ResourceKind = "volume"
	KindImage     ResourceKind = "image"
)

// ResourcePrefix is the name prefix agentbox gives every engine resource it
// creates. Matching on it is what keeps prune off other people's containers.
const ResourcePrefix = "agentbox-"

// ImageRepoPrefix is the repository agentbox builds its images under.
const ImageRepoPrefix = "agentbox/"

// Inventory lists and removes engine resources through one engine CLI.
type Inventory struct {
	Bin    string
	Runner func(args ...string) *exec.Cmd
}

func NewInventory(bin string) *Inventory {
	return &Inventory{
		Bin:    bin,
		Runner: func(args ...string) *exec.Cmd { return exec.Command(bin, args...) },
	}
}

func (inv *Inventory) listArgs(kind ResourceKind) []string {
	switch kind {
	case KindContainer:
		return []string{"ps", "-a", "--format", "{{.Names}}"}
	case KindNetwork:
		return []string{"network", "ls", "--format", "{{.Name}}"}
	case KindVolume:
		return []string{"volume", "ls", "--format", "{{.Name}}"}
	case KindImage:
		return []string{"images", "--format", "{{.Repository}}:{{.Tag}}"}
	}
	return nil
}

// Names lists agentbox-owned resources of a kind. An engine that cannot be
// reached yields nothing rather than an error: prune reports what it can
// see, and a missing engine is not a reason to refuse the whole report.
func (inv *Inventory) Names(kind ResourceKind) []string {
	args := inv.listArgs(kind)
	if args == nil {
		return nil
	}
	out, err := engineOutput(inv.Runner, args...)
	if err != nil {
		return nil
	}
	prefix := ResourcePrefix
	if kind == KindImage {
		prefix = ImageRepoPrefix
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || name == "<none>:<none>" {
			continue
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// Running lists the agentbox containers this engine currently has running.
// It exists because presence and liveness are different answers: a stopped
// proxy sidecar beside a running box is exactly the state a listing that
// only knew "the container exists" would hide.
func (inv *Inventory) Running() map[string]bool {
	out, err := engineOutput(inv.Runner, "ps", "--format", "{{.Names}}")
	if err != nil {
		return nil
	}
	running := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, ResourcePrefix) {
			running[name] = true
		}
	}
	return running
}

// ImageSize returns the engine's own size string for an image ("1.08GB"),
// empty when unknown. It is reported verbatim rather than parsed: the number
// is for a human deciding whether to reclaim it.
func (inv *Inventory) ImageSize(ref string) string {
	out, err := engineOutput(inv.Runner, "images", "--format", "{{.Size}}", ref)
	if err != nil {
		return ""
	}
	if line, _, ok := strings.Cut(strings.TrimSpace(out), "\n"); ok {
		return strings.TrimSpace(line)
	}
	return strings.TrimSpace(out)
}

// Remove deletes one resource. Containers are forced because a candidate may
// still be running; everything else is removed plainly, so a resource that
// turns out to be in use fails loudly instead of taking something with it.
func (inv *Inventory) Remove(kind ResourceKind, name string) error {
	switch kind {
	case KindContainer:
		return engineRun(inv.Bin, inv.Runner, "rm", "-f", name)
	case KindNetwork:
		return engineRun(inv.Bin, inv.Runner, "network", "rm", name)
	case KindVolume:
		return engineRun(inv.Bin, inv.Runner, "volume", "rm", name)
	case KindImage:
		return engineRun(inv.Bin, inv.Runner, "rmi", name)
	}
	return nil
}
