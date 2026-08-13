package config

import (
	"fmt"
	"sort"
	"strings"
)

// A committed workspace config is written by whoever wrote the repository,
// not by the person about to run an agent inside it, and it sits above the
// user layer in precedence. Cloning a repo and running agentbox therefore
// applies configuration you did not write -- including, potentially,
// configuration that drops your isolation tier, opens your egress, or turns
// off masking.
//
// agentbox resolves this by letting the workspace layer win, as any layered
// config would, and then saying so out loud. Silence is the thing that is
// forbidden: the invariant is that nothing may reduce an enforced property
// quietly, not that a project may never ask for a weaker box. A warning on
// every invocation, naming the key, both values and the file that did it, is
// what makes the reduction a decision the user gets to make rather than a
// fact they never learn.
//
// strictness ranks the values of one security-relevant key from loosest to
// strictest. A key is only listed here if its values are genuinely ordered;
// anything else (an allowlist, a backend name) is not a "weaker/stronger"
// question and is reported by `agentbox config --origin` instead.
var strictness = map[string][]any{
	// A VM boundary is strictly stronger than a container boundary.
	"security.min_isolation": {"container", "vm"},
	// No egress at all is stronger than a filtered proxy, which is stronger
	// than an unfiltered route to the internet.
	"network.mode": {"open", "proxy", "off"},
	// Lookup-time filtering catches secrets created after the box starts;
	// a static view does not. "auto" lands between them by construction.
	"security.mask_mode": {"view", "auto", "filter"},

	"security.strip_setuid":                {false, true},
	"workspace.readonly":                   {false, true},
	"security.container.read_only_root":    {false, true},
	"security.container.no_new_privileges": {false, true},
	// A guest that can become root can unmount the masks expressed inside it.
	"security.vm.guest_root": {"allow", "deny"},
}

// WeakenedByWorkspace reports every security-relevant key where the workspace
// layer overrode a value the user had set, in the loosening direction. These
// become warnings printed on every invocation.
func (m *Merged) WeakenedByWorkspace() []string {
	var keys []string
	for k := range strictness {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []string
	for _, key := range keys {
		order := strictness[key]
		hist := m.History[key]

		// The strictest value any layer below the workspace asked for, and
		// who asked for it. Built-in defaults count: a default that is
		// stricter than what the repo requests is still a reduction the user
		// never chose.
		bestRank, bestLayer, bestValue := -1, "", any(nil)
		wsRank, wsValue, wsLayer := -1, any(nil), ""
		for _, c := range hist {
			rank := rankOf(order, c.Value)
			if rank < 0 {
				continue
			}
			if isLayer(c.Layer, LayerWorkspace) {
				wsRank, wsValue, wsLayer = rank, c.Value, c.Layer
				continue
			}
			if isLayer(c.Layer, LayerFlags) {
				// Flags are typed by the person at the prompt. They are
				// allowed to loosen anything, deliberately and per
				// invocation, and they are the last word -- so a flag both
				// clears any prior complaint and is not itself one.
				bestRank, bestLayer, bestValue = -1, "", nil
				wsRank = -1
				continue
			}
			if rank > bestRank {
				bestRank, bestLayer, bestValue = rank, c.Layer, c.Value
			}
		}

		if wsRank < 0 || bestRank < 0 || wsRank >= bestRank {
			continue
		}
		msg := fmt.Sprintf(
			"%s: %s lowered this from %s to %s (%s set %s); the workspace value is in effect",
			key, describeLayer(wsLayer), render(bestValue), render(wsValue),
			describeLayer(bestLayer), render(bestValue))
		if flag := flagFor(key); flag != "" {
			msg += fmt.Sprintf(" -- pass --%s to override it", flag)
		}
		out = append(out, msg)
	}
	return out
}

// rankOf returns the strictness index of v within order, or -1 if v is not a
// value this key ranks.
func rankOf(order []any, v any) int {
	for i, want := range order {
		if want == v {
			return i
		}
	}
	return -1
}

// isLayer reports whether an origin attribution belongs to a layer. File
// backed layers are recorded as "<layer>:<abs path>".
func isLayer(origin, layer string) bool {
	return origin == layer || strings.HasPrefix(origin, layer+":")
}

// describeLayer renders an origin attribution for a human: the file path when
// there is one, the bare layer name otherwise.
func describeLayer(origin string) string {
	if i := strings.IndexByte(origin, ':'); i >= 0 {
		return origin[i+1:]
	}
	if origin == LayerBuiltin {
		return "the built-in default"
	}
	return origin
}

func render(v any) string {
	if s, ok := v.(string); ok {
		return `"` + s + `"`
	}
	return fmt.Sprintf("%v", v)
}

// flagFor names the CLI flag that overrides a key, for the "you can take it
// back" half of the warning. A warning that only scolds is noise; one that
// says what to do about it is not.
//
// It returns "" for the keys no flag can reach, and the caller then omits the
// clause. Naming a flag that does not do what the sentence says is worse than
// naming none: -c/--config takes a path and replaces the whole workspace
// layer rather than overriding one key, so "pass --config to override it"
// sends the user to `flag --config requires a value` and exit 64.
func flagFor(key string) string {
	switch key {
	case "security.min_isolation":
		return "min-isolation"
	case "network.mode":
		return "network"
	default:
		return ""
	}
}
