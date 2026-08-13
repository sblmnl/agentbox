package main

import (
	"strings"
	"testing"
)

// consumeFlags replays what dispatch does to args: consume the
// subcommand-local boolean flags within the scan limit, then drop a leading
// `--`. It exists so the interpretation boundary can be tested without a
// workspace, a config, or an engine.
func consumeFlags(cmd string, args []string, names ...string) (map[string]bool, []string) {
	scan := flagScanLimit(cmd, args)
	seen := map[string]bool{}
	for _, name := range names {
		for j := 0; j < scan; j++ {
			if args[j] == name {
				args = append(args[:j:j], args[j+1:]...)
				scan--
				seen[name] = true
				break
			}
		}
	}
	return seen, stripFlagTerminator(cmd, args)
}

// The command after `run` belongs to the box. agentbox reading its own flag
// names out of the middle of it rewrites the user's command line silently,
// and `--root` is a name real tools use.
func TestRunArgsAreNotRewritten(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		args     []string
		wantRoot bool
		wantRest []string
	}{
		{
			name:     "leading flag is agentbox's",
			cmd:      "run",
			args:     []string{"--root", "mytool"},
			wantRoot: true,
			wantRest: []string{"mytool"},
		},
		{
			name:     "trailing flag belongs to the in-box command",
			cmd:      "run",
			args:     []string{"mytool", "--root"},
			wantRoot: false,
			wantRest: []string{"mytool", "--root"},
		},
		{
			name:     "-- ends agentbox's flags and is dropped",
			cmd:      "run",
			args:     []string{"--", "mytool", "--root"},
			wantRoot: false,
			wantRest: []string{"mytool", "--root"},
		},
		{
			name:     "--json is not lifted out of the command either",
			cmd:      "run",
			args:     []string{"mytool", "--json"},
			wantRest: []string{"mytool", "--json"},
		},
		{
			name:     "both leading flags still parse",
			cmd:      "run",
			args:     []string{"--root", "--json", "mytool", "sub"},
			wantRoot: true,
			wantRest: []string{"mytool", "sub"},
		},
		{
			name:     "subcommands without in-box args keep scanning everywhere",
			cmd:      "logs",
			args:     []string{"--json"},
			wantRest: []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seen, rest := consumeFlags(c.cmd, c.args, "--json", "--root")
			if seen["--root"] != c.wantRoot {
				t.Errorf("--root consumed = %v, want %v", seen["--root"], c.wantRoot)
			}
			if strings.Join(rest, " ") != strings.Join(c.wantRest, " ") {
				t.Errorf("in-box argv = %v, want %v", rest, c.wantRest)
			}
		})
	}
}
