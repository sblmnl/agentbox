package identity

import (
	"strings"
	"testing"
)

func TestBoxKey(t *testing.T) {
	k1 := BoxKey("/home/u/src/myapp")
	k2 := BoxKey("/home/u/src/myapp")
	k3 := BoxKey("/home/u/other/myapp")
	if k1 != k2 {
		t.Error("key must be deterministic")
	}
	// Same basename, different path: same slug, different digest -- the digest
	// carries identity, the slug is for humans.
	if k1 == k3 {
		t.Error("different canonical paths must yield different keys")
	}
	if !strings.HasPrefix(k1, "myapp-") || len(k1) != len("myapp-")+8 {
		t.Errorf("key format: %s", k1)
	}
}

// A git worktree is how a project gets a second box, so two worktrees of one
// repository must key differently. If they collided, `git worktree add` would
// silently hand the second checkout the first one's box.
func TestWorktreesGetDistinctKeys(t *testing.T) {
	main := BoxKey("/home/u/src/myapp")
	feature := BoxKey("/home/u/src/myapp-feature")
	if main == feature {
		t.Error("a worktree beside its main checkout must get its own box key")
	}
}

func TestSanitizeSlug(t *testing.T) {
	for in, want := range map[string]string{
		"MyApp":                 "myapp",
		"my.app":                "my-app",
		"-weird--":              "weird",
		"":                      "workspace",
		strings.Repeat("x", 40): strings.Repeat("x", 24),
	} {
		if got := SanitizeSlug(in); got != want {
			t.Errorf("SanitizeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// Truncation must never eat the digest: the digest is the only part that
// distinguishes two workspaces sharing a basename, so trimming it would let
// them collide on one container name.
func TestTruncateForLimitKeepsTheDigest(t *testing.T) {
	got := TruncateForLimit(strings.Repeat("s", 40), "deadbeef", 20)
	if len(got) > 20 {
		t.Errorf("length %d > 20: %s", len(got), got)
	}
	if !strings.HasSuffix(got, "deadbeef") {
		t.Errorf("digest must survive truncation: %s", got)
	}
}
