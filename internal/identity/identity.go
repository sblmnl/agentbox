// Package identity implements the workspace-rooted box key.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

const (
	slugMax     = 24
	digestChars = 8
)

// SanitizeSlug lowercases and reduces a name to [a-z0-9_-], truncated to 24.
func SanitizeSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "workspace"
	}
	if len(s) > slugMax {
		s = s[:slugMax]
	}
	return s
}

// BoxKey computes "{slug}-{sha256(realpath)[0:8]}" -- the identity of the one
// box belonging to a workspace root.
//
// There is exactly one box per workspace root, and the workspace root is the
// whole of its identity. That is what makes agentbox behave the way an agent
// tool is expected to: cd into a project and you are in its box, with no name
// to remember and no list to consult. Parallelism has an answer that costs
// nothing here -- `git worktree add ../feature` is a new root, so it gets its
// own box for free, with its own branch, by virtue of being a different
// directory.
//
// The caller must pass the already-resolved real path; the digest carries
// identity, the slug is only for humans reading `docker ps`.
func BoxKey(canonicalPath string) string {
	sum := sha256.Sum256([]byte(canonicalPath))
	return SanitizeSlug(filepath.Base(canonicalPath)) + "-" + hex.EncodeToString(sum[:])[:digestChars]
}

// TruncateForLimit shortens a derived resource name to limit by truncating
// the slug, never the digest: the digest is what makes the name unique, so
// trimming it would let two workspaces collide on one container name.
func TruncateForLimit(slug, digest string, limit int) string {
	room := limit - len(digest) - 1 // one joining dash
	if room < 1 {
		room = 1
	}
	if len(slug) > room {
		slug = slug[:room]
	}
	return slug + "-" + digest
}
