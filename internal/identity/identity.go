// Package identity implements project keys, box ids, and instance names.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	slugMax     = 24
	digestChars = 8
)

var instanceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

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

// ProjectKey computes "{slug}-{sha256(realpath)[0:8]}". The caller must pass
// the already-resolved real path; the digest carries identity, the slug is
// for humans.
func ProjectKey(canonicalPath string) string {
	sum := sha256.Sum256([]byte(canonicalPath))
	return SanitizeSlug(filepath.Base(canonicalPath)) + "-" + hex.EncodeToString(sum[:])[:digestChars]
}

// TruncateForLimit shortens a derived resource name to limit by truncating
// the slug, never the digest or instance name.
func TruncateForLimit(slug, digest, rest string, limit int) string {
	fixed := len(digest) + len(rest) + 2 // two joining dashes
	room := limit - fixed
	if room < 1 {
		room = 1
	}
	if len(slug) > room {
		slug = slug[:room]
	}
	return slug + "-" + digest + "-" + rest
}

// ValidInstanceName reports whether name matches [a-z0-9][a-z0-9_-]{0,31}.
func ValidInstanceName(name string) bool { return instanceNameRe.MatchString(name) }

// IsBareInteger reports whether s parses as a decimal integer; such strings
// are reserved for ordinal aliases and rejected as instance names.
func IsBareInteger(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// BoxID is "{project_key}/{instance_name}".
func BoxID(projectKey, instance string) string { return projectKey + "/" + instance }

// Word lists for generated instance names: a word pair, never a
// bare integer, so ordinal aliases stay unambiguous.
var adjectives = []string{
	"amber", "brisk", "calm", "deft", "eager", "fond", "glad", "hardy",
	"ideal", "jolly", "keen", "lucid", "mellow", "nimble", "open", "prime",
	"quick", "rapid", "solid", "tidy", "usable", "vivid", "warm", "young",
}
var nouns = []string{
	"anvil", "boat", "cedar", "delta", "ember", "fjord", "grove", "harbor",
	"inlet", "jade", "kite", "lagoon", "meadow", "north", "orchid", "pine",
	"quartz", "ridge", "spruce", "trail", "upland", "vale", "willow", "yarrow",
}

// GenerateName returns a word-pair instance name not present in taken.
// rng may be nil for the default source.
func GenerateName(taken map[string]bool, rng *rand.Rand) string {
	pick := func(n int) int {
		if rng != nil {
			return rng.Intn(n)
		}
		return rand.Intn(n)
	}
	for i := 0; i < 1000; i++ {
		name := adjectives[pick(len(adjectives))] + "-" + nouns[pick(len(nouns))]
		if !taken[name] {
			return name
		}
	}
	// Exhausted pairs: extend with a suffix derived from attempts.
	for i := 2; ; i++ {
		name := fmt.Sprintf("%s-%s-%c", adjectives[pick(len(adjectives))], nouns[pick(len(nouns))], 'a'+rune(pick(26)))
		if !taken[name] {
			return name
		}
	}
}
