// Package ignore implements .gitignore pattern semantics. It is the
// single shared matcher used by every masking layer: Layer 0 mount
// construction and the Layer 3 lookup filter MUST evaluate the same compiled
// pattern set from the same code.
//
// Semantics match gitignore:
//   - '#' comments; blank lines ignored; trailing whitespace insignificant
//     unless backslash-escaped
//   - '!' negates; the last matching pattern wins
//   - trailing '/' matches directories only
//   - a leading or embedded '/' anchors the pattern to the root; otherwise
//     it matches at any depth
//   - '*' and '?' do not cross '/'; '**' does
//   - '[...]' character classes, with '!' or '^' negation
//
// All patterns are evaluated relative to the workspace root: there are
// exactly two pattern sources (a user-global file and workspace-root files),
// so there is no per-directory anchoring as in nested .gitignore files.
package ignore

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Rule is one compiled pattern line.
type Rule struct {
	Pattern  string // original line, for diagnostics
	Source   string // file it came from
	Line     int
	Negate   bool
	DirOnly  bool
	anchored bool // pattern is relative to the root (a '/' in the body)
	re       *regexp.Regexp
}

// Matcher is an ordered rule list; later rules override earlier ones.
type Matcher struct {
	rules []Rule
}

// Decision is the outcome of matching one path against the rule list.
type Decision int

const (
	NoMatch  Decision = iota // no rule matched
	Ignored                  // last matching rule ignores
	Included                 // last matching rule was a negation
)

// AddFile parses one ignore file and appends its rules. Later files take
// precedence over earlier ones via last-match-wins.
func (m *Matcher) AddFile(r io.Reader, source string) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if rule, ok := CompileLine(sc.Text(), source, line); ok {
			m.rules = append(m.rules, rule)
		}
	}
	return sc.Err()
}

// Rules exposes the compiled set (for masks.json and diagnostics).
func (m *Matcher) Rules() []Rule { return m.rules }

// HasAnchored reports whether any rule is anchored to the root (its body
// contains a '/'). Unanchored rules match by basename at any depth, so they
// are invariant under renaming an ancestor directory; anchored rules are not.
// The Layer 3 daemon uses this to decide whether a directory rename can
// relocate a masked path out from under its pattern. Negated rules count:
// an anchored negation can re-expose a path when its parent is renamed.
func (m *Matcher) HasAnchored() bool {
	for i := range m.rules {
		if m.rules[i].anchored {
			return true
		}
	}
	return false
}

// CompileLine compiles a single pattern line. ok is false for blanks and
// comments.
func CompileLine(raw, source string, line int) (Rule, bool) {
	text := trimTrailingSpace(raw)
	if text == "" || strings.HasPrefix(text, "#") {
		return Rule{}, false
	}
	rule := Rule{Pattern: raw, Source: source, Line: line}

	if strings.HasPrefix(text, "!") {
		rule.Negate = true
		text = text[1:]
	} else if strings.HasPrefix(text, `\!`) || strings.HasPrefix(text, `\#`) {
		text = text[1:]
	}

	if strings.HasSuffix(text, "/") {
		rule.DirOnly = true
		text = strings.TrimSuffix(text, "/")
	}
	if text == "" {
		return Rule{}, false
	}

	// Anchoring: a leading or embedded '/' anchors to the root; otherwise
	// the pattern matches at any depth (equivalent to a "**/" prefix).
	anchored := strings.Contains(text, "/")
	rule.anchored = anchored
	text = strings.TrimPrefix(text, "/")
	if text == "" {
		return Rule{}, false
	}

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString(`(?:.*/)?`)
	}
	translateBody(&b, text)
	b.WriteString("$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		// An unmatched '[' makes the pattern unusable; git treats such
		// patterns as never matching. Do the same rather than failing.
		return Rule{}, false
	}
	rule.re = re
	return rule, true
}

// translateBody converts the slash-separated pattern into a regexp.
func translateBody(b *strings.Builder, text string) {
	segs := strings.Split(text, "/")
	for i, seg := range segs {
		last := i == len(segs)-1
		if seg == "**" {
			if i == 0 && last {
				b.WriteString(`.*`)
			} else if i == 0 {
				b.WriteString(`(?:.*/)?`)
			} else if last {
				// "a/**" matches everything inside a, not a itself.
				b.WriteString(`.*`)
			} else {
				b.WriteString(`(?:.*/)?`)
			}
			continue
		}
		translateSegment(b, seg)
		if !last {
			// If the next segment is a middle "**", it emits its own
			// separator handling; otherwise emit '/'.
			next := segs[i+1]
			if next == "**" && i+1 < len(segs)-1 {
				b.WriteString(`/`)
			} else if next == "**" && i+1 == len(segs)-1 {
				b.WriteString(`/`)
			} else {
				b.WriteString(`/`)
			}
		}
	}
}

// translateSegment converts one path segment ('*', '?', '[...]', escapes).
func translateSegment(b *strings.Builder, seg string) {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch c {
		case '*':
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '\\':
			if i+1 < len(seg) {
				b.WriteString(regexp.QuoteMeta(string(seg[i+1])))
				i++
			} else {
				b.WriteString(regexp.QuoteMeta(`\`))
			}
		case '[':
			j, class, ok := translateClass(seg[i:])
			if ok {
				b.WriteString(class)
				i += j - 1
			} else {
				b.WriteString(regexp.QuoteMeta("["))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
}

// translateClass translates a '[...]' class starting at s[0]=='['. Returns
// the number of bytes consumed and the regexp fragment.
func translateClass(s string) (int, string, bool) {
	var b strings.Builder
	b.WriteString("[")
	i := 1
	if i < len(s) && (s[i] == '!' || s[i] == '^') {
		b.WriteString("^")
		i++
	}
	if i < len(s) && s[i] == ']' {
		// Literal ']' first in class.
		b.WriteString(`\]`)
		i++
	}
	for i < len(s) {
		switch s[i] {
		case ']':
			b.WriteString("]")
			return i + 1, b.String(), true
		case '\\':
			if i+1 < len(s) {
				b.WriteString(regexp.QuoteMeta(string(s[i+1])))
				i += 2
			} else {
				return 0, "", false
			}
		case '[':
			// POSIX classes like [:alpha:] pass through; a bare '[' is
			// literal inside a class.
			if strings.HasPrefix(s[i:], "[:") {
				end := strings.Index(s[i:], ":]")
				if end < 0 {
					return 0, "", false
				}
				b.WriteString(s[i : i+end+2])
				i += end + 2
			} else {
				b.WriteString(`\[`)
				i++
			}
		case '/':
			// A slash never matches inside a class in gitignore.
			b.WriteString(`\/`)
			i++
		default:
			// Copy ranges and ordinary characters, escaping regexp
			// metacharacters other than '-'.
			c := s[i]
			if c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				b.WriteByte(c)
			} else {
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
			i++
		}
	}
	return 0, "", false
}

func trimTrailingSpace(s string) string {
	// Trailing whitespace is insignificant unless escaped.
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	if end > 0 && s[end-1] == '\\' && end < len(s) {
		end++ // keep one escaped trailing space
		// Remove the backslash by rebuilding.
		return s[:end-2] + s[end-1:end]
	}
	return s[:end]
}

// MatchPath returns the decision for one path (no ancestor logic).
// rel uses '/' separators and no leading './'.
func (m *Matcher) MatchPath(rel string, isDir bool) (Decision, *Rule) {
	d := NoMatch
	var winner *Rule
	for i := range m.rules {
		r := &m.rules[i]
		if r.DirOnly && !isDir {
			continue
		}
		if r.re.MatchString(rel) {
			if r.Negate {
				d = Included
			} else {
				d = Ignored
			}
			winner = r
		}
	}
	return d, winner
}

// IsIgnored applies full gitignore semantics including the parent rule: a
// path inside an ignored directory is ignored regardless of negations
// (re-inclusion under an excluded directory is not possible).
func (m *Matcher) IsIgnored(rel string, isDir bool) bool {
	ignored, _ := m.Explain(rel, isDir)
	return ignored
}

// Explain returns the decision and the rule responsible.
func (m *Matcher) Explain(rel string, isDir bool) (bool, *Rule) {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		anc := strings.Join(parts[:i], "/")
		if d, r := m.MatchPath(anc, true); d == Ignored {
			return true, r
		}
	}
	d, r := m.MatchPath(rel, isDir)
	return d == Ignored, r
}
