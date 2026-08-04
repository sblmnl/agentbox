// Package mask computes the mask set for a box tree and constructs the
// Layer 0 mask view plan. The pattern matcher is shared code
// (internal/ignore) under every layer; agentbox never maintains two mask
// generators.
package mask

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sblmnl/agentbox/internal/ignore"
)

// EntryKind describes what a masked path is on the host.
type EntryKind string

const (
	KindFile    EntryKind = "file"
	KindDir     EntryKind = "dir"
	KindSymlink EntryKind = "symlink"
)

// Mechanism is the Layer 0 mount used to hide the path.
type Mechanism string

const (
	MechDevNull Mechanism = "devnull-bind" // reads EOF; writes EROFS
	MechTmpfs   Mechanism = "tmpfs"        // appears empty; writes stay in memory
)

// Entry is one masked path in the mask set (masks.json representation,
// shared between Layer 0 and the Layer 3 filter).
type Entry struct {
	// Path is workspace-relative, '/'-separated.
	Path      string    `json:"path"`
	Kind      EntryKind `json:"kind"`
	Mechanism Mechanism `json:"mechanism"`
	// Rule names the pattern that matched, for `mounts` and `masks` output:
	// "why can the agent not see this file".
	Rule       string `json:"rule"`
	RuleSource string `json:"rule_source"`
	RuleLine   int    `json:"rule_line"`
}

// Set is the computed mask set for one box tree.
type Set struct {
	TreeRoot string  `json:"tree_root"`
	Mode     string  `json:"mode"` // "view" | "filter"
	Entries  []Entry `json:"entries"`
	// Sources lists the ignore files consulted, lowest precedence first.
	Sources []string `json:"sources"`
}

// SourceBlob is one ignore file captured as contents, not as a path to
// re-read: the Layer 3 share daemon compiles its filter from blobs frozen
// at spawn, because pattern files live in the guest-writable tree and an
// agent that could edit its own mask patterns could unmask any path.
type SourceBlob struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

// ReadSources reads the ignore files once, in discovery order: the
// user-global agentignore first (lowest precedence), then each
// [masking].ignore_files entry resolved against the tree root. Every
// masking layer is built from the same read, so the compiled matcher and
// any recorded copy of the patterns cannot diverge.
func ReadSources(userGlobalPath, treeRoot string, ignoreFiles []string) ([]SourceBlob, error) {
	var blobs []SourceBlob
	add := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		blobs = append(blobs, SourceBlob{Path: path, Contents: string(data)})
		return nil
	}
	if userGlobalPath != "" {
		if err := add(userGlobalPath); err != nil {
			return nil, err
		}
	}
	for _, rel := range ignoreFiles {
		p := rel
		if !filepath.IsAbs(p) {
			p = filepath.Join(treeRoot, rel)
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}
	return blobs, nil
}

// MatcherFromSources compiles the shared matcher from captured blobs.
func MatcherFromSources(blobs []SourceBlob) (*ignore.Matcher, []string, error) {
	m := &ignore.Matcher{}
	var sources []string
	for _, b := range blobs {
		if err := m.AddFile(strings.NewReader(b.Contents), b.Path); err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", b.Path, err)
		}
		sources = append(sources, b.Path)
	}
	return m, sources, nil
}

// LoadMatcher builds the shared matcher from the discovery order; it is
// ReadSources + MatcherFromSources for callers that do not need to keep
// the blobs.
func LoadMatcher(userGlobalPath, treeRoot string, ignoreFiles []string) (*ignore.Matcher, []string, error) {
	blobs, err := ReadSources(userGlobalPath, treeRoot, ignoreFiles)
	if err != nil {
		return nil, nil, err
	}
	return MatcherFromSources(blobs)
}

// Compute walks the box's tree and produces the mask set. A matched
// directory is masked as a single mount and never descended; a
// symlink is masked as a file regardless of target type, so no mount is
// ever placed over an arbitrary link destination.
func Compute(treeRoot string, m *ignore.Matcher, mode string, sources []string) (*Set, error) {
	set := &Set{TreeRoot: treeRoot, Mode: mode, Sources: sources}

	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("reading %s: %w", dir, err)
		}
		for _, de := range entries {
			name := de.Name()
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			childAbs := filepath.Join(dir, name)

			isSymlink := de.Type()&os.ModeSymlink != 0
			isDir := de.IsDir() && !isSymlink

			decision, rule := m.MatchPath(childRel, isDir)
			if decision == ignore.Ignored {
				e := Entry{Path: childRel}
				switch {
				case isSymlink:
					e.Kind, e.Mechanism = KindSymlink, MechDevNull
				case isDir:
					e.Kind, e.Mechanism = KindDir, MechTmpfs
				default:
					e.Kind, e.Mechanism = KindFile, MechDevNull
				}
				if rule != nil {
					e.Rule, e.RuleSource, e.RuleLine = rule.Pattern, rule.Source, rule.Line
				}
				set.Entries = append(set.Entries, e)
				continue // never descend into a masked directory
			}
			if isDir {
				if err := walk(childAbs, childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(treeRoot, ""); err != nil {
		return nil, err
	}
	sort.Slice(set.Entries, func(i, j int) bool { return set.Entries[i].Path < set.Entries[j].Path })
	return set, nil
}

// MountOp is one Layer 0 mount operation. Ordering is by target depth so
// nested masks apply correctly; container runtimes sort the same way.
type MountOp struct {
	Target    string    `json:"target"` // absolute path inside the view/guest
	Mechanism Mechanism `json:"mechanism"`
	ReadOnly  bool      `json:"read_only"`
	TmpfsSize string    `json:"tmpfs_size,omitempty"`
}

// Layer0Plan converts a mask set into ordered mount operations against the
// guest mount point.
func (s *Set) Layer0Plan(guestMount, tmpfsSize string, filesReadonly bool) []MountOp {
	ops := make([]MountOp, 0, len(s.Entries))
	for _, e := range s.Entries {
		op := MountOp{Target: filepath.Join(guestMount, filepath.FromSlash(e.Path))}
		switch e.Mechanism {
		case MechTmpfs:
			op.Mechanism = MechTmpfs
			op.TmpfsSize = tmpfsSize
		default:
			op.Mechanism = MechDevNull
			op.ReadOnly = filesReadonly
		}
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool {
		di := strings.Count(ops[i].Target, "/")
		dj := strings.Count(ops[j].Target, "/")
		if di != dj {
			return di < dj
		}
		return ops[i].Target < ops[j].Target
	})
	return ops
}

// RetargetOps rebases a Layer 0 plan from the guest mount point onto a
// host-side view root, for the vm backend's share view (Layer 2). An
// op whose target escapes guestMount is a bug upstream and is refused.
func RetargetOps(ops []MountOp, guestMount, viewRoot string) ([]MountOp, error) {
	out := make([]MountOp, 0, len(ops))
	for _, op := range ops {
		rel, err := filepath.Rel(guestMount, op.Target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return nil, fmt.Errorf("mask target %s is outside the guest mount %s", op.Target, guestMount)
		}
		op.Target = filepath.Join(viewRoot, rel)
		out = append(out, op)
	}
	return out, nil
}

// FilterFn returns the Layer 3 lookup predicate: whether a path must be
// reported ENOENT and omitted from directory listings. It is
// evaluated against the same compiled pattern set as Layer 0, from the same
// code — that is the point of the shared matcher.
func FilterFn(m *ignore.Matcher) func(rel string, isDir bool) bool {
	return func(rel string, isDir bool) bool {
		return m.IsIgnored(rel, isDir)
	}
}
