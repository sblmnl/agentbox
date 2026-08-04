// Package state implements the on-disk layout, project and box
// metadata, and two-level locking.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Dir returns $XDG_STATE_HOME/agentbox (or ~/.local/state/agentbox).
func Dir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "agentbox")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "agentbox")
}

// CacheDir returns $XDG_CACHE_HOME/agentbox.
func CacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "agentbox")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "agentbox")
}

// ProjectMeta is projects/<key>/meta.json.
type ProjectMeta struct {
	WorkspaceRealpath string    `json:"workspace_realpath"`
	Slug              string    `json:"slug"`
	DefaultBox        string    `json:"default_box"`
	CreatedAt         time.Time `json:"created_at"`
	// VMTierNoticed records that the one-time notice about
	// auto-selecting the vm tier has been shown for this workspace.
	VMTierNoticed bool `json:"vm_tier_noticed,omitempty"`
}

// BoxMeta is boxes/<instance>/meta.json: everything frozen at
// creation, recomputed and compared on every subsequent invocation.
type BoxMeta struct {
	Instance       string    `json:"instance"`
	ProjectKey     string    `json:"project_key"`
	Backend        string    `json:"backend"`
	Tier           string    `json:"tier"`
	TreeMode       string    `json:"tree_mode"`
	TreeRoot       string    `json:"tree_root"`
	Branch         string    `json:"branch,omitempty"` // worktree mode
	ConfigDigest   string    `json:"config_digest"`
	ImageRef       string    `json:"image_ref"`
	MaskDigest     string    `json:"mask_digest"`
	MaskMode       string    `json:"mask_mode"`
	ForceIsolation string    `json:"force_isolation,omitempty"` // recorded and surfaced
	MemoryLimit    string    `json:"memory_limit"`
	CreatedAt      time.Time `json:"created_at"`
	LastExecAt     time.Time `json:"last_exec_at"`
}

// Store wraps the state directory root (injectable for tests).
type Store struct{ Root string }

func Open(root string) *Store {
	if root == "" {
		root = Dir()
	}
	return &Store{Root: root}
}

func (s *Store) ProjectDir(key string) string { return filepath.Join(s.Root, "projects", key) }
func (s *Store) BoxDir(key, instance string) string {
	return filepath.Join(s.ProjectDir(key), "boxes", instance)
}
func (s *Store) TreeDir(key, instance string) string {
	return filepath.Join(s.BoxDir(key, instance), "tree")
}

func (s *Store) LoadProject(key string) (*ProjectMeta, error) {
	var m ProjectMeta
	if err := readJSON(filepath.Join(s.ProjectDir(key), "meta.json"), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) SaveProject(key string, m *ProjectMeta) error {
	dir := s.ProjectDir(key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "meta.json"), m)
}

func (s *Store) LoadBox(key, instance string) (*BoxMeta, error) {
	var m BoxMeta
	if err := readJSON(filepath.Join(s.BoxDir(key, instance), "meta.json"), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) SaveBox(m *BoxMeta) error {
	dir := s.BoxDir(m.ProjectKey, m.Instance)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "meta.json"), m)
}

// ListBoxes returns a project's boxes ordered by creation time — the order
// that defines ordinal aliases.
func (s *Store) ListBoxes(key string) ([]*BoxMeta, error) {
	dir := filepath.Join(s.ProjectDir(key), "boxes")
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var boxes []*BoxMeta
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if m, err := s.LoadBox(key, e.Name()); err == nil {
			boxes = append(boxes, m)
		}
	}
	sort.Slice(boxes, func(i, j int) bool {
		if boxes[i].CreatedAt.Equal(boxes[j].CreatedAt) {
			return boxes[i].Instance < boxes[j].Instance
		}
		return boxes[i].CreatedAt.Before(boxes[j].CreatedAt)
	})
	return boxes, nil
}

// ListProjects enumerates all project keys.
func (s *Store) ListProjects() ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(s.Root, "projects"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, e := range ents {
		if e.IsDir() {
			keys = append(keys, e.Name())
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// ResolveOrdinal maps a decimal alias to an instance name: ordered
// by creation time, 1-based. Aliases are display sugar and never appear in
// meta.json.
func (s *Store) ResolveOrdinal(key string, n int) (string, error) {
	boxes, err := s.ListBoxes(key)
	if err != nil {
		return "", err
	}
	if n < 1 || n > len(boxes) {
		return "", fmt.Errorf("no box with ordinal %d (project has %d)", n, len(boxes))
	}
	return boxes[n-1].Instance, nil
}

func (s *Store) RemoveBox(key, instance string) error {
	return os.RemoveAll(s.BoxDir(key, instance))
}

func (s *Store) RemoveProject(key string) error {
	return os.RemoveAll(s.ProjectDir(key))
}

// GeneratedFileHeader builds the header generated files carry, naming
// the tool, version, and source config, and are safe to delete.
func GeneratedFileHeader(version, sourceConfig string) string {
	return fmt.Sprintf("# generated by agentbox %s from %s\n# safe to delete: reconstructible from configuration and workspace state\n", version, sourceConfig)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteJSONFile is the exported form for generated artifacts (masks.json,
// spec.json).
func WriteJSONFile(path string, v any) error { return writeJSON(path, v) }
