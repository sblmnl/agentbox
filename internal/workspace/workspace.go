// Package workspace implements workspace root detection and working
// directory mapping.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrRefused is returned when detection would select "/" or $HOME.
type ErrRefused struct{ Path string }

func (e *ErrRefused) Error() string {
	return fmt.Sprintf("refusing to use %q as the workspace root: mounting it would defeat the purpose; pass an explicit --workspace", e.Path)
}

var vcsMarkers = []string{".git", ".hg", ".jj", ".svn"}
var configNames = []string{"agentbox.toml", ".agentbox.toml"}

// Detect resolves the workspace root. First match wins:
//  1. explicit override (--workspace)
//  2. AGENTBOX_WORKSPACE
//  3. nearest ancestor containing agentbox.toml or .agentbox.toml
//  4. nearest ancestor containing a VCS root marker
//  5. the starting directory
//
// The search stops at $HOME and at filesystem boundaries, and never selects
// "/" or $HOME itself.
func Detect(startDir, override string) (string, error) {
	if override == "" {
		override = os.Getenv("AGENTBOX_WORKSPACE")
	}
	if override != "" {
		root, err := filepath.Abs(override)
		if err != nil {
			return "", err
		}
		fi, err := os.Stat(root)
		if err != nil {
			return "", fmt.Errorf("workspace %q: %w", override, err)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("workspace %q is not a directory", override)
		}
		return root, nil
	}

	start, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(start); err != nil {
		return "", err
	} else if !fi.IsDir() {
		return "", fmt.Errorf("starting directory %q is not a directory", startDir)
	}

	home, _ := os.UserHomeDir()

	// Pass 1: config file; pass 2: VCS marker. Nearest ancestor wins within
	// each pass, and a config file anywhere on the path beats a VCS marker.
	for _, names := range [][]string{configNames, vcsMarkers} {
		if root := searchUp(start, home, names); root != "" {
			return checkNotForbidden(root, home)
		}
	}
	return checkNotForbidden(start, home)
}

func checkNotForbidden(root, home string) (string, error) {
	if root == "/" || (home != "" && root == filepath.Clean(home)) {
		return "", &ErrRefused{Path: root}
	}
	return root, nil
}

// searchUp walks from dir toward the root looking for any of names,
// stopping at $HOME and at filesystem boundaries. A marker at $HOME or "/"
// never matches: neither may become a workspace root, so a .git in
// $HOME must not capture every project beneath it.
func searchUp(dir, home string, names []string) string {
	startDev, ok := deviceOf(dir)
	for d := dir; ; {
		atForbidden := d == "/" || (home != "" && d == filepath.Clean(home))
		if !atForbidden {
			for _, n := range names {
				if _, err := os.Lstat(filepath.Join(d, n)); err == nil {
					return d
				}
			}
		}
		if home != "" && d == filepath.Clean(home) {
			return "" // do not search above $HOME
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		if ok {
			if pdev, pok := deviceOf(parent); pok && pdev != startDev {
				return "" // filesystem boundary
			}
		}
		d = parent
	}
}

func deviceOf(path string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, false
	}
	return uint64(st.Dev), true
}

// GuestWorkdir maps the starting directory into the guest: the
// workspace mount point joined with the starting directory's path relative
// to the workspace root. Starting outside the root falls back to the mount
// point.
func GuestWorkdir(mount, workspaceRoot, startDir string) string {
	rel, err := filepath.Rel(workspaceRoot, startDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return mount
	}
	if rel == "." {
		return mount
	}
	return filepath.Join(mount, rel)
}
