// Package tree implements tree modes: how concurrent boxes obtain a
// working tree.
package tree

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	ModeAuto     = "auto"
	ModeShared   = "shared"
	ModeWorktree = "worktree"
	ModeCopy     = "copy"
)

// IsGitRepo reports whether root is inside a git work tree.
func IsGitRepo(root string) bool {
	out, err := git(root, "rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

// CurrentBranch returns the checked-out branch name, or "" when detached.
func CurrentBranch(root string) string {
	out, err := git(root, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// ResolveAuto maps "auto" to a concrete mode: shared for the first
// box; worktree for each additional box when the workspace is a git repo,
// else copy.
func ResolveAuto(mode string, existingBoxes int, isGit bool) string {
	if mode != ModeAuto {
		return mode
	}
	if existingBoxes == 0 {
		return ModeShared
	}
	if isGit {
		return ModeWorktree
	}
	return ModeCopy
}

// Result describes the created tree.
type Result struct {
	Root   string // host path the box mounts
	Branch string // non-empty in worktree mode
}

// Create materializes the working tree for a box. treeDir is the box's
// state-directory tree/ location (worktrees live outside the
// workspace by default, so `git status` stays clean and no .gitignore entry
// is required).
func Create(mode, workspaceRoot, treeDir, instance string) (*Result, error) {
	switch mode {
	case ModeShared:
		return &Result{Root: workspaceRoot}, nil

	case ModeWorktree:
		if !IsGitRepo(workspaceRoot) {
			return nil, fmt.Errorf("tree_mode %q requires a git workspace; use \"copy\" for non-git workspaces", mode)
		}
		branch := "agentbox/" + instance
		if err := os.MkdirAll(filepath.Dir(treeDir), 0o700); err != nil {
			return nil, err
		}
		// A new branch at HEAD; if the branch already exists (a recreated
		// box), reattach to it rather than failing.
		if _, err := git(workspaceRoot, "rev-parse", "--verify", "refs/heads/"+branch); err == nil {
			if out, err := git(workspaceRoot, "worktree", "add", treeDir, branch); err != nil {
				return nil, fmt.Errorf("git worktree add: %v\n%s", err, out)
			}
		} else {
			if out, err := git(workspaceRoot, "worktree", "add", "-b", branch, treeDir); err != nil {
				return nil, fmt.Errorf("git worktree add: %v\n%s", err, out)
			}
		}
		return &Result{Root: treeDir, Branch: branch}, nil

	case ModeCopy:
		if err := os.MkdirAll(filepath.Dir(treeDir), 0o700); err != nil {
			return nil, err
		}
		// Prefer a reflink snapshot (btrfs, xfs, zfs with reflink); fall
		// back to a plain recursive copy.
		cmd := exec.Command("cp", "-a", "--reflink=auto", workspaceRoot, treeDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("copying workspace: %v\n%s", err, out)
		}
		return &Result{Root: treeDir}, nil
	}
	return nil, fmt.Errorf("unknown tree mode %q", mode)
}

// Remove tears down a box's tree. The branch is preserved unless
// deleteBranch: unreviewed agent work is the most valuable thing in the box
// and the easiest to destroy by accident.
func Remove(mode, workspaceRoot, treeRoot, branch string, deleteBranch bool) error {
	switch mode {
	case ModeShared:
		return nil // the workspace itself; never touched
	case ModeWorktree:
		if out, err := git(workspaceRoot, "worktree", "remove", "--force", treeRoot); err != nil {
			// The worktree directory may already be gone; prune bookkeeping.
			_, _ = git(workspaceRoot, "worktree", "prune")
			_ = out
		}
		if deleteBranch && branch != "" {
			if out, err := git(workspaceRoot, "branch", "-D", branch); err != nil {
				return fmt.Errorf("deleting branch %s: %v\n%s", branch, err, out)
			}
		}
		return nil
	case ModeCopy:
		return os.RemoveAll(treeRoot)
	}
	return nil
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
