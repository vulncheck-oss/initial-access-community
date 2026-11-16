package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const RuleUnsafeSymlink = "vc-unsafe-symlink"

// lintChangedSymlinks checks symlinks added or modified since baseRef. It
// rejects targets that cannot be transferred safely into another workspace.
func lintChangedSymlinks(feedDir, baseRef string) int {
	repoRoot, err := filepath.Abs(filepath.Join(feedDir, ".."))
	if err != nil {
		return logSymlinkError("repository root", err)
	}
	repoRoot, err = filepath.EvalSymlinks(repoRoot)
	if err != nil {
		return logSymlinkError("repository root", err)
	}

	cmd := exec.Command("git", "diff", "--name-only", "-z", "--diff-filter=ACMRT", baseRef)
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		return logSymlinkError("list changed paths", err)
	}

	failed := 0
	for _, name := range strings.Split(string(output), "\x00") {
		if name == "" {
			continue
		}
		path := filepath.Join(repoRoot, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if err := validateSymlink(repoRoot, path); err != nil {
			failed += logSymlinkError(filepath.ToSlash(name), err)
		}
	}
	return failed
}

// validateSymlink requires a relative, resolvable target whose final path is
// contained by repoRoot, including when the target crosses other symlinks.
func validateSymlink(repoRoot, path string) error {
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("absolute target %q", target)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(path), target))
	if err != nil {
		return fmt.Errorf("target %q cannot be resolved: %w", target, err)
	}
	inside, err := filepath.Rel(repoRoot, resolved)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("target %q resolves outside the repository", target)
	}
	return nil
}

func logSymlinkError(path string, err error) int {
	fmt.Fprintf(os.Stderr, "ERROR [%s] %s: %v\n", RuleUnsafeSymlink, path, err)
	return 1
}
