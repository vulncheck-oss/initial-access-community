package main

import (
	"bufio"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RuleGoModModule identifies go.mod module path findings.
const RuleGoModModule = "gomod-module"

// goModModuleRe matches the module line of a feed package's go.mod. The group
// is the package path relative to the feed directory.
var goModModuleRe = regexp.MustCompile(`^module github\.com/vulncheck/initial-access/feed/(.*)$`)

// lintGoMod checks the first line of every go.mod under the entry directory.
// The module path must be github.com/vulncheck-oss/initial-access-community/feed/<path>,
// where <path> mirrors the go.mod's directory below the feed directory (the
// entry ID, plus the sub-package path for a nested go.mod).
func lintGoMod(dir, entryID string) int {
	failed := 0
	root := filepath.Join(dir, entryID)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "go.mod" {
			return nil
		}

		first, err := firstLine(path)
		if err != nil {
			log.Printf("ERROR: %s - unable to read %s: %v [%s]", strings.ToUpper(entryID), path, err, RuleGoModModule)
			failed++
			return nil
		}

		rel, err := filepath.Rel(dir, filepath.Dir(path))
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		m := goModModuleRe.FindStringSubmatch(strings.TrimSpace(first))
		if m == nil || m[1] != rel {
			log.Printf("ERROR: %s - %s has module line %q, expected `module github.com/vulncheck-oss/initial-access-community/feed/%s` [%s]", strings.ToUpper(entryID), path, first, rel, RuleGoModModule)
			failed++
		}

		return nil
	})

	return failed
}

func firstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()

	return scanner.Text(), scanner.Err()
}
