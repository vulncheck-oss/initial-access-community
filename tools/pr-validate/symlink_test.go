package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSymlink(t *testing.T) {
	repo := t.TempDir()
	entry := filepath.Join(repo, "feed", "entry")
	shared := filepath.Join(repo, "shared")
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "artifact"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(repo), filepath.Base(repo)+"-outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	outsideArtifact := filepath.Join(outside, "artifact")
	if err := os.WriteFile(outsideArtifact, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	outsideTarget, err := filepath.Rel(entry, outsideArtifact)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "repository relative", target: "../../shared/artifact"},
		{name: "absolute", target: filepath.Join(repo, "shared", "artifact"), want: "absolute target"},
		{name: "outside repository", target: outsideTarget, want: "resolves outside"},
		{name: "dangling", target: "../../shared/missing", want: "cannot be resolved"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(entry, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.Symlink(test.target, path); err != nil {
				t.Fatal(err)
			}
			err := validateSymlink(repo, path)
			if test.want == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestLintChangedSymlinksWithSymlinkedRepoRoot(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if _, err := git(repo, args...); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	run("-c", "core.hooksPath="+t.TempDir(), "-c", "user.name=t", "-c", "user.email=t@t",
		"-c", "commit.gpgsign=false",
		"commit", "--allow-empty", "-q", "-m", "base")

	shared := filepath.Join(repo, "shared")
	entry := filepath.Join(repo, "feed", "entry")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "artifact"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../shared/artifact", filepath.Join(entry, "artifact")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	run("add", ".")

	alias := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(repo, alias); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if failures := lintChangedSymlinks(filepath.Join(alias, "feed"), "HEAD"); failures != 0 {
		t.Fatalf("lintChangedSymlinks returned %d failures, want 0", failures)
	}
}
