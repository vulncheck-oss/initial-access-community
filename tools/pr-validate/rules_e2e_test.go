package main

import (
	"bytes"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fixtureFeed copies testdata/feed to a temporary feed, restoring the .rule
// suffix of the fixtures' *.rule.txt files, and indexes it like main does.
func fixtureFeed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir("testdata/feed", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("testdata/feed", path)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, strings.TrimSuffix(rel, ".txt"))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		if !strings.HasSuffix(rel, ".rule.txt") {
			dst = filepath.Join(dir, rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(dst, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}

	savedSIDs, savedFix, savedRef := feedSIDs, flagFixRules, ruleBaseRef
	flagFixRules, ruleBaseRef = false, nil
	buildFeedSIDIndex(dir)
	t.Cleanup(func() { feedSIDs, flagFixRules, ruleBaseRef = savedSIDs, savedFix, savedRef })

	return dir
}

// fixtureLine matches a logged finding: its level, position and check id.
var fixtureLine = regexp.MustCompile(`(?m)(ERROR|WARN): \S+ - \S+?:(\d+):\d+: .*\[([a-z0-9-]+)\]$`)

// lintFixtureEntry runs lintRules over a fixture entry and returns its error
// count and the "LEVEL line id" of every finding it logged.
func lintFixtureEntry(t *testing.T, entryID string) (int, []string) {
	t.Helper()

	return lintFeedEntry(t, fixtureFeed(t), entryID)
}

// lintFeedEntry is lintFixtureEntry over a feed already set up.
func lintFeedEntry(t *testing.T, dir, entryID string) (int, []string) {
	t.Helper()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	failed := lintRules(dir, entryID)
	log.SetOutput(prev)

	var findings []string
	for _, m := range fixtureLine.FindAllStringSubmatch(buf.String(), -1) {
		findings = append(findings, m[1]+" "+m[2]+" "+m[3])
	}
	slices.Sort(findings)

	return failed, findings
}

func Test_lintRules_fixtureGood(t *testing.T) {
	if failed, findings := lintFixtureEntry(t, "cve-0000-0001"); failed != 0 || len(findings) != 0 {
		t.Errorf("lintRules = %d errors, findings %v, want none", failed, findings)
	}
}

func Test_lintRules_shortPathDepth(t *testing.T) {
	dir := fixtureFeed(t)
	path := filepath.Join(dir, "cve-0000-0001", "cve-0000-0001.snort.rule")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	short := bytes.Replace(src, []byte(`content:"/cgi-bin/widget"; depth:15;`), []byte(`content:"/cgi-bin/widget"; depth:14;`), 1)
	if bytes.Equal(short, src) {
		t.Fatal("fixture has no /cgi-bin/widget depth to shorten")
	}
	if err := os.WriteFile(path, short, 0o600); err != nil {
		t.Fatal(err)
	}

	// idsrule's content-depth-too-short on the same depth is dropped.
	failed, findings := lintFeedEntry(t, dir, "cve-0000-0001")
	if want := []string{"ERROR 5 vc-uri-path-depth"}; failed != 1 || !slices.Equal(findings, want) {
		t.Errorf("lintRules = %d errors, findings %v, want %v", failed, findings, want)
	}
}

func Test_lintRules_fixtureBad(t *testing.T) {
	failed, findings := lintFixtureEntry(t, "cve-0000-0002")
	errors := 0
	ids := map[string]bool{}
	for _, f := range findings {
		fields := strings.Fields(f)
		if fields[0] == "ERROR" {
			errors++
		}
		ids[fields[0]+" "+fields[2]] = true
	}
	if failed != errors {
		t.Errorf("lintRules = %d errors, logged %d", failed, errors)
	}
	want := []string{
		"ERROR content-snort3-modifiers",
		"ERROR sid-out-of-range",
		"ERROR style-continuation-indent",
		"ERROR vc-classtype",
		"ERROR vc-deployment-metadata",
		"ERROR vc-msg-format",
		"ERROR vc-no-comments",
		"ERROR vc-no-fast-pattern",
		"ERROR vc-option-per-line",
		"ERROR vc-pcre-capture-group",
		"ERROR vc-pcre-trailing",
		"ERROR vc-reference-cve",
		"ERROR vc-sid-rev-line",
		"ERROR vc-snort-pcre-flag",
		"WARN vc-nocase-case-sensitive",
	}
	got := make([]string, 0, len(ids))
	for id := range ids {
		got = append(got, id)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
}

func Test_fixtureFeed_hidesRules(t *testing.T) {
	// Committed fixtures must never carry a .rule suffix: the SID tooling
	// scans the whole tree for them.
	_ = filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && isRuleFile(d.Name()) {
			t.Errorf("%s is a rule file; name it %s.txt", path, d.Name())
		}

		return nil
	})
}
