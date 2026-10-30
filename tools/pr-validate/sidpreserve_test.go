package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

func Test_compareSIDs(t *testing.T) {
	r := func(msg string, sid uint64) sidRule { return sidRule{msg: msg, sid: sid} }
	known := map[uint64]bool{12701000: true, 12701001: true, 12701002: true}
	tests := []struct {
		name       string
		head, base []sidRule
		want       []uint64 // sids of the HEAD rules reported
	}{
		{"a new rule with a placeholder", []sidRule{r("a", 1)}, nil, nil},
		{"an untouched assigned rule", []sidRule{r("a", 12701000)}, []sidRule{r("a", 12701000)}, nil},
		{"an assigned rule reset to a placeholder", []sidRule{r("a", 1)}, []sidRule{r("a", 12701000)}, []uint64{1}},
		{"an assigned sid changed", []sidRule{r("a", 12701001)}, []sidRule{r("a", 12701000)}, []uint64{12701001}},
		{"an invented real sid", []sidRule{r("a", 12709999)}, nil, []uint64{12709999}},
		{"a msg reworded, sid kept", []sidRule{r("a2", 12701000)}, []sidRule{r("a", 12701000)}, nil},
		{"a rule moved in from another file keeps its sid", []sidRule{r("b", 12701002)}, nil, nil},
		{"a placeholder rule beside an assigned one", []sidRule{r("a", 12701000), r("b", 1)}, []sidRule{r("a", 12701000)}, nil},
		{
			"repeated msgs keep their own sids",
			[]sidRule{r("a", 12701000), r("a", 12701001)},
			[]sidRule{r("a", 12701000), r("a", 12701001)},
			nil,
		},
		{
			"one of two repeated msgs reset to a placeholder",
			[]sidRule{r("a", 12701000), r("a", 1)},
			[]sidRule{r("a", 12701000), r("a", 12701001)},
			[]uint64{1},
		},
		{
			"a third copy of a repeated msg is new",
			[]sidRule{r("a", 12701000), r("a", 12701001), r("a", 1)},
			[]sidRule{r("a", 12701000), r("a", 12701001)},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint64
			for _, f := range compareSIDs(tt.head, tt.base, known) {
				got = append(got, f.rule.sid)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("reported sids %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkSIDPreservation_git(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if _, err := git(dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	rule := func(msg string, sid int) string {
		return mkRule(snortHeader, `msg:"VULNCHECK `+msg+` Attempt";`, "sid:"+strconv.Itoa(sid)+"; rev:1;")
	}
	write := func(rel, src string) string {
		t.Helper()
		path := filepath.Join(dir, "feed", rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}
	check := func(ref *baseRef, path string) int {
		t.Helper()
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		diags, err := checkSIDPreservation(ref, path, src)
		if err != nil {
			t.Fatal(err)
		}

		return len(diags)
	}

	run("init", "-q")
	path := write("cve-2026-0001/cve-2026-0001.snort.rule", rule("a", 12701000)+rule("b", 12701001))
	write("cve-2026-0003/cve-2026-0003.snort.rule", rule("e", 12701002))
	run("add", ".")
	run("commit", "-q", "-m", "base")

	// The PR resets one assigned rule, renumbers the other and adds one.
	write("cve-2026-0001/cve-2026-0001.snort.rule", rule("a", 1)+rule("b", 12701005)+rule("c", 2))
	// It also renames an entry, keeping its SIDs, and adds a new one.
	run("mv", "feed/cve-2026-0003", "feed/cve-2026-0004")
	renamed := filepath.Join(dir, "feed", "cve-2026-0004", "cve-2026-0003.snort.rule")
	newPath := write("cve-2026-0002/cve-2026-0002.suricata.rule", rule("d", 1))

	ref, err := loadBaseRef(filepath.Join(dir, "feed"), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if n := check(ref, path); n != 2 {
		t.Errorf("changed file: %d findings, want 2", n)
	}
	if n := check(ref, renamed); n != 0 {
		t.Errorf("renamed file: %d findings, want 0", n)
	}
	if n := check(ref, newPath); n != 0 {
		t.Errorf("new file: %d findings, want 0", n)
	}
	for _, bad := range []string{"nope", "--output=x"} {
		if _, err := loadBaseRef(dir, bad); err == nil {
			t.Errorf("loadBaseRef accepted %q", bad)
		}
	}
}
