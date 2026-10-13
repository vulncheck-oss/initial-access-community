package main

import (
	"os"
	"path/filepath"
	"testing"
)

func Test_fixRuleSource(t *testing.T) {
	src := "alert tcp any any -> any any ( \\\n" +
		"  msg:\"VULNCHECK CVE-2026-0001 Acme Widget Path Traversal Attempt\"; \\\n" +
		"  flow:to_server,established; \\\n" +
		"  content:\"/start_apply.htm\", depth 17; http_uri; \\\n" +
		"  reference:cve,CVE-2026-0001; \\\n" +
		"  classtype:web-application-attack; \\\n" +
		"  sid:1; rev:1; \\\n" +
		"  metadata: deployment Datacenter, deployment SSLDecrypt;)"
	want := "alert tcp any any -> any any ( \\\n" +
		"    msg:\"VULNCHECK CVE-2026-0001 Acme Widget Path Traversal Attempt\"; \\\n" +
		"    flow:to_server,established; \\\n" +
		"    content:\"/start_apply.htm\"; depth:16; http_uri; \\\n" +
		"    reference:cve,CVE-2026-0001; \\\n" +
		"    classtype:web-application-attack; \\\n" +
		"    sid:1; rev:1; \\\n" +
		"    metadata: deployment Datacenter, deployment SSLDecrypt;)\n"
	got, applied, err := fixRuleSource("x.snort.rule", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("fixed source:\n%s\nwant:\n%s", got, want)
	}
	if applied == 0 {
		t.Error("no fixes applied")
	}
}

func Test_fixRuleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.snort.rule")
	if err := os.WriteFile(path, []byte(goodSnortRule), 0o640); err != nil {
		t.Fatal(err)
	}
	if applied, err := fixRuleFile(path); err != nil || applied != 0 {
		t.Errorf("a clean file: applied %d, err %v", applied, err)
	}
	if err := os.WriteFile(path, []byte(goodSnortRule[:len(goodSnortRule)-1]), 0o640); err != nil {
		t.Fatal(err)
	}
	if applied, err := fixRuleFile(path); err != nil || applied != 1 {
		t.Errorf("a missing final newline: applied %d, err %v", applied, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != goodSnortRule {
		t.Errorf("fixed file:\n%s", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640", info.Mode().Perm())
	}
}
