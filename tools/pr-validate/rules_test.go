package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
)

// goodSnortRule and goodSuricataRule follow every rule-file convention.
const goodSnortRule = `alert tcp any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Command Injection Attempt"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    content:"/cgi-bin/widget"; depth:15; http_uri; \
    content:"cmd="; http_uri; \
    pcre:"/cmd=[^&]*[\;|` + "`" + `\$(){}]/U"; \
    reference:cve,CVE-2026-0001; \
    classtype:web-application-attack; \
    sid:1; rev:1; \
    metadata: deployment Datacenter, deployment SSLDecrypt; \
)
`

const goodSuricataRule = `alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Command Injection Attempt"; \
    flow:to_server,established; \
    http.method; content:"GET"; \
    http.uri; content:"/cgi-bin/widget"; startswith; \
    content:"cmd="; \
    pcre:"/cmd=[^&]*[\;|` + "`" + `\$(){}]/"; \
    reference:cve,CVE-2026-0001; \
    classtype:web-application-attack; \
    sid:1; rev:1; \
    metadata: deployment Datacenter, deployment SSLDecrypt; \
)
`

// lintIDs lints src as the named rule file and returns the sorted check ids
// it reports at the given severity ("" for any).
func lintIDs(t *testing.T, name, src string, sev idsrule.Severity) []string {
	t.Helper()
	var ids []string
	for _, d := range idsrule.Lint(name, []byte(src), ruleLintOptions(idsrule.DialectFromFilename(name))) {
		if sev == "" || d.Severity == sev {
			ids = append(ids, d.Rule)
		}
	}
	slices.Sort(ids)

	return ids
}

func Test_ruleLintOptions(t *testing.T) {
	for _, d := range []idsrule.Dialect{idsrule.DialectSnort2, idsrule.DialectSuricata} {
		if err := ruleLintOptions(d).Validate(); err != nil {
			t.Errorf("ruleLintOptions(%v) does not validate: %v", d, err)
		}
	}
}

func Test_isRuleFile(t *testing.T) {
	for name, want := range map[string]bool{
		"cve-2026-0001.snort.rule":    true,
		"cve-2026-0001.suricata.rule": true,
		"vulncheck.suricata.rules":    false,
		"cve-2026-0001.go":            false,
	} {
		if got := isRuleFile(name); got != want {
			t.Errorf("isRuleFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func Test_lintRules_good(t *testing.T) {
	for name, src := range map[string]string{
		"cve-2026-0001.snort.rule":    goodSnortRule,
		"cve-2026-0001.suricata.rule": goodSuricataRule,
	} {
		if ids := lintIDs(t, name, src, ""); len(ids) != 0 {
			t.Errorf("%s: unexpected findings %v", name, ids)
		}
	}
}

func Test_lintRules_generic(t *testing.T) {
	tests := []struct {
		name string
		file string
		src  string
		want []string
	}{
		{
			"snort3 content modifiers are errors",
			"x.snort.rule",
			"alert tcp any any -> any any (msg:\"VULNCHECK a Attempt\"; content:\"/a\", depth 2; http_uri; sid:1; rev:1;)\n",
			[]string{"content-snort3-modifiers"},
		},
		{
			"two-space indent is an error",
			"x.snort.rule",
			"alert tcp any any -> any any ( \\\n  msg:\"VULNCHECK a Attempt\"; \\\n  sid:1; rev:1;)\n",
			[]string{"style-continuation-indent", "style-continuation-indent"},
		},
		{
			"missing VULNCHECK prefix is an error",
			"x.snort.rule",
			"alert tcp any any -> any any (msg:\"a Attempt\"; sid:1; rev:1;)\n",
			[]string{"msg-prefix"},
		},
		{
			"sid outside the VulnCheck block is an error",
			"x.snort.rule",
			"alert tcp any any -> any any (msg:\"VULNCHECK a Attempt\"; sid:90000200; rev:1;)\n",
			[]string{"sid-out-of-range"},
		},
		{
			"deprecated http_ modifiers in suricata are errors",
			"x.suricata.rule",
			"alert http any any -> any any (msg:\"VULNCHECK a Attempt\"; content:\"/a\"; http_uri; sid:1; rev:1;)\n",
			[]string{"keyword-deprecated"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lintIDs(t, tt.file, tt.src, idsrule.SeverityError); !slices.Equal(got, tt.want) {
				t.Errorf("errors = %v, want %v", got, tt.want)
			}
		})
	}
}

// writeFeed writes rule files into a temporary feed directory, keyed by path
// relative to it, and indexes it like main does.
func writeFeed(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := feedSIDs
	buildFeedSIDIndex(dir)
	t.Cleanup(func() { feedSIDs = saved })

	return dir
}

func Test_lintRules_sids(t *testing.T) {
	rule := func(msg string, sid int) string {
		return fmt.Sprintf("alert tcp any any -> any any ( \\\n    msg:\"VULNCHECK %s Attempt\"; \\\n    flow:to_server,established; \\\n    classtype:misc-attack; \\\n    sid:%d; rev:1; \\\n)\n", msg, sid)
	}
	tests := []struct {
		name  string
		files map[string]string
		entry string
		want  int
	}{
		{
			"a real sid reused in another entry",
			map[string]string{
				"cve-2026-0001/cve-2026-0001.snort.rule": rule("a", 90000010),
				"cve-2026-0002/cve-2026-0002.snort.rule": rule("b", 90000010),
			},
			"cve-2026-0001", 1,
		},
		{
			"a reuse from a sub-package is found",
			map[string]string{
				"cve-2026-0001/variant/cve-2026-0001.snort.rule": rule("a", 90000010),
				"cve-2026-0002/cve-2026-0002.snort.rule":         rule("b", 90000010),
			},
			"cve-2026-0002", 1,
		},
		{
			"snort and suricata twins share a sid",
			map[string]string{
				"cve-2026-0001/cve-2026-0001.snort.rule":    rule("a", 90000010),
				"cve-2026-0001/cve-2026-0001.suricata.rule": strings.Replace(rule("a", 90000010), "tcp", "http", 1),
			},
			"cve-2026-0001", 0,
		},
		{
			"placeholders repeat across entries",
			map[string]string{
				"cve-2026-0001/cve-2026-0001.snort.rule": rule("a", 1),
				"cve-2026-0002/cve-2026-0002.snort.rule": rule("b", 1),
			},
			"cve-2026-0001", 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFeed(t, tt.files)
			if got := lintRules(dir, tt.entry); got != tt.want {
				t.Errorf("lintRules = %d errors, want %d", got, tt.want)
			}
		})
	}
}

func Test_lintRules_warningsDoNotFail(t *testing.T) {
	src := "alert http any any -> any any ( \\\n    msg:\"VULNCHECK a Attempt\"; \\\n    flow:to_server,established; \\\n    classtype:misc-attack; \\\n    http.uri; \\\n    sid:1; rev:1; \\\n)\n"
	if ids := lintIDs(t, "x.suricata.rule", src, idsrule.SeverityWarning); !slices.Equal(ids, []string{"sticky-buffer-empty"}) {
		t.Errorf("warnings = %v, want [sticky-buffer-empty]", ids)
	}
	dir := writeFeed(t, map[string]string{"cve-2026-0001/cve-2026-0001.suricata.rule": src})
	if got := lintRules(dir, "cve-2026-0001"); got != 0 {
		t.Errorf("lintRules = %d errors, want 0", got)
	}
}

func Test_formatRuleDiagnostic(t *testing.T) {
	d := idsrule.Diagnostic{
		File:    filepath.Join("..", "feed", "cve-2026-0001", "a.snort.rule"),
		Line:    3,
		Column:  5,
		Message: "duplicate sid 90000010: also declared in " + filepath.Join("..", "feed", "cve-2026-0002", "b.snort.rule"),
	}
	want := "cve-2026-0001/a.snort.rule:3:5: duplicate sid 90000010: also declared in cve-2026-0002/b.snort.rule"
	if got := formatRuleDiagnostic("../feed/", d); got != want {
		t.Errorf("formatRuleDiagnostic = %q, want %q", got, want)
	}
}

func Test_parityDiagnostics(t *testing.T) {
	suri := vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`)
	snort := vcRule(snortHeader, `content:"/a"; depth:2; http_uri;`)
	tests := []struct {
		name  string
		suri  string
		snort string
		want  int
	}{
		{"equal pair", suri, snort, 0},
		{"different msg", suri, strings.Replace(snort, "Command Injection Attempt", "RCE Attempt", 1), 1},
		{"different classtype", suri, strings.Replace(snort, "web-application-attack", "misc-attack", 1), 1},
		{"different flowbits", vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`, "flowbits:set,vc-cve-2026-0001;"), snort, 1},
		{"different rule count", suri, snort + snort, 1},
		{
			// style-rules §4: a Suricata-only feature forgives any divergence.
			"a suricata-only base64 feature is forgiven",
			strings.Replace(vcRule(suricataHeader, `http.request_body; content:"x"; base64_decode; base64_data; content:"y";`), "Command Injection Attempt", "RCE Attempt", 1),
			snort, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sp := filepath.Join(dir, "cve-2026-0001.suricata.rule")
			np := filepath.Join(dir, "cve-2026-0001.snort.rule")
			if err := os.WriteFile(sp, []byte(tt.suri), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(np, []byte(tt.snort), 0o600); err != nil {
				t.Fatal(err)
			}
			diags, err := parityDiagnostics(sp, np)
			if err != nil {
				t.Fatal(err)
			}
			if len(diags) != tt.want {
				t.Errorf("parityDiagnostics = %d findings, want %d: %v", len(diags), tt.want, diags)
			}
			for _, d := range diags {
				if d.Rule != RuleParity {
					t.Errorf("finding id = %q, want %q", d.Rule, RuleParity)
				}
			}
		})
	}
}

// Test_lintRules_parity proves parity is wired into lintRules: an otherwise
// clean pair whose msgs differ is one error.
func Test_lintRules_parity(t *testing.T) {
	suri := vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`)
	snort := strings.Replace(vcRule(snortHeader, `content:"/a"; depth:2; http_uri;`), "Command Injection Attempt", "RCE Attempt", 1)
	dir := writeFeed(t, map[string]string{
		"cve-2026-0001/cve-2026-0001.suricata.rule": suri,
		"cve-2026-0001/cve-2026-0001.snort.rule":    snort,
	})
	if got := lintRules(dir, "cve-2026-0001"); got != 1 {
		t.Errorf("lintRules = %d errors, want 1 (parity msg mismatch)", got)
	}
}
