package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
)

// coverageRules has one rule of each kind lintRulesFired sees: one a capture
// must trigger (sid:1), a variant (sid:2), a flowbits:noalert setter (sid:3)
// and a rule a capture must trigger that tests the setter's flowbit (sid:4).
const coverageRules = `alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Exploit Attempt"; \
    sid:1; rev:1; \
)
alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Exploit Attempt (Metasploit Variant)"; \
    sid:2; rev:1; \
)
alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Login Attempt"; \
    flowbits:set,vc-cve-2026-0001; \
    flowbits:noalert; \
    sid:3; rev:1; \
)
alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Exploit Success"; \
    flowbits:isset,vc-cve-2026-0001; \
    sid:4; rev:1; \
)
`

func Test_ruleNeedsCapture(t *testing.T) {
	tree, _ := idsrule.Parse("x.suricata.rule", []byte(coverageRules+`alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Exploit Attempt (zero science variant)"; \
    sid:5; rev:1; \
)
alert http any any -> any any ( \
    msg:"VULNCHECK CVE-2026-0001 Acme Widget Probe Attempt"; \
    noalert; \
    sid:6; rev:1; \
)
`))
	want := map[uint64]bool{1: true, 2: false, 3: false, 4: true, 5: false, 6: false}
	for _, r := range tree.Rules() {
		sid, _, _ := ruleSIDValue(r)
		if got := ruleNeedsCapture(r); got != want[sid] {
			t.Errorf("ruleNeedsCapture(sid:%d) = %v, want %v", sid, got, want[sid])
		}
	}
}

func Test_lintRulesFired(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "cve-2026-0001", "cve-2026-0001.suricata.rule")
	if err := os.MkdirAll(filepath.Dir(rule), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte(coverageRules), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := engineFor(rule)

	tests := []struct {
		name   string
		fired  map[int]bool
		failed int
		lines  []string
	}{
		{"variant and noalert need not fire", map[int]bool{1: true, 4: true}, 0, nil},
		{"one missing", map[int]bool{1: true, 2: true, 3: true}, 1, []string{"cve-2026-0001.suricata.rule:15: suricata rule sid:4"}},
		{"none fired", map[int]bool{}, 2, []string{"rule:1: suricata rule sid:1", "rule:15: suricata rule sid:4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&buf)
			failed := lintRulesFired(dir, "CVE-2026-0001", engine, rule, tt.fired)
			log.SetOutput(prev)

			if failed != tt.failed {
				t.Errorf("lintRulesFired() = %d, want %d\n%s", failed, tt.failed, buf.String())
			}
			for _, line := range tt.lines {
				if !strings.Contains(buf.String(), line) {
					t.Errorf("log does not contain %q:\n%s", line, buf.String())
				}
			}
			if n := strings.Count(buf.String(), "did not alert on any capture"); n != tt.failed {
				t.Errorf("logged %d findings, want %d:\n%s", n, tt.failed, buf.String())
			}
		})
	}
}
