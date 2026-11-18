package main

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
)

// issueRule is the rule from issue 6358: gonids rejects the valueless
// `variant` metadata that Suricata ignores.
const issueRule = `alert http any any -> any any ( msg:"VULNCHECK CVE-2009-3548 Apache Tomcat Host Manager (Source Variant) Blank Admin Password Use Attempt"; flow:established,to_server; http.uri; content:"/host-manager"; startswith; reference:cve,CVE-2009-3548; classtype:default-login-attempt; sid:12702785; rev:1; metadata: deployment Datacenter, deployment SSLDecrypt, variant; )
`

func Test_gonidsDiagnostics(t *testing.T) {
	t.Run("good rule", func(t *testing.T) {
		if got := gonidsDiagnostics("a.suricata.rule", []byte(goodSuricataRule), idsrule.DialectSuricata); len(got) != 0 {
			t.Fatalf("unexpected findings: %v", got)
		}
	})
	t.Run("valueless metadata", func(t *testing.T) {
		got := gonidsDiagnostics("a.suricata.rule", []byte(issueRule), idsrule.DialectSuricata)
		if len(got) != 1 || got[0].Rule != RuleGonidsParse || got[0].Severity != idsrule.SeverityError || got[0].Line != 1 {
			t.Fatalf("got %+v", got)
		}
		if !strings.Contains(got[0].Message, "invalid metadata definition") {
			t.Errorf("message %q lacks the gonids error", got[0].Message)
		}
	})
	t.Run("multi-line rule reports its first line", func(t *testing.T) {
		src := "# comment\n\n" + strings.Replace(goodSuricataRule, "deployment SSLDecrypt;", "deployment SSLDecrypt, variant;", 1)
		got := gonidsDiagnostics("a.suricata.rule", []byte(src), idsrule.DialectSuricata)
		if len(got) != 1 || got[0].Line != 3 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("each rule is parsed", func(t *testing.T) {
		src := goodSuricataRule + issueRule + goodSuricataRule
		got := gonidsDiagnostics("a.suricata.rule", []byte(src), idsrule.DialectSuricata)
		want := strings.Count(goodSuricataRule, "\n") + 1
		if len(got) != 1 || got[0].Line != want {
			t.Fatalf("want one finding on line %d, got %+v", want, got)
		}
	})
	t.Run("snort is skipped", func(t *testing.T) {
		if got := gonidsDiagnostics("a.snort.rule", []byte(issueRule), idsrule.DialectSnort2); len(got) != 0 {
			t.Fatalf("unexpected findings: %v", got)
		}
	})
}
