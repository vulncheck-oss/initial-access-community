package main

import (
	"strings"

	"github.com/google/gonids"
	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
)

// RuleGonidsParse identifies Suricata rules gonids cannot parse.
const RuleGonidsParse = "gonids-parse"

// gonidsDiagnostics parses every rule of a Suricata rule file with gonids and
// reports each rule it rejects. The canary intel pipeline parses our rules with
// gonids to edit their metadata, and gonids is stricter than Suricata, so a
// rule it rejects is silently dropped from canary detections. Snort rule files
// are not parsed: gonids targets Suricata syntax.
func gonidsDiagnostics(file string, src []byte, d idsrule.Dialect) []idsrule.Diagnostic {
	if d != idsrule.DialectSuricata {
		return nil
	}
	b := diag.Builder{File: file, Lines: source.NewLineTable(src)}
	var out []idsrule.Diagnostic
	for _, r := range splitRules(string(src)) {
		if _, err := gonids.ParseRule(r.text); err != nil {
			out = append(out, b.New(RuleGonidsParse, idsrule.SeverityError, source.Span{Start: r.start, End: r.start + r.length}, "gonids cannot parse the rule: %v", err))
		}
	}

	return out
}

// sourceRule is one logical rule of a rule file.
type sourceRule struct {
	text   string // the rule with its line continuations joined
	start  int    // byte offset of the rule's first line
	length int    // byte length of the rule's first line
}

// splitRules splits a rule file into its rules, joining backslash-continued
// lines and skipping blank lines and comments.
func splitRules(src string) []sourceRule {
	var rules []sourceRule
	var cur *sourceRule
	var text strings.Builder
	flush := func() {
		if cur != nil {
			cur.text = text.String()
			rules = append(rules, *cur)
			cur = nil
			text.Reset()
		}
	}
	off := 0
	for _, line := range strings.SplitAfter(src, "\n") {
		start := off
		off += len(line)
		trimmed := strings.TrimSpace(line)
		if cur == nil && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if cur == nil {
			cur = &sourceRule{start: start, length: len(strings.TrimRight(line, "\r\n"))}
		}
		if body, ok := strings.CutSuffix(strings.TrimRight(line, " \t\r\n"), "\\"); ok {
			text.WriteString(body)

			continue
		}
		text.WriteString(strings.TrimRight(line, "\r\n"))
		flush()
	}
	flush()

	return rules
}
