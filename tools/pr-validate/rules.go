package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/adrg/frontmatter"
	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/diag"
)

// The VulnCheck SID block. Rules below sidPlaceholderBelow carry a
// placeholder (sid:1, sid:2, ...) that CI replaces with a real SID after
// merge. Mirrors SID_RANGE_START/SID_RANGE_END in
// .github/scripts/reassign_sids.py and sidMin/sidMax in ia-feed's sid_test.go.
const (
	sidPlaceholderBelow = 12_700_000
	sidMin              = 12_700_001
	sidMax              = 12_800_001
)

// RuleRuleLint identifies rule files pr-validate could not lint.
const RuleRuleLint = "rule-lint"

// ruleFileSuffixes are the rule files lintRules checks.
var ruleFileSuffixes = []string{".suricata.rule", ".snort.rule"}

// feedSIDs holds the real SIDs of every rule file in the feed, one index per
// dialect (a .snort.rule and its .suricata.rule twin share SIDs by design).
// buildFeedSIDIndex fills it before any entry is linted, so a SID reused
// anywhere in the feed is reported whatever order entries are linted in.
var feedSIDs = map[idsrule.Dialect]*idsrule.SIDIndex{}

// ruleBaseRef is the -base-ref rule files are compared with for SID
// preservation, or nil to skip that check.
var ruleBaseRef *baseRef

// isRuleFile reports whether name is a Suricata or Snort rule file.
func isRuleFile(name string) bool {
	for _, suffix := range ruleFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

// ruleLintOptions returns the idsrule options rule files of dialect d are
// held to. Every finding counts as an error unless listed in
// ruleLintWarnings.
func ruleLintOptions(d idsrule.Dialect) idsrule.Options {
	opts := idsrule.DefaultOptions()
	opts.Dialect = d
	opts.Policy.SIDMin = sidMin
	opts.Policy.SIDMax = sidMax
	opts.Policy.PlaceholderBelow = sidPlaceholderBelow
	opts.Policy.MsgPrefix = "VULNCHECK "
	opts.Policy.Style.ContinuationIndent = continuationIndent
	opts.Checks.Style = true
	opts.Checks.Severity = map[string]idsrule.Severity{}
	for _, id := range idsrule.CheckIDs() {
		sev := idsrule.SeverityError
		if ruleLintWarnings[id] {
			sev = idsrule.SeverityWarning
		}
		opts.Checks.Severity[id] = sev
	}
	opts.SIDs = feedSIDs[d]

	return opts
}

// ruleLintWarnings are the idsrule checks whose findings are reported as
// warnings: they need a human to judge whether the rule is wrong.
var ruleLintWarnings = map[string]bool{
	"keyword-unknown":       true, // the keyword tables may lag the engines
	"sticky-buffer-empty":   true,
	"value-unescaped-quote": true,
}

// buildFeedSIDIndex indexes the real SIDs of every rule file under dir.
func buildFeedSIDIndex(dir string) {
	feedSIDs = map[idsrule.Dialect]*idsrule.SIDIndex{
		idsrule.DialectSnort2:   idsrule.NewSIDIndex(),
		idsrule.DialectSuricata: idsrule.NewSIDIndex(),
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isRuleFile(d.Name()) {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		dialect := idsrule.DialectFromFilename(path)
		opts := ruleLintOptions(dialect)
		opts.Checks = idsrule.Selection{Disable: idsrule.CheckIDs()}
		// Linting indexes the file's SIDs whatever checks run.
		_ = idsrule.Lint(path, src, opts)

		return nil
	})
}

// lintRules lints every Suricata and Snort rule file of the entry, sub-packages
// included, and logs each finding. It returns the number of errors.
func lintRules(dir, entryID string) int {
	var files []string
	_ = filepath.WalkDir(filepath.Join(dir, entryID), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && isRuleFile(d.Name()) {
			files = append(files, path)
		}

		return nil
	})
	slices.Sort(files)

	upperID := strings.ToUpper(entryID)
	entry := loadRuleEntryInfo(dir, entryID)
	failed := 0
	for _, path := range files {
		if flagFixRules {
			if applied, err := fixRuleFile(path); err != nil {
				log.Printf("ERROR: %s - unable to fix %s: %v [%s]", upperID, relPath(dir, path), err, RuleRuleLint)
				failed++
			} else if applied > 0 {
				log.Printf("FIXED: %s - %s: applied %d autofixes [%s]", upperID, relPath(dir, path), applied, RuleRuleLint)
			}
		}
		src, err := os.ReadFile(path)
		if err != nil {
			log.Printf("ERROR: %s - unable to read %s: %v [%s]", upperID, relPath(dir, path), err, RuleRuleLint)
			failed++

			continue
		}
		dialect := idsrule.DialectFromFilename(path)
		diags := idsrule.Lint(path, src, ruleLintOptions(dialect))
		var info *ruleEntryInfo
		if entry != nil {
			info = &ruleEntryInfo{
				encryptedComms:   entry.encryptedComms,
				hasEncryptedPcap: hasEncryptedPcap(filepath.Dir(path)),
			}
		}
		diags = append(diags, runRuleChecks(path, src, dialect, info)...)
		if ruleBaseRef != nil {
			preserved, err := checkSIDPreservation(ruleBaseRef, path, src)
			if err != nil {
				log.Printf("ERROR: %s - unable to compare %s with %s: %v [%s]", upperID, relPath(dir, path), ruleBaseRef.ref, err, RuleSIDPreserved)
				failed++
			}
			diags = append(diags, preserved...)
		}
		diags = dropSupersededDepth(diags)
		diag.Sort(diags)
		for _, d := range diags {
			if logRuleDiagnostic(dir, upperID, d) {
				failed++
			}
		}
	}

	return failed
}

// loadRuleEntryInfo reads what the entry-level rule checks need from the
// entry's README frontmatter, or returns nil when it does not parse
// (lintEntryFrontmatter reports that).
func loadRuleEntryInfo(dir, entryID string) *ruleEntryInfo {
	data, err := os.ReadFile(filepath.Join(dir, entryID, "README.md"))
	if err != nil {
		return nil
	}
	if !bytes.HasPrefix(data, []byte("---\n")) {
		return nil
	}
	var entry Entry
	if _, err := frontmatter.MustParse(bytes.NewReader(data), &entry); err != nil || len(entry.Artifacts) == 0 {
		return nil
	}
	info := &ruleEntryInfo{}
	for _, a := range entry.Artifacts {
		info.encryptedComms = append(info.encryptedComms, a.TargetEncryptedComms)
	}

	return info
}

// encryptedPcapRe matches the encrypted captures rules deployed with
// SSLDecrypt are verified against (00-exploited-encrypted.pcap and its
// siblings).
var encryptedPcapRe = regexp.MustCompile(`(?i)^\d{2}-(?:exploited|exploit-attempt)-encrypted\.pcap(?:ng)?$`)

// hasEncryptedPcap reports whether dir holds an encrypted capture.
func hasEncryptedPcap(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && encryptedPcapRe.MatchString(e.Name()) {
			return true
		}
	}

	return false
}

// logRuleDiagnostic logs one rule finding in pr-validate's format and reports
// whether it is an error.
func logRuleDiagnostic(dir, upperID string, d idsrule.Diagnostic) bool {
	level := "WARN"
	if d.Severity == idsrule.SeverityError {
		level = "ERROR"
	}
	log.Printf("%s: %s - %s [%s]", level, upperID, formatRuleDiagnostic(dir, d), d.Rule)
	for _, r := range d.Related {
		log.Printf("    %s:%d:%d: %s", relPath(dir, r.File), r.Line, r.Column, r.Message)
	}

	return d.Severity == idsrule.SeverityError
}

// formatRuleDiagnostic renders a finding's position and message. Paths
// idsrule writes into a message (the other file of a duplicate sid, say) are
// made relative to dir like the position.
func formatRuleDiagnostic(dir string, d idsrule.Diagnostic) string {
	msg := strings.ReplaceAll(d.Message, filepath.Clean(dir)+string(filepath.Separator), "")

	return fmt.Sprintf("%s:%d:%d: %s", relPath(dir, d.File), d.Line, d.Column, msg)
}
