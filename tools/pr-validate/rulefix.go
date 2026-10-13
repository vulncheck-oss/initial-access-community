package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/source"
)

// maxFixPasses bounds fixRuleFile: one pass is normally enough, and a fix
// skipped because it overlaps another waits for the next pass.
const maxFixPasses = 10

// fixRuleSource applies every autofix the rule checks offer to src: idsrule's
// (spacing, Snort 3 content modifiers, final newline, ...), the continuation
// indent and the VulnCheck checks' (vc-uri-path-depth). It returns the fixed
// source and the number of fixes applied.
func fixRuleSource(path string, src []byte) ([]byte, int, error) {
	dialect := idsrule.DialectFromFilename(path)
	total := 0
	for pass := range maxFixPasses + 1 {
		diags := idsrule.Lint(path, src, ruleLintOptions(dialect))
		diags = append(diags, runRuleChecks(path, src, dialect, nil)...)
		addIndentFixes(diags)
		out, applied, err := idsrule.Fix(src, diags)
		if err != nil {
			return src, total, err
		}
		if applied == 0 {
			return src, total, nil
		}
		if pass == maxFixPasses {
			return src, total, fmt.Errorf("autofixes did not settle after %d passes", maxFixPasses)
		}
		src, total = out, total+applied
	}

	return src, total, nil
}

// continuationIndent is the indent of a rule's continuation lines.
const continuationIndent = "    "

// addIndentFixes gives each style-continuation-indent finding, which idsrule
// reports on the line's indent without a fix, the edit to the policy indent.
func addIndentFixes(diags []idsrule.Diagnostic) {
	for i := range diags {
		if d := &diags[i]; d.Rule == "style-continuation-indent" && !d.HasFix() {
			d.Edits = []source.TextEdit{{Span: d.Span, NewText: continuationIndent}}
		}
	}
}

// fixRuleFile rewrites a rule file with its autofixes applied and returns
// how many were applied. A symlinked rule file is left alone: rewriting it
// would change its target, possibly in another entry.
func fixRuleFile(path string) (int, error) {
	if info, err := os.Lstat(path); err != nil {
		return 0, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("is a symlink; fix its target instead")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	out, applied, err := fixRuleSource(path, src)
	if err != nil {
		return 0, err
	}
	if applied == 0 || bytes.Equal(out, src) {
		return 0, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	return applied, os.WriteFile(path, out, info.Mode().Perm())
}
