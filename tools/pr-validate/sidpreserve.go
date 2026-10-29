package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
)

// RuleSIDPreserved identifies rules whose SID does not carry over from the
// base ref.
const RuleSIDPreserved = "vc-sid-preserved"

// A new rule carries a placeholder SID (sid:1, sid:2, ...) that CI replaces
// after merge (.github/workflows/reassign-sids.yml); a rule that already went
// through CI keeps the real SID it was given. checkSIDPreservation compares a
// rule file with its version at the base ref (-base-ref) to enforce both,
// pairing rules by msg as .github/scripts/reassign_sids.py does. Renamed
// files are followed, and a real SID found anywhere in the base tree is
// accepted, so moving rules between files or entries keeps their SIDs.

// sidRule is one rule's normalised msg and sid.
type sidRule struct {
	msg  string
	sid  uint64
	span source.Span // the sid option
}

// isRealSID reports whether sid was assigned by CI.
func isRealSID(sid uint64) bool { return sid >= sidMin }

// normaliseMsg matches normalise_msg in reassign_sids.py.
func normaliseMsg(msg string) string {
	return strings.ToLower(strings.Join(strings.Fields(msg), " "))
}

// sidRules returns the msg and sid of every rule of src that has both.
func sidRules(name string, src []byte) []sidRule {
	tree, _ := idsrule.Parse(name, src)
	var out []sidRule
	for _, r := range tree.Rules() {
		msg, _ := ruleMsg(r)
		sid, o, ok := ruleSIDValue(r)
		if msg == "" || !ok {
			continue
		}
		out = append(out, sidRule{msg: normaliseMsg(msg), sid: sid, span: o.Span()})
	}

	return out
}

// sidFinding is one SID preservation problem of a HEAD rule.
type sidFinding struct {
	rule    sidRule
	message string
	args    []any
}

// compareSIDs checks the rules of a file at HEAD against the same file at the
// base ref. known holds every real SID of the base tree.
func compareSIDs(head, base []sidRule, known map[uint64]bool) []sidFinding {
	// The real SIDs each msg had at base. A msg may repeat (HTTP and HTTPS
	// variants of one rule), each copy with its own SID.
	baseSIDs := map[string][]uint64{}
	for _, r := range base {
		if isRealSID(r.sid) {
			baseSIDs[r.msg] = append(baseSIDs[r.msg], r.sid)
		}
	}
	// What is left of each msg's base SIDs once the HEAD rules that kept
	// one are matched up.
	unclaimed := map[string][]uint64{}
	for msg, sids := range baseSIDs {
		unclaimed[msg] = slices.Clone(sids)
	}
	for _, r := range head {
		if i := slices.Index(unclaimed[r.msg], r.sid); i >= 0 {
			unclaimed[r.msg] = slices.Delete(unclaimed[r.msg], i, i+1)
		}
	}

	var out []sidFinding
	for _, r := range head {
		switch {
		case !isRealSID(r.sid) && len(unclaimed[r.msg]) > 0:
			was := unclaimed[r.msg][0]
			unclaimed[r.msg] = unclaimed[r.msg][1:]
			out = append(out, sidFinding{r, "this rule was assigned sid:%d; keep it instead of a placeholder", []any{was}})
		case isRealSID(r.sid) && !known[r.sid]:
			out = append(out, sidFinding{r, "sid:%d was never assigned; CI assigns real SIDs, so use a placeholder (sid:1, sid:2, ...)", []any{r.sid}})
		case isRealSID(r.sid) && len(baseSIDs[r.msg]) > 0 && !slices.Contains(baseSIDs[r.msg], r.sid) && len(unclaimed[r.msg]) > 0:
			was := unclaimed[r.msg][0]
			unclaimed[r.msg] = unclaimed[r.msg][1:]
			out = append(out, sidFinding{r, "this rule was assigned sid:%d; do not change it to sid:%d", []any{was, r.sid}})
		}
	}

	return out
}

// baseRef is what SID preservation knows about the base ref.
type baseRef struct {
	ref      string
	toplevel string            // the repository root, absolute
	renamed  map[string]string // absolute path now -> repository path at ref
	known    map[uint64]bool   // every real SID of a rule file at ref
}

// git runs git in dir with a fixed locale and returns its stdout.
func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("git %s: %s", args[0], msg)
		}

		return out, fmt.Errorf("git %s: %w", args[0], err)
	}

	return out, nil
}

// sidValueRe finds the sid options of a rule file.
var sidValueRe = regexp.MustCompile(`\bsid\s*:\s*(\d+)\s*;`)

// loadBaseRef verifies ref and indexes it for the repository holding dir.
func loadBaseRef(dir, ref string) (*baseRef, error) {
	if strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("base ref %q must not start with '-'", ref)
	}
	if _, err := git(dir, "rev-parse", "--verify", ref+"^{commit}"); err != nil {
		return nil, fmt.Errorf("base ref %s: %w", ref, err)
	}
	top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	b := &baseRef{
		ref:      ref,
		toplevel: strings.TrimSpace(string(top)),
		renamed:  map[string]string{},
		known:    map[uint64]bool{},
	}

	// Real SIDs anywhere in the tree at ref. git grep exits 1 when nothing
	// matches.
	out, err := git(b.toplevel, "grep", "-h", "-E", `sid[[:space:]]*:[[:space:]]*[0-9]+`, ref, "--", "*.suricata.rule", "*.snort.rule")
	if err != nil && len(out) != 0 {
		return nil, err
	}
	for _, m := range sidValueRe.FindAllSubmatch(out, -1) {
		if sid, err := strconv.ParseUint(string(m[1]), 10, 64); err == nil && isRealSID(sid) {
			b.known[sid] = true
		}
	}

	// Rule files renamed or moved since ref.
	out, err = git(b.toplevel, "diff", "-M", "--name-status", "-z", "--diff-filter=R", ref, "--", "*.suricata.rule", "*.snort.rule")
	if err != nil {
		return nil, err
	}
	fields := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	for i := 0; i+2 < len(fields); i += 3 {
		// R<score> NUL old NUL new
		b.renamed[filepath.Join(b.toplevel, fields[i+2])] = fields[i+1]
	}

	return b, nil
}

// pathAtRef returns the repository path a file had at the ref.
func (b *baseRef) pathAtRef(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(real, filepath.Base(abs))
	}
	if old, ok := b.renamed[abs]; ok {
		return old, nil
	}
	top := b.toplevel
	if real, err := filepath.EvalSymlinks(top); err == nil {
		top = real
	}
	rel, err := filepath.Rel(top, abs)
	if err != nil {
		return "", err
	}

	return filepath.ToSlash(rel), nil
}

// show returns a file's content at the ref, or nil when it did not exist.
func (b *baseRef) show(path string) ([]byte, error) {
	rel, err := b.pathAtRef(path)
	if err != nil {
		return nil, err
	}
	object := b.ref + ":" + rel
	if _, err := git(b.toplevel, "cat-file", "-e", object); err != nil {
		return nil, nil //nolint:nilerr // absent at the ref: a new file
	}

	return git(b.toplevel, "show", object)
}

// checkSIDPreservation compares a rule file with its version at the ref.
func checkSIDPreservation(b *baseRef, path string, src []byte) ([]idsrule.Diagnostic, error) {
	base, err := b.show(path)
	if err != nil {
		return nil, err
	}

	builder := diag.Builder{File: path, Lines: source.NewLineTable(src)}
	var out []idsrule.Diagnostic
	for _, f := range compareSIDs(sidRules(path, src), sidRules(path, base), b.known) {
		out = append(out, builder.New(RuleSIDPreserved, idsrule.SeverityError, f.rule.span, f.message, f.args...))
	}

	return out, nil
}
