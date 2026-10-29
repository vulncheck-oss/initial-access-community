package main

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/value"
)

// The VulnCheck rule checks enforce the vc-iai style-rules skill on top of the
// generic idsrule checks. Each is a function over one parsed rule file; the
// skill section a check enforces is noted on it.

// ruleCheck is one VulnCheck rule check.
type ruleCheck struct {
	id  string
	sev idsrule.Severity
	run func(*ruleCheckCtx)
}

// ruleChecks are the VulnCheck rule checks, in the order they run.
var ruleChecks = []ruleCheck{
	{"vc-msg-format", idsrule.SeverityError, checkMsgFormat},
	{"vc-msg-first", idsrule.SeverityError, checkMsgFirst},
	{"vc-reference-cve", idsrule.SeverityError, checkReferenceCVE},
	{"vc-classtype", idsrule.SeverityError, checkClasstype},
	{"vc-classtype-admin", idsrule.SeverityWarning, checkClasstypeAdmin},
	{"vc-flow-established", idsrule.SeverityError, checkFlowEstablished},
	{"vc-flowbits-name", idsrule.SeverityError, checkFlowbitsName},
	{"vc-flowbits-unset", idsrule.SeverityError, checkFlowbitsUnset},
	{"vc-success-impact", idsrule.SeverityError, checkSuccessImpact},
	{"vc-success-direction", idsrule.SeverityError, checkSuccessDirection},
	{"vc-success-classtype", idsrule.SeverityError, checkSuccessClasstype},
	{"vc-no-comments", idsrule.SeverityError, checkNoComments},
	{"vc-option-per-line", idsrule.SeverityError, checkOptionPerLine},
	{"vc-sid-rev-line", idsrule.SeverityError, checkSIDRevLine},
	{"vc-sid-placeholder-sequence", idsrule.SeverityWarning, checkPlaceholderSequence},
	{"vc-no-fast-pattern", idsrule.SeverityError, checkNoFastPattern},
	{"vc-content-hex", idsrule.SeverityError, checkContentHex},
	{"vc-pcre-buffer-flag", idsrule.SeverityError, checkPCREBufferFlag},
	{"vc-snort-pcre-flag", idsrule.SeverityError, checkSnortPCREFlag},
	{"vc-pcre-anchor", idsrule.SeverityError, checkPCREAnchor},
	{"vc-pcre-capture-group", idsrule.SeverityError, checkPCRECaptureGroup},
	{"vc-pcre-trailing", idsrule.SeverityError, checkPCRETrailing},
	{"vc-pcre-fixed-string", idsrule.SeverityError, checkPCREFixedString},
	{"vc-pcre-dotstar", idsrule.SeverityWarning, checkPCREDotStar},
	{"vc-nocase-case-sensitive", idsrule.SeverityWarning, checkNocaseCaseSensitive},
	{"vc-uri-path-anchor", idsrule.SeverityWarning, checkURIPathAnchor},
	{"vc-uri-path-depth", idsrule.SeverityError, checkURIPathDepth},
	{"vc-tcp-unbounded-content", idsrule.SeverityWarning, checkTCPUnboundedContent},
	{"vc-snort-put-body", idsrule.SeverityWarning, checkSnortPUTBody},
	{"vc-sticky-buffer-scope", idsrule.SeverityError, checkStickyBufferScope},
	{"vc-deployment-metadata", idsrule.SeverityError, checkDeploymentMetadata},
	{"vc-encrypted-pcap", idsrule.SeverityError, checkEncryptedPcap},
}

// ruleEntryInfo is what the entry-level checks know about the feed entry a
// rule file belongs to. A nil *ruleEntryInfo skips them.
type ruleEntryInfo struct {
	// encryptedComms are the targetEncryptedComms values of the entry's
	// artifacts, as written.
	encryptedComms []string
	// hasEncryptedPcap reports whether the rule file's directory holds
	// 00-exploited-encrypted.pcap(ng).
	hasEncryptedPcap bool
}

// ruleCheckCtx is what a check sees for one rule file.
type ruleCheckCtx struct {
	dialect idsrule.Dialect
	tree    *cst.File
	lines   *source.LineTable
	entry   *ruleEntryInfo

	builder diag.Builder
	id      string
	sev     idsrule.Severity
	out     []idsrule.Diagnostic
}

// report records a finding of the running check at span. The pointer is
// valid until the next report.
func (c *ruleCheckCtx) report(span source.Span, format string, args ...any) *idsrule.Diagnostic {
	c.out = append(c.out, c.builder.New(c.id, c.sev, span, format, args...))

	return &c.out[len(c.out)-1]
}

// line returns the 1-based line of a source offset.
func (c *ruleCheckCtx) line(off int) int {
	return c.lines.Position(off).Line
}

// keyword looks up an option's keyword in the file's dialect.
func (c *ruleCheckCtx) keyword(o *cst.Option) (dialect.Keyword, bool) {
	return dialect.Lookup(c.dialect, o.Name())
}

// runRuleChecks runs the VulnCheck checks over one rule file.
func runRuleChecks(file string, src []byte, d idsrule.Dialect, entry *ruleEntryInfo) []idsrule.Diagnostic {
	tree, _ := idsrule.Parse(file, src)
	ctx := &ruleCheckCtx{
		dialect: d,
		tree:    tree,
		lines:   tree.Lines(),
		entry:   entry,
	}
	ctx.builder = diag.Builder{File: file, Lines: ctx.lines}
	if d == idsrule.DialectUnknown {
		return nil
	}
	for _, rc := range ruleChecks {
		ctx.id, ctx.sev = rc.id, rc.sev
		rc.run(ctx)
	}
	diag.Sort(ctx.out)

	return ctx.out
}

// -- helpers ----------------------------------------------------------------

var (
	cveRe         = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	cveExactRe    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	flowbitNameRe = regexp.MustCompile(`^vc-cve-\d{4}-\d{4,}(?:-[a-z0-9]+)*$`)
)

const msgPrefix = "VULNCHECK "

// logical returns an option's value as the engines see it.
func logical(o *cst.Option) string {
	v, _ := o.LogicalValue()

	return v
}

// ruleMsg returns the decoded msg of r and its option, or "" and nil.
func ruleMsg(r *cst.Rule) (string, *cst.Option) {
	o := r.Option("msg")
	if o == nil || !o.HasValue() {
		return "", nil
	}
	msg, err := value.ParseQuoted(logical(o))
	if err != nil {
		return "", nil
	}

	return msg, o
}

// ruleMetadata returns every metadata entry of r, in order, with the option
// each came from.
func ruleMetadata(r *cst.Rule) ([]value.MetadataEntry, []*cst.Option) {
	var entries []value.MetadataEntry
	var opts []*cst.Option
	for _, o := range r.OptionsNamed("metadata") {
		m, err := value.ParseMetadata(logical(o))
		if err != nil {
			continue
		}
		for _, e := range m.Entries {
			entries = append(entries, e)
			opts = append(opts, o)
		}
	}

	return entries, opts
}

// isSuccessImpact reports whether a metadata entry marks a success rule.
func isSuccessImpact(e value.MetadataEntry) bool {
	return e.Key == "impact" && e.Value == "successful-exploitation"
}

// ruleFlow returns the flow tokens of r.
func ruleFlow(r *cst.Rule) []string {
	o := r.Option("flow")
	if o == nil {
		return nil
	}
	f, err := value.ParseFlow(logical(o))
	if err != nil {
		return nil
	}

	return f.Tokens
}

// suricataOnlyFeatures are detection features that exist in Suricata but not
// reliably in Snort 2.9, so style-rules §4 lets the twins diverge where one is
// in use. base64 operations are the canonical example: Snort's base64_decode
// is unreliable, so the Snort twin routinely works around it or drops the rule,
// which shifts the rule count and the per-rule pairing.
var suricataOnlyFeatures = map[string]bool{
	"base64_decode": true,
	"base64_data":   true,
}

// usesSuricataOnlyFeature reports whether any rule in tree uses a feature with
// no reliable Snort equivalent, which parity forgives (style-rules §4).
func usesSuricataOnlyFeature(tree *cst.File) bool {
	if tree == nil {
		return false
	}
	for _, r := range tree.Rules() {
		for _, o := range r.Options() {
			if suricataOnlyFeatures[o.Name()] {
				return true
			}
		}
	}

	return false
}

// ruleClasstypes returns r's classtype values, sorted, for cross-engine
// comparison.
func ruleClasstypes(r *cst.Rule) []string {
	var out []string
	for _, o := range r.OptionsNamed("classtype") {
		out = append(out, logical(o))
	}
	slices.Sort(out)

	return out
}

// ruleFlowbitActions returns the verbs of r's flowbits options, sorted, for
// cross-engine comparison.
func ruleFlowbitActions(r *cst.Rule) []string {
	var out []string
	for _, o := range r.OptionsNamed("flowbits") {
		if fb, err := value.ParseFlowbits(logical(o)); err == nil {
			out = append(out, fb.Verb)
		}
	}
	slices.Sort(out)

	return out
}

// ruleSIDValue returns the sid of r and its option.
func ruleSIDValue(r *cst.Rule) (uint64, *cst.Option, bool) {
	o := r.Option("sid")
	if o == nil {
		return 0, nil, false
	}
	sid, err := value.ParseUint(logical(o))
	if err != nil {
		return 0, nil, false
	}

	return sid, o, true
}

// payload is one content or pcre of a rule with the buffer it inspects and
// the modifiers that follow it.
type payload struct {
	opt  *cst.Option
	pcre bool
	// content is the decoded content (nil for a pcre or a content that does
	// not decode); re is the decoded pcre.
	content *value.Content
	re      *value.PCRE
	// buffer is the buffer inspected, as a Suricata sticky buffer name
	// ("http.uri"), or "" for the raw stream or packet.
	buffer string
	mods   []*cst.Option
	// modAfterPCRE is an http_* content modifier written after a pcre, which
	// does not scope the pcre (Snort).
	modAfterPCRE *cst.Option
}

// hasMod reports whether the payload carries the named modifier.
func (p *payload) hasMod(name string) *cst.Option {
	for _, m := range p.mods {
		if m.Name() == name {
			return m
		}
	}

	return nil
}

// snortModifierBuffers maps the Snort HTTP content modifiers to the
// equivalent Suricata sticky buffer.
var snortModifierBuffers = map[string]string{
	"http_uri":         "http.uri",
	"http_raw_uri":     "http.uri.raw",
	"http_client_body": "http.request_body",
	"http_header":      "http.header",
	"http_raw_header":  "http.header.raw",
	"http_method":      "http.method",
	"http_cookie":      "http.cookie",
	"http_raw_cookie":  "http.cookie.raw",
	"http_stat_code":   "http.stat_code",
	"http_stat_msg":    "http.stat_msg",
	// Suricata's legacy content modifiers.
	"http_user_agent":  "http.user_agent",
	"http_host":        "http.host",
	"http_raw_host":    "http.host.raw",
	"http_server_body": "http.response_body",
}

// pcreFlagBuffers maps the PCRE flags that select an HTTP buffer to the
// equivalent Suricata sticky buffer. Snort 2 and Suricata share them.
var pcreFlagBuffers = map[rune]string{
	'U': "http.uri",
	'I': "http.uri.raw",
	'P': "http.request_body",
	'Q': "http.response_body",
	'H': "http.header",
	'D': "http.header.raw",
	'M': "http.method",
	'C': "http.cookie",
	'K': "http.cookie.raw",
	'S': "http.stat_code",
	'Y': "http.stat_msg",
	'V': "http.user_agent",
	'W': "http.host",
}

// bufferFlagOf returns the buffer-selecting flags of a pcre and the buffer
// they select (the last one wins).
func bufferFlagOf(flags string) (string, string) {
	var found, buffer string
	for _, f := range flags {
		if b, ok := pcreFlagBuffers[f]; ok {
			found += string(f)
			buffer = b
		}
	}

	return found, buffer
}

// payloads splits r into its content and pcre matches.
func (c *ruleCheckCtx) payloads(r *cst.Rule) []*payload {
	var out []*payload
	var last *payload
	sticky := ""
	for _, o := range r.Options() {
		k, ok := c.keyword(o)
		if !ok {
			continue
		}
		switch {
		case k.Role == dialect.RoleStickyBuffer:
			sticky = o.Name()
			if k.Successor != "" {
				sticky = k.Successor
			}
			last = nil
		case o.Name() == "content" || o.Name() == "uricontent" || o.Name() == "pcre":
			p := &payload{opt: o, pcre: o.Name() == "pcre", buffer: sticky}
			if o.Name() == "uricontent" {
				p.buffer = "http.uri"
			}
			if p.pcre {
				if re, err := value.ParsePCRE(logical(o)); err == nil {
					p.re = &re
					if _, b := bufferFlagOf(re.Flags); b != "" {
						p.buffer = b
					}
				}
			} else if ct, err := value.ParseContent(logical(o)); err == nil {
				p.content = &ct
			}
			out = append(out, p)
			last = p
		case k.Role == dialect.RoleModifier && last != nil:
			// As in both engines, a modifier applies to the latest content
			// or pcre even past an isdataat or byte_test in between.
			if b, ok := snortModifierBuffers[o.Name()]; ok {
				if last.pcre {
					last.modAfterPCRE = o
				} else {
					last.buffer = b
				}
			}
			last.mods = append(last.mods, o)
		}
	}

	return out
}

// uriPathAnchor returns the content that anchors the URI path: the first
// content in http.uri, when it looks like a path: it starts with '/', is
// more than "/" and holds no traversal. A content written with Snort 3
// modifiers is skipped: content-snort3-modifiers reports it.
func uriPathAnchor(ps []*payload) *payload {
	for _, p := range ps {
		if p.pcre || p.buffer != "http.uri" || p.content == nil || p.content.Negated {
			continue
		}
		pat := p.content.Pattern
		if p.content.Trailing == "" && len(pat) > 1 && pat[0] == '/' && !bytes.Contains(pat, []byte("..")) {
			return p
		}

		return nil // the first URI content is not a path
	}

	return nil
}

// -- msg, reference, classtype (skill §2, §11) -------------------------------

func checkMsgFormat(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		msg, o := ruleMsg(r)
		if o == nil || !strings.HasPrefix(msg, msgPrefix) {
			continue // msg-missing and msg-prefix report these
		}
		if !strings.HasSuffix(msg, " Attempt") && !strings.HasSuffix(msg, " Success") {
			c.report(o.Span(), "msg %q must end in \" Attempt\" or \" Success\"", msg)
		}
		if loc := cveRe.FindStringIndex(msg); loc != nil && loc[0] != len(msgPrefix) {
			c.report(o.Span(), "msg %q names %s; the CVE must come right after %q", msg, msg[loc[0]:loc[1]], strings.TrimSpace(msgPrefix))
		}
	}
}

func checkMsgFirst(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		opts := r.Options()
		if len(opts) == 0 || r.Option("msg") == nil || opts[0].Name() == "msg" {
			continue
		}
		c.report(opts[0].Span(), "msg must be the first option, not %q", opts[0].Name())
	}
}

func checkReferenceCVE(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		cves := map[string]bool{}
		for _, o := range r.OptionsNamed("reference") {
			ref, err := value.ParseReference(logical(o))
			if err != nil || !strings.EqualFold(ref.Scheme, "cve") {
				continue
			}
			if !cveExactRe.MatchString(ref.ID) {
				c.report(o.Span(), "reference:cve,%s must be written reference:cve,CVE-YYYY-NNNNN", ref.ID)
			}
			cves[strings.ToUpper(ref.ID)] = true
		}
		msg, o := ruleMsg(r)
		if o == nil {
			continue
		}
		if cve := cveRe.FindString(msg); cve != "" && !cves[cve] {
			c.report(o.Span(), "msg names %s but the rule has no reference:cve,%s", cve, cve)
		}
	}
}

// classtypes are the classtypes rules may use: the style-rules skill's list
// (with successful-user spelled correctly) and targeted-activity.
var classtypes = map[string]bool{
	"not-suspicious": true, "unknown": true, "bad-unknown": true,
	"attempted-recon": true, "successful-recon-limited": true, "successful-recon-largescale": true,
	"attempted-dos": true, "successful-dos": true,
	"attempted-user": true, "unsuccessful-user": true, "successful-user": true,
	"attempted-admin": true, "successful-admin": true,
	"rpc-portmap-decode": true, "shellcode-detect": true, "string-detect": true,
	"suspicious-filename-detect": true, "suspicious-login": true, "system-call-detect": true,
	"tcp-connection": true, "trojan-activity": true, "unusual-client-port-connection": true,
	"network-scan": true, "denial-of-service": true, "non-standard-protocol": true,
	"protocol-command-decode": true, "web-application-activity": true, "web-application-attack": true,
	"misc-activity": true, "misc-attack": true, "icmp-event": true, "inappropriate-content": true,
	"policy-violation": true, "default-login-attempt": true, "sdf": true, "file-format": true,
	"malware-cnc": true, "client-side-exploit": true, "targeted-activity": true,
}

func checkClasstype(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		o := r.Option("classtype")
		if o == nil {
			c.report(r.Header.Span(), "rule has no classtype")

			continue
		}
		if ct := logical(o); !classtypes[ct] {
			c.report(o.Span(), "classtype %q is not one of the allowed classtypes", ct)
		}
	}
}

func checkClasstypeAdmin(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		if o := r.Option("classtype"); o != nil {
			if ct := logical(o); ct == "attempted-admin" || ct == "successful-admin" {
				c.report(o.Span(), "classtype %s is only for privilege escalation; confirm the exploit is one", ct)
			}
		}
	}
}

// checkFlowEstablished holds every rule to an established flow: a feed rule
// matches a step of an exploit mid-session, so it keys on a flow the engine has
// already seen traffic for, never a stray packet. The convention is a flow
// option carrying the established token (flow:to_server,established or
// flow:from_server,established).
func checkFlowEstablished(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		if slices.Contains(ruleFlow(r), "established") {
			continue
		}
		span := r.Header.Span()
		if o := r.Option("flow"); o != nil {
			span = o.Span()
		}
		c.report(span, "a rule must track an established flow; add the established token to flow (flow:to_server,established)")
	}
}

// -- flowbits and success rules (skill §1, §5) -------------------------------

// flowbitNames returns the names of a flowbits value, splitting Suricata's
// "a&b" form too.
func flowbitNames(fb value.Flowbits) []string {
	var names []string
	for _, n := range fb.Names {
		names = append(names, strings.Split(n, "&")...)
	}

	return names
}

func checkFlowbitsName(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, o := range r.OptionsNamed("flowbits") {
			fb, err := value.ParseFlowbits(logical(o))
			if err != nil {
				continue
			}
			for _, name := range flowbitNames(fb) {
				if !flowbitNameRe.MatchString(name) {
					c.report(o.Span(), "flowbit %q must be named vc-cve-YYYY-NNNNN, optionally with a -stage suffix", name)
				}
			}
		}
	}
}

func checkFlowbitsUnset(c *ruleCheckCtx) {
	set := map[string]bool{}
	type use struct {
		o    *cst.Option
		name string
	}
	var tested []use
	for _, r := range c.tree.Rules() {
		for _, o := range r.OptionsNamed("flowbits") {
			fb, err := value.ParseFlowbits(logical(o))
			if err != nil {
				continue
			}
			switch fb.Verb {
			case "set", "setx", "toggle":
				for _, n := range flowbitNames(fb) {
					set[n] = true
				}
			case "isset", "isnotset":
				for _, n := range flowbitNames(fb) {
					tested = append(tested, use{o, n})
				}
			}
		}
	}
	for _, u := range tested {
		if !set[u.name] {
			c.report(u.o.Span(), "flowbit %q is tested but no rule in the file sets it", u.name)
		}
	}
}

func checkSuccessImpact(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		msg, msgOpt := ruleMsg(r)
		entries, opts := ruleMetadata(r)
		at := -1
		for i, e := range entries {
			if isSuccessImpact(e) {
				at = i
			}
		}
		success := strings.HasSuffix(msg, " Success")
		switch {
		case success && at < 0:
			c.report(msgOpt.Span(), "a Success rule must end its metadata with impact successful-exploitation")
		case at >= 0 && strings.HasSuffix(msg, " Attempt"): // vc-msg-format reports other msgs
			c.report(opts[at].Span(), "impact successful-exploitation is only for rules whose msg ends in \" Success\"")
		case at >= 0 && at != len(entries)-1:
			c.report(opts[at].Span(), "impact successful-exploitation must be the last metadata entry")
		}
	}
}

func checkSuccessDirection(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		entries, opts := ruleMetadata(r)
		for i, e := range entries {
			if !isSuccessImpact(e) {
				continue
			}
			if !c.matchesResponse(r) {
				c.report(opts[i].Span(), "impact successful-exploitation must sit on a rule matching the server response (flow:from_server or to_client)")
			}

			break
		}
	}
}

// responseBuffers only exist in a server response.
var responseBuffers = map[string]bool{
	"http.stat_code": true, "http.stat_msg": true, "http.response_body": true,
	"http.response_line": true, "http.response_header": true, "http.server": true,
	"http.location": true,
}

// matchesResponse reports whether r keys on the server response: its flow
// says so, it inspects a response-only buffer, or, without a flow, its
// header pins the server's source port.
func (c *ruleCheckCtx) matchesResponse(r *cst.Rule) bool {
	flow := ruleFlow(r)
	if slices.Contains(flow, "from_server") || slices.Contains(flow, "to_client") {
		return true
	}
	for _, p := range c.payloads(r) {
		if responseBuffers[p.buffer] {
			return true
		}
	}
	if r.Option("flow") == nil && r.Header.SrcPort != nil && r.Header.SrcPort.Word != nil {
		port := r.Header.SrcPort.Word.Lit
		return port != "" && port != "any" && r.Header.SrcPort.Bang == nil
	}

	return false
}

// hasFlowbitsIsset reports whether r tests a flowbit, the structural tell of
// the success half of an attempt/success pair.
func hasFlowbitsIsset(r *cst.Rule) bool {
	for _, o := range r.OptionsNamed("flowbits") {
		if fb, err := value.ParseFlowbits(logical(o)); err == nil && fb.Verb == "isset" {
			return true
		}
	}

	return false
}

// isSuccessSide reports whether r is the success half of a pair: either signal
// is enough, a tested flowbit (structural) or a " Success" msg (declared).
func isSuccessSide(r *cst.Rule) bool {
	if hasFlowbitsIsset(r) {
		return true
	}
	msg, _ := ruleMsg(r)

	return strings.HasSuffix(msg, " Success")
}

// successClasstype maps an attempt classtype to the one a success rule uses
// instead.
var successClasstype = map[string]string{
	"attempted-admin": "successful-admin",
	"attempted-user":  "successful-user",
	"attempted-dos":   "successful-dos",
	"attempted-recon": "successful-recon-limited or successful-recon-largescale",
}

// checkSuccessClasstype holds a success rule to a successful-* classtype
// (skill §11): the rule fires because the exploit worked, so it must not keep
// the attempt's classtype, which is how the operator's console ranks the alert.
func checkSuccessClasstype(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		if !isSuccessSide(r) {
			continue
		}
		o := r.Option("classtype")
		if o == nil {
			continue // vc-classtype reports a missing classtype
		}
		if want, ok := successClasstype[logical(o)]; ok {
			c.report(o.Span(), "a success rule fires because the exploit worked; use %s, not %s", want, logical(o))
		}
	}
}

// -- layout (skill §8, §12, §6) -----------------------------------------------

func checkNoComments(c *ruleCheckCtx) {
	for _, it := range c.tree.Items {
		if cm, ok := it.(*cst.Comment); ok {
			c.report(cm.Hash.Span(), "comments are not allowed in rule files; explain the rule in the PR description")
		}
	}
}

// startsClause reports whether option i of opts starts a new clause: a clause
// is one option, a content or pcre with the modifiers after it (optionally
// preceded by its sticky buffer and that buffer's transforms), or sid with
// rev.
func (c *ruleCheckCtx) startsClause(opts []*cst.Option, i int) bool {
	if i == 0 {
		return true
	}
	o, prev := opts[i], opts[i-1]
	if (o.Name() == "rev" && prev.Name() == "sid") || (o.Name() == "sid" && prev.Name() == "rev") {
		return false
	}
	k, ok := c.keyword(o)
	if !ok {
		return true
	}
	switch k.Role {
	case dialect.RoleModifier, dialect.RoleTransform, dialect.RoleBufferTest:
		return false
	case dialect.RolePayload:
		// A match may share the line of the sticky buffer (and transforms)
		// it is the first match of.
		for j := i - 1; j >= 0; j-- {
			pk, ok := c.keyword(opts[j])
			if !ok {
				return true
			}
			switch pk.Role {
			case dialect.RoleTransform, dialect.RoleBufferTest:
				continue
			case dialect.RoleStickyBuffer:
				return false
			}

			return true
		}
	}

	return true
}

func checkOptionPerLine(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		opts := r.Options()
		if len(opts) == 0 {
			continue
		}
		if c.line(opts[0].Span().Start) == c.line(r.Header.Span().Start) {
			c.report(opts[0].Span(), "rule options must start on the line after the header; end the header line with \"( \\\"")
		}
		// owner maps a line to the clause whose option it holds first.
		owner := map[int]int{}
		reported := map[int]bool{}
		clause := -1
		for i, o := range opts {
			if c.startsClause(opts, i) {
				clause++
			}
			l := c.line(o.Span().Start)
			first, seen := owner[l]
			switch {
			case !seen:
				owner[l] = clause
			case first != clause && !reported[l]:
				c.report(o.Span(), "%q shares a line with the option before it; put one option per line", o.Name())
				reported[l] = true
			}
		}
	}
}

func checkSIDRevLine(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		sid, rev := r.Option("sid"), r.Option("rev")
		if sid == nil || rev == nil {
			continue
		}
		if c.line(sid.Span().Start) != c.line(rev.Span().Start) {
			c.report(rev.Span(), "sid and rev must share a line")
		}
	}
}

func checkPlaceholderSequence(c *ruleCheckCtx) {
	seen := map[uint64]bool{}
	next := uint64(1)
	for _, r := range c.tree.Rules() {
		sid, o, ok := ruleSIDValue(r)
		if !ok || sid >= sidMin {
			continue
		}
		switch {
		case seen[sid]:
			d := c.builder.New(c.id, idsrule.SeverityError, o.Span(), "placeholder sid:%d is used twice in the file; number placeholders sid:1, sid:2, ...", sid)
			c.out = append(c.out, d)
		case sid != next:
			c.report(o.Span(), "placeholder sid:%d is out of sequence; number placeholders sid:1, sid:2, ... (expected sid:%d)", sid, next)
		}
		seen[sid] = true
		next = max(next, sid+1)
	}
}

// -- content and pcre (skill §9, §10, §13, §15, §17, §18) --------------------

// contentHexRe matches a |..| hex run inside a content value.
var contentHexRe = regexp.MustCompile(`\|([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\|`)

// hexMustEncode are the bytes a content can only carry hex-encoded, so their
// |XX| is never unnecessary: the quote and semicolon that would otherwise end
// the value or the option, the backslash that escapes, and the pipe that
// delimits hex.
var hexMustEncode = map[byte]bool{'"': true, ';': true, '\\': true, '|': true}

// checkContentHex reports a content that hex-encodes a printable ASCII byte it
// could carry literally (skill §28): a rule reads far more clearly as
// content:"GET" than content:"|47 45 54|", and the hex hides what is matched.
// Bytes that can only be written as hex are left alone.
func checkContentHex(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, o := range r.Options() {
			if o.Name() != "content" && o.Name() != "uricontent" {
				continue
			}
			for _, m := range contentHexRe.FindAllStringSubmatch(logical(o), -1) {
				done := false
				for _, hb := range strings.Fields(m[1]) {
					b, err := strconv.ParseUint(hb, 16, 8)
					if err != nil {
						continue
					}
					if code := byte(b); code >= 0x20 && code <= 0x7e && !hexMustEncode[code] {
						c.report(o.Span(), "content hex-encodes the printable byte |%s|; write it literally as %q", hb, string(rune(code)))
						done = true

						break
					}
				}
				if done {
					break // one finding per content is enough
				}
			}
		}
	}
}

func checkNoFastPattern(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, o := range r.OptionsNamed("fast_pattern") {
			c.report(o.Span(), "do not use fast_pattern; let the engine choose")
		}
	}
}

func checkPCREBufferFlag(c *ruleCheckCtx) {
	if c.dialect != idsrule.DialectSuricata {
		return
	}
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.re == nil {
				continue
			}
			if flags, buffer := bufferFlagOf(p.re.Flags); flags != "" {
				c.report(p.opt.Span(), "pcre flag %q selects a buffer; use the %s sticky buffer before the pcre instead", flags, buffer)
			}
		}
	}
}

func checkSnortPCREFlag(c *ruleCheckCtx) {
	if c.dialect != idsrule.DialectSnort2 {
		return
	}
	flagFor := map[string]string{}
	for f, b := range pcreFlagBuffers {
		flagFor[b] = string(f)
	}
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.modAfterPCRE == nil {
				continue
			}
			b := snortModifierBuffers[p.modAfterPCRE.Name()]
			c.report(p.modAfterPCRE.Span(), "%s does not apply to a pcre; give the pcre the %s flag instead", p.modAfterPCRE.Name(), flagFor[b])
		}
	}
}

func checkPCREAnchor(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		anchored := map[string]bool{}
		for _, p := range c.payloads(r) {
			if !p.pcre {
				if p.content != nil && !p.content.Negated {
					anchored[p.buffer] = true
				}

				continue
			}
			if !anchored[p.buffer] && p.modAfterPCRE == nil { // vc-snort-pcre-flag reports those
				where := "the raw stream"
				if p.buffer != "" {
					where = p.buffer
				}
				c.report(p.opt.Span(), "pcre in %s needs a content match in the same buffer before it", where)
			}
		}
	}
}

// pcreScan walks a pcre pattern and calls visit for every top-level atom
// outside a character class: the byte at i, whether it is escaped, and
// whether i starts a character class (which then spans to end).
func pcreScan(pat string, visit func(i, end int, escaped, class bool)) {
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '\\':
			visit(i, min(i+2, len(pat)), true, false)
			i++
		case '[':
			end := classEnd(pat, i)
			visit(i, end, false, true)
			i = end - 1
		default:
			visit(i, i+1, false, false)
		}
	}
}

// classEnd returns the offset just past the character class opening at i.
func classEnd(pat string, i int) int {
	j := i + 1
	if j < len(pat) && pat[j] == '^' {
		j++
	}
	if j < len(pat) && pat[j] == ']' {
		j++ // a leading ']' is literal
	}
	for ; j < len(pat); j++ {
		switch pat[j] {
		case '\\':
			j++
		case ']':
			return j + 1
		}
	}

	return len(pat)
}

func checkPCRECaptureGroup(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.re == nil {
				continue
			}
			pat := p.re.Pattern
			if backrefRe.MatchString(pat) {
				continue // the groups a backreference needs must capture
			}
			at := -1
			pcreScan(pat, func(i, _ int, escaped, class bool) {
				if at >= 0 || escaped || class || pat[i] != '(' {
					return
				}
				if isCaptureGroup(pat[i+1:]) {
					at = i
				}
			})
			if at >= 0 {
				c.report(p.opt.Span(), "pcre has a capture group at %q; use (?:...)", pat[at:min(at+12, len(pat))])
			}
		}
	}
}

// backrefRe matches a pcre backreference: \1 to \9, \g{n}, \g1 or \k<name>.
var backrefRe = regexp.MustCompile(`(?:^|[^\\])(?:\\\\)*\\(?:[1-9]|g\{?-?\d|k[<{'])`)

// isCaptureGroup reports whether a group whose text after '(' is rest
// captures: a plain group or a named one, not (?:...), a lookaround, an
// inline flag or a (*VERB).
func isCaptureGroup(rest string) bool {
	switch {
	case strings.HasPrefix(rest, "*"):
		return false
	case strings.HasPrefix(rest, "?P<"), strings.HasPrefix(rest, "?'"):
		return true
	case strings.HasPrefix(rest, "?<") && !strings.HasPrefix(rest, "?<=") && !strings.HasPrefix(rest, "?<!"):
		return true
	case strings.HasPrefix(rest, "?"):
		return false
	}

	return true
}

// pcreTrailer describes what a pcre pattern ends in when that is a wildcard,
// an open class or '$', or returns "".
func pcreTrailer(pat string) string {
	type atom struct {
		start, end int
		escaped    bool
		class      bool
	}
	var atoms []atom
	pcreScan(pat, func(i, end int, escaped, class bool) {
		atoms = append(atoms, atom{i, end, escaped, class})
	})
	// Drop closing parentheses: "(?:a.*)" ends in ".*" all the same.
	for len(atoms) > 0 {
		a := atoms[len(atoms)-1]
		if a.escaped || a.class || pat[a.start] != ')' {
			break
		}
		atoms = atoms[:len(atoms)-1]
	}
	if len(atoms) == 0 {
		return ""
	}
	last := atoms[len(atoms)-1]
	if !last.escaped && !last.class && pat[last.start] == '$' {
		return "$"
	}
	// A lazy quantifier's '?' leaves the quantifier before it.
	end := last.end
	if !last.escaped && !last.class && pat[last.start] == '?' && len(atoms) > 1 {
		if q := atoms[len(atoms)-2]; !q.escaped && !q.class && (pat[q.start] == '*' || pat[q.start] == '+') {
			atoms, last = atoms[:len(atoms)-1], q
		}
	}
	if last.escaped || last.class || (pat[last.start] != '*' && pat[last.start] != '+') || len(atoms) < 2 {
		return ""
	}
	prev := atoms[len(atoms)-2]
	switch {
	case prev.class:
		return pat[prev.start:end]
	case !prev.escaped && pat[prev.start] == '.':
		return pat[prev.start:end]
	}

	return ""
}

func checkPCRETrailing(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.re == nil {
				continue
			}
			if t := pcreTrailer(p.re.Pattern); t != "" {
				c.report(p.opt.Span(), "pcre ends in %q; end the pattern at the last byte the technique needs", t)
			}
		}
	}
}

// pcreLiteral returns the bytes a pcre pattern matches when it is a plain
// string (no metacharacters, only escaped punctuation), or false.
func pcreLiteral(pat string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		ch := pat[i]
		switch {
		case ch == '\\':
			if i+1 >= len(pat) {
				return "", false
			}
			n := pat[i+1]
			if (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '0' && n <= '9') {
				return "", false // \d, \s, \x41, \1, ...
			}
			b.WriteByte(n)
			i++
		case strings.IndexByte(".^$*+?()[]{}|", ch) >= 0:
			return "", false
		default:
			b.WriteByte(ch)
		}
	}

	return b.String(), true
}

func checkPCREFixedString(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.re == nil || strings.ContainsRune(p.re.Flags, 'x') {
				continue
			}
			if lit, ok := pcreLiteral(p.re.Pattern); ok && lit != "" {
				c.report(p.opt.Span(), "pcre %q is a fixed string; match it with content", lit)
			}
		}
	}
}

func checkPCREDotStar(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		for _, p := range c.payloads(r) {
			if p.re == nil || pcreTrailer(p.re.Pattern) != "" {
				continue // vc-pcre-trailing reports the pattern
			}
			pat := p.re.Pattern
			found := false
			pcreScan(pat, func(i, _ int, escaped, class bool) {
				if !found && !escaped && !class && pat[i] == '.' && i+1 < len(pat) && (pat[i+1] == '*' || pat[i+1] == '+') {
					found = true
				}
			})
			if found {
				c.report(p.opt.Span(), "pcre uses an unbounded .* or .+; bound it with a class such as [^&]*")
			}
		}
	}
}

func checkNocaseCaseSensitive(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		ps := c.payloads(r)
		anchor := uriPathAnchor(ps)
		for _, p := range ps {
			m := p.hasMod("nocase")
			if m == nil {
				continue
			}
			switch {
			case p.buffer == "http.method":
				c.report(m.Span(), "HTTP methods are case-sensitive; drop nocase unless the target is shown to ignore case")
			case p == anchor:
				c.report(m.Span(), "URI paths are case-sensitive; drop nocase unless the target is shown to ignore case")
			}
		}
	}
}

func checkURIPathAnchor(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		p := uriPathAnchor(c.payloads(r))
		if p == nil {
			continue
		}
		switch c.dialect {
		case idsrule.DialectSuricata:
			if p.hasMod("startswith") == nil {
				c.report(p.opt.Span(), "anchor the URI path with startswith")
			}
		case idsrule.DialectSnort2:
			if p.hasMod("depth") == nil {
				c.report(p.opt.Span(), "anchor the URI path with depth:%d", len(p.content.Pattern))
			}
		}
	}
}

// checkURIPathDepth holds the depth of a URI path anchor to the length of
// the path (skill §15): LLM-written rules keep getting it off by one or two.
func checkURIPathDepth(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		p := uriPathAnchor(c.payloads(r))
		if p == nil {
			continue
		}
		if off := p.hasMod("offset"); off != nil {
			if v, err := value.ParseIntOrVar(logical(off)); err == nil && v.Var == "" && v.Value != 0 {
				c.report(off.Span(), "the URI path anchor must start at the beginning of the URI; drop offset:%d", v.Value)
			}
		}
		depth := p.hasMod("depth")
		if depth == nil || p.hasMod("startswith") != nil {
			continue // vc-uri-path-anchor reports a missing anchor; startswith already fixes the length
		}
		v, err := value.ParseIntOrVar(logical(depth))
		want := int64(len(p.content.Pattern))
		if err != nil || v.Var != "" || v.Value == want {
			continue
		}
		path := string(p.content.Pattern)
		d := c.report(depth.Span(), "depth:%d should be %d, the length of %q", v.Value, want, path)
		d.Edits = []source.TextEdit{{Span: depth.ValueSpan(), NewText: strconv.FormatInt(want, 10)}}
	}
}

// dropSupersededDepth removes idsrule's content-depth-too-short findings on
// a depth that vc-uri-path-depth also reports: its message gives the right
// value and carries the autofix.
func dropSupersededDepth(diags []idsrule.Diagnostic) []idsrule.Diagnostic {
	pathDepths := map[source.Span]bool{}
	for _, d := range diags {
		if d.Rule == "vc-uri-path-depth" {
			pathDepths[d.Span] = true
		}
	}

	return slices.DeleteFunc(diags, func(d idsrule.Diagnostic) bool {
		return d.Rule == "content-depth-too-short" && pathDepths[d.Span]
	})
}

// boundingModifiers bound where a content may match.
var boundingModifiers = []string{"offset", "depth", "distance", "within", "startswith", "endswith"}

func checkTCPUnboundedContent(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		proto := strings.ToLower(r.Header.Proto.Lit)
		if proto != "tcp" && proto != "udp" && proto != "ip" && proto != "tcp-pkt" && proto != "tcp-stream" {
			continue
		}
		if r.Option("isdataat") != nil || r.Option("bsize") != nil || r.Option("dsize") != nil {
			continue
		}
		for _, p := range c.payloads(r) {
			if p.pcre || p.buffer != "" || (p.content != nil && p.content.Trailing != "") {
				continue
			}
			bounded := false
			for _, name := range boundingModifiers {
				if p.hasMod(name) != nil {
					bounded = true
				}
			}
			if !bounded {
				c.report(p.opt.Span(), "content scans the whole stream; bound it with a buffer, offset/depth or distance/within")
			}
		}
	}
}

func checkSnortPUTBody(c *ruleCheckCtx) {
	if c.dialect != idsrule.DialectSnort2 {
		return
	}
	for _, r := range c.tree.Rules() {
		ps := c.payloads(r)
		put := false
		for _, p := range ps {
			if p.buffer == "http.method" && p.content != nil && string(p.content.Pattern) == "PUT" {
				put = true
			}
		}
		if !put {
			continue
		}
		for _, p := range ps {
			if p.buffer == "http.request_body" {
				c.report(p.opt.Span(), "Snort fills http_client_body from POST bodies only; match a PUT body as raw content")

				break
			}
		}
	}
}

// stickyBufferSetters move the detection cursor to a buffer; the options that
// follow search it. These three are shared by Snort and Suricata. Suricata's
// dotted sticky buffers (http.response_body, ...) are deliberately left out so
// the check stays engine-neutral and free of false positives on those names.
var stickyBufferSetters = map[string]bool{"file_data": true, "pkt_data": true, "base64_data": true}

// bufferConsumers read from whatever buffer is currently selected.
var bufferConsumers = map[string]bool{
	"content": true, "uricontent": true, "pcre": true,
	"byte_test": true, "byte_jump": true, "byte_extract": true, "byte_math": true,
	"isdataat": true,
}

// checkStickyBufferScope reports a file_data/pkt_data/base64_data setter with
// no content, pcre or byte_* after it to search the buffer it selects. Written
// at the tail of a rule the setter scopes nothing, and a content before it
// silently matched the default buffer instead, so the rule no longer mirrors
// its paired http.response_body; content:... Suricata rule. The pcap replay
// misses this because the content still matches the raw payload.
func checkStickyBufferScope(c *ruleCheckCtx) {
	for _, r := range c.tree.Rules() {
		opts := r.Options()
		for i, o := range opts {
			if !stickyBufferSetters[o.Name()] {
				continue
			}
			scoped := false
			for _, next := range opts[i+1:] {
				if bufferConsumers[next.Name()] {
					scoped = true

					break
				}
				if stickyBufferSetters[next.Name()] {
					break
				}
			}
			if !scoped {
				c.report(o.Span(), "%s sets a buffer with no content, pcre or byte_* after it to search; put the setter before the match it scopes", o.Name())
			}
		}
	}
}

// -- entry level (skill §7) ----------------------------------------------------

// deploymentFor maps a targetEncryptedComms value to the deployment metadata
// a rule must carry.
var deploymentFor = map[string][]string{
	"either": {"Datacenter", "SSLDecrypt"},
	"no":     {"Datacenter"},
	"yes":    {"SSLDecrypt"},
}

func checkDeploymentMetadata(c *ruleCheckCtx) {
	if c.entry == nil {
		return
	}
	var allowed [][]string
	for _, v := range c.entry.encryptedComms {
		if want, ok := deploymentFor[strings.TrimSpace(v)]; ok {
			allowed = append(allowed, want)
		}
	}
	rules := c.tree.Rules()
	if len(rules) == 0 {
		return
	}
	if len(allowed) == 0 {
		c.report(rules[0].Header.Span(), "the entry's targetEncryptedComms is %q; it must be either, yes or no to check the deployment metadata", strings.Join(c.entry.encryptedComms, ","))

		return
	}
	for _, r := range rules {
		entries, _ := ruleMetadata(r)
		var got []string
		for _, e := range entries {
			if e.Key == "deployment" && !slices.Contains(got, e.Value) {
				got = append(got, e.Value)
			}
		}
		slices.Sort(got)
		ok := false
		for _, want := range allowed {
			if slices.Equal(got, want) {
				ok = true
			}
		}
		if !ok {
			span := r.Header.Span()
			if o := r.Option("metadata"); o != nil {
				span = o.Span()
			}
			var needs []string
			for _, want := range allowed {
				needs = append(needs, describeDeployment(want))
			}
			c.report(span, "deployment metadata is %s; targetEncryptedComms %s needs %s", describeDeployment(got), strings.Join(c.entry.encryptedComms, ","), strings.Join(needs, " or "))
		}
	}
}

// describeDeployment renders deployment values as metadata text.
func describeDeployment(values []string) string {
	if len(values) == 0 {
		return "missing"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = "deployment " + v
	}

	return fmt.Sprintf("%q", strings.Join(parts, ", "))
}

func checkEncryptedPcap(c *ruleCheckCtx) {
	if c.entry == nil || c.entry.hasEncryptedPcap {
		return
	}
	for _, r := range c.tree.Rules() {
		entries, opts := ruleMetadata(r)
		for i, e := range entries {
			if e.Key == "deployment" && e.Value == "SSLDecrypt" {
				c.report(opts[i].Span(), "a rule with deployment SSLDecrypt needs 00-exploited-encrypted.pcap next to it")

				return
			}
		}
	}
}
