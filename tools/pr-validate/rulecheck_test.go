package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
)

// mkRule formats a rule the way the style skill wants it: the header, then
// one line per element of lines, indented four spaces.
func mkRule(header string, lines ...string) string {
	var b strings.Builder
	b.WriteString(header + " ( \\\n")
	for _, l := range lines {
		b.WriteString("    " + l + " \\\n")
	}
	b.WriteString(")\n")

	return b.String()
}

const (
	snortHeader    = "alert tcp any any -> any any"
	suricataHeader = "alert http any any -> any any"
	attemptMsg     = `msg:"VULNCHECK CVE-2026-0001 Acme Widget Command Injection Attempt";`
	successMsg     = `msg:"VULNCHECK CVE-2026-0001 Acme Widget Command Injection Success";`
	reference      = "reference:cve,CVE-2026-0001;"
	classtype      = "classtype:web-application-attack;"
	sidRev         = "sid:1; rev:1;"
	deployBoth     = "metadata: deployment Datacenter, deployment SSLDecrypt;"
	toServer       = "flow:to_server,established;"
)

// vcRule builds a rule with the boilerplate every rule needs around body.
func vcRule(header string, body ...string) string {
	lines := []string{attemptMsg, toServer}
	lines = append(lines, body...)
	lines = append(lines, reference, classtype, sidRev, deployBoth)

	return mkRule(header, lines...)
}

// vcIDs runs the VulnCheck checks over src and returns the sorted ids.
func vcIDs(t *testing.T, file, src string, entry *ruleEntryInfo) []string {
	t.Helper()
	var ids []string
	for _, d := range runRuleChecks(file, []byte(src), idsrule.DialectFromFilename(file), entry) {
		ids = append(ids, d.Rule)
	}
	slices.Sort(ids)

	return ids
}

var eitherEntry = &ruleEntryInfo{encryptedComms: []string{"either"}, hasEncryptedPcap: true}

func Test_ruleChecks_good(t *testing.T) {
	for file, src := range map[string]string{
		"x.snort.rule":    goodSnortRule,
		"x.suricata.rule": goodSuricataRule,
		"pair.snort.rule": mkRule(snortHeader, attemptMsg, toServer,
			`content:"POST"; http_method;`, `content:"/run"; depth:4; http_uri;`,
			reference, classtype, "flowbits:set,vc-cve-2026-0001;", "flowbits:noalert;", sidRev, deployBoth) +
			mkRule(snortHeader, successMsg, "flow:from_server,established;",
				`content:"200"; http_stat_code;`, reference, classtype,
				"flowbits:isset,vc-cve-2026-0001;", "sid:2; rev:1;",
				"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;"),
	} {
		if ids := vcIDs(t, file, src, eitherEntry); len(ids) != 0 {
			t.Errorf("%s: unexpected findings %v", file, ids)
		}
	}
}

func Test_ruleChecks(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		src   string
		entry *ruleEntryInfo
		want  []string
	}{
		// msg, reference, classtype
		{
			"msg must end in Attempt or Success", "x.snort.rule",
			mkRule(snortHeader, `msg:"VULNCHECK CVE-2026-0001 Acme Widget RCE";`, toServer, `content:"a"; http_uri;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-msg-format"},
		},
		{
			"the CVE must follow VULNCHECK", "x.snort.rule",
			mkRule(snortHeader, `msg:"VULNCHECK Acme CVE-2026-0001 Widget Attempt";`, toServer, `content:"a"; http_uri;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-msg-format"},
		},
		{
			"a msg without a CVE is fine", "x.snort.rule",
			mkRule(snortHeader, `msg:"VULNCHECK Acme Widget Version Probe Attempt";`, toServer, `content:"a"; http_uri;`, classtype, sidRev, deployBoth),
			nil, nil,
		},
		{
			"msg must come first", "x.snort.rule",
			mkRule(snortHeader, toServer, attemptMsg, `content:"a"; http_uri;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-msg-first"},
		},
		{
			"the msg CVE needs a reference", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, classtype, sidRev, deployBoth),
			nil, []string{"vc-reference-cve"},
		},
		{
			"a cve reference must be well formed", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, reference, "reference:cve,2026-0001;", classtype, sidRev, deployBoth),
			nil, []string{"vc-reference-cve"},
		},
		{
			"classtype must be allowed", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, reference, "classtype:succesful-user;", sidRev, deployBoth),
			nil, []string{"vc-classtype"},
		},
		{
			"classtype is required", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, reference, sidRev, deployBoth),
			nil, []string{"vc-classtype"},
		},
		{
			"targeted-activity is allowed, admin classtypes warn", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`) + strings.Replace(strings.Replace(vcRule(snortHeader, `content:"a"; http_uri;`), classtype, "classtype:attempted-admin;", 1), "sid:1;", "sid:2;", 1),
			nil, []string{"vc-classtype-admin"},
		},
		{
			"a rule must track an established flow", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, `content:"a"; http_uri;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-flow-established"},
		},
		{
			"a flow without established is reported", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, "flow:to_server;", `content:"a"; http_uri;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-flow-established"},
		},
		// flowbits and success
		{
			"flowbits must be named vc-cve-", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`, "flowbits:set,cve_2026_0001;"),
			nil, []string{"vc-flowbits-name"},
		},
		{
			"a tested flowbit must be set in the file", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`, "flowbits:isset,vc-cve-2026-0001;"),
			nil, []string{"vc-flowbits-unset"},
		},
		{
			"a Success rule needs the impact metadata", "x.snort.rule",
			mkRule(snortHeader, successMsg, "flow:from_server,established;", `content:"200"; http_stat_code;`, reference, classtype, sidRev, deployBoth),
			nil, []string{"vc-success-impact"},
		},
		{
			"an Attempt rule must not claim impact, and must match the response", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, reference, classtype, sidRev,
				"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;"),
			nil, []string{"vc-success-direction", "vc-success-impact"},
		},
		{
			"impact must be the last metadata entry", "x.snort.rule",
			mkRule(snortHeader, successMsg, "flow:from_server,established;", `content:"200"; http_stat_code;`, reference, classtype, sidRev,
				"metadata: impact successful-exploitation, deployment Datacenter, deployment SSLDecrypt;"),
			nil, []string{"vc-success-impact"},
		},
		{
			"a success rule must not keep an attempted-* classtype", "x.snort.rule",
			mkRule(snortHeader, successMsg, "flow:from_server,established;", `content:"200"; http_stat_code;`, reference, "classtype:attempted-user;", sidRev,
				"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;"),
			nil, []string{"vc-success-classtype"},
		},
		{
			"a success rule with a successful-* classtype is fine", "x.snort.rule",
			mkRule(snortHeader, successMsg, "flow:from_server,established;", `content:"200"; http_stat_code;`, reference, "classtype:successful-user;", sidRev,
				"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;"),
			nil, nil,
		},
		// layout
		{
			"no comments", "x.snort.rule",
			"# explain the rule\n" + vcRule(snortHeader, `content:"a"; http_uri;`),
			nil, []string{"vc-no-comments"},
		},
		{
			"two options on one line", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri; content:"b"; http_uri;`),
			nil, []string{"vc-option-per-line"},
		},
		{
			"a single-line rule is reported once per line", "x.snort.rule",
			snortHeader + ` (` + attemptMsg + " " + toServer + ` content:"a"; http_uri; ` + reference + " " + classtype + " " + sidRev + " " + deployBoth + ")\n",
			nil, []string{"vc-option-per-line", "vc-option-per-line"},
		},
		{
			"a sticky buffer shares its line with its first match only", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`, `http.content_len; byte_test:0,>=,1,0,string,dec;`, `http.request_body; content:"b"; content:"c";`),
			nil, []string{"vc-option-per-line"},
		},
		{
			"sid and rev share a line", "x.snort.rule",
			mkRule(snortHeader, attemptMsg, toServer, `content:"a"; http_uri;`, reference, classtype, "sid:1;", "rev:1;", deployBoth),
			nil, []string{"vc-sid-rev-line"},
		},
		{
			"placeholders run 1..N", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`) + strings.Replace(vcRule(snortHeader, `content:"b"; http_uri;`), "sid:1;", "sid:3;", 1),
			nil, []string{"vc-sid-placeholder-sequence"},
		},
		// content and pcre
		{
			"no fast_pattern", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; fast_pattern; http_uri;`),
			nil, []string{"vc-no-fast-pattern"},
		},
		{
			"content must not hex-encode printable ASCII", "x.snort.rule",
			vcRule(snortHeader, `content:"a|2f 62|c"; http_uri;`),
			nil, []string{"vc-content-hex"},
		},
		{
			"hex for bytes that need it is fine", "x.snort.rule",
			vcRule(snortHeader, `content:"a|22 3b 5c 7c|b"; http_uri;`),
			nil, nil,
		},
		{
			"a sticky buffer setter needs a match after it", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`, "file_data;"),
			nil, []string{"vc-sticky-buffer-scope"},
		},
		{
			"a sticky buffer setter with a following content is fine", "x.snort.rule",
			vcRule(snortHeader, "file_data;", `content:"a";`),
			nil, nil,
		},
		{
			"suricata pcre must not pick its buffer with a flag", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=[^&]*b/U";`),
			nil, []string{"vc-pcre-buffer-flag"},
		},
		{
			"snort http modifier after a pcre", "x.snort.rule",
			vcRule(snortHeader, `content:"a="; http_uri;`, `pcre:"/a=[^&]*b/"; http_uri;`),
			nil, []string{"vc-snort-pcre-flag"},
		},
		{
			"pcre without a content in its buffer", "x.snort.rule",
			vcRule(snortHeader, `content:"a="; http_uri;`, `pcre:"/b=[^&]*c/P";`),
			nil, []string{"vc-pcre-anchor"},
		},
		{
			"pcre with its anchor in the same snort buffer", "x.snort.rule",
			vcRule(snortHeader, `content:"a="; http_client_body;`, `pcre:"/a=[^&]*b/P";`),
			nil, nil,
		},
		{
			"capture groups", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=(b|c)[(]\(x\)(?:d)/";`),
			nil, []string{"vc-pcre-capture-group"},
		},
		{
			"trailing wildcard, open class and dollar", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=b.*/";`, `pcre:"/a=(?:b[^&]+)/";`, `pcre:"/a=b$/";`, `pcre:"/a=\d\$/";`),
			nil, []string{"vc-pcre-trailing", "vc-pcre-trailing", "vc-pcre-trailing"},
		},
		{
			"fixed-string pcre", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=\/etc/i";`),
			nil, []string{"vc-pcre-fixed-string"},
		},
		{
			"unbounded .* inside a pcre warns", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=.*b/";`),
			nil, []string{"vc-pcre-dotstar"},
		},
		{
			"nocase on the method and the path", "x.suricata.rule",
			vcRule(suricataHeader, `http.method; content:"GET"; nocase;`, `http.uri; content:"/a"; startswith; nocase;`),
			nil, []string{"vc-nocase-case-sensitive", "vc-nocase-case-sensitive"},
		},
		{
			"an unanchored URI path warns", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"/a";`),
			nil, []string{"vc-uri-path-anchor"},
		},
		{
			"a snort URI path needs depth", "x.snort.rule",
			vcRule(snortHeader, `content:"/a"; http_uri;`),
			nil, []string{"vc-uri-path-anchor"},
		},
		{
			"naked raw tcp content warns", "x.snort.rule",
			vcRule(snortHeader, `content:"|00 01|";`, `content:"|02|"; distance:0;`),
			nil, []string{"vc-tcp-unbounded-content"},
		},
		{
			"snort http_client_body on a PUT warns", "x.snort.rule",
			vcRule(snortHeader, `content:"PUT"; http_method;`, `content:"a"; http_client_body;`),
			nil, []string{"vc-snort-put-body"},
		},
		{
			"capture groups are reported once per pcre; named groups capture", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"a=";`, `pcre:"/a=(b)(c)(d)/";`, `pcre:"/a=(?<n>b)/";`),
			nil, []string{"vc-pcre-capture-group", "vc-pcre-capture-group"},
		},
		{
			"groups a backreference needs may capture", "x.suricata.rule",
			vcRule(suricataHeader, `http.header; content:"Id:";`, `pcre:"/Id:\s*(\S+)[^\r]*?Bearer\s+(?!\1)/";`),
			nil, nil,
		},
		{
			"a response rule without flow is recognised by its buffer or source port", "x.suricata.rule",
			mkRule(suricataHeader, successMsg, `http.stat_code; content:"200";`, reference, classtype, "flowbits:isset,vc-cve-2026-0001;", sidRev,
				"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;") +
				mkRule("alert udp any 12346 -> any any", successMsg, `content:"|01|"; depth:1;`, reference, classtype, "flowbits:isset,vc-cve-2026-0001;", "sid:2; rev:1;",
					"metadata: deployment Datacenter, deployment SSLDecrypt, impact successful-exploitation;") +
				vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`, "flowbits:set,vc-cve-2026-0001;", "flowbits:noalert;"),
			nil, []string{"vc-flow-established", "vc-flow-established", "vc-sid-placeholder-sequence"},
		},
		{
			"two matches on the line after their sticky buffer", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri;`, `content:"/a"; startswith; content:"b";`),
			nil, []string{"vc-option-per-line"},
		},
		{
			"a buffer test may sit between a sticky buffer and its match", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; bsize:>10; content:"/a"; startswith;`),
			nil, nil,
		},
		{
			"a modifier after isdataat still scopes the content", "x.snort.rule",
			vcRule(snortHeader, `content:"/a"; depth:2;`, `isdataat:!1,relative;`, `http_uri;`),
			nil, nil,
		},
		{
			"flowbits may carry a stage suffix and the & form", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"/a"; startswith;`, "flowbits:set,vc-cve-2026-0001-probe;", "flowbits:set,vc-cve-2026-0001;", "flowbits:isset,vc-cve-2026-0001-probe&vc-cve-2026-0001;"),
			nil, nil,
		},
		{
			"the snort path depth equals the path length", "x.snort.rule",
			vcRule(snortHeader, `content:"/start_apply.htm"; depth:16; http_uri;`) +
				strings.Replace(vcRule(snortHeader, `content:"/a\;b|3b|"; depth:5; http_uri;`), "sid:1;", "sid:2;", 1),
			nil, nil,
		},
		{
			"an off-by-one path depth", "x.snort.rule",
			vcRule(snortHeader, `content:"/start_apply.htm"; depth:17; http_uri;`) +
				strings.Replace(vcRule(snortHeader, `content:"/setup.cgi"; depth:12; http_uri;`), "sid:1;", "sid:2;", 1),
			nil, []string{"vc-uri-path-depth", "vc-uri-path-depth"},
		},
		{
			"escapes and hex count once", "x.snort.rule",
			vcRule(snortHeader, `content:"/a\;b|3b|"; depth:7; http_uri;`),
			nil, []string{"vc-uri-path-depth"},
		},
		{
			"a suricata path anchored with depth", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"/api/notebook/"; depth:15;`),
			nil, []string{"vc-uri-path-anchor", "vc-uri-path-depth"},
		},
		{
			"the path anchor starts at offset 0", "x.snort.rule",
			vcRule(snortHeader, `content:"/a"; offset:1; depth:2; http_uri;`),
			nil, []string{"vc-uri-path-depth"},
		},
		{
			"a non-path first URI content is ignored", "x.snort.rule",
			vcRule(snortHeader, `content:"cmd="; depth:9; http_uri;`, `content:"/a"; depth:9; http_uri;`),
			nil, nil,
		},
		{
			"depth windows on other buffers are fine", "x.snort.rule",
			vcRule(snortHeader, `content:"/a"; depth:2; http_uri;`, `content:"<?xml"; depth:9; http_client_body;`),
			nil, nil,
		},
		{
			"traversal and a bare slash are not path anchors", "x.snort.rule",
			vcRule(snortHeader, `content:"/../"; depth:200; http_uri;`) +
				strings.Replace(vcRule(snortHeader, `content:"/"; depth:50; http_uri;`), "sid:1;", "sid:2;", 1),
			nil, nil,
		},
		{
			"raw URI contents are not path anchors", "x.snort.rule",
			vcRule(snortHeader, `content:"/a"; depth:9; http_raw_uri;`),
			nil, nil,
		},
		{
			"uricontent is a URI path anchor", "x.snort.rule",
			vcRule(snortHeader, `uricontent:"/a"; depth:9;`),
			nil, []string{"vc-uri-path-depth"},
		},
		{
			"a suricata depth beside startswith is left to idsrule", "x.suricata.rule",
			vcRule(suricataHeader, `http.uri; content:"/a"; startswith; depth:9;`),
			nil, nil,
		},
		// entry level
		{
			"deployment metadata must match targetEncryptedComms", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`),
			&ruleEntryInfo{encryptedComms: []string{"no"}, hasEncryptedPcap: true},
			[]string{"vc-deployment-metadata"},
		},
		{
			"targetEncryptedComms must be set", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`),
			&ruleEntryInfo{encryptedComms: []string{""}, hasEncryptedPcap: true},
			[]string{"vc-deployment-metadata"},
		},
		{
			"SSLDecrypt needs an encrypted capture", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`),
			&ruleEntryInfo{encryptedComms: []string{"either"}},
			[]string{"vc-encrypted-pcap"},
		},
		{
			"any artifact's targetEncryptedComms may match", "x.snort.rule",
			vcRule(snortHeader, `content:"a"; http_uri;`),
			&ruleEntryInfo{encryptedComms: []string{"no", "either"}, hasEncryptedPcap: true},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vcIDs(t, tt.file, tt.src, tt.entry)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			// The checks under test are the only ones that may fire.
			if !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
			}
		})
	}
}

func Test_pcreTrailer(t *testing.T) {
	for pat, want := range map[string]string{
		`a.*`:         ".*",
		`a.+?`:        ".+?",
		`a[^&]*`:      "[^&]*",
		`(?:a[^&]+)`:  "[^&]+",
		`a$`:          "$",
		`a\$`:         "",
		`a\.*`:        "",
		`a[.*]`:       "",
		`[\]]*`:       `[\]]*`,
		`a[^&]*b`:     "",
		`a(?:x|y)`:    "",
		`(?:a|b.*)`:   ".*",
		`[]a]*`:       "[]a]*",
		`x[^\]&]+`:    `[^\]&]+`,
		`\x24`:        "",
		`a\\$`:        "$",
		`a\\\$`:       "",
		`a.*?\/`:      "",
		`foo(?:bar)?`: "",
	} {
		if got := pcreTrailer(pat); got != want {
			t.Errorf("pcreTrailer(%q) = %q, want %q", pat, got, want)
		}
	}
}

func Test_pcreLiteral(t *testing.T) {
	for pat, want := range map[string]bool{
		`a=\/etc`:   true,
		`a\;b`:      true,
		`a\d`:       false,
		`a.b`:       false,
		`a[bc]`:     false,
		`\x41`:      false,
		`(?:ab)`:    false,
		`file:\/\/`: true,
	} {
		if _, got := pcreLiteral(pat); got != want {
			t.Errorf("pcreLiteral(%q) = %v, want %v", pat, got, want)
		}
	}
}

func Test_checkURIPathDepth_message(t *testing.T) {
	tests := []struct {
		body string
		want string // "" for no finding
	}{
		{`content:"/start_apply.htm"; depth: 17; http_uri;`, `depth:17 should be 16, the length of "/start_apply.htm"`},
		{`content:"/a"; offset:1; depth:2; http_uri;`, "drop offset:1"},
		{`content:"/abc"; depth:2; http_uri;`, `depth:2 should be 4, the length of "/abc"`},
	}
	for _, tt := range tests {
		var msgs []string
		for _, d := range runRuleChecks("x.snort.rule", []byte(vcRule(snortHeader, tt.body)), idsrule.DialectSnort2, nil) {
			if d.Rule == "vc-uri-path-depth" {
				msgs = append(msgs, d.Message)
			}
		}
		switch {
		case tt.want == "" && len(msgs) != 0:
			t.Errorf("%s: unexpected %v", tt.body, msgs)
		case tt.want != "" && (len(msgs) != 1 || !strings.Contains(msgs[0], tt.want)):
			t.Errorf("%s: messages %v, want one containing %q", tt.body, msgs, tt.want)
		}
	}
}

func Test_checkURIPathDepth_fix(t *testing.T) {
	src := vcRule(snortHeader, `content:"/start_apply.htm"; depth: 17; http_uri;`)
	diags := runRuleChecks("x.snort.rule", []byte(src), idsrule.DialectSnort2, nil)
	out, applied, err := idsrule.Fix([]byte(src), diags)
	if err != nil || applied != 1 {
		t.Fatalf("Fix applied %d, err %v", applied, err)
	}
	if !strings.Contains(string(out), `content:"/start_apply.htm"; depth:16; http_uri;`) {
		t.Errorf("fixed rule:\n%s", out)
	}
}

func Test_dropSupersededDepth(t *testing.T) {
	src := []byte(vcRule(snortHeader, `content:"/start_apply.htm"; depth:15; http_uri;`, `content:"abcdef"; distance:0; within:3;`))
	diags := idsrule.Lint("x.snort.rule", src, ruleLintOptions(idsrule.DialectSnort2))
	diags = append(diags, runRuleChecks("x.snort.rule", src, idsrule.DialectSnort2, nil)...)
	var got []string
	for _, d := range dropSupersededDepth(diags) {
		if d.Rule == "content-depth-too-short" || d.Rule == "vc-uri-path-depth" {
			got = append(got, d.Rule)
		}
	}
	slices.Sort(got)
	// The path anchor's short depth is vc-uri-path-depth's; the within on
	// the other content stays idsrule's.
	if want := []string{"content-depth-too-short", "vc-uri-path-depth"}; !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}
