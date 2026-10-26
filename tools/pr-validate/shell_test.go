package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// writeSyntheticPcap writes an Ethernet capture of an exploit request from
// 10.0.0.1 to 10.0.0.2:80 with its response and, when callback is set, the
// target's reverse shell connecting back to 10.0.0.1:4444 and running id.
func writeSyntheticPcap(t *testing.T, path string, callback bool) {
	t.Helper()
	writeSyntheticPcapAt(t, path, callback, time.Unix(1_700_000_000, 0))
}

// writeSyntheticPcapAt is writeSyntheticPcap with the capture's start time,
// so a "recapture" differs from the capture it replaces.
func writeSyntheticPcapAt(t *testing.T, path string, callback bool, start time.Time) {
	t.Helper()
	attacker, target := net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	ts := start
	write := func(src net.IP, sp uint16, dst net.IP, dp uint16, syn, ack bool, payload string) {
		t.Helper()
		eth := &layers.Ethernet{
			SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, src[3]}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, dst[3]},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), SYN: syn, ACK: ack, PSH: payload != "", Window: 65535}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		ts = ts.Add(time.Millisecond)
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	conn := func(c net.IP, cp uint16, s net.IP, sp uint16, request, response string) {
		write(c, cp, s, sp, true, false, "")
		write(s, sp, c, cp, true, true, "")
		write(c, cp, s, sp, false, true, "")
		if request != "" {
			write(c, cp, s, sp, false, true, request)
		}
		if response != "" {
			write(s, sp, c, cp, false, true, response)
		}
	}
	conn(attacker, 40000, target, 80, "GET /cgi-bin/widget?cmd=id HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if callback {
		conn(target, 50000, attacker, 4444, "uid=0(root) gid=0(root) groups=0(root)\n", "id\n")
	}
}

// shellFindingLine matches a logged finding: its level and check id.
var shellFindingLine = regexp.MustCompile(`(?m)^.*(ERROR|WARN): \S+ - .*\[([a-z0-9-]+)\]$`)

// shellFindings runs lintShellEvidence over an entry and returns its error
// count and the sorted "LEVEL id" of every finding it logged.
func shellFindings(t *testing.T, dir, entryID string) (int, []string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	failed := lintShellEvidence(dir, entryID)
	log.SetOutput(prev)

	var findings []string
	for _, m := range shellFindingLine.FindAllStringSubmatch(buf.String(), -1) {
		findings = append(findings, m[1]+" "+m[2])
	}
	slices.Sort(findings)
	t.Log(buf.String())

	return failed, findings
}

func Test_parseExploitC2(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		modes []string
		shell bool
	}{
		{"supportedC2 slice", "supportedC2 := []c2.Impl{\n\tc2.SSLShellServer,\n\tc2.SimpleShellServer,\n\tc2.HTTPServeShell,\n}\nc2.HadSessions(conf.C2Type)", []string{"SSLShellServer", "SimpleShellServer", "HTTPServeShell"}, true},
		{"inline list", "config.CodeExecution, []c2.Impl{c2.SimpleShellServer}, \"Acme\"", []string{"SimpleShellServer"}, true},
		{"serve shell only, polled", "[]c2.Impl{c2.HTTPServeShell}\nreturn c2.HadSessions(conf.C2Type)", []string{"HTTPServeShell"}, true},
		{"serve shell only, not polled", "[]c2.Impl{c2.HTTPServeShell}", []string{"HTTPServeShell"}, false},
		{"webshell", "config.Webshell, []c2.Impl{}, \"Acme\"", nil, false},
		{"webshell with a dead poll", "config.Webshell, []c2.Impl{},\nc2.HadSessions(conf.C2Type)", nil, false},
		{"no list, polled", "return c2.HadSessions(conf.C2Type)", nil, true},
		{"no c2 at all", "package main", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseExploitC2([]byte(tt.src))
			if !slices.Equal(got.modes, tt.modes) {
				t.Errorf("modes = %v, want %v", got.modes, tt.modes)
			}
			if got.reverseShell() != tt.shell {
				t.Errorf("reverseShell() = %v, want %v", got.reverseShell(), tt.shell)
			}
		})
	}
}

func Test_lintShellEvidence_fixtureGood(t *testing.T) {
	dir := fixtureFeed(t)
	root := filepath.Join(dir, "cve-0000-0003")
	writeSyntheticPcap(t, filepath.Join(root, "00-exploited-unencrypted.pcap"), true)
	if err := os.Symlink("cve-0000-0003.go", filepath.Join(root, "alias.go")); err != nil {
		t.Fatal(err)
	}
	if failed, findings := shellFindings(t, dir, "cve-0000-0003"); failed != 0 || len(findings) != 0 {
		t.Errorf("lintShellEvidence = %d errors, findings %v, want none", failed, findings)
	}

	// The rest of the validator accepts the fixture too.
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	failed := lintEntryFrontmatter(dir, "cve-0000-0003") + lintRules(dir, "cve-0000-0003") + lintPcap(dir, "cve-0000-0003") + lintGoMod(dir, "cve-0000-0003")
	log.SetOutput(prev)
	if failed != 0 {
		t.Errorf("other stages: %d errors\n%s", failed, buf.String())
	}
}

func Test_lintShellEvidence_fixtureBad(t *testing.T) {
	dir := fixtureFeed(t)
	root := filepath.Join(dir, "cve-0000-0004")
	if err := os.Symlink("../../shells/linux/basicsh/reverse_shell.go", filepath.Join(root, "reverse_shell.go")); err != nil {
		t.Fatal(err)
	}
	failed, findings := shellFindings(t, dir, "cve-0000-0004")
	want := []string{
		"ERROR " + RuleDockerfileSymlinkCopy,
		"ERROR " + RuleReadmeListener,
	}
	if failed != len(want) || !slices.Equal(findings, want) {
		t.Errorf("lintShellEvidence = %d errors, findings:\n got %v\nwant %v", failed, findings, want)
	}
}

func Test_lintShellEvidence_notShell(t *testing.T) {
	dir := fixtureFeed(t)
	root := filepath.Join(dir, "cve-0000-0004")
	writeSyntheticPcap(t, filepath.Join(root, "00-exploited-unencrypted.pcap"), false)
	path := filepath.Join(root, "cve-0000-0004.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	webshell := regexp.MustCompile(`(?s)supportedC2 := \[\]c2\.Impl\{.*?\}`).ReplaceAll(src, []byte("supportedC2 := []c2.Impl{}"))
	if bytes.Equal(webshell, src) {
		t.Fatal("fixture has no supportedC2 to empty")
	}
	if err := os.WriteFile(path, webshell, 0o600); err != nil {
		t.Fatal(err)
	}
	if failed, findings := shellFindings(t, dir, "cve-0000-0004"); failed != 0 || len(findings) != 0 {
		t.Errorf("lintShellEvidence = %d errors, findings %v, want none for a webshell entry", failed, findings)
	}
}

func Test_lintShellEvidence_pcapOlderThanSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := fixtureFeed(t)
	run := func(args ...string) {
		t.Helper()
		if _, err := git(dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	shell := filepath.Join(dir, "cve-0000-0003")
	writeSyntheticPcap(t, filepath.Join(shell, "00-exploited-unencrypted.pcap"), true)
	// A webshell entry: the check applies whether or not a shell is caught.
	web := filepath.Join(dir, "cve-0000-0005")
	if err := os.Mkdir(web, 0o755); err != nil {
		t.Fatal(err)
	}
	webSrc := filepath.Join(web, "cve-0000-0005.go")
	if err := os.WriteFile(webSrc, []byte("package main\n\nvar _ = []c2.Impl{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSyntheticPcap(t, filepath.Join(web, "00-exploited-unencrypted.pcap"), false)
	run("init", "-q")
	run("add", ".")
	run("commit", "-q", "-m", "base")

	ref, err := loadBaseRef(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	saved := ruleBaseRef
	ruleBaseRef = ref
	t.Cleanup(func() { ruleBaseRef = saved })

	// Nothing changed: no finding.
	if failed, findings := shellFindings(t, dir, "cve-0000-0003"); failed != 0 || len(findings) != 0 {
		t.Errorf("unchanged entry: %d errors, findings %v, want none", failed, findings)
	}

	// The source changed, the capture did not.
	for _, src := range []string{filepath.Join(shell, "cve-0000-0003.go"), webSrc} {
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("\n// changed\n"); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	for _, id := range []string{"cve-0000-0003", "cve-0000-0005"} {
		if failed, findings := shellFindings(t, dir, id); failed != 1 || !slices.Equal(findings, []string{"ERROR " + RulePcapOlderThanSource}) {
			t.Errorf("%s with stale capture: %d errors, findings %v, want the one error", id, failed, findings)
		}
	}

	// A recaptured (uncommitted, even untracked) capture clears it.
	writeSyntheticPcapAt(t, filepath.Join(shell, "00-exploited-unencrypted.pcap"), true, time.Unix(1_700_000_001, 0))
	writeSyntheticPcap(t, filepath.Join(web, "01-exploited-unencrypted.pcap"), false)
	for _, id := range []string{"cve-0000-0003", "cve-0000-0005"} {
		if failed, findings := shellFindings(t, dir, id); failed != 0 || len(findings) != 0 {
			t.Errorf("%s recaptured: %d errors, findings %v, want none", id, failed, findings)
		}
	}
}
