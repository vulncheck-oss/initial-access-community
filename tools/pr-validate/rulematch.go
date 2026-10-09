package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// RuleRuleMatch identifies rule-vs-capture replay findings.
const RuleRuleMatch = "rule-pcap-match"

// engineTimeout bounds a single engine replay of one capture.
const engineTimeout = 120 * time.Second

// snortDefaultHTTPPorts is the HTTP_PORTS list from the stock Snort 2.9
// snort.conf. The server ports seen in the capture are added to it so
// http_inspect decodes traffic to non-standard ports.
var snortDefaultHTTPPorts = []uint16{
	80, 81, 311, 383, 591, 593, 901, 1220, 1414, 1741, 1830, 2301, 2381, 2809,
	3037, 3128, 3702, 4343, 4848, 5250, 6988, 7000, 7001, 7144, 7145, 7510,
	7777, 7779, 8000, 8008, 8014, 8028, 8080, 8085, 8088, 8090, 8118, 8123,
	8180, 8181, 8243, 8280, 8300, 8800, 8888, 8899, 9000, 9060, 9080, 9090,
	9091, 9443, 9999, 11371, 34443, 34444, 41080, 50002, 55555,
}

//go:embed snort.conf.tmpl
var snortConfTemplate string

var snortConf = template.Must(template.New("snort.conf").Parse(snortConfTemplate))

// snortAlertRe matches a Snort 2 console alert line:
//
//	10/08-12:00:00.000000  [**] [1:1000001:1] VULNCHECK ... [**] [Classification: ...] ...
var snortAlertRe = regexp.MustCompile(`\[\*\*\] \[(\d+):(\d+):(\d+)\] (.*?) \[\*\*\]`)

type ruleAlert struct {
	SID int
	Msg string
}

type ruleEngine struct {
	Name   string
	Suffix string
	Binary string
	Run    func(rule, pcap string, capture captureInfo) ([]ruleAlert, error)
}

// captureInfo is what the engines need to know about a capture beyond its path.
type captureInfo struct {
	// Path is the file handed to the engines: the capture itself, or a copy
	// with its snapshot length clamped for older libpcap.
	Path string
	// ServerPorts are the TCP ports connections were opened to.
	ServerPorts []uint16
	// Truncated is set when the last record is cut short. Suricata replays up
	// to it and exits cleanly; Snort exits non-zero after alerting.
	Truncated bool
}

var ruleEngines = []ruleEngine{
	{Name: "suricata", Suffix: ".suricata.rule", Binary: "suricata", Run: runSuricata},
	{Name: "snort", Suffix: ".snort.rule", Binary: "snort", Run: runSnort},
}

// lintRuleMatch replays every unencrypted capture in the entry through each
// Suricata and Snort rule file next to it, and requires every capture to raise
// at least one alert from every rule file. Rules and captures are paired per
// directory, so a sub-package (cve-x/variant/) is checked against its own
// captures. Encrypted captures are ignored; a directory with rules but no
// unencrypted capture is a warning. A rule file the engine fails to load is an
// error.
func lintRuleMatch(dir, entryID string) int {
	if flagSkipRuleMatch {
		return 0
	}

	type ruleGroup struct {
		rules []string
		pcaps []string
	}
	groups := map[string]*ruleGroup{}
	root := filepath.Join(dir, entryID)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // skip unreadable paths and directories
		}
		isRule := false
		for _, engine := range ruleEngines {
			if strings.HasSuffix(d.Name(), engine.Suffix) {
				isRule = true
			}
		}
		isPcap := isUnencryptedPcap(d.Name())
		if !isRule && !isPcap {
			return nil
		}
		g := groups[filepath.Dir(path)]
		if g == nil {
			g = &ruleGroup{}
			groups[filepath.Dir(path)] = g
		}
		if isRule {
			g.rules = append(g.rules, path)
		} else {
			g.pcaps = append(g.pcaps, path)
		}
		return nil
	})

	upperID := strings.ToUpper(entryID)
	failed := 0
	captures := map[string]captureInfo{}

	// Holds snaplen-clamped capture copies (see clampPcapSnaplen).
	clampDir, err := os.MkdirTemp("", "pr-validate-pcap-")
	if err != nil {
		log.Printf("ERROR: %s - unable to create temp dir: %v [%s]", upperID, err, RuleRuleMatch)
		return 1
	}
	defer os.RemoveAll(clampDir)
	for _, groupDir := range slices.Sorted(maps.Keys(groups)) {
		g := groups[groupDir]
		if len(g.rules) == 0 {
			continue
		}
		if len(g.pcaps) == 0 {
			log.Printf("WARN: %s - %s has rules but no unencrypted capture to verify them against [%s]",
				upperID, relPath(dir, groupDir), RuleRuleMatch)
			continue
		}
		slices.Sort(g.rules)
		slices.Sort(g.pcaps)

		for _, rule := range g.rules {
			engine := engineFor(rule)
			if _, err := exec.LookPath(engine.Binary); err != nil {
				log.Printf("ERROR: %s - %s is not installed, cannot verify %s (use -skip-rule-match to skip locally) [%s]",
					upperID, engine.Binary, relPath(dir, rule), RuleRuleMatch)
				failed++
				continue
			}
			for _, pcap := range g.pcaps {
				if _, ok := captures[pcap]; !ok {
					p, err := pcapServerPorts(pcap)
					capture := captureInfo{ServerPorts: p}
					switch {
					case errors.Is(err, io.ErrUnexpectedEOF):
						capture.Truncated = true
						log.Printf("WARN: %s - %s is truncated (last packet cut short) [%s]",
							upperID, relPath(dir, pcap), RuleRuleMatch)
					case err != nil:
						// lintPcap already reports unreadable captures.
						log.Printf("WARN: %s - unable to read server ports from %s: %v [%s]",
							upperID, relPath(dir, pcap), err, RuleRuleMatch)
					}
					capture.Path, err = clampPcapSnaplen(pcap, clampDir)
					if err != nil {
						capture.Path = pcap
					}
					captures[pcap] = capture
				}
				alerts, err := engine.Run(rule, captures[pcap].Path, captures[pcap])
				if err != nil {
					msg := fmt.Sprintf("ERROR: %s - %s failed running %s against %s: %v [%s]",
						upperID, engine.Name, relPath(dir, rule), relPath(dir, pcap), err, RuleRuleMatch)
					var engineErr *engineError
					if errors.As(err, &engineErr) {
						msg += "\n" + outputTail(engineErr.output, 20)
					}
					log.Print(msg)
					failed++
					break // a rule load error repeats for every capture
				}
				if len(alerts) == 0 {
					log.Printf("ERROR: %s - %s rule file %s did not alert on %s [%s]",
						upperID, engine.Name, relPath(dir, rule), relPath(dir, pcap), RuleRuleMatch)
					failed++
				}
			}
		}
	}

	return failed
}

// isUnencryptedPcap reports whether a file name is an unencrypted capture,
// per the NN-<status>-unencrypted.pcap[ng] naming convention.
func isUnencryptedPcap(name string) bool {
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)
	if ext != ".pcap" && ext != ".pcapng" {
		return false
	}

	return strings.HasSuffix(strings.TrimSuffix(lower, ext), "-unencrypted")
}

func engineFor(rule string) ruleEngine {
	for _, engine := range ruleEngines {
		if strings.HasSuffix(rule, engine.Suffix) {
			return engine
		}
	}
	panic("no engine for " + rule)
}

func relPath(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return rel
	}

	return path
}

// runEngine runs an engine command with the replay timeout and returns its
// stdout. A non-zero exit returns an *engineError holding the combined output,
// alongside whatever stdout was produced.
func runEngine(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), engineTimeout)
	defer cancel()

	var stdout, combined bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.MultiWriter(&stdout, &combined)
	cmd.Stderr = &combined
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("timed out after %s", engineTimeout)
	}
	if err != nil {
		return stdout.Bytes(), &engineError{err: err, output: combined.String()}
	}

	return stdout.Bytes(), nil
}

// engineError is an engine run that exited non-zero, typically because a rule
// failed to load. output holds the engine's combined stdout and stderr.
type engineError struct {
	err    error
	output string
}

func (e *engineError) Error() string { return e.err.Error() }

func outputTail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	return "    " + strings.Join(lines, "\n    ")
}

// runSuricata replays pcap through the Suricata rule file and returns the
// alerts from eve.json. --init-errors-fatal turns any rule that fails to load
// into a non-zero exit.
func runSuricata(rule, pcap string, _ captureInfo) ([]ruleAlert, error) {
	tmp, err := os.MkdirTemp("", "pr-validate-suricata-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	_, err = runEngine("suricata",
		"-c", flagSuricataConfig,
		"-S", rule,
		"-r", pcap,
		"-l", tmp,
		"-k", "none",
		"--runmode", "single",
		"--init-errors-fatal",
		"--set", "vars.address-groups.HOME_NET=any",
		"--set", "vars.address-groups.EXTERNAL_NET=any",
	)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(filepath.Join(tmp, "eve.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	alerts := []ruleAlert{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for scanner.Scan() {
		var event struct {
			EventType string `json:"event_type"`
			Alert     struct {
				SignatureID int    `json:"signature_id"`
				Signature   string `json:"signature"`
			} `json:"alert"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.EventType != "alert" {
			continue
		}
		alerts = append(alerts, ruleAlert{SID: event.Alert.SignatureID, Msg: event.Alert.Signature})
	}

	return alerts, scanner.Err()
}

// runSnort replays pcap through the Snort 2 rule file using a generated
// snort.conf, and returns the alerts printed to the console. Snort exits
// non-zero on any rule parse error, and also when it hits a truncated last
// record, after it has already processed (and alerted on) everything before it.
func runSnort(rule, pcap string, capture captureInfo) ([]ruleAlert, error) {
	tmp, err := os.MkdirTemp("", "pr-validate-snort-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	absRule, err := filepath.Abs(rule)
	if err != nil {
		return nil, err
	}
	httpPorts := slices.Clone(snortDefaultHTTPPorts)
	for _, port := range capture.ServerPorts {
		if !slices.Contains(httpPorts, port) {
			httpPorts = append(httpPorts, port)
		}
	}
	portStrs := make([]string, len(httpPorts))
	for i, port := range httpPorts {
		portStrs[i] = strconv.Itoa(int(port))
	}

	var conf bytes.Buffer
	err = snortConf.Execute(&conf, map[string]string{
		"EtcDir":       flagSnortEtc,
		"LibDir":       flagSnortLib,
		"HTTPPortVar":  strings.Join(portStrs, ","),
		"HTTPPortList": strings.Join(portStrs, " "),
		"RuleFile":     absRule,
	})
	if err != nil {
		return nil, err
	}
	confPath := filepath.Join(tmp, "snort.conf")
	if err := os.WriteFile(confPath, conf.Bytes(), 0o644); err != nil {
		return nil, err
	}

	out, err := runEngine("snort",
		"-c", confPath,
		"-r", pcap,
		"-l", tmp,
		"-A", "console",
		"-q",
		"-N",
		"-k", "none",
	)
	var engineErr *engineError
	if err != nil && !(capture.Truncated && errors.As(err, &engineErr)) {
		return nil, err
	}

	alerts := []ruleAlert{}
	for _, m := range snortAlertRe.FindAllStringSubmatch(string(out), -1) {
		sid, _ := strconv.Atoi(m[2])
		alerts = append(alerts, ruleAlert{SID: sid, Msg: m[4]})
	}

	return alerts, nil
}
