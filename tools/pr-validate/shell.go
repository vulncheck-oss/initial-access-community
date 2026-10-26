package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Shell-evidence check ids. The exploit source is the only input the rest of
// pr-validate never reads; these checks parse it for the C2 modes it registers
// and then hold the evidence beside it (captures, README, Dockerfile) to what
// a reverse shell needs.
const (
	RulePcapOlderThanSource   = "vc-pcap-older-than-source"
	RuleReadmeListener        = "vc-readme-listener-consistent"
	RuleDockerfileSymlinkCopy = "vc-dockerfile-symlink-copy"
)

var (
	// c2ImplListRe matches a []c2.Impl literal (the supportedC2 slice or the
	// list passed straight to config.New*); c2ModeRe its c2.<Mode> elements.
	c2ImplListRe = regexp.MustCompile(`\[\]c2\.Impl\{([^}]*)\}`)
	c2ModeRe     = regexp.MustCompile(`\bc2\.([A-Za-z0-9_]+)`)
	// c2HadSessionsRe matches the framework's reverse-shell success poll.
	c2HadSessionsRe = regexp.MustCompile(`\bc2\.HadSessions\(`)

	// readmeHeadingRe matches an ATX heading; readmeFenceRe a code fence.
	readmeHeadingRe = regexp.MustCompile(`^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$`)
	readmeFenceRe   = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	// readmeLhostRe and readmeLportRe pick the listener a run command asks
	// for; readmeListenerRe the listener the framework reports starting.
	readmeLhostRe    = regexp.MustCompile(`(?:^|\s)--?lhost[= ]+(\S+)`)
	readmeLportRe    = regexp.MustCompile(`(?:^|\s)--?lport[= ]+(\d+)`)
	readmeListenerRe = regexp.MustCompile(`Starting (?:TLS )?listener on ([^\s"':]+|\[[^\]]+\]):(\d+)`)

	// dockerCopyAllGoRe matches a Dockerfile line copying every *.go.
	dockerCopyAllGoRe = regexp.MustCompile(`(?m)^[ \t]*(?:COPY|ADD)\s+(?:--\S+\s+)*(?:\./)?\*\.go(?:\s|$)`)
)

// exploitC2 is what an entry's exploit source registers for C2.
type exploitC2 struct {
	modes       []string // every c2.<Mode> of its []c2.Impl literals, in order
	listFound   bool     // at least one []c2.Impl literal was found
	hadSessions bool     // the source polls c2.HadSessions
}

// parseExploitC2 reads the C2 registration out of exploit source.
func parseExploitC2(src []byte) exploitC2 {
	var c exploitC2
	for _, list := range c2ImplListRe.FindAllSubmatch(src, -1) {
		c.listFound = true
		for _, m := range c2ModeRe.FindAllSubmatch(list[1], -1) {
			mode := string(m[1])
			if !slices.Contains(c.modes, mode) {
				c.modes = append(c.modes, mode)
			}
		}
	}
	c.hadSessions = c2HadSessionsRe.Match(src)

	return c
}

// reverseShell reports whether the exploit catches a reverse shell: it lists
// a shell listener C2, or polls c2.HadSessions for one. An exploit whose only
// C2 list is empty (a webshell entry) is not one, whatever else it mentions.
func (c exploitC2) reverseShell() bool {
	if c.listFound && len(c.modes) == 0 {
		return false
	}

	return c.hadSessions || slices.Contains(c.modes, "SimpleShellServer") || slices.Contains(c.modes, "SSLShellServer")
}

// entryExploitSources returns the entry's top-level cve-*.go files, tests
// excluded, sorted.
func entryExploitSources(root string) []string {
	sources, _ := filepath.Glob(filepath.Join(root, "cve-*.go"))
	sources = slices.DeleteFunc(sources, func(p string) bool { return strings.HasSuffix(p, "_test.go") })
	slices.Sort(sources)

	return sources
}

// entryUnencryptedPcaps returns every unencrypted capture under root, sorted.
func entryUnencryptedPcaps(root string) []string {
	var pcaps []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && isUnencryptedPcap(d.Name()) {
			pcaps = append(pcaps, path)
		}

		return nil
	})
	slices.Sort(pcaps)

	return pcaps
}

// lintShellEvidence is the shell-evidence stage. For every entry with exploit
// source it requires a new unencrypted capture when that source changed
// against -base-ref (vc-pcap-older-than-source). For an entry whose exploit
// catches a reverse shell (exploitC2.reverseShell) it then requires the
// listener each README run reports to match its run command, and the
// Dockerfile not to COPY a symlinked *.go the build context cannot follow.
func lintShellEvidence(dir, entryID string) int {
	root := filepath.Join(dir, entryID)
	upperID := strings.ToUpper(entryID)
	sources := entryExploitSources(root)
	if len(sources) == 0 {
		return 0
	}
	pcaps := entryUnencryptedPcaps(root)
	failed := checkPcapOlderThanSource(dir, upperID, root, pcaps)

	var c2 exploitC2
	for _, path := range sources {
		src, err := os.ReadFile(path)
		if err != nil {
			log.Printf("WARN: %s - unable to read %s: %v [%s]", upperID, relPath(dir, path), err, RuleReadmeListener)
			continue
		}
		parsed := parseExploitC2(src)
		c2.listFound = c2.listFound || parsed.listFound
		c2.hadSessions = c2.hadSessions || parsed.hadSessions
		for _, mode := range parsed.modes {
			if !slices.Contains(c2.modes, mode) {
				c2.modes = append(c2.modes, mode)
			}
		}
	}
	if !c2.reverseShell() {
		return failed
	}

	failed += checkReadmeListener(dir, upperID, root)
	failed += checkDockerfileSymlinkCopy(dir, upperID, root)

	return failed
}

// changedFiles returns the paths under dir, relative to dir, that differ from
// the base ref in the working tree, untracked files included.
func (b *baseRef) changedFiles(dir string) ([]string, error) {
	rel, err := b.pathAtRef(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, args := range [][]string{
		{"diff", "--name-only", "-z", b.ref, "--", rel},
		{"ls-files", "--others", "--exclude-standard", "-z", "--", rel},
	} {
		raw, err := git(b.toplevel, args...)
		if err != nil {
			return nil, err
		}
		for _, path := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
			if path == "" {
				continue
			}
			if sub, ok := strings.CutPrefix(path, rel+"/"); ok {
				out = append(out, filepath.FromSlash(sub))
			}
		}
	}
	slices.Sort(out)

	return slices.Compact(out), nil
}

// checkPcapOlderThanSource reports an entry whose exploit source changed
// against -base-ref while none of its unencrypted captures did: the committed
// evidence then shows an older exploit than the one under review.
func checkPcapOlderThanSource(dir, upperID, root string, pcaps []string) int {
	if ruleBaseRef == nil || len(pcaps) == 0 {
		return 0
	}
	changed, err := ruleBaseRef.changedFiles(root)
	if err != nil {
		log.Printf("WARN: %s - unable to diff %s against %s: %v [%s]", upperID, relPath(dir, root), ruleBaseRef.ref, err, RulePcapOlderThanSource)

		return 0
	}
	var sources []string
	pcapChanged := false
	for _, path := range changed {
		base := filepath.Base(path)
		if filepath.Dir(path) == "." && strings.HasPrefix(base, "cve-") && strings.HasSuffix(base, ".go") && !strings.HasSuffix(base, "_test.go") {
			sources = append(sources, base)
		}
		if isUnencryptedPcap(base) {
			pcapChanged = true
		}
	}
	if len(sources) == 0 || pcapChanged {
		return 0
	}
	log.Printf("ERROR: %s - %s changed against %s but no *-unencrypted.pcap did; the evidence capture predates the exploit source, recapture it from the current build [%s]",
		upperID, strings.Join(sources, ", "), ruleBaseRef.ref, RulePcapOlderThanSource)

	return 1
}

// readmeBlock is a fenced code block of a README.
type readmeBlock struct {
	line  int // 1-based line of the opening fence
	lines []string
}

// readmeSection is a README heading with the code blocks below it, up to the
// next heading of any level. The preamble before the first heading is a
// section of level 0.
type readmeSection struct {
	line    int
	level   int
	heading string
	blocks  []readmeBlock
}

// parseReadmeSections splits a README into its sections and code blocks.
func parseReadmeSections(src string) []readmeSection {
	sections := []readmeSection{{}}
	fence := ""
	var block *readmeBlock
	for i, line := range strings.Split(src, "\n") {
		if fence != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, fence[:1]) == "" {
				cur := &sections[len(sections)-1]
				cur.blocks = append(cur.blocks, *block)
				fence, block = "", nil

				continue
			}
			block.lines = append(block.lines, line)

			continue
		}
		if m := readmeFenceRe.FindStringSubmatch(line); m != nil {
			fence = m[1]
			block = &readmeBlock{line: i + 1}

			continue
		}
		if m := readmeHeadingRe.FindStringSubmatch(line); m != nil {
			sections = append(sections, readmeSection{line: i + 1, level: len(m[1]), heading: m[2]})
		}
	}
	if block != nil { // an unterminated block still counts
		cur := &sections[len(sections)-1]
		cur.blocks = append(cur.blocks, *block)
	}

	return sections
}

// readEntryReadme returns the entry README's sections, or nil when it cannot
// be read (lintEntryFrontmatter reports that).
func readEntryReadme(root string) (string, []readmeSection) {
	path := filepath.Join(root, "README.md")
	src, err := os.ReadFile(path)
	if err != nil {
		return path, nil
	}

	return path, parseReadmeSections(string(src))
}

// checkReadmeListener requires the listener each captured run reports
// (Starting listener on X:N) to be the one its run command asked for
// (-lhost X -lport N). A run command sets the expectation for the output
// below it until the next run command or heading.
func checkReadmeListener(dir, upperID, root string) int {
	path, sections := readEntryReadme(root)
	if sections == nil {
		return 0
	}
	failed := 0
	for _, s := range sections {
		var host, port string
		for _, b := range s.blocks {
			for i, line := range b.lines {
				h, p := readmeLhostRe.FindStringSubmatch(line), readmeLportRe.FindStringSubmatch(line)
				if h != nil && p != nil {
					host, port = h[1], p[1]

					continue
				}
				m := readmeListenerRe.FindStringSubmatch(line)
				if m == nil || host == "" {
					continue
				}
				if m[1] != host || m[2] != port {
					log.Printf("ERROR: %s - %s:%d: the run command passes -lhost %s -lport %s but its captured output reports a listener on %s:%s; recapture so the command and its output agree [%s]",
						upperID, relPath(dir, path), b.line+1+i, host, port, m[1], m[2], RuleReadmeListener)
					failed++
				}
			}
		}
	}

	return failed
}

// checkDockerfileSymlinkCopy flags a Dockerfile that copies every *.go when
// one of them is a symlink out of the entry: the build context cannot follow
// it, so the image build breaks.
func checkDockerfileSymlinkCopy(dir, upperID, root string) int {
	dockerfile := filepath.Join(root, "Dockerfile")
	data, err := os.ReadFile(dockerfile)
	if err != nil {
		return 0
	}
	loc := dockerCopyAllGoRe.FindIndex(data)
	if loc == nil {
		return 0
	}
	line := 1 + strings.Count(string(data[:loc[0]]), "\n")

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return 0
	}
	sources, _ := filepath.Glob(filepath.Join(root, "*.go"))
	slices.Sort(sources)
	failed := 0
	for _, path := range sources {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(path)
		if err != nil {
			continue
		}
		resolved := target
		if !filepath.IsAbs(target) {
			resolved = filepath.Join(absRoot, target)
		}
		if strings.HasPrefix(resolved, absRoot+string(filepath.Separator)) {
			continue
		}
		log.Printf("ERROR: %s - %s:%d: copies every *.go, but %s is a symlink to %s outside the build context, which docker cannot follow; use `COPY cve-*.go ./` [%s]",
			upperID, relPath(dir, dockerfile), line, filepath.Base(path), target, RuleDockerfileSymlinkCopy)
		failed++
	}

	return failed
}
