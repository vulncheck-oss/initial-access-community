package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/frontmatter"
)

type Entry struct {
	Ready     bool       `json:"ready"     yaml:"ready"`
	ID        string     `json:"id"        yaml:"id"`
	CVE       string     `json:"cve"       yaml:"cve"`
	Artifacts []Artifact `json:"artifacts" yaml:"artifacts"`
}

type Artifact struct {
	Vendor                 string   `json:"vendor"    yaml:"vendor"`
	Product                []string `json:"product"   yaml:"product"`
	DateAdded              string   `json:"dateAdded" yaml:"dateAdded"`
	DateTime               time.Time
	ArtifactName           string   `json:"artifactName"           yaml:"artifactName"`
	Exploit                bool     `json:"exploit"                yaml:"exploit"`
	Chain                  []string `json:"chain"                  yaml:"chain"`
	Related                []string `json:"related"                yaml:"related"`
	VersionScanner         bool     `json:"versionScanner"         yaml:"versionScanner"`
	Pcap                   bool     `json:"pcap"                   yaml:"pcap"`
	SigmaRule              bool     `json:"sigmaRule"              yaml:"sigmaRule"`
	SuricataRule           bool     `json:"suricataRule"           yaml:"suricataRule"`
	SnortRule              bool     `json:"snortRule"              yaml:"snortRule"`
	Yara                   bool     `json:"yara"                   yaml:"yara"`
	NmapScript             bool     `json:"nmapScript"             yaml:"nmapScript"`
	Zeroday                bool     `json:"zeroday"                yaml:"zeroday"`
	TargetService          string   `json:"targetService"          yaml:"targetService"`
	TargetEncryptedComms   string   `json:"targetEncryptedComms"   yaml:"targetEncryptedComms"`
	TargetDocker           bool     `json:"targetDocker"           yaml:"targetDocker"`
	MitreAttackTechniques  []string `json:"mitreAttackTechniques"  yaml:"mitreAttackTechniques"`
	FOFAQueries            []string `json:"fofaQueries"            yaml:"fofaQueries"`
	ZoomEyeQueries         []string `json:"zoomEyeQueries"         yaml:"zoomEyeQueries"`
	ShodanQueries          []string `json:"shodanQueries"          yaml:"shodanQueries"`
	CensysQueries          []string `json:"censysQueries"          yaml:"censysQueries"`
	CensysLegacyQueries    []string `json:"censysLegacyQueries"    yaml:"censysLegacyQueries"`
	DriftnetQueries        []string `json:"driftnetQueries"        yaml:"driftnetQueries"`
	GreynoiseQueries       []string `json:"greynoiseQueries"       yaml:"greynoiseQueries"`
	GoogleQueries          []string `json:"googleQueries"          yaml:"googleQueries"`
	BaiduQueries           []string `json:"baiduQueries"           yaml:"baiduQueries"`
	ShodanRawQueries       []string `json:"shodanRawQueries"       yaml:"shodanRawQueries"`
	CensysRawQueries       []string `json:"censysRawQueries"       yaml:"censysRawQueries"`
	CensysLegacyRawQueries []string `json:"censysLegacyRawQueries" yaml:"censysLegacyRawQueries"`
	FOFARawQueries         []string `json:"fofaRawQueries"         yaml:"fofaRawQueries"`
	ZoomEyeRawQueries      []string `json:"zoomEyeRawQueries"      yaml:"zoomEyeRawQueries"`
	DriftnetRawQueries     []string `json:"driftnetRawQueries"     yaml:"driftnetRawQueries"`
	GoogleRawQueries       []string `json:"googleRawQueries"       yaml:"googleRawQueries"`
	BaiduRawQueries        []string `json:"baiduRawQueries"        yaml:"baiduRawQueries"`
}

type stringSlice []string

func (s *stringSlice) String() string {
	return fmt.Sprint(*s)
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	flagDirectory string
	flagEntryIDs  stringSlice
	flagOffline   bool
)

type FileMatch struct {
	Name     string
	Prefix   string
	Suffixes []string
}

var (
	sigmaFileMatch    = FileMatch{"sigma", "", []string{`.sigma.yml`}}
	snortFileMatch    = FileMatch{"snort", "", []string{`.snort.rule`}}
	suricataFileMatch = FileMatch{"suricata", "", []string{`.suricata.rule`}}
	yaraFileMatch     = FileMatch{"yara", "", []string{`.yara`}}
	pcapFileMatch     = FileMatch{"pcap", `00-`, []string{`.pcap`, `.pcapng`}}
	dockerPrefix      = `target-`
	total_failures    = 0
)

func checkFilePresence(files []string, entry Entry, isChain bool, settingValue bool, fileMatch FileMatch) bool {
	matched := false
	matchedTopLevel := false
	cveLower := strings.ToLower(entry.CVE)
	needle := cveLower + "/"
	for _, file := range files {
		idx := strings.Index(file, needle)
		if idx < 0 {
			continue
		}
		hasSuffix := false
		for _, fileSuffix := range fileMatch.Suffixes {
			if strings.HasSuffix(file, fileSuffix) {
				hasSuffix = true
				break
			}
		}
		if !hasSuffix {
			continue
		}
		matched = true
		// Top level means the file sits directly in the entry directory, not in
		// a sub-package (cve-x/foo.pcap, not cve-x/subpkg/foo.pcap).
		if !strings.Contains(file[idx+len(needle):], "/") {
			matchedTopLevel = true
			break // a top-level match settles both directions
		}
	}

	// A sub-package file satisfies an expected-present flag but does not
	// contradict an expected-absent one: a multi-package entry may carry
	// artifacts (pcaps, rules, ...) in its sub-packages without tripping a
	// sibling artifact's `false` flag.
	effectiveMatched := matched
	if !settingValue {
		effectiveMatched = matchedTopLevel
	}

	if settingValue != effectiveMatched {
		messageBody := fmt.Sprintf("%s - has %s marked as %s but `%s/*%s` ", entry.CVE, fileMatch.Name, strconv.FormatBool(settingValue), cveLower, fileMatch.Suffixes[0])
		if effectiveMatched {
			messageBody += "was found"
		} else {
			messageBody += "was not found"
		}
		if isChain {
			log.Printf("WARN: %s, but is in a chain", messageBody)
		} else {
			log.Printf("ERROR: %s", messageBody)
			return false
		}
	}
	return true
}

func main() {
	flag.StringVar(&flagDirectory, "dir", "./feed", "Directory to read feed from")
	flag.Var(&flagEntryIDs, "entry-id", "An entry ID (CVE) to process from the feed (repeatable)")
	flag.BoolVar(&flagOffline, "offline", false, "skip online checks (disables the docker-compose amd64 platform check)")

	skiplist := map[string]string{
		"CVE-2021-44228": "Multitarget CVE does not map cleanly to predictable paths",
		"CVE-2023-29300": "CVE Changed",
		"CVE-2023-4220":  "Docker references external CVE",
		"CVE-2024-2961":  "Unclean chain",
		"CVE-2025-31161": "CVE Changed",
		"CVE-2026-1470":  "Matches CVE-2025-68613",
		"CVE-2025-47813": "Chain",
		"CVE-2026-29053": "Chain",
		"CVE-2026-50656": "CPP Exploit",
		"CVE-2026-60137": "Chain",
		"CVE-2026-63520": "Chain",
		"CVE-2026-81578": "Chain",
		"CVE-2026-67279": "Chain",
		"CVE-2026-83549": "Chain",
	}
	flag.Parse()

	// Entry IDs map to directory names in the feed (lowercase, almost always a
	// CVE but e.g. vc-2025-1 is an exception). When none are given, scan all.
	// The map value records whether the requested ID was found and scanned; any
	// left false at the end were never matched (e.g. a typo) and are reported.
	requested := map[string]bool{}
	for _, id := range flagEntryIDs {
		requested[strings.ToLower(id)] = false
	}

	dirEntries, err := os.ReadDir(flagDirectory)
	if err != nil {
		log.Fatal(err)
	}

	// Allow aggregating errors to allow fixing of multiple issues
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		if len(requested) == 0 {
			// A directory without a README.md is not a feed entry (e.g.
			// other-detections). Skip it silently unless it was explicitly
			// requested, in which case the missing README is reported as an error.
			if !hasReadme(flagDirectory, dirEntry.Name()) {
				continue
			}
			skipReason := skiplist[strings.ToUpper(dirEntry.Name())]
			if skipReason != "" {
				log.Printf("Skipping validations for %s... %s", strings.ToUpper(dirEntry.Name()), skipReason)
			}
		} else {
			_, explicit := requested[strings.ToLower(dirEntry.Name())]
			if !explicit {
				continue
			}

			requested[strings.ToLower(dirEntry.Name())] = true
		}

		total_failures += lintEntryFrontmatter(flagDirectory, dirEntry.Name())
		total_failures += lintDocker(flagDirectory, dirEntry.Name())
		total_failures += lintPcap(flagDirectory, dirEntry.Name())
	}
	for id, scanned := range requested {
		if !scanned {
			log.Printf("ERROR: requested entry ID %q does not match any feed directory", id)
			total_failures++
		}
	}

	if total_failures > 0 {
		log.Printf("Validation failed... Total validation failures: %d", total_failures)

		os.Exit(1)
	}
}

func lintEntryFrontmatter(dir, entryID string) int {
	entry, files, ok := loadEntryFrontmatter(dir, entryID)
	if !ok {
		log.Printf("ERROR: Failed to load frontmatter for entry: %s", entryID)
		return 1
	}

	failed := 0

	cveLower := strings.ToLower(entry.CVE)
	for _, artifact := range entry.Artifacts {
		isChain := false
		// Once the chain component is merged we should probably add support for iterating into the chain entries and still having more aggressive validation.
		if len(artifact.Chain) != 0 {
			if !slices.Contains(artifact.Chain, entry.CVE) {
				log.Printf("ERROR: %s - Entry CVE is not in chain: %v", entry.CVE, artifact.Chain)
				failed++
				continue
			} else {
				log.Printf("Skipping validations for %s due to it being a chain", entry.CVE)
				isChain = true
			}
		}
		const shortForm = "2006-01-02"
		t, _ := time.Parse(shortForm, artifact.DateAdded)
		future := time.Now().Add(time.Hour * 24 * 3)
		if t.After(future) {
			log.Printf("ERROR: %s - Date is too far in the future: %s", entry.CVE, artifact.DateAdded)
			failed++
		}
		if len(artifact.MitreAttackTechniques) == 0 {
			log.Printf("ERROR: %s - 'mitreAttackTechniques' was not populated", entry.CVE)
			failed++
		}
		matched := false
		for _, file := range files {
			if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
				if strings.Contains(file, cveLower+".go") {
					matched = true
				}
			}
		}
		if artifact.Exploit {
			if !matched {
				if isChain {
					log.Printf("WARN: %s - has exploit marked as true but `%s/%s.go` was not found, but the exploit is marked as a chain", entry.CVE, cveLower, cveLower)
				} else {
					log.Printf("ERROR: %s - has exploit marked as true but `%s/%s.go` was not found", entry.CVE, cveLower, cveLower)
					failed++
				}
			}
		} else {
			if matched {
				data, err := os.ReadFile(fmt.Sprintf("%s/%s/%s.go", flagDirectory, cveLower, cveLower))
				if err != nil {
					log.Fatal(err)
				}
				if !strings.Contains(string(data), `RunExploit(_ *config.Config)`) {
					if isChain {
						log.Printf("WARN: %s - has exploit marked as false but `%s/%s.go` was found, but the exploit is marked as a chain", entry.CVE, cveLower, cveLower)
					} else {

						log.Printf("ERROR: %s - has exploit marked as false but `%s/%s.go` was found", entry.CVE, cveLower, cveLower)
						failed++
					}
				}
			}
		}

		if !checkFilePresence(files, entry, isChain, artifact.SigmaRule, sigmaFileMatch) {
			failed++
		}
		if !checkFilePresence(files, entry, isChain, artifact.SnortRule, snortFileMatch) {
			failed++
		}
		if !checkFilePresence(files, entry, isChain, artifact.SuricataRule, suricataFileMatch) {
			failed++
		}
		if !checkFilePresence(files, entry, isChain, artifact.Yara, yaraFileMatch) {
			failed++
		}
		if !checkFilePresence(files, entry, isChain, artifact.Pcap, pcapFileMatch) {
			failed++
		}

		matched = false
		for _, file := range files {
			if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
				if strings.Contains(file, fmt.Sprintf("%s%s", dockerPrefix, cveLower)) {
					matched = true
				}
			}
		}

		if artifact.TargetDocker {
			if !matched {
				if isChain {
					log.Printf("WARN: %s - has docker marked as true but `%s/%s%s` was not found, but is in a chain", entry.CVE, cveLower, dockerPrefix, cveLower)
				} else {
					log.Printf("ERROR: %s - has docker marked as true but `%s/%s%s` was not found", entry.CVE, cveLower, dockerPrefix, cveLower)
					failed++
				}
			}
		} else {
			if matched {
				if isChain {
					log.Printf("WARN: %s - has docker marked as false but `%s/%s%s` was found, but is in a chain", entry.CVE, cveLower, dockerPrefix, cveLower)
				} else {

					log.Printf("ERROR: %s - has docker marked as false but `%s/%s%s` was found", entry.CVE, cveLower, dockerPrefix, cveLower)
					failed++
				}
			}
		}

		if len(artifact.GoogleQueries) != 0 {
			for _, query := range artifact.GoogleQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Google URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}
		if len(artifact.BaiduQueries) != 0 {
			for _, query := range artifact.BaiduQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Baidu URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}
		if len(artifact.ShodanQueries) != 0 {
			for _, query := range artifact.ShodanQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Shodan URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}
		if len(artifact.FOFAQueries) != 0 {
			for _, query := range artifact.FOFAQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - FOFA URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}
		if len(artifact.ZoomEyeQueries) != 0 {
			for _, query := range artifact.ZoomEyeQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - ZoomEye URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}
		if len(artifact.CensysQueries) != 0 {
			for _, query := range artifact.CensysQueries {
				u, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Censys URI invalid error: %s", entry.CVE, err.Error())
					failed++
					continue
				}
				if u.Host != "platform.censys.io" {
					log.Printf("ERROR: %s - Censys URI is set to legacy search: %s", entry.CVE, u.String())
					failed++
				}
			}
		}
		if len(artifact.CensysLegacyQueries) != 0 {
			for _, query := range artifact.CensysLegacyQueries {
				u, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Censys Legacy URI invalid error: %s", entry.CVE, err.Error())
					failed++
					continue
				}
				if u.Host != "search.censys.io" {
					log.Printf("ERROR: %s - Censys Legacy URI is set to platform search: %s", entry.CVE, u.String())
					failed++
				}
			}
		}
		if len(artifact.GreynoiseQueries) != 0 {
			for _, query := range artifact.GreynoiseQueries {
				_, err := url.ParseRequestURI(query)
				if err != nil {
					log.Printf("ERROR: %s - Greynoise URI invalid error: %s", entry.CVE, err.Error())
					failed++
				}
			}
		}

	}

	return failed
}

func frontmatterToEntry(data string, name string) (Entry, bool) {
	entry := Entry{}
	_, err := frontmatter.MustParse(strings.NewReader(data), &entry)
	if err != nil {
		log.Printf("ERROR: Frontmatter (%s): %s", name, err.Error())
		return Entry{}, false
	}

	return entry, true
}

// hasReadme reports whether the given feed directory holds a README.md, which
// is what distinguishes an entry directory from a helper directory.
func hasReadme(dir, entryID string) bool {
	info, err := os.Stat(filepath.Join(dir, entryID, "README.md"))

	return err == nil && !info.IsDir()
}

// loadEntryFrontmatter reads a single feed entry's README frontmatter along with the list
// of files contained in its directory. File paths are returned relative to dir
// (e.g. "cve-2010-0103/README.md") so the per-entry presence checks continue to
// match on "<cveLower>/".
func loadEntryFrontmatter(dir, entryID string) (Entry, []string, bool) {
	readmePath := filepath.Join(dir, entryID, "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		log.Printf("ERROR: %s - unable to read README.md: %s", entryID, err.Error())
		return Entry{}, nil, false
	}
	if !strings.HasPrefix(string(data), "---\n") {
		log.Printf("ERROR: %s - README.md is missing YAML frontmatter", entryID)
		return Entry{}, nil, false
	}
	entry, ok := frontmatterToEntry(string(data), readmePath)
	if !ok {
		return Entry{}, nil, false
	}
	if entry.Artifacts == nil && entry.CVE == "" {
		log.Printf("ERROR: %s - no artifacts or CVE found in frontmatter", entryID)
		return Entry{}, nil, false
	}
	for i := range entry.Artifacts {
		if entry.Artifacts[i].DateAdded != "" {
			dTime, err := time.Parse(time.DateOnly, entry.Artifacts[i].DateAdded)
			if err != nil {
				log.Printf("WARN: parse time failed on %s: %s", entry.CVE, err.Error())
			} else {
				entry.Artifacts[i].DateTime = dTime
			}
		}
	}

	files := []string{}
	fileSystem := os.DirFS(dir)
	err = fs.WalkDir(fileSystem, entryID, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			log.Print(err.Error())

			return nil
		}
		files = append(files, path)

		return nil
	})
	if err != nil {
		log.Print(err.Error())
	}

	return entry, files, true
}
