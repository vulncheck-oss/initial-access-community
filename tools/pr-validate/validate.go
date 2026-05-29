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
	"strings"
	"time"

	"github.com/adrg/frontmatter"
)

type Feed struct {
	Entries []Entry
}

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

var flagDirectory string

var (
	snortSuffix    = `.snort.rule`
	suricataSuffix = `.suricata.rule`
	yaraSuffix     = `.yara`
	pcapPrefix     = `00-`
	pcapSuffix     = `.pcap`
	dockerPrefix   = `target-`
)

func exists(files []string, name string) bool {
	for _, file := range files {
		if strings.Contains(file, name) {
			return true
		}
	}
	return false
}

func main() {
	flag.StringVar(&flagDirectory, "dir", "./feed", "Directory to read feed from")
	skiplist := map[string]string{
		"CVE-2021-44228": "Multitarget CVE does not map cleanly to predictable paths",
		"CVE-2023-29300": "CVE Changed",
		"CVE-2023-4220":  "Docker references external CVE",
		"CVE-2024-2961":  "Unclean chain",
		"CVE-2025-31161": "CVE Changed",
		"CVE-2026-1470":  "Matches CVE-2025-68613",
		"CVE-2025-47813": "Chain",
		"CVE-2026-29053": "Chain",
	}
	flag.Parse()

	f, files, _ := MarkdownToFeed(flagDirectory)

	// Allow aggregating errors to allow fixing of multiple issues
	failed := 0
	for _, entry := range f.Entries {
		cveLower := strings.ToLower(entry.CVE)
		for _, artifact := range entry.Artifacts {
			isChain := false
			if skiplist[entry.CVE] != "" {
				log.Printf("Skipping validations for %s... %s", entry.CVE, skiplist[entry.CVE])
				continue
			}
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

			matched = false
			for _, file := range files {
				if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
					if strings.Contains(file, ".snort.rule") {
						matched = true
					}
				}
			}
			if artifact.SnortRule {
				if !matched {
					if isChain {
						log.Printf("WARN: %s - has snort marked as true but `%s/*%s` was not found, but is in a chain", entry.CVE, cveLower, snortSuffix)
					} else {

						log.Printf("ERROR: %s - has snort marked as true but `%s/*%s` was not found", entry.CVE, cveLower, snortSuffix)

						failed++
					}
				}
			} else {
				if matched {
					if isChain {
						log.Printf("WARN: %s - has snort marked as false but `%s/*%s` was found, but is in a chain", entry.CVE, cveLower, snortSuffix)
					} else {
						log.Printf("ERROR: %s - has snort marked as false but `%s/*%s` was found", entry.CVE, cveLower, snortSuffix)
						failed++
					}
				}
			}

			matched = false
			for _, file := range files {
				if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
					if strings.Contains(file, suricataSuffix) {
						matched = true
					}
				}
			}
			if artifact.SuricataRule {
				if !matched {
					if isChain {
						log.Printf("WARN: %s - has suricata marked as true but `%s/*%s` was not found, but is in chain", entry.CVE, cveLower, suricataSuffix)
					} else {
						log.Printf("ERROR: %s - has suricata marked as true but `%s/*%s` was not found", entry.CVE, cveLower, suricataSuffix)
						failed++
					}
				}
			} else {
				if matched {
					if isChain {
						log.Printf("WARN: %s - has suricata marked as false but `%s/*%s` was found, but is in chain", entry.CVE, cveLower, suricataSuffix)
					} else {
						log.Printf("ERROR: %s - has suricata marked as false but `%s/*%s` was found", entry.CVE, cveLower, suricataSuffix)
						failed++
					}
				}
			}

			matched = false
			for _, file := range files {
				if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
					if strings.Contains(file, ".yara") {
						matched = true
					}
				}
			}
			if artifact.Yara {
				if !matched {
					if isChain {
						log.Printf("WARN: %s - has yara marked as true but `%s/*%s` was not found, but is in chain", entry.CVE, cveLower, yaraSuffix)
					} else {
						log.Printf("ERROR: %s - has yara marked as true but `%s/*%s` was not found", entry.CVE, cveLower, yaraSuffix)
						failed++
					}
				}
			} else {
				if matched {
					if isChain {
						log.Printf("WARN: %s - has yara marked as false but `%s/*%s` was found, but is in chain", entry.CVE, cveLower, yaraSuffix)
					} else {
						log.Printf("ERROR: %s - has yara marked as false but `%s/*%s` was found", entry.CVE, cveLower, yaraSuffix)
						failed++
					}
				}
			}

			// pcap checks
			matched = false
			for _, file := range files {
				if strings.Contains(file, fmt.Sprintf("%s/", cveLower)) {
					if strings.Contains(file, pcapPrefix) {
						if strings.Contains(file, pcapSuffix) {
							matched = true
						}
					}
				}
			}
			if artifact.Pcap {
				if !matched {
					if isChain {
						log.Printf("WARN: %s - has pcaps marked as true but `%s/%s*%s` was not found, but is in a chain", entry.CVE, cveLower, pcapPrefix, pcapSuffix)
					} else {
						log.Printf("ERROR: %s - has pcaps marked as true but `%s/%s*%s` was not found", entry.CVE, cveLower, pcapPrefix, pcapSuffix)
						failed++
					}
				}
			} else {
				if matched {
					if isChain {
						log.Printf("WARN: %s - has pcaps marked as false but `%s/%s*%s` was found, but is in a chain", entry.CVE, cveLower, pcapPrefix, pcapSuffix)
					} else {
						log.Printf("ERROR: %s - has pcaps marked as false but `%s/%s*%s` was found", entry.CVE, cveLower, pcapPrefix, pcapSuffix)
						failed++
					}
				}
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
	}
	if failed > 0 {
		log.Printf("Validation failed... Total validation failures: %d", failed)

		os.Exit(1)
	}
}

func frontmatterToEntry(data string, name string) (Entry, bool) {
	entry := Entry{}
	_, err := frontmatter.MustParse(strings.NewReader(data), &entry)
	if err != nil {
		log.Printf("WARN: Frontmatter (%s): %s", name, err.Error())

		return Entry{}, false
	}

	return entry, true
}

func MarkdownToFeed(dir string) (Feed, []string, error) {
	f := Feed{}
	files := []string{}
	fileSystem := os.DirFS(dir)
	err := fs.WalkDir(fileSystem, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			log.Print(err.Error())
		}
		files = append(files, path)
		if filepath.Ext(path) == ".md" {
			data, err := os.ReadFile(dir + "/" + path)
			if err != nil {
				log.Print(err.Error())

				return err
			}
			if strings.Contains(string(data), "---\n") {
				e, ok := frontmatterToEntry(string(data), dir+"/"+path)
				if ok {
					if e.Artifacts != nil || e.CVE != "" {
						for i := range e.Artifacts {
							if e.Artifacts[i].DateAdded != "" {
								dTime, err := time.Parse(time.DateOnly, e.Artifacts[i].DateAdded)
								if err != nil {
									log.Printf("WARN: parse time failed on %s: %s", e.CVE, err.Error())
								} else {
									e.Artifacts[i].DateTime = dTime
								}
							}
						}
						f.Entries = append(f.Entries, e)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return Feed{}, []string{}, err
	}

	return f, files, nil
}
