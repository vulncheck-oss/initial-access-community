package main

import (
	"flag"
	"fmt"
	"github.com/buger/jsonparser"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type VulnType int

const (
	ClientSide                VulnType = 0
	Local                     VulnType = 1
	DoS                       VulnType = 2
	InitialAccess             VulnType = 3
	Credentialed_IntialAccess VulnType = 4
	InfoLeak                  VulnType = 5
	NoCategory                VulnType = 6
)

type ia struct {
	Signature bool
	Shodan    bool
	Censys    bool
	Exploit   bool
	Scanner   bool
}

// Categorizes the CVE based on elements from the CVSSv3 or CVSSv2 vector:
// attack_vector == AV
// privs ==  PR (v3) || Au (v2)
// user_interaction == UI (v3) || userInteractionRequired (v2 *base* metric)
// confident == C
// integrity == I
// availability == A
func doSort(attack_vector string, privs string, user_interaction bool, confident string, integrity string, availability string) VulnType {
	if attack_vector == "NETWORK" {
		if confident != "NONE" && integrity != "NONE" {
			if !user_interaction {
				if privs == "NONE" {
					// remote, no user interaction, affects or accesses system data, no privs
					return InitialAccess
				} else {
					// remote, no user interaction, affects or access system data, requires privs
					return Credentialed_IntialAccess
				}
			} else {
				// remote, affects or accesses system data, requires user interaction
				return ClientSide
			}
		} else if confident != "NONE" && privs == "NONE" && integrity == "NONE" && !user_interaction {
			// remote, no auth, no user interaction, data leak
			return InfoLeak
		} else if availability != "NONE" {
			// remote, does not affect or access system data, impacts availability
			return DoS
		}
	} else if attack_vector == "LOCAL" {
		if user_interaction {
			// local with user intaction
			return ClientSide
		} else {
			return Local
		}
	}

	return NoCategory
}

func doCVSSv3(baseMetricV3 []byte) VulnType {

	attack_vector, _ := jsonparser.GetString(baseMetricV3, "attackVector")
	privs, _ := jsonparser.GetString(baseMetricV3, "privilegesRequired")
	user_interaction, _ := jsonparser.GetString(baseMetricV3, "userInteraction")
	confident, _ := jsonparser.GetString(baseMetricV3, "confidentialityImpact")
	integrity, _ := jsonparser.GetString(baseMetricV3, "integrityImpact")
	availability, _ := jsonparser.GetString(baseMetricV3, "availabilityImpact")

	return doSort(attack_vector, privs, user_interaction != "NONE", confident, integrity, availability)
}

func doCVSSv2(baseMetricV2 []byte, user_interaction bool) VulnType {

	access_vector, _ := jsonparser.GetString(baseMetricV2, "accessVector")
	authentication, _ := jsonparser.GetString(baseMetricV2, "authentication")
	confident, _ := jsonparser.GetString(baseMetricV2, "confidentialityImpact")
	integrity, _ := jsonparser.GetString(baseMetricV2, "integrityImpact")
	availability, _ := jsonparser.GetString(baseMetricV2, "availabilityImpact")

	return doSort(access_vector, authentication, user_interaction, confident, integrity, availability)
}

func fetch_vulnerability(token string, vulnerability string) ([]byte, bool) {
	req, _ := http.NewRequest("GET", "https://api.vulncheck.com/v2/vulnerabilities/cve/"+vulnerability, nil)
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Failed client creation")
		return nil, false
	}

	defer resp.Body.Close()
	body_bytes, _ := io.ReadAll(resp.Body)
	return body_bytes, true
}

func get_ia_json(token string) (map[string]ia, bool) {
	cve_map := make(map[string]ia)
	req, _ := http.NewRequest("GET", "https://api.vulncheck.com/v3/index/initial-access", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Failed client creation")
		return nil, false
	}

	defer resp.Body.Close()
	body_bytes, _ := io.ReadAll(resp.Body)

	// TODO when IA exceeds 100, we'll have to handle paging.
	json, _, _, _ := jsonparser.Get(body_bytes, "data")
	_, _ = jsonparser.ArrayEach(json, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		cve, _ := jsonparser.GetString(value, "cve")

		// note that indexing to [0] is technically wrong but sufficient for this script
		signature, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "suricataRule")
		_, shodan_err := jsonparser.GetString(value, "artifacts", "[0]", "shodanQueries", "[0]")
		_, censys_err := jsonparser.GetString(value, "artifacts", "[0]", "censysQueries", "[0]")
		exploit, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "exploit")
		scanner, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "versionScanner")

		cve_map[cve] = ia{Signature: signature, Shodan: shodan_err == nil, Censys: censys_err == nil, Exploit: exploit, Scanner: scanner}
	})

	return cve_map, true
}

func get_emerging_threat_rules() (map[string]int, bool) {
	cve_map := make(map[string]int)
	resp, err := http.Get("https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules")
	if err != nil {
		fmt.Println("[-] ET rules download failed.")
		return cve_map, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	rules := string(bodyBytes)

	rules_slice := strings.Split(rules, "\n")
	for _, rule := range rules_slice {

		if !strings.Contains(rule, "reference:cve,") {
			continue
		}

		re := regexp.MustCompile(`reference:cve,(\d{4}-\d{4,})`)
		res := re.FindAllStringSubmatch(rule, -1)
		if len(res) == 0 {
			continue
		}

		cve := "CVE-" + res[0][1]
		cve_map[cve] = 1
	}

	return cve_map, true
}

func get_kev_catalog() (map[string]int, bool) {
	cve_map := make(map[string]int)
	resp, err := http.Get("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv")
	if err != nil {
		fmt.Println("[-] KEV download failed.")
		return cve_map, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	allKev := string(bodyBytes)
	kev_slice := strings.Split(allKev, "\n")
	for _, kev := range kev_slice {

		kevSplit := strings.Split(kev, ",")
		if !strings.Contains(kevSplit[0], "CVE-") {
			continue
		}

		cve := strings.ReplaceAll(kevSplit[0], `"`, "")
		cve_map[cve] = 1
	}

	return cve_map, true
}

func get_metasploit(kev map[string]int) (map[string]int, bool) {
	cve_map := make(map[string]int)
	resp, err := http.Get("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json")
	if err != nil {
		fmt.Println("[-] Metasploit download failed.")
		return cve_map, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	_ = jsonparser.ObjectEach(bodyBytes, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		_, _ = jsonparser.ArrayEach(value, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			if ref := string(value); strings.HasPrefix(ref, "CVE-") && kev[ref] == 1 {
				cve_map[ref] = 1
			}
		}, "references")

		return nil
	})

	return cve_map, true
}

func get_nuclei(kev map[string]int) (map[string]int, bool) {
	cve_map := make(map[string]int)
	resp, err := http.Get("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json")
	if err != nil {
		fmt.Println("[-] Nuclei download failed.")
		return cve_map, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// weirdly, the cves.json isn't one big valid json doc, but a series of small json blobs. So we'll be lazy
	// and use strings to hunt for the data we want
	for cve := range kev {
		if strings.Contains(body, `{"ID":"`+cve+`"`) {
			cve_map[cve] = 1
		}
	}
	return cve_map, true
}

func isIA(cve_json []byte) bool {
	entry_json, _, _, err := jsonparser.Get(cve_json, "results", "[0]")
	if err != nil {
		return false
	}

	var result VulnType
	v3, _, _, err := jsonparser.Get(entry_json, "impact", "baseMetricV3", "cvssV3")
	if err == nil {
		result = doCVSSv3(v3)
	} else {
		v2, _, _, err := jsonparser.Get(entry_json, "impact", "baseMetricV2", "cvssV2")
		if err != nil {
			// fmt.Println("Failed to parse v2: " + string(cve_json))
			return false
		}
		userInter, _ := jsonparser.GetBoolean(entry_json, "impact", "baseMetricV2", "userInteractionRequired")
		result = doCVSSv2(v2, userInter)
	}

	return result == InitialAccess || result == InfoLeak
}

func ia_filter(token string, kev_catalog map[string]int) (map[string]int, bool) {
	cve_map := make(map[string]int)
	for cve := range kev_catalog {
		vuln_json, result := fetch_vulnerability(token, cve)
		if !result {
			//fmt.Printf("[-] Failed to fetch %s\n", cve)
			return cve_map, false
		}

		ok := isIA(vuln_json)
		if ok {
			cve_map[cve] = 1
		}
	}

	return cve_map, true
}

func generate_output(ia_feed map[string]ia, et_rules map[string]int, kev map[string]int, metasploit map[string]int, nuclei map[string]int) {
	fmt.Println("# KEV Measurements")

	et_for_kev := 0
	ia_sig_kev := 0
	ia_shodan_kev := 0
	ia_censys_kev := 0
	ia_exploit_kev := 0
	ia_version_scanner := 0
	metasploit_coverage := 0
	nuclei_coverage := 0

	// sort the kev entries
	kev_keys := make([]string, 0, len(kev))
	for k := range kev {
		kev_keys = append(kev_keys, k)
	}
	sort.Strings(kev_keys)

	// reverse (why is this not a builtin?). Thanks SO.
	for i, j := 0, len(kev_keys)-1; i < j; i, j = i+1, j-1 {
		kev_keys[i], kev_keys[j] = kev_keys[j], kev_keys[i]
	}

	table := "|CVE|ET Sig|IA Sig|IA Shodan|IA Censys|IA Exploit|IA Scanner|Metasploit|Nuclei\n"
	table += "| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
	for _, cve := range kev_keys {
		table += cve
		table += "|"
		_, ok := et_rules[cve]
		if ok {
			table += "✔️|"
			et_for_kev += 1
		} else {
			table += "|"
		}

		ia_entry, ok := ia_feed[cve]
		if ok {
			if ia_entry.Signature {
				table += "✔️|"
				ia_sig_kev += 1
			} else {
				table += "|"
			}

			if ia_entry.Shodan {
				table += "✔️|"
				ia_shodan_kev += 1
			} else {
				table += "|"
			}

			if ia_entry.Censys {
				table += "✔️|"
				ia_censys_kev += 1
			} else {
				table += "|"
			}

			if ia_entry.Exploit {
				table += "✔️|"
				ia_exploit_kev += 1
			} else {
				table += "|"
			}

			if ia_entry.Scanner {
				table += "✔️|"
				ia_version_scanner += 1
			} else {
				table += "|"
			}
		} else {
			table += "|||||"
		}

		_, ok = metasploit[cve]
		if ok {
			table += "✔️|"
			metasploit_coverage += 1
		} else {
			table += "|"
		}

		_, ok = nuclei[cve]
		if ok {
			table += "✔️|"
			nuclei_coverage += 1
		} else {
			table += "|"
		}
		table += "\n"
	}

	fmt.Printf("The total number of \"Initial Access\" KEV entries includes all the traditional IA, plus credentialed IA and remote/unauth info leak.  \nThe reason for that is there are a number of exploit chains that achieve unauth rce via infoleak+credentialed rce.  \n")
	fmt.Println("  ")
	fmt.Printf("*Total Initial-Access KEV Entries*: %d\n  ", len(kev))
	fmt.Println("  ")
	fmt.Printf("*Emerging Threats Coverage*: %d / %d  \n", et_for_kev, len(kev))
	fmt.Printf("*IA Signature Coverage*: %d / %d  \n", ia_sig_kev, len(kev))
	fmt.Printf("*IA Shodan Coverage*: %d / %d  \n", ia_shodan_kev, len(kev))
	fmt.Printf("*IA Censys Coverage*: %d / %d  \n", ia_censys_kev, len(kev))
	fmt.Printf("*IA Exploit Coverage*: %d / %d  \n", ia_exploit_kev, len(kev))
	fmt.Printf("*IA Version Scanner*: %d / %d  \n", ia_version_scanner, len(kev))
	fmt.Printf("*Metasploit*: %d / %d  \n", metasploit_coverage, len(kev))
	fmt.Printf("*Nuclei*: %d / %d  \n", nuclei_coverage, len(kev))
	fmt.Println("  ")
	fmt.Println("\n## Coverage Table")
	fmt.Println(table)
}

func main() {

	var bearer_token string
	flag.StringVar(&bearer_token, "bearer_token", "", "The VulnCheck API Client ID")
	flag.Parse()

	if len(bearer_token) == 0 {
		fmt.Println("Please provide your API bearer token.")
		return
	}

	ia_feed, ok := get_ia_json(bearer_token)
	if !ok {
		return
	}

	et_rules, ok := get_emerging_threat_rules()
	if !ok {
		return
	}

	kev_catalog, ok := get_kev_catalog()
	if !ok {
		return
	}

	ia_only, ok := ia_filter(bearer_token, kev_catalog)
	if !ok {
		return
	}

	metasploit, ok := get_metasploit(ia_only)
	if !ok {
		return
	}

	nuclei, ok := get_nuclei(ia_only)
	if !ok {
		return
	}

	generate_output(ia_feed, et_rules, ia_only, metasploit, nuclei)
}
