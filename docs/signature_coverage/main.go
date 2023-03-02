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

type ia struct {
	Suricata_signature bool
	Snort_signature    bool
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
		suricataSignature, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "suricataRule")
		snortSignature, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "snortRule")

		cve_map[cve] = ia{Suricata_signature: suricataSignature, Snort_signature: snortSignature}
	})

	return cve_map, true
}

func get_emerging_threat_suricata_rules() (map[string]int, bool) {
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

func get_emerging_threat_snort_rules() (map[string]int, bool) {
	cve_map := make(map[string]int)
	resp, err := http.Get("https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules")
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

func generate_output(ia_feed map[string]ia, et_suricata_rules map[string]int, et_snort_rules map[string]int) {
	fmt.Println("# Initial Access vs. Emerging Threats")

	et_suri_sig := 0
	et_snort_sig := 0
	ia_suri_sig := 0
	ia_snort_sig := 0

	// create a monst map of all the keys
	cve_map := make(map[string]int)
	for key := range ia_feed {
		cve_map[key] = 1
	}
	for key := range et_suricata_rules {
		cve_map[key] = 1
	}
	for key := range et_snort_rules {
		cve_map[key] = 1
	}

	// combine all the keys
	map_keys := make([]string, 0, len(cve_map))
	for k := range cve_map {
		map_keys = append(map_keys, k)
	}
	sort.Strings(map_keys)

	// reverse (why is this not a builtin?). Thanks SO.
	for i, j := 0, len(map_keys)-1; i < j; i, j = i+1, j-1 {
		map_keys[i], map_keys[j] = map_keys[j], map_keys[i]
	}

	table := "|CVE|ET Suri|ET Snort|IA Suri|IA Snort|\n"
	table += "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
	for _, cve := range map_keys {
		table += cve
		table += "|"
		_, ok := et_suricata_rules[cve]
		if ok {
			table += "✔️|"
			et_suri_sig += 1
		} else {
			table += "|"
		}

		_, ok = et_snort_rules[cve]
		if ok {
			table += "✔️|"
			et_snort_sig += 1
		} else {
			table += "|"
		}

		ia_entry, ok := ia_feed[cve]
		if ok {
			if ia_entry.Suricata_signature {
				table += "✔️|"
				ia_suri_sig += 1
			} else {
				table += "|"
			}

			if ia_entry.Snort_signature {
				table += "✔️|"
				ia_snort_sig += 1
			} else {
				table += "|"
			}
		} else {
			table += "||"
		}
		table += "\n"
	}

	fmt.Printf("*Emerging Threats Suricata Coverage*: %d / %d  \n", et_suri_sig, len(map_keys))
	fmt.Printf("*Emerging Threats Snort Coverage*: %d / %d  \n", et_snort_sig, len(map_keys))
	fmt.Printf("*IA Suricata Signature Coverage*: %d / %d  \n", ia_suri_sig, len(map_keys))
	fmt.Printf("*IA Snort Signature Coverage*: %d / %d  \n", ia_snort_sig, len(map_keys))
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

	et_suricata_rules, ok := get_emerging_threat_suricata_rules()
	if !ok {
		return
	}

	et_snort_rules, ok := get_emerging_threat_snort_rules()
	if !ok {
		return
	}

	generate_output(ia_feed, et_suricata_rules, et_snort_rules)
}
