package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/buger/jsonparser"
)

type ia struct {
	Suricata_signature bool
}

func get_ia_json(token string) (map[string]bool, bool) {
	cve_map := make(map[string]bool)
	// broken when we exceed 1000
	req, _ := http.NewRequest("GET", "https://api.vulncheck.com/v3/index/initial-access?limit=1000", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Failed client creation")
		return nil, false
	}

	defer resp.Body.Close()
	body_bytes, _ := io.ReadAll(resp.Body)

	json, _, _, _ := jsonparser.Get(body_bytes, "data")
	_, _ = jsonparser.ArrayEach(json, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		cve, _ := jsonparser.GetString(value, "cve")

		// note that indexing to [0] is technically wrong but sufficient for this script
		suricataSignature, _ := jsonparser.GetBoolean(value, "artifacts", "[0]", "suricataRule")
		if suricataSignature {
			cve_map[cve] = true
		}
	})

	return cve_map, true
}

func get_emerging_threat_suricata_rules(ia_rules map[string]bool) (string, bool) {

	ruleSet := ""

	resp, err := http.Get("https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules")
	if err != nil {
		fmt.Println("ET rules download failed.")
		return ruleSet, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	rules := string(bodyBytes)

	rules_slice := strings.Split(rules, "\n")
	for _, rule := range rules_slice {

		// skip over rules that are commened out
		if strings.HasPrefix(rule, "#") {
			continue
		}

		// only look at rules with cve references
		if !strings.Contains(rule, "reference:cve,") {
			continue
		}

		re := regexp.MustCompile(`reference:cve,(?:CVE-|cve-)?(\d{4}-\d{4,})`)
		res := re.FindAllStringSubmatch(rule, -1)
		if len(res) == 0 {
			continue
		}

		cve := "CVE-" + res[0][1]
		_, ok := ia_rules[cve]
		if ok {
			ruleSet += rule
			ruleSet += "\n"
		}
	}

	return ruleSet, true
}

func main() {

	var bearer_token string
	flag.StringVar(&bearer_token, "bearer_token", "", "The VulnCheck API Client ID")
	flag.Parse()

	if len(bearer_token) == 0 {
		fmt.Println("Please provide your API bearer token.")
		return
	}

	fmt.Println("[+] Downloading Initial Access JSON")
	ia_rules, ok := get_ia_json(bearer_token)
	if !ok {
		return
	}

	fmt.Println("[+] Downloading and Generating ET Ruleset")
	et_ruleset, ok := get_emerging_threat_suricata_rules(ia_rules)
	if !ok {
		return
	}

	fmt.Println("[+] Writing rules to disk")
	err := os.WriteFile("emerging.suricata.rules", []byte(et_ruleset), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
