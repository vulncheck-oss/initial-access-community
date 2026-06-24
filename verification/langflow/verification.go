package main

import (
	"regexp"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

func DoValidateTarget(conf *config.Config) bool {
	_, body, ok := protocol.HTTPGetCache(conf.GenerateURL("/"))
	if ok {
		title, ok := search.XPath(body, "//title")
		if ok && strings.Contains(title, "Langflow") && strings.Contains(body, "manifest.json") {
			return true
		}
	}

	return false
}

var rcRegex = regexp.MustCompile(`\d+\.\d+\.\d+rc\d+`)

func DoCheckVersion(conf *config.Config, vulnerableVersions []string) exploit.VersionCheckType {
	url := conf.GenerateURL("/api/v1/version")
	res, body, ok := protocol.HTTPSendAndRecv("GET", url, "")
	if !ok || res.StatusCode != 200 {
		return exploit.Unknown
	}

	version, e := jsonparser.GetString([]byte(body), "version")
	if e != nil {
		return exploit.Unknown
	}

	exploit.StoreVersion(conf, version)
	for _, r := range vulnerableVersions {
		// It looks like CheckSemVer cannot check version strings with "rc" in that format.
		// So that we have two different checks here.
		matched := rcRegex.MatchString(r)
		if matched {
			if r == version {
				return exploit.Vulnerable
			}
		} else {
			if search.CheckSemVer(version, r) {
				return exploit.Vulnerable
			}
		}
	}

	return exploit.NotVulnerable
}
