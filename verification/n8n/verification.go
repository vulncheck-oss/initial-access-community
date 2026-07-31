package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

func DoValidateTarget(conf *config.Config) bool {
	resp, body, ok := protocol.HTTPGetCache(conf.GenerateURL("/"))
	if !ok || resp.StatusCode != http.StatusOK {
		return false
	}
	if strings.Contains(body, `<title>n8n.io - Workflow Automation</title>`) {
		if strings.Contains(body, `We're sorry but the n8n Editor-UI doesn't work properly without JavaScript enabled.`) {
			return true
		}
	}

	return false
}

func DoCheckVersion(conf *config.Config, constraint string) exploit.VersionCheckType {
	resp, body, ok := protocol.HTTPGetCache(conf.GenerateURL("/rest/settings"))
	if !ok || resp.StatusCode != http.StatusOK {
		return exploit.Unknown
	}
	versionCli, err := jsonparser.GetString([]byte(body), "data", "versionCli")
	if err != nil {
		output.PrintfDebug("Could not find versionCli number: %s", err.Error())
		output.PrintDebug("Proceeding with constants asset method")
	} else {
		exploit.StoreVersion(conf, versionCli)
		if search.CheckSemVer(versionCli, constraint) {
			return exploit.Vulnerable
		}

		return exploit.NotVulnerable
	}

	url := conf.GenerateURL("/")
	resp, body, ok = protocol.HTTPGetCache(url)
	if !ok {
		return exploit.Unknown
	}

	if resp.StatusCode != http.StatusOK {
		output.PrintfDebug("Target responded with an unexpected status code: %d", resp.StatusCode)

		return exploit.Unknown
	}

	val, found := search.XPath(body, `//link[contains(@href, "/assets/constants-")]/@href`)
	if !found {
		return exploit.Unknown
	}

	constURL := conf.GenerateURL(val)
	resp, body, ok = protocol.HTTPGetCache(constURL)
	if !ok {
		return exploit.Unknown
	}

	if resp.StatusCode != http.StatusOK {
		output.PrintfDebug("Constants asset page responded with unexpected status code: %d", resp.StatusCode)

		return exploit.Unknown
	}

	// `n8n@2.10.0
	rgx := regexp.MustCompile(`n8n@((?:\d+\.\d+)\.\d+)+`)
	matches := rgx.FindStringSubmatch(body)
	if len(matches) < 2 {
		output.PrintfDebug("Failed to find version on assets page, resp=%v, body=%s", resp, body)

		return exploit.Unknown
	}

	version := matches[1]
	exploit.StoreVersion(conf, version)

	if !search.CheckSemVer(version, constraint) {
		return exploit.NotVulnerable
	}

	return exploit.Vulnerable
}

func DoLogin(conf *config.Config, email, password string) (string, bool) {
	url := conf.GenerateURL("/rest/login")

	// Send all possible username fields and hope one works
	json := fmt.Sprintf(`{"email":%q,"emailOrLdapLoginId":%q,"password":%q}`, email, email, password)

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	output.PrintfStatus("Logging in as %s:%s", email, password)

	resp, body, ok := protocol.HTTPSendAndRecvWithHeaders("POST", url, json, headers)
	if !ok {
		return "", false
	}

	cookies := protocol.ParseCookies(resp)
	if resp.StatusCode != 200 || !strings.Contains(cookies, "n8n-auth=eyJ") {
		output.PrintError("Failed to get a valid cookie")
		output.PrintfDebug("DoLogin failed: resp=%#v body=%q", resp, body)

		return "", false
	}

	output.PrintfSuccess("Cookies: %s", cookies)

	return cookies, true
}
