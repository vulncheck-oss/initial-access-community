package main

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

var versionPattern = regexp.MustCompile(`(\d+\.\d+\.\d+)`) // used to validate that a semver was returned

func DoValidateTarget(conf *config.Config) bool {
	url := conf.GenerateURL("/")
	resp, body, ok := protocol.HTTPGetCache(url)
	if !ok {
		return false
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// login page enabled, this does not affect exploitability, just what strings are available at '/'
	title, found := search.XPath(body, "//title")
	if !found {
		return false
	}

	if strings.ToLower(title) == "marimo" && strings.Contains(body, `<form method="POST" action="/auth/login" style="`) && strings.Contains(body, `">Access Token / Password</label>`) {
		return true
	}

	// these will validate in the less-likely case that the --no-token flag was used.
	return strings.Contains(body, `content="a marimo app" />`) && strings.Contains(body, `__MARIMO_MOUNT_CONFIG__`) && strings.Contains(body, `<script data-marimo="true">`)
}

func DoGetVersion(conf *config.Config) (string, bool) {
	url := conf.GenerateURL("/api/version")
	resp, body, ok := protocol.HTTPGetCache(url)
	if !ok {
		output.PrintDebug("Failed to make request")

		return "", false
	}

	if resp.StatusCode != http.StatusOK {
		output.PrintfDebug("Unexpected status code: %d", resp.StatusCode)

		return "", false
	}

	matches := versionPattern.FindStringSubmatch(body)
	if len(matches) < 2 {
		output.PrintfDebug("Insufficient matches found(%d) matches=%q body=%s", len(matches), matches, body)

		return "", false
	}

	version := matches[1]
	exploit.StoreVersion(conf, version)

	return version, true
}
