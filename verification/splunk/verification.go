package main

import (
	"net/http"
	"strings"

	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
)

func DoValidateTarget(conf *config.Config) bool {
	getURL := conf.GenerateURL("/")
	resp, body, ok := protocol.HTTPGetCache(getURL)
	if !ok {
		output.PrintDebug("Failed to send GET request")

		return false
	}

	if resp.StatusCode != http.StatusOK {
		output.PrintfDebug("Received unexpected status code (%d) from GET request, expected a 200.", resp.StatusCode)

		return false
	}

	return strings.Contains(body, `Splunk relies on JavaScript to function properly.`) && strings.Contains(body, `"product_type":"enterprise"`) && strings.Contains(body, `splunkweb_uid`)
}
