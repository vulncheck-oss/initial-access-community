package main

import (
	"strings"

	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
)

// CopelandXWEBValidate fingerprints an XWEB supervisor on its root page, which serves
// a branded error page (not 200) carrying the XWEB title and the xweb-logo asset.
func CopelandXWEBValidate(conf *config.Config) bool {
	resp, body, ok := protocol.HTTPGetCache(conf.GenerateURL(""))
	if !ok || resp == nil {
		output.PrintDebug("root request failed")

		return false
	}
	// The web UI is a client-routed SPA, so "/" answers with a branded error page at a
	// non-200 status. Gate on the XWEB markers it carries, not the status code: a status
	// filter (for example < 500) would wrongly reject the real device, which returns 500.
	if strings.Contains(body, "<title>XWEB") && strings.Contains(body, "xweb-logo") {
		return true
	}
	output.PrintfDebug("root page is not an XWEB UI: status=%d", resp.StatusCode)

	return false
}
