package main

import (
	"strings"

	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/protocol"
)

func DoValidateTarget(conf *config.Config) bool {
	resp, body, ok := protocol.HTTPGetCache(conf.GenerateURL("/"))
	if !ok {
		return false
	}

	if resp.StatusCode == 401 {
		return strings.Contains(resp.Header.Get("WWW-Authenticate"), `realm="ActiveMQRealm"`)
	}

	if strings.Contains(body, "<title>Apache ActiveMQ</title>") {
		return strings.Contains(body, `<div id="activemq_logo">`)
	}

	return false
}
