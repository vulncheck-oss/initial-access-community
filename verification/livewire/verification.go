package main

import (
	"strings"

	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

func DoValidateTarget(conf *config.Config) bool {
	url := protocol.GenerateURL(conf.Rhost, conf.Rport, conf.SSL, "/")

	resp, body, ok := protocol.HTTPGetCache(url)

	if !ok {
		return false
	}

	if resp.StatusCode != 200 || !strings.Contains(body, "/livewire/livewire.js") {
		output.PrintfDebug("ValidateTarget failed: resp=%#v body=%q", resp, body)

		return false
	}

	return true
}

func DoGetVersion(conf *config.Config) string {
	url := protocol.GenerateURL(conf.Rhost, conf.Rport, conf.SSL, "/")
	versionMap := map[string]string{"af0b760a": "v3.0.0", "3605227a": "v3.0.0-beta.3", "78f6b8d8": "v3.0.0-beta.10", "66b543cf": "v3.0.0-beta.11", "578b80d0": "v3.0.0-beta.4", "777821c0": "v3.0.0-beta.5", "b67331b2": "v3.0.0-beta.6", "99a05389": "v3.0.0-beta.7", "3948ee27": "v3.0.0-beta.8", "fc319290": "v3.0.0-beta.9", "11c49d7e": "v3.0.1", "2f6e5d4d": "v3.0.9", "51f84ddf": "v3.0.2", "75fdc007": "v3.0.3", "28cda9ab": "v3.0.4", "f41737f6": "v3.0.5", "5d3e67e0": "v3.0.7", "178de384": "v3.0.8", "c4077c56": "v3.1.0", "d38cabc2": "v3.2.0", "2b77c128": "v3.2.1", "eaa5c323": "v3.2.2", "8afc12b0": "v3.2.3", "29c31048": "v3.2.4", "8a579aa1": "v3.2.5", "f477dd12": "v3.2.6", "8a199ab2": "v3.3.0", "f121a5df": "v3.3.3", "6c8cb814": "v3.3.4", "e2b302e9": "v3.3.5", "b713ce84": "v3.4.0", "5eee0fac": "v3.4.1", "239a5c52": "v3.4.10", "44144c23": "v3.4.11", "770f7738": "v3.4.12", "8ed4c109": "v3.4.2", "94b2c3e6": "v3.4.3", "a27c4ca2": "v3.4.4", "6b5eb707": "v3.4.6", "d02a3788": "v3.4.7", "4495682f": "v3.4.8", "5d8beb2e": "v3.4.9", "07f22875": "v3.5.0", "87e1046f": "v3.5.1", "ec3a716b": "v3.5.10", "36c381f7": "v3.5.11", "38dc8241": "v3.5.12", "4ce12f49": "v3.5.13", "0f65591d": "v3.5.14", "def850b5": "v3.5.15", "da3bb356": "v3.5.16", "02b08710": "v3.5.17", "951e6947": "v3.5.18", "13b7c601": "v3.5.20", "c4fc8c5d": "v3.5.2", "7bfaddcd": "v3.5.3", "cc800bf4": "v3.5.6", "923613aa": "v3.5.9", "65f3e655": "v3.6.1", "fcf8c2ad": "v3.6.2", "df3a17f2": "v3.6.4", "f084fdfb": "v3.7.0", "646f9d24": "v3.7.1", "a1f2ce31": "v3.7.2", "0f6341c0": "v3.7.3"}

	resp, body, ok := protocol.HTTPGetCache(url)
	if !ok {
		return ""
	}
	if resp.StatusCode != 200 {
		output.PrintfDebug("CheckVersion failed: resp=%#v body=%q", resp, body)

		return ""
	}

	versionHash, ok := search.XPath(body, `//script[contains(@src, "/livewire/livewire.js?id=")]/@src`)
	if !ok {
		return ""
	}
	versionHash = strings.Replace(versionHash, "/livewire/livewire.js?id=", "", 1)

	version, ok := versionMap[versionHash]
	if !ok {
		output.PrintfError("Unable to find version in lookup table for hash: %s", versionHash)

		return ""
	}

	return version
}
