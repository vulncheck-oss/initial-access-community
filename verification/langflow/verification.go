package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	exploit "github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

const versionURI = "/api/v1/version"

// urlAt builds the URL for uri under basePath. Slashes are trimmed from both parts
// before protocol.BuildURI joins them, so "" and "/" both mean the server root and
// no slash doubles.
func urlAt(conf *config.Config, basePath, uri string) string {
	return conf.GenerateURL(protocol.BuildURI(strings.Trim(basePath, "/"), strings.Trim(uri, "/")))
}

// versionResponse fetches /api/v1/version under basePath and returns (package, version, ok).
// Older releases (< 1.1.0) only carry "version"; newer ones also have "main_version".
func versionResponse(conf *config.Config, basePath string) (string, string, bool) {
	url := urlAt(conf, basePath, versionURI)
	resp, body, ok := protocol.HTTPGetCache(url)
	if !ok || resp.StatusCode != http.StatusOK {
		return "", "", false
	}

	pkg, err := jsonparser.GetString([]byte(body), "package")
	if err != nil {
		return "", "", false
	}

	version, err := jsonparser.GetString([]byte(body), "version")
	if err != nil {
		version, err = jsonparser.GetString([]byte(body), "main_version")
		if err != nil {
			output.PrintfDebug("%s has no version or main_version field: err=%v", versionURI, err)
		}
	}

	return pkg, version, true
}

// DoValidateTarget checks for Langflow mounted at the server root.
func DoValidateTarget(conf *config.Config) bool {
	return DoValidateTargetAt(conf, "")
}

// DoValidateTargetAt checks for Langflow mounted under basePath ("" or "/" for the root).
func DoValidateTargetAt(conf *config.Config, basePath string) bool {
	pkg, _, ok := versionResponse(conf, basePath)
	if !ok || pkg != "Langflow" {
		return false
	}

	resp, body, ok := protocol.HTTPGetCache(urlAt(conf, basePath, ""))
	if !ok || resp.StatusCode != http.StatusOK {
		return false
	}

	title, ok := search.XPath(body, "//title")
	if ok && strings.Contains(title, "Langflow") && strings.Contains(body, "crossorigin src") {
		return true
	}

	return false
}

// normalizeRe splits a PEP 440-ish version into major, minor, patch and an optional pre/post suffix.
var normalizeRe = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?[._-]?([A-Za-z][0-9A-Za-z.]*)?$`)

// version is a parsed Langflow version. suffix is lower-cased and empty when the
// version is a plain release.
type version struct {
	major  int
	minor  int
	patch  int
	suffix string
}

// base renders just the release triple, which is all CheckSemVer can parse.
func (v version) base() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

// isPost reports whether the suffix is a post-release, which follows its release,
// as opposed to a pre-release, which precedes it.
func (v version) isPost() bool {
	return strings.HasPrefix(v.suffix, "post")
}

// normalizeVersion parses a version string; a missing patch component is rejected.
func normalizeVersion(v string) (version, bool) {
	m := normalizeRe.FindStringSubmatch(strings.TrimSpace(v))
	if len(m) < 5 || m[3] == "" {
		return version{}, false
	}

	major, err := strconv.Atoi(m[1])
	if err != nil {
		return version{}, false
	}

	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return version{}, false
	}

	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return version{}, false
	}

	return version{major, minor, patch, strings.ToLower(m[4])}, true
}

// matchConstraint reports whether target satisfies a single vulnerableVersions entry.
func matchConstraint(target version, constraint string) bool {
	if strings.ContainsAny(constraint, "<>=,") {
		return search.CheckSemVer(target.base(), constraint)
	}

	c, ok := normalizeVersion(constraint)
	if !ok {
		return false
	}

	if c.suffix != "" {
		return target.base() == c.base() && target.suffix == c.suffix
	}

	if target.suffix != "" && !target.isPost() {
		return false
	}

	return search.CheckSemVer(target.base(), c.base())
}

// DoCheckVersion reports whether the Langflow version at the server root matches
// any vulnerableVersions entry.
func DoCheckVersion(conf *config.Config, vulnerableVersions []string) exploit.VersionCheckType {
	return DoCheckVersionAt(conf, "", vulnerableVersions)
}

// DoCheckVersionAt reports whether the Langflow version under basePath ("" or "/" for
// the root) matches any vulnerableVersions entry.
func DoCheckVersionAt(conf *config.Config, basePath string, vulnerableVersions []string) exploit.VersionCheckType {
	_, raw, ok := versionResponse(conf, basePath)
	if !ok || raw == "" {
		return exploit.Unknown
	}

	exploit.StoreVersion(conf, raw)

	target, ok := normalizeVersion(raw)
	if !ok {
		return exploit.Unknown
	}

	for _, constraint := range vulnerableVersions {
		if matchConstraint(target, constraint) {
			return exploit.Vulnerable
		}
	}

	return exploit.NotVulnerable
}
