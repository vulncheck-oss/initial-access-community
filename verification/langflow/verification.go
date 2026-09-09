package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/search"
)

const versionURI = "/api/v1/version"

// versionResponse fetches /api/v1/version and returns (package, version, ok).
// Older releases (< 1.1.0) only carry "version"; newer ones also have "main_version".
func versionResponse(conf *config.Config) (string, string, bool) {
	url := conf.GenerateURL(versionURI)
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

func DoValidateTarget(conf *config.Config) bool {
	pkg, _, ok := versionResponse(conf)
	if !ok || pkg != "Langflow" {
		return false
	}

	resp, body, ok := protocol.HTTPGetCache(conf.GenerateURL("/"))
	if !ok || resp.StatusCode != http.StatusOK {
		return false
	}

	title, ok := search.XPath(body, "//title")
	if ok && strings.Contains(title, "Langflow") && strings.Contains(body, "crossorigin src") {
		return true
	}

	return false
}

// normalizeRe splits a PEP 440-ish version into major, minor, patch and an
// optional pre/post-release suffix. Langflow ships all of "1.10.1rc3",
// "1.11.0.dev20", "0.5.0a1" and "1.0.19.post1", so the separator before the
// suffix is optional and the suffix itself must start with a letter.
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

// normalizeVersion parses a version string. A missing patch component is
// rejected rather than defaulted: Langflow reports a truncated "1.8." in
// main_version for pre-release builds, and reading that as 1.8.0 would claim a
// precision the string does not carry -- the real version is some 1.8.0 release
// candidate, which may sit on either side of a fix.
func normalizeVersion(v string) (version, bool) {
	m := normalizeRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil || m[3] == "" {
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

// matchConstraint reports whether target satisfies a single vulnerableVersions
// entry. Suffix handling is deliberately asymmetric:
//
//   - A range (">=1.6.0,<=1.6.9") compares on the release base, so a pre-release
//     built inside a vulnerable range is still flagged.
//   - An exact entry carrying a suffix ("1.8.0rc2") must match that suffix
//     exactly. CheckSemVer cannot separate 1.8.0rc2 from 1.8.0, and for some
//     issues the release candidates are vulnerable while the release is not.
//   - An exact entry without a suffix ("1.8.0") means the release itself, so a
//     target pre-release is excluded -- but a post-release is that release plus
//     packaging fixes, so it still matches.
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

func DoCheckVersion(conf *config.Config, vulnerableVersions []string) exploit.VersionCheckType {
	_, raw, ok := versionResponse(conf)
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
