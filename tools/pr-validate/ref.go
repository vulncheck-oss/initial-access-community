package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Reference is a parsed, normalized image reference.
type Reference struct {
	Registry   string // canonical host, e.g. "docker.io", "ghcr.io"
	Repository string // e.g. "vulncheck/api", "library/postgres"
	Tag        string
	Digest     string
}

var (
	pathComponent = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	repoRe        = regexp.MustCompile(`^` + pathComponent + `(?:/` + pathComponent + `)*$`)
	tagRe         = regexp.MustCompile(`^\w[\w.-]{0,127}$`)
	digestRe      = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]{32,}$`)
)

// ParseReference parses an image reference the way docker does, applying the
// docker.io and library/ defaults.
func ParseReference(s string) (Reference, error) {
	var r Reference
	rest := s

	if name, digest, ok := strings.Cut(rest, "@"); ok {
		if !digestRe.MatchString(digest) {
			return r, fmt.Errorf("invalid digest %q", digest)
		}
		rest, r.Digest = name, digest
	}

	first, remainder, hasSlash := strings.Cut(rest, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry, rest = normalizeRegistry(first), remainder
	} else {
		r.Registry = "docker.io"
	}

	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		r.Tag, rest = rest[i+1:], rest[:i]
		if !tagRe.MatchString(r.Tag) {
			return r, fmt.Errorf("invalid tag %q", r.Tag)
		}
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}

	if r.Registry == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	if !repoRe.MatchString(rest) {
		return r, fmt.Errorf("invalid repository name %q (lowercase letters, digits, and separators only)", rest)
	}
	r.Repository = rest
	return r, nil
}

func normalizeRegistry(host string) string {
	switch host {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return host
}

// Namespace is the first path component ("vulncheck" in "vulncheck/api"),
// or "" for single-component repositories on non-Docker-Hub registries.
func (r Reference) Namespace() string {
	ns, _, ok := strings.Cut(r.Repository, "/")
	if !ok {
		return ""
	}
	return ns
}

// APIHost is the host that actually serves the registry API.
func (r Reference) APIHost() string {
	if r.Registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.Registry
}

// ManifestRef is the tag or digest to request from /manifests/.
func (r Reference) ManifestRef() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

func (r Reference) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}
