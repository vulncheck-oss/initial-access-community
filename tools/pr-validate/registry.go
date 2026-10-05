package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

const maxBody = 4 << 20

// ErrTransient marks a lookup failure that may succeed on retry -- a network
// problem, a 5xx, or rate limiting -- as opposed to a deterministic answer such
// as a 404 (a missing or mistagged image), which should fail the lint. Callers
// test for it with errors.Is to decide whether to fail open.
var ErrTransient = errors.New("transient registry error")

// PlatformChecker looks up which platforms an image is published for,
// using the OCI distribution API directly.
type PlatformChecker struct {
	Client   *http.Client
	OS, Arch string
	// Optional credentials, sent only to the token endpoint (or as Basic
	// auth to registries that ask for it). APIKey is the secret: with a
	// Username it is the password half of Basic auth (e.g. a Docker Hub PAT);
	// without one it is sent as a Bearer identity token.
	Username, APIKey string
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type manifestDoc struct {
	MediaType     string `json:"mediaType"`
	SchemaVersion int    `json:"schemaVersion"`
	Manifests     []struct {
		Platform *platform `json:"platform"`
	} `json:"manifests"`
	Config *struct {
		Digest string `json:"digest"`
	} `json:"config"`
}

// Platforms returns the "os/arch" pairs ref is published for. Attestation
// entries (unknown/unknown) are omitted.
func (c *PlatformChecker) Platforms(ctx context.Context, ref Reference) ([]string, error) {
	s := &session{c: c, repo: ref.Repository, base: "https://" + ref.APIHost() + "/v2/" + ref.Repository}

	var m manifestDoc
	if err := s.getJSON(ctx, "/manifests/"+ref.ManifestRef(), manifestAccept, &m); err != nil {
		return nil, err
	}

	switch {
	case m.Manifests != nil: // OCI index or Docker manifest list
		var out []string
		for _, d := range m.Manifests {
			if d.Platform != nil && d.Platform.OS != "unknown" {
				out = append(out, d.Platform.OS+"/"+d.Platform.Architecture)
			}
		}
		return out, nil
	case m.Config != nil && m.Config.Digest != "": // single-arch: platform is in the config blob
		var p platform
		if err := s.getJSON(ctx, "/blobs/"+m.Config.Digest, "*/*", &p); err != nil {
			return nil, fmt.Errorf("config blob: %w", err)
		}
		return []string{p.OS + "/" + p.Architecture}, nil
	default:
		return nil, fmt.Errorf("unsupported manifest (mediaType %q, schemaVersion %d)", m.MediaType, m.SchemaVersion)
	}
}

type session struct {
	c    *PlatformChecker
	repo string
	base string
	auth string // Authorization header value once obtained
}

func (s *session) do(ctx context.Context, target, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if s.auth != "" {
		// net/http drops this on redirects to a different domain (e.g. the
		// blob CDN), so the token never leaks off the registry.
		req.Header.Set("Authorization", s.auth)
	}
	return s.c.Client.Do(req)
}

func (s *session) getJSON(ctx context.Context, path, accept string, v any) error {
	target := s.base + path
	resp, err := s.do(ctx, target, accept)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransient, err)
	}
	if resp.StatusCode == http.StatusUnauthorized && s.auth == "" {
		challenge := resp.Header.Get("WWW-Authenticate")
		drain(resp)
		if err := s.authenticate(ctx, challenge); err != nil {
			return err
		}
		if resp, err = s.do(ctx, target, accept); err != nil {
			return fmt.Errorf("%w: %v", ErrTransient, err)
		}
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("access denied (%s): private repository or bad credentials", resp.Status)
	case http.StatusNotFound:
		return errors.New("not found: repository or tag does not exist (or is private)")
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: rate limited by registry; set registry credentials", ErrTransient)
	default:
		if resp.StatusCode >= 500 {
			return fmt.Errorf("%w: registry error %s", ErrTransient, resp.Status)
		}
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (s *session) authenticate(ctx context.Context, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	switch strings.ToLower(scheme) {
	case "bearer":
	case "basic":
		if s.c.APIKey == "" {
			return errors.New("registry requires basic auth; set registry credentials")
		}
		cred := base64.StdEncoding.EncodeToString([]byte(s.c.Username + ":" + s.c.APIKey))
		s.auth = "Basic " + cred
		return nil
	default:
		return fmt.Errorf("unsupported auth challenge %q", challenge)
	}

	fields := make(map[string]string)
	for _, m := range challengeParam.FindAllStringSubmatch(params, -1) {
		fields[m[1]] = m[2]
	}
	realm := fields["realm"]
	if realm == "" {
		return fmt.Errorf("bearer challenge without realm: %q", challenge)
	}
	delete(fields, "realm")
	if fields["scope"] == "" {
		fields["scope"] = "repository:" + s.repo + ":pull"
	}

	u, err := url.Parse(realm)
	if err != nil {
		return fmt.Errorf("bad token realm %q: %w", realm, err)
	}
	q := u.Query()
	for k, v := range fields {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	switch {
	case s.c.Username != "":
		// Username + key: Basic auth (e.g. a Docker Hub PAT).
		req.SetBasicAuth(s.c.Username, s.c.APIKey)
	case s.c.APIKey != "":
		// Key only: present it as a Bearer identity token.
		req.Header.Set("Authorization", "Bearer "+s.c.APIKey)
	}
	resp, err := s.c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("token request: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request: unexpected status %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&tok); err != nil {
		return fmt.Errorf("token response: %w", err)
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return errors.New("token response contained no token")
	}
	s.auth = "Bearer " + t
	return nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}
