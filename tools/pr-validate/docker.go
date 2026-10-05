package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// composeFileNames lists the compose filenames accepted inside a target-<cve>
// directory, in priority order.
var composeFileNames = []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

// dockerComposeConfig is the docker-compose policy: images must be published
// under docker.io/vulncheck, or be an allowed official (library/) or
// base/sidecar image.
func dockerComposeConfig() Config {
	return Config{
		Org:          "vulncheck",
		Registry:     "docker.io",
		AllowLibrary: true, // docker.io/library/* official images (postgres, nginx, redis, ...)
		AllowRepos: map[string]bool{
			"docker.io/apache/superset":                          true,
			"docker.io/axllent/mailpit":                          true,
			"docker.io/confluentinc/cp-kafka":                    true,
			"docker.io/confluentinc/cp-zookeeper":                true,
			"docker.io/curlimages/curl":                          true,
			"docker.io/prom/statsd-exporter":                     true,
			"docker.io/rudderlabs/rudder-server":                 true,
			"docker.io/rudderstack/rudder-transformer":           true,
			"docker.io/springcloud/baseimage":                    true,
			"docker.io/springcloud/spring-cloud-dataflow-server": true,
			"docker.io/springcloud/spring-cloud-skipper-server":  true,
			"docker.io/wazuh/wazuh-certs-generator":              true,
			"docker.io/wazuh/wazuh-dashboard":                    true,
			"docker.io/wazuh/wazuh-indexer":                      true,
			"docker.io/wazuh/wazuh-manager":                      true,
		},
	}
}

// newPlatformChecker builds the linux/amd64 platform checker. Credentials, when
// available in the environment, avoid anonymous registry rate limits.
func newPlatformChecker() *PlatformChecker {
	return &PlatformChecker{
		Client:   &http.Client{Timeout: 30 * time.Second},
		OS:       "linux",
		Arch:     "amd64",
		Username: os.Getenv("COMPOSE_LINT_REGISTRY_USER"),
		APIKey:   os.Getenv("COMPOSE_LINT_REGISTRY_PAT"),
	}
}

// checkPlatforms looks up each distinct image once, concurrently, and reports
// every use of an image lacking the required platform. Lookup failures are
// errors: an unverifiable image fails the lint rather than passing silently.
func checkPlatforms(ctx context.Context, c *PlatformChecker, uses []ImageUse, jobs int) []Finding {
	type result struct {
		platforms []string
		err       error
	}
	refs := make(map[string]Reference)
	for _, u := range uses {
		refs[u.Ref.String()] = u.Ref
	}

	results := make(map[string]result, len(refs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(jobs, 1))
	for key, ref := range refs {
		wg.Add(1)
		go func(key string, ref Reference) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, err := c.Platforms(ctx, ref)
			mu.Lock()
			results[key] = result{p, err}
			mu.Unlock()
		}(key, ref)
	}
	wg.Wait()

	want := c.OS + "/" + c.Arch
	var findings []Finding
	for _, u := range uses {
		r := results[u.Ref.String()]
		f := Finding{
			File: u.File, Line: u.Line, Column: u.Column, Severity: SevError,
			Rule: RuleImagePlatform, Service: u.Service,
		}
		switch {
		case r.err != nil:
			// Fail open only on transient failures (network, 5xx, rate limit):
			// Docker Hub can go down or the CI runner can get rate limited, and
			// we don't want that to block progress. A deterministic failure --
			// a 404 for a mistyped tag or an image that was never pushed -- stays
			// an error (the default severity) so CI blocks it.
			f.Message = fmt.Sprintf("could not verify %s for %s: %v", want, u.Ref, r.err)
			if errors.Is(r.err, ErrTransient) {
				f.Severity = SevWarning
			}
		case !slices.Contains(r.platforms, want):
			found := "none"
			if len(r.platforms) > 0 {
				found = strings.Join(r.platforms, ", ")
			}
			f.Message = fmt.Sprintf("%s has no %s build (found: %s)", u.Ref, want, found)
		default:
			continue
		}
		findings = append(findings, f)
	}
	return findings
}

// lintDocker runs the docker-compose policy checks for an entry whenever a
// compose file is present under target-<cve>. It reuses the compose linter
// (compose.go) for the static rules -- every image must be published under
// docker.io/vulncheck and every service with an exposed port must set
// restart: unless-stopped -- and,
// unless -offline is set, the registry platform checker (registry.go) to require
// a linux/amd64 build. Findings follow the standard pattern: each is an ERROR
// counted as a failure, unless the entry is a chain, in which case it is
// downgraded to a WARN.
func lintDocker(dir, entryID string) int {
	composeFile := ""
	for _, name := range composeFileNames {
		candidate := filepath.Join(dir, entryID, dockerPrefix+entryID, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			composeFile = candidate
			break
		}
	}
	if composeFile == "" {
		return 0
	}

	data, err := os.ReadFile(composeFile)
	if err != nil {
		log.Printf("ERROR: %s - reading %s: %v", entryID, composeFile, err)
		return 1
	}

	failed := 0
	cfg := dockerComposeConfig()
	report := func(findings []Finding) {
		for _, fd := range findings {
			if fd.Severity == SevError {
				log.Printf("ERROR: %s", fd)
				failed++
			} else {
				log.Printf("WARN: %s", fd)
			}
		}
	}

	// Static rules: image org and restart policy.
	findings, uses := lintDockerCompose(composeFile, data, cfg)
	report(findings)

	// At least one image must be published under the vulncheck org.
	if len(uses) == 0 {
		msg := fmt.Sprintf("%s: no image published under %s/%s [%s]", composeFile, cfg.Registry, cfg.Org, RuleImageOrg)
		log.Printf("ERROR: %s", msg)
		failed++
	}

	// Registry rule: each vulncheck image must publish a linux/amd64 build.
	if !flagOffline && len(uses) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		report(checkPlatforms(ctx, newPlatformChecker(), uses, 8))
	}

	return failed
}
