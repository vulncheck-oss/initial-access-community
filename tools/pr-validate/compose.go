package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Rule identifiers.
const (
	RuleYAMLSyntax    = "yaml-syntax"
	RuleYAMLStructure = "yaml-structure"
	RuleDuplicateKey  = "duplicate-key"
	RuleImageMissing  = "image-missing"
	RuleImageRef      = "image-ref"
	RuleImageOrg      = "image-org"
	RuleImagePlatform = "image-platform"
	RuleRestart       = "restart-policy"
)

const requiredRestart = "unless-stopped"

type Finding struct {
	File     string
	Line     int
	Column   int
	Severity Severity
	Rule     string
	Service  string
	Message  string
}

func (f Finding) String() string {
	svc := ""
	if f.Service != "" {
		svc = " service " + strconv.Quote(f.Service) + ":"
	}
	return fmt.Sprintf("%s:%d:%d: %s [%s]%s %s", f.File, f.Line, f.Column, f.Severity, f.Rule, svc, f.Message)
}

type Config struct {
	Org          string          // required namespace, e.g. "vulncheck"
	Registry     string          // required canonical registry, e.g. "docker.io"
	AllowLibrary bool            // permit docker.io/library/* official images (postgres, nginx, ...)
	AllowRepos   map[string]bool // permit specific "<registry>/<repository>" base/sidecar images
}

// allowsImage reports whether r satisfies the org policy: it is under the
// required registry/org, or an explicitly allowed official (library/) or
// base/sidecar image.
func (c Config) allowsImage(r Reference) bool {
	if r.Registry == c.Registry && r.Namespace() == c.Org {
		return true
	}
	if c.AllowLibrary && r.Registry == "docker.io" && r.Namespace() == "library" {
		return true
	}
	return c.AllowRepos[r.Registry+"/"+r.Repository]
}

// ImageUse is an image that passed the static rules and still needs a
// registry lookup for the platform rule.
type ImageUse struct {
	Ref     Reference
	File    string
	Line    int
	Column  int
	Service string
}

type serviceSpec struct {
	Image   string    `yaml:"image"`
	Restart string    `yaml:"restart"`
	Build   yaml.Node `yaml:"build"`
	Ports   yaml.Node `yaml:"ports"`
}

// exposesPorts reports whether the service publishes or exposes any port.
func (s serviceSpec) exposesPorts() bool {
	nonEmpty := func(n yaml.Node) bool {
		return n.Kind == yaml.SequenceNode && len(n.Content) > 0
	}
	return nonEmpty(s.Ports)
}

var yamlErrLine = regexp.MustCompile(`line (\d+)`)

// lintDockerCompose runs every rule that doesn't need the network.
func lintDockerCompose(file string, data []byte, cfg Config) ([]Finding, []ImageUse) {
	var findings []Finding
	var uses []ImageUse

	add := func(n *yaml.Node, sev Severity, rule, svc, format string, args ...any) {
		f := Finding{
			File: file, Line: 1, Column: 1, Severity: sev, Rule: rule, Service: svc,
			Message: fmt.Sprintf(format, args...),
		}
		if n != nil && n.Line > 0 {
			f.Line, f.Column = n.Line, n.Column
		}
		findings = append(findings, f)
	}
	syntaxErr := func(err error) {
		f := Finding{
			File: file, Line: 1, Column: 1, Severity: SevError, Rule: RuleYAMLSyntax,
			Message: strings.TrimPrefix(err.Error(), "yaml: "),
		}
		if m := yamlErrLine.FindStringSubmatch(err.Error()); m != nil {
			f.Line, _ = strconv.Atoi(m[1])
		}
		findings = append(findings, f)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			add(nil, SevError, RuleYAMLStructure, "", "file is empty")
		} else {
			syntaxErr(err)
		}
		return findings, nil
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		add(firstContent(&extra), SevError, RuleYAMLStructure, "", "multiple YAML documents; a compose file must contain exactly one")
	case !errors.Is(err, io.EOF):
		syntaxErr(err)
		return findings, nil
	}

	if len(doc.Content) == 0 {
		add(nil, SevError, RuleYAMLStructure, "", "file is empty")
		return findings, nil
	}
	root := resolve(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		add(root, SevError, RuleYAMLStructure, "", "top level must be a mapping")
		return findings, nil
	}

	checkDuplicates(&doc, func(dup, first *yaml.Node) {
		add(dup, SevError, RuleDuplicateKey, "", "duplicate key %q (first defined at line %d)", dup.Value, first.Line)
	})
	services := lookup(root, "services")
	if services == nil {
		add(root, SevError, RuleYAMLStructure, "", "no top-level \"services\" key")
		return findings, uses
	}
	if services.Kind != yaml.MappingNode {
		add(services, SevError, RuleYAMLStructure, "", "\"services\" must be a mapping of service name to definition")
		return findings, uses
	}

	for i := 0; i+1 < len(services.Content); i += 2 {
		keyN, valN := services.Content[i], resolve(services.Content[i+1])
		name := keyN.Value

		if valN.Kind != yaml.MappingNode {
			add(keyN, SevError, RuleYAMLStructure, name, "service definition must be a mapping")
			continue
		}
		var spec serviceSpec
		// Duplicates were already reported; decode a de-duplicated copy
		// (last value wins) so the remaining rules still run.
		if err := dedupKeys(valN).Decode(&spec); err != nil {
			msgs := []string{err.Error()}
			var te *yaml.TypeError
			if errors.As(err, &te) {
				msgs = te.Errors
			}
			for _, msg := range msgs {
				f := Finding{
					File: file, Line: valN.Line, Column: valN.Column, Severity: SevError,
					Rule: RuleYAMLStructure, Service: name, Message: strings.TrimPrefix(msg, "yaml: "),
				}
				if m := yamlErrLine.FindStringSubmatch(msg); m != nil {
					f.Line, _ = strconv.Atoi(m[1])
					f.Column = 1
					f.Message = strings.TrimPrefix(f.Message, m[0]+": ")
				}
				findings = append(findings, f)
			}
			continue
		}

		// Rule: restart policy, for services with an exposed port. Values may
		// come from merge keys (<<: *defaults), so decode for the value and fall
		// back to the service key for position.
		if spec.exposesPorts() {
			restartAt := keyN
			if n := lookup(valN, "restart"); n != nil {
				restartAt = n
			}
			switch spec.Restart {
			case requiredRestart:
			case "":
				add(keyN, SevError, RuleRestart, name, "missing \"restart: %s\"", requiredRestart)
			default:
				add(restartAt, SevError, RuleRestart, name, "restart is %q; must be %q", spec.Restart, requiredRestart)
			}
		}

		// Rules: image present, parseable, and in the right org.
		imageAt := keyN
		if n := lookup(valN, "image"); n != nil {
			imageAt = n
		}
		if spec.Image == "" {
			if spec.Build.Kind != 0 {
				add(keyN, SevWarning, RuleImageMissing, name, "build-only service; must use a published %s image", cfg.Org)
			} else {
				add(keyN, SevError, RuleImageMissing, name, "no image specified")
			}
			continue
		}
		if strings.Contains(spec.Image, "$") {
			add(imageAt, SevWarning, RuleImageRef, name, "image %q uses variable interpolation; org and platform cannot be verified", spec.Image)
			continue
		}
		ref, err := ParseReference(spec.Image)
		if err != nil {
			add(imageAt, SevError, RuleImageRef, name, "image %q: %v", spec.Image, err)
			continue
		}
		if !cfg.allowsImage(ref) {
			add(imageAt, SevError, RuleImageOrg, name, "image %q resolves to %s, not under %s/%s",
				spec.Image, ref, cfg.Registry, cfg.Org)
			continue
		}
		uses = append(uses, ImageUse{Ref: ref, File: file, Line: imageAt.Line, Column: imageAt.Column, Service: name})
	}
	return findings, uses
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func firstContent(n *yaml.Node) *yaml.Node {
	if len(n.Content) > 0 {
		return n.Content[0]
	}
	return n
}

// lookup finds a key written directly in mapping m (not via merge keys).
func lookup(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return resolve(m.Content[i+1])
		}
	}
	return nil
}

// dedupKeys returns a shallow copy of mapping m keeping only the last
// occurrence of each key.
func dedupKeys(m *yaml.Node) *yaml.Node {
	last := make(map[string]int)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && k.Value != "<<" {
			last[k.Value] = i
		}
	}
	out := *m
	out.Content = nil
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if j, ok := last[k.Value]; ok && j != i && k.Kind == yaml.ScalarNode {
			continue
		}
		out.Content = append(out.Content, k, m.Content[i+1])
	}
	return &out
}

// checkDuplicates walks the tree reporting repeated mapping keys. Aliases are
// not followed, so each anchored block is checked exactly once.
func checkDuplicates(n *yaml.Node, report func(dup, first *yaml.Node)) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			checkDuplicates(c, report)
		}
	case yaml.MappingNode:
		seen := make(map[string]*yaml.Node)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.ScalarNode && k.Value != "<<" {
				if first, ok := seen[k.Value]; ok {
					report(k, first)
				} else {
					seen[k.Value] = k
				}
			}
			checkDuplicates(n.Content[i+1], report)
		}
	}
}
