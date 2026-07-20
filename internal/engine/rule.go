// Package engine evaluates MobileGate's rules — currently just MG-001 —
// against parser output. Rule parameters (patterns, exclusions) live as
// data in /rules/*.yaml, not hardcoded in Go; this package is the runner.
package engine

import (
	"fmt"

	"github.com/goccy/go-yaml"
)

// RuleMeta is the metadata common to every rule, regardless of what kind
// of detection drives it (pattern-matching for MG-001, structural checks
// for MG-002). Embedded (inline) into each rule-specific def type rather
// than duplicated.
type RuleMeta struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	Confidence  string `yaml:"confidence"`
	Platform    string `yaml:"platform"`
	Blocking    bool   `yaml:"blocking"`
	MASVS       string `yaml:"masvs"`
	CWE         string `yaml:"cwe"`
	Description string `yaml:"description"`
	Remediation string `yaml:"remediation"`
}

// RuleDef is a pattern-matching rule (MG-001) loaded from a
// /rules/*.yaml file.
type RuleDef struct {
	RuleMeta   `yaml:",inline"`
	Patterns   []PatternDef    `yaml:"patterns"`
	Entropy    EntropyConfig   `yaml:"entropy"`
	Exclusions ExclusionConfig `yaml:"exclusions"`
}

// PatternDef is one known-credential-format signal within a rule.
type PatternDef struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Provider   string `yaml:"provider"`
	Regex      string `yaml:"regex"`
	Structured bool   `yaml:"structured"`
	Confidence string `yaml:"confidence"`
}

// EntropyConfig is the length-gated entropy signal's parameters. See
// rules/MG-001-hardcoded-secret.yaml's header comment: implemented and
// unit-tested (ShannonEntropy below), but not yet wired to an active
// pattern, since generic unstructured-blob detection is warning-tier by
// spec and no such pattern exists yet.
type EntropyConfig struct {
	MinLength int `yaml:"min_length"`
}

// ExclusionConfig is signal 3: what never counts as a finding even if a
// pattern matches.
type ExclusionConfig struct {
	PathExtensions []string `yaml:"path_extensions"`
	ValuePatterns  []string `yaml:"value_patterns"`
}

// LoadRule parses a rule definition from YAML bytes.
func LoadRule(data []byte) (*RuleDef, error) {
	var r RuleDef
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: parse rule: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing id")
	}
	if len(r.Patterns) == 0 {
		return nil, fmt.Errorf("engine: rule %s has no patterns", r.ID)
	}
	return &r, nil
}
