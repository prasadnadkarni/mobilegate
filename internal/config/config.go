// Package config loads .mobilegate.yml — MobileGate's own policy config
// file (spec: "Config file (.mobilegate.yml)"). Policy belongs here, in
// a file a team reviews and commits, not scattered across whoever's CI
// invocation happens to pass which flags.
//
// Schema covered: policy.mode (strict/baseline), policy.baseline_file,
// policy.first_party_domains (MG-002's domain allowlist — the original,
// pre-baseline-mode field, now folded into the same loader rather than
// living on its own), policy.first_party_packages (MG-004's origin-
// heuristic override, same principle), policy.source_manifest_path
// (-sarif output's manifest-finding location mapping), and ignore_rules
// (ruleset suppression with a mandatory reason). policy.new_findings_only
// and a score threshold
// override are NOT implemented — not asked for, and new_findings_only
// in particular is redundant with what mode: baseline already does
// unconditionally; adding a second knob for the same behavior would be
// exactly the kind of not-in-scope config option CLAUDE.md's scope
// discipline warns against.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

// Mode values for Policy.Mode.
const (
	ModeStrict   = "strict"
	ModeBaseline = "baseline"
)

// Config is the parsed contents of .mobilegate.yml.
type Config struct {
	Policy      Policy       `yaml:"policy"`
	IgnoreRules []IgnoreRule `yaml:"ignore_rules"`
}

// Policy holds the policy.* keys.
type Policy struct {
	// Mode is ModeStrict or ModeBaseline. Empty (unset) means strict —
	// the safe default when a team hasn't adopted baseline mode yet. A
	// CLI -mode flag always overrides this (see cmd/mobilegate), so CI
	// can force strict regardless of what's committed here — policy
	// lives in the reviewed file, but an operator can still tighten it
	// for a specific run.
	Mode string `yaml:"mode"`

	// BaselineFile is where baseline mode looks for its baseline, when
	// Mode is ModeBaseline. Empty means the caller's own default path
	// (cmd/mobilegate's defaultBaselinePath) — this package doesn't
	// hardcode that path, to keep it a pure schema/validation layer
	// with no CLI-level knowledge.
	BaselineFile string `yaml:"baseline_file"`

	// FirstPartyDomains is the allowlist MG-002 checks a
	// network_security_config <domain-config>'s <domain> entries
	// against. Exact match or subdomain match (per that domain's own
	// includeSubdomains) — see internal/engine's transport scanner.
	FirstPartyDomains []string `yaml:"first_party_domains"`

	// FirstPartyPackages overrides MG-004's default 2-segment-org
	// origin heuristic (internal/engine.isLibraryOrigin) — exact or
	// sub-package match against a component's fully-qualified name.
	// Same override principle as FirstPartyDomains above: no inferred
	// heuristic can fully resolve a team's own package roots after a
	// fork, an acquisition, a rename, or a white-label build, so a
	// reviewed config entry always wins over the guess.
	FirstPartyPackages []string `yaml:"first_party_packages"`

	// SourceManifestPath is where -sarif output points a manifest-based
	// finding's artifactLocation.uri — the app's own, uncompiled
	// AndroidManifest.xml source file in this repo, NOT the merged,
	// compiled manifest MobileGate actually parses out of the APK (see
	// internal/sarif's package doc comment for why that distinction
	// matters: attribute values match, line numbers don't, and this
	// tool never fabricates a line it can't verify). Empty means the
	// caller's own default (cmd/mobilegate's defaultSourceManifestPath,
	// "app/src/main/AndroidManifest.xml" — the standard Gradle module
	// layout) — this package doesn't hardcode that default, same reason
	// BaselineFile doesn't.
	SourceManifestPath string `yaml:"source_manifest_path"`
}

// IgnoreRule is one policy-driven rule suppression — spec: "Rule
// suppression with mandatory justification... Suppression without a
// reason is a config validation error. This keeps the audit trail
// honest." Reason is required; validate() (called from LoadFile)
// rejects the whole config if any entry is missing one — not a warning,
// not a skip-just-that-entry, a load failure, so a broken suppression
// can't silently pass review along with everything else in the file.
type IgnoreRule struct {
	ID     string   `yaml:"id"`
	Reason string   `yaml:"reason"`
	Paths  []string `yaml:"paths"` // empty: suppresses ID everywhere; set: only findings whose Source is in this list
}

// LoadFile reads and parses path.
//
// A missing file is not an error — it returns an empty Config (strict
// mode, no suppressions, no first-party domains), the correct default
// when a team hasn't written one yet: with nothing configured, MG-002's
// domain-config signal has nothing to match against and never fires,
// and there is nothing to suppress or baseline against.
//
// A present-but-invalid file (malformed YAML, an unrecognized
// policy.mode value, or an ignore_rules entry missing its reason) IS an
// error — fail closed, same discipline as core.LoadBaseline: the caller
// must not silently proceed as if the file said nothing. Unlike a
// missing file (a legitimate default), an invalid one means the
// author's actual intent is unknown, so this package refuses to guess
// at it — see cmd/mobilegate for how the caller falls back (safe
// defaults, loud warning) rather than crashing outright.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	switch c.Policy.Mode {
	case "", ModeStrict, ModeBaseline:
	default:
		return fmt.Errorf("policy.mode must be %q or %q (or unset, defaulting to %q), got %q", ModeStrict, ModeBaseline, ModeStrict, c.Policy.Mode)
	}
	for i, r := range c.IgnoreRules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("ignore_rules[%d]: missing id", i)
		}
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("ignore_rules[%d] (id %q): missing reason — suppressing a rule without a documented reason is not allowed", i, r.ID)
		}
	}
	return nil
}
