// Package config loads .mobilegate.yml — MobileGate's own policy config
// file (spec: "Config file (.mobilegate.yml)").
//
// This is a deliberately minimal slice of that file's eventual schema:
// only policy.first_party_domains, the one field MG-002's
// network_security_config signal structurally depends on ("First-party
// domains come from the config file's allowlist, not from inferred
// runtime behavior" — spec). policy.mode, new_findings_only, ignore_rules
// (with mandatory justification), and score threshold overrides are ALL
// deliberately not implemented here — those belong to baseline mode
// (CLAUDE.md build order step 5) and are out of scope until then. Adding
// this field now, rather than a bespoke one-off flag, is so the eventual
// full schema doesn't have to replace a throwaway mechanism later.
package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// Config is the (currently minimal) parsed contents of .mobilegate.yml.
type Config struct {
	Policy Policy `yaml:"policy"`
}

// Policy holds the policy.* keys this build-order step reads.
type Policy struct {
	// FirstPartyDomains is the allowlist MG-002 checks a
	// network_security_config <domain-config>'s <domain> entries
	// against. Exact match or subdomain match (per that domain's own
	// includeSubdomains) — see internal/engine's transport scanner.
	FirstPartyDomains []string `yaml:"first_party_domains"`
}

// LoadFile reads and parses path. A missing file is not an error — it
// returns an empty Config (no first-party domains), which is the correct
// fail-closed behavior: with nothing configured, MG-002's
// network_security_config domain-config signal simply has nothing to
// match against and never fires, rather than guessing.
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
	return &c, nil
}
