package engine

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// HygieneRuleDef is MG-010's rule definition — a structural manifest
// check, same shape as TransportRuleDef/StorageRuleDef: no
// patterns/exclusions/entropy. MG-010 is not in the original spec's
// MG-001–MG-009 catalog; it was split out of MG-003 deliberately (see
// rules/MG-010-debug-build-artifact.yaml's header) because debuggable/
// testOnly are a build-artifact-hygiene concern, not a storage-exposure
// one — different threat model, different remediation owner.
type HygieneRuleDef struct {
	RuleMeta `yaml:",inline"`
}

// LoadHygieneRule parses a structural-rule definition from YAML bytes.
func LoadHygieneRule(data []byte) (*HygieneRuleDef, error) {
	var r HygieneRuleDef
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: parse rule: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing id")
	}
	return &r, nil
}

// MG-010 signal subtypes — unlike MG-003, both are uniformly blocking
// with no warning-tier variant, so unlike StorageScanner, HygieneScanner
// uses the rule's own Severity/Blocking directly rather than taking them
// as per-call parameters.
const (
	SignalDebuggable = "debuggable-true"
	SignalTestOnly   = "test-only-true"
)

// HygieneScanner evaluates a loaded MG-010 rule against manifest data.
type HygieneScanner struct {
	rule *HygieneRuleDef
}

// NewHygieneScanner builds a scanner for rule.
func NewHygieneScanner(rule *HygieneRuleDef) *HygieneScanner {
	return &HygieneScanner{rule: rule}
}

// CheckManifest evaluates android:debuggable and android:testOnly.
// Each is reported independently — an app can have either, both, or
// neither, and they're distinct findings with distinct excerpts even
// when both fire on the same release candidate.
func (s *HygieneScanner) CheckManifest(m *manifest.Manifest) []Finding {
	var out []Finding
	if m.Debuggable == manifest.True {
		out = append(out, s.finding(SignalDebuggable,
			"AndroidManifest.xml", "application",
			`android:debuggable="true"`,
			"explicit android:debuggable=\"true\" on <application> — a debuggable release build allows attaching a debugger, arbitrary code injection via JDWP, and (on API < 31) bypasses adb backup's data-extraction restriction; there is no legitimate reason for this to be set on a release candidate"))
	}
	if m.TestOnly == manifest.True {
		out = append(out, s.finding(SignalTestOnly,
			"AndroidManifest.xml", "application",
			`android:testOnly="true"`,
			"explicit android:testOnly=\"true\" on <application> — marks the app as a test-only build; the platform package installer refuses to install it via normal channels (install -t/dev-tooling required), meaning this artifact was never meant to reach a release track"))
	}
	return out
}

func (s *HygieneScanner) finding(signal, source, location, excerpt, detail string) Finding {
	return Finding{
		RuleID:       s.rule.ID,
		RuleName:     s.rule.Name,
		PatternID:    signal,
		Title:        fmt.Sprintf("Release build artifact hygiene failure (%s)", signal),
		Severity:     s.rule.Severity,
		Confidence:   s.rule.Confidence,
		MASVS:        s.rule.MASVS,
		CWE:          s.rule.CWE,
		Blocking:     s.rule.Blocking,
		Source:       source,
		Location:     location,
		Excerpt:      excerpt,
		SignalDetail: detail,
		WhyItBlocks:  detail,
		Remediation:  strings.TrimSpace(s.rule.Remediation),
		FindingHash:  core.ComputeFindingHash(s.rule.ID, source, signal, excerpt),
	}
}
