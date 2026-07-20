// This file is MG-010's acceptance-gate suite. Same relationship to
// HygieneScanner (internal/engine/hygiene.go) that mg002/mg003's fixture
// suites have to their scanners: manifest field resolution is already
// independently verified elsewhere, so these fixtures exercise
// CheckManifest's decision logic directly against constructed
// manifest.Manifest values.
package engine_test

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

func mg010TestRule(t *testing.T) *engine.HygieneRuleDef {
	t.Helper()
	rule, err := engine.LoadHygieneRule([]byte(`
id: MG-010
name: Debug/test build artifact shipped as release candidate
severity: critical
confidence: high
platform: android
blocking: true
masvs: MASVS-RESILIENCE-2
cwe: CWE-489
`))
	if err != nil {
		t.Fatalf("LoadHygieneRule: %v", err)
	}
	return rule
}

// --- positive fixtures: one per signal, plus the both-at-once case ---

func TestMG010_PositiveFixtures(t *testing.T) {
	cases := []struct {
		name        string
		m           *manifest.Manifest
		wantSignals []string
	}{
		{
			name:        "debuggable_true_only",
			m:           &manifest.Manifest{Debuggable: manifest.True, TestOnly: manifest.Unset},
			wantSignals: []string{engine.SignalDebuggable},
		},
		{
			name:        "test_only_true_only",
			m:           &manifest.Manifest{Debuggable: manifest.Unset, TestOnly: manifest.True},
			wantSignals: []string{engine.SignalTestOnly},
		},
		{
			name:        "both_debuggable_and_test_only_true_two_distinct_findings",
			m:           &manifest.Manifest{Debuggable: manifest.True, TestOnly: manifest.True},
			wantSignals: []string{engine.SignalDebuggable, engine.SignalTestOnly},
		},
	}
	scanner := engine.NewHygieneScanner(mg010TestRule(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != len(tc.wantSignals) {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), len(tc.wantSignals), findings)
			}
			for i, sig := range tc.wantSignals {
				if findings[i].PatternID != sig {
					t.Errorf("signal[%d] PatternID = %q, want %q", i, findings[i].PatternID, sig)
				}
				if !findings[i].Blocking {
					t.Errorf("signal[%d] should be blocking-tier: %+v", i, findings[i])
				}
				if findings[i].Severity != "critical" {
					t.Errorf("signal[%d] Severity = %q, want %q", i, findings[i].Severity, "critical")
				}
			}
		})
	}
}

// --- negative fixtures: the acceptance gate ---

func TestMG010_NegativeFixtures(t *testing.T) {
	cases := []struct {
		name string
		m    *manifest.Manifest
	}{
		{"both_unset", &manifest.Manifest{Debuggable: manifest.Unset, TestOnly: manifest.Unset}},
		{"both_explicit_false", &manifest.Manifest{Debuggable: manifest.False, TestOnly: manifest.False}},
		{"debuggable_false_test_only_unset", &manifest.Manifest{Debuggable: manifest.False, TestOnly: manifest.Unset}},
		{"debuggable_unset_test_only_false", &manifest.Manifest{Debuggable: manifest.Unset, TestOnly: manifest.False}},
	}
	scanner := engine.NewHygieneScanner(mg010TestRule(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}
