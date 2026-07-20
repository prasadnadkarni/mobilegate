// This file is MG-002's acceptance-gate suite. Unlike MG-001's
// mg001_fixtures_test.go, it does not build synthetic APKs from raw
// bytes: MG-002 is a structural check over already-parsed
// manifest.Manifest / []nsc.Config values, not a pattern match over raw
// string pools, and the PARSING side (manifest field resolution,
// network_security_config CDATA extraction) is already independently
// verified — oracle-tested against real APKs (tools/oracle/
// manifest_oracle_test.go, nsc_oracle_test.go) and unit-tested
// (pkg/parser/manifest, pkg/parser/nsc's own tests). Building a
// namespaced binary-XML manifest writer here to re-prove that parsing
// works would duplicate that coverage for little additional confidence.
// What's actually new and untested is TransportScanner's decision logic
// (internal/engine/transport.go), so these fixtures exercise that
// directly against constructed inputs — the same relationship
// secrets_test.go (direct engine unit tests) has to
// mg001_fixtures_test.go (full-pipeline fixtures) for MG-001. The CLI
// wiring step separately runs the real end-to-end pipeline (including
// real binary XML) against the real corpus, Tusky's real domain-config
// included, which is the full-pipeline check for this rule.
package engine_test

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/nsc"
)

func mg002TestRule(t *testing.T) *engine.TransportRuleDef {
	t.Helper()
	rule, err := engine.LoadTransportRule([]byte(`
id: MG-002
name: Cleartext / accept-all transport
severity: critical
confidence: high
platform: android
blocking: true
masvs: MASVS-NETWORK-1
cwe: CWE-319
`))
	if err != nil {
		t.Fatalf("LoadTransportRule: %v", err)
	}
	return rule
}

func sdk(n int) *int { return &n }

// --- positive fixtures: one per signal subtype ---

func TestMG002_PositiveFixtures_Manifest(t *testing.T) {
	cases := []struct {
		name       string
		m          *manifest.Manifest
		wantSignal string
	}{
		{
			name:       "explicit_cleartext_true",
			m:          &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: sdk(34)},
			wantSignal: engine.SignalManifestExplicit,
		},
		{
			name:       "implicit_cleartext_low_target_sdk",
			m:          &manifest.Manifest{UsesCleartextTraffic: manifest.Unset, TargetSdkVersion: sdk(26)},
			wantSignal: engine.SignalManifestImplicitLowSDK,
		},
		{
			name:       "implicit_cleartext_at_exact_boundary_27_still_low",
			m:          &manifest.Manifest{UsesCleartextTraffic: manifest.Unset, TargetSdkVersion: sdk(27)},
			wantSignal: engine.SignalManifestImplicitLowSDK,
		},
	}
	scanner := engine.NewTransportScanner(mg002TestRule(t), nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %+v", len(findings), findings)
			}
			if findings[0].PatternID != tc.wantSignal {
				t.Errorf("PatternID = %q, want %q", findings[0].PatternID, tc.wantSignal)
			}
			if !findings[0].Blocking {
				t.Errorf("finding should be blocking-tier: %+v", findings[0])
			}
			if findings[0].TargetSDK == nil || *findings[0].TargetSDK != *tc.m.TargetSdkVersion {
				t.Errorf("TargetSDK not recorded correctly: got %v, want %v", findings[0].TargetSDK, tc.m.TargetSdkVersion)
			}
		})
	}
}

func TestMG002_PositiveFixtures_NetworkSecurityConfig(t *testing.T) {
	cases := []struct {
		name              string
		configs           []nsc.Config
		firstPartyDomains []string
		wantSignal        string
	}{
		{
			name: "domain_config_exact_first_party_match",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.True,
				Domains: []nsc.Domain{{Name: "api.example.com", IncludeSubdomains: false}},
			}},
			firstPartyDomains: []string{"api.example.com"},
			wantSignal:        engine.SignalNSCDomainConfig,
		},
		{
			name: "domain_config_first_party_subdomain_match",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.True,
				Domains: []nsc.Domain{{Name: "example.com", IncludeSubdomains: true}},
			}},
			firstPartyDomains: []string{"api.example.com"},
			wantSignal:        engine.SignalNSCDomainConfig,
		},
		{
			name: "base_config_unconditional_no_first_party_list_needed",
			configs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.True,
			}},
			firstPartyDomains: nil,
			wantSignal:        engine.SignalNSCBaseConfig,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := engine.NewTransportScanner(mg002TestRule(t), tc.firstPartyDomains)
			findings := scanner.CheckNetworkSecurityConfig("res/nsc.xml", tc.configs, sdk(30))
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %+v", len(findings), findings)
			}
			if findings[0].PatternID != tc.wantSignal {
				t.Errorf("PatternID = %q, want %q", findings[0].PatternID, tc.wantSignal)
			}
			if !findings[0].Blocking {
				t.Errorf("finding should be blocking-tier: %+v", findings[0])
			}
			if findings[0].TargetSDK == nil || *findings[0].TargetSDK != 30 {
				t.Errorf("TargetSDK not recorded: got %v", findings[0].TargetSDK)
			}
		})
	}
}

// --- negative fixtures: the acceptance gate ---

func TestMG002_NegativeFixtures_Manifest(t *testing.T) {
	cases := []struct {
		name string
		m    *manifest.Manifest
	}{
		{"explicit_cleartext_false", &manifest.Manifest{UsesCleartextTraffic: manifest.False, TargetSdkVersion: sdk(26)}},
		{"unset_high_target_sdk", &manifest.Manifest{UsesCleartextTraffic: manifest.Unset, TargetSdkVersion: sdk(28)}},
		{"unset_high_target_sdk_well_above", &manifest.Manifest{UsesCleartextTraffic: manifest.Unset, TargetSdkVersion: sdk(34)}},
		{"unset_unknown_target_sdk_never_guessed", &manifest.Manifest{UsesCleartextTraffic: manifest.Unset, TargetSdkVersion: nil}},
	}
	scanner := engine.NewTransportScanner(mg002TestRule(t), nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

func TestMG002_NegativeFixtures_NetworkSecurityConfig(t *testing.T) {
	cases := []struct {
		name              string
		configs           []nsc.Config
		firstPartyDomains []string
	}{
		{
			// The explicit tricky case: cleartext IS permitted for this
			// domain-config, but the domain is third-party (an ad SDK,
			// say) — must never fire just because SOME domain-config
			// somewhere permits cleartext for SOMETHING.
			name: "domain_config_third_party_domain_only",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.True,
				Domains: []nsc.Domain{{Name: "ads.thirdpartysdk.example", IncludeSubdomains: true}},
			}},
			firstPartyDomains: []string{"example.com"},
		},
		{
			name: "domain_config_cleartext_explicitly_false",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.False,
				Domains: []nsc.Domain{{Name: "example.com", IncludeSubdomains: true}},
			}},
			firstPartyDomains: []string{"example.com"},
		},
		{
			// Precision-first: an omitted cleartextTrafficPermitted is
			// not treated as permitted just because it's not explicitly
			// false — only an explicit "true" fires.
			name: "domain_config_cleartext_unset",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.Unset,
				Domains: []nsc.Domain{{Name: "example.com", IncludeSubdomains: true}},
			}},
			firstPartyDomains: []string{"example.com"},
		},
		{
			name: "base_config_cleartext_false",
			configs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.False,
			}},
			firstPartyDomains: nil,
		},
		{
			name: "domain_config_permitted_but_no_first_party_domains_configured",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.True,
				Domains: []nsc.Domain{{Name: "example.com", IncludeSubdomains: true}},
			}},
			firstPartyDomains: nil, // fail-closed: nothing to match against, so nothing matches
		},
		{
			name: "more_specific_entry_does_not_broaden_to_parent_first_party_domain",
			configs: []nsc.Config{{
				Kind: nsc.KindDomainConfig, CleartextPermitted: manifest.True,
				Domains: []nsc.Domain{{Name: "cdn.example.com", IncludeSubdomains: true}},
			}},
			firstPartyDomains: []string{"example.com"}, // example.com is the PARENT of the entry, not covered by it
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := engine.NewTransportScanner(mg002TestRule(t), tc.firstPartyDomains)
			findings := scanner.CheckNetworkSecurityConfig("res/nsc.xml", tc.configs, sdk(30))
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}
