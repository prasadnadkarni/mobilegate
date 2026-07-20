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
			findings := scanner.CheckManifest(tc.m, false) // no NSC referenced — precedence rule doesn't apply, see TestMG002_ManifestNSCPrecedence
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
			findings := scanner.CheckManifest(tc.m, false)
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

// --- precedence: NSC supersedes the manifest flag on API 24+ ---
//
// android:usesCleartextTraffic is not consulted by the platform at all
// once a network security config is present and honored (targetSdk 24+)
// — the NSC alone determines the effective policy. Getting this wrong in
// either direction is a real correctness bug, not a style nit: reporting
// both signals for one effective condition (found in MG-002 corpus
// batch 1 — 4 apps) is noise; missing the case the corpus didn't
// surface — manifest says true, NSC actually denies cleartext, so the
// app does NOT permit it — is a false positive on a correctly configured
// app.
func TestMG002_ManifestNSCPrecedence(t *testing.T) {
	cases := []struct {
		name        string
		m           *manifest.Manifest
		hasNSC      bool
		nscConfigs  []nsc.Config
		wantSignals []string // in the order CheckManifest then CheckNetworkSecurityConfig fire
	}{
		{
			// The case the corpus lacked: manifest opts in, but the NSC
			// that actually governs denies cleartext. Effective policy
			// is "cleartext not permitted" — must be clean.
			name:   "manifest_true_nsc_denies_must_be_clean",
			m:      &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: sdk(30), NetworkSecurityConfig: "res/nsc.xml"},
			hasNSC: true,
			nscConfigs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.False,
			}},
			wantSignals: nil,
		},
		{
			// The case explicitly asked for: manifest opts in AND the
			// NSC permits — must report ONE finding (the NSC's), not two.
			name:   "manifest_true_nsc_permits_one_finding_not_two",
			m:      &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: sdk(30), NetworkSecurityConfig: "res/nsc.xml"},
			hasNSC: true,
			nscConfigs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.True,
			}},
			wantSignals: []string{engine.SignalNSCBaseConfig},
		},
		{
			// Below API 24 the platform never reads the NSC file at all
			// — precedence does not apply, and neither does the NSC's
			// own content. Only the manifest flag governs.
			name:   "target_sdk_below_24_nsc_not_honored_manifest_governs",
			m:      &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: sdk(23), NetworkSecurityConfig: "res/nsc.xml"},
			hasNSC: true,
			nscConfigs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.True,
			}},
			wantSignals: []string{engine.SignalManifestExplicit},
		},
		{
			// Unknown targetSdkVersion: neither side can confirm the
			// other is authoritative, so neither is suppressed —
			// consistent with this package's "don't guess" rule
			// elsewhere (e.g. the implicit-low-target-sdk signal itself
			// never fires on an unknown target SDK either).
			name:   "unknown_target_sdk_neither_signal_suppressed",
			m:      &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: nil, NetworkSecurityConfig: "res/nsc.xml"},
			hasNSC: true,
			nscConfigs: []nsc.Config{{
				Kind: nsc.KindBaseConfig, CleartextPermitted: manifest.True,
			}},
			wantSignals: []string{engine.SignalManifestExplicit, engine.SignalNSCBaseConfig},
		},
		{
			// No NSC referenced at all: precedence question doesn't
			// arise, manifest flag governs normally (regression check
			// against the pre-precedence behavior).
			name:        "no_nsc_referenced_manifest_governs_normally",
			m:           &manifest.Manifest{UsesCleartextTraffic: manifest.True, TargetSdkVersion: sdk(30)},
			hasNSC:      false,
			nscConfigs:  nil,
			wantSignals: []string{engine.SignalManifestExplicit},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := engine.NewTransportScanner(mg002TestRule(t), nil)
			var got []string
			for _, f := range scanner.CheckManifest(tc.m, tc.hasNSC) {
				got = append(got, f.PatternID)
			}
			for _, f := range scanner.CheckNetworkSecurityConfig("res/nsc.xml", tc.nscConfigs, tc.m.TargetSdkVersion) {
				got = append(got, f.PatternID)
			}
			if len(got) != len(tc.wantSignals) {
				t.Fatalf("got signals %v, want %v", got, tc.wantSignals)
			}
			for i, sig := range tc.wantSignals {
				if got[i] != sig {
					t.Errorf("signal[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], sig, got, tc.wantSignals)
				}
			}
		})
	}
}
