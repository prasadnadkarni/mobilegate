package engine

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/nsc"
)

// TransportRuleDef is MG-002's rule definition — a structural check, not
// a pattern-matching one, so unlike RuleDef it carries no
// patterns/exclusions/entropy: those concepts don't apply here. The
// signals themselves are fixed Go logic below, not YAML-configurable, the
// same way MG-001's structural DEX-identifier exclusion is code, not
// data — see rules/MG-002-cleartext-transport.yaml's header comment.
type TransportRuleDef struct {
	RuleMeta `yaml:",inline"`
}

// LoadTransportRule parses a structural-rule definition from YAML bytes.
func LoadTransportRule(data []byte) (*TransportRuleDef, error) {
	var r TransportRuleDef
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: parse rule: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing id")
	}
	return &r, nil
}

// Transport signal subtypes, reported as distinct PatternID values so
// findings are never collapsed together: a deliberate <base-config>
// opt-in, a deliberate <domain-config> opt-in, and an implicit
// low-target-sdk platform default are three different situations with
// three different remediations, even though all three mean the same
// thing at runtime — cleartext is permitted.
const (
	SignalManifestExplicit       = "manifest-explicit-cleartext"
	SignalManifestImplicitLowSDK = "manifest-implicit-cleartext-low-target-sdk"
	SignalNSCDomainConfig        = "network-security-config-domain"
	SignalNSCBaseConfig          = "network-security-config-base"
)

// minCleartextDefaultSDK is the targetSdkVersion at and above which the
// Android platform's own cleartext default flips from permitted to
// denied (API 28 / Android 9 — see Android's Network Security
// Configuration docs). Below this, an app with no explicit
// android:usesCleartextTraffic gets cleartext permitted by the platform
// itself, with no explicit opt-in anywhere in the app's own config.
const minCleartextDefaultSDK = 28

// TransportScanner evaluates a loaded MG-002 rule against manifest and
// network_security_config data. It does not evaluate a custom
// TrustManager/HostnameVerifier accepting all certificates/hosts — see
// rules/MG-002-cleartext-transport.yaml for why that signal from the
// spec is out of scope for this parser.
type TransportScanner struct {
	rule              *TransportRuleDef
	firstPartyDomains []string
}

// NewTransportScanner builds a scanner for rule, checking
// network_security_config <domain-config> blocks against
// firstPartyDomains (from .mobilegate.yml's policy.first_party_domains —
// see internal/config). An empty list is valid: it just means the
// domain-config signal can never fire, since there is nothing to compare
// against and this package does not infer first-party status from
// anything else (e.g. the app's own package name) — spec: "First-party
// domains come from the config file's allowlist, not from inferred
// runtime behavior."
func NewTransportScanner(rule *TransportRuleDef, firstPartyDomains []string) *TransportScanner {
	return &TransportScanner{rule: rule, firstPartyDomains: firstPartyDomains}
}

// CheckManifest evaluates the two manifest-level signals: an explicit
// android:usesCleartextTraffic="true", or cleartext permitted implicitly
// because the attribute is absent and the app targets an SDK below the
// platform's own default cutoff. Fires at most one finding — the two
// signals are mutually exclusive by construction (Unset vs True).
func (s *TransportScanner) CheckManifest(m *manifest.Manifest) []Finding {
	switch m.UsesCleartextTraffic {
	case manifest.True:
		return []Finding{s.finding(SignalManifestExplicit,
			"AndroidManifest.xml", "application",
			`android:usesCleartextTraffic="true"`,
			"explicit android:usesCleartextTraffic=\"true\" on <application>",
			m.TargetSdkVersion)}
	case manifest.Unset:
		if m.TargetSdkVersion != nil && *m.TargetSdkVersion < minCleartextDefaultSDK {
			return []Finding{s.finding(SignalManifestImplicitLowSDK,
				"AndroidManifest.xml", "application",
				fmt.Sprintf("targetSdkVersion=%d (no explicit usesCleartextTraffic)", *m.TargetSdkVersion),
				fmt.Sprintf("no android:usesCleartextTraffic is set, and targetSdkVersion %d is below %d — the Android platform itself defaults to permitting cleartext below that line, with no explicit opt-in anywhere in the app", *m.TargetSdkVersion, minCleartextDefaultSDK),
				m.TargetSdkVersion)}
		}
	}
	return nil
}

// CheckNetworkSecurityConfig evaluates domain-config (first-party
// domains only) and base-config (unconditional) blocks. sourcePath is
// the resolved in-APK path (e.g. "res/8G.xml"), recorded as each
// Finding's Source.
func (s *TransportScanner) CheckNetworkSecurityConfig(sourcePath string, configs []nsc.Config, targetSDK *int) []Finding {
	var out []Finding
	for _, c := range configs {
		if c.CleartextPermitted != manifest.True {
			continue
		}
		switch c.Kind {
		case nsc.KindBaseConfig:
			out = append(out, s.finding(SignalNSCBaseConfig,
				sourcePath, string(nsc.KindBaseConfig),
				`cleartextTrafficPermitted="true"`,
				"<base-config cleartextTrafficPermitted=\"true\"> permits cleartext unconditionally, for every domain the app talks to that no more specific <domain-config> overrides — not domain-scoped, so no first-party check applies",
				targetSDK))

		case nsc.KindDomainConfig:
			for _, d := range c.Domains {
				fp, ok := firstPartyMatch(d, s.firstPartyDomains)
				if !ok {
					continue
				}
				out = append(out, s.finding(SignalNSCDomainConfig,
					sourcePath, fmt.Sprintf("domain-config[%s]", d.Name),
					fmt.Sprintf(`cleartextTrafficPermitted="true" domain=%q includeSubdomains=%v`, d.Name, d.IncludeSubdomains),
					fmt.Sprintf("<domain-config cleartextTrafficPermitted=\"true\"> permits cleartext for %q, matching configured first-party domain %q", d.Name, fp),
					targetSDK))
			}
		}
	}
	return out
}

func (s *TransportScanner) finding(signal, source, location, excerpt, detail string, targetSDK *int) Finding {
	return Finding{
		RuleID:       s.rule.ID,
		PatternID:    signal,
		Title:        fmt.Sprintf("Cleartext traffic permitted (%s)", signal),
		Severity:     s.rule.Severity,
		Confidence:   s.rule.Confidence,
		MASVS:        s.rule.MASVS,
		CWE:          s.rule.CWE,
		Blocking:     s.rule.Blocking,
		Source:       source,
		Location:     location,
		Excerpt:      excerpt,
		SignalDetail: detail,
		TargetSDK:    targetSDK,
	}
}

// firstPartyMatch reports whether d (a <domain-config>'s <domain> entry)
// applies to any configured first-party domain: an exact
// (case-insensitive) match, or — only when d itself permits it via
// includeSubdomains — a first-party domain that is a subdomain of d.
// Direction matters here: <domain includeSubdomains="true">example.com
// </domain> covers api.example.com, but <domain>api.example.com</domain>
// (no wildcard, or a different, more specific entry) does NOT cover the
// broader example.com. Returns the matched first-party domain for
// evidence.
func firstPartyMatch(d nsc.Domain, firstPartyDomains []string) (string, bool) {
	entry := strings.ToLower(d.Name)
	for _, fp := range firstPartyDomains {
		fpLower := strings.ToLower(fp)
		if fpLower == entry {
			return fp, true
		}
		if d.IncludeSubdomains && strings.HasSuffix(fpLower, "."+entry) {
			return fp, true
		}
	}
	return "", false
}
