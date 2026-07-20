package core

import "testing"

func TestSplitBySuppression_MatchingRuleIDSuppressesEverywhere(t *testing.T) {
	rules := []SuppressionRule{{RuleID: "MG-007", Reason: "reviewed"}}
	findings := []Finding{
		{RuleID: "MG-007", Source: "AndroidManifest.xml", Blocking: false},
		{RuleID: "MG-007", Source: "res/other.xml", Blocking: false},
		{RuleID: "MG-001", Source: "assets/a.json", Blocking: true},
	}
	rest, suppressed := SplitBySuppression(findings, rules)
	if len(suppressed) != 2 {
		t.Fatalf("got %d suppressed, want 2: %+v", len(suppressed), suppressed)
	}
	if len(rest) != 1 || rest[0].RuleID != "MG-001" {
		t.Fatalf("got %+v, want only the MG-001 finding left", rest)
	}
	for _, s := range suppressed {
		if s.Rule.Reason != "reviewed" {
			t.Errorf("suppressed finding lost its reason: %+v", s)
		}
	}
}

func TestSplitBySuppression_PathScopedRuleOnlyMatchesListedPaths(t *testing.T) {
	rules := []SuppressionRule{{RuleID: "MG-007", Reason: "reviewed", Paths: []string{"AndroidManifest.xml"}}}
	findings := []Finding{
		{RuleID: "MG-007", Source: "AndroidManifest.xml"},
		{RuleID: "MG-007", Source: "res/other.xml"}, // not in Paths — must NOT be suppressed
	}
	rest, suppressed := SplitBySuppression(findings, rules)
	if len(suppressed) != 1 || suppressed[0].Finding.Source != "AndroidManifest.xml" {
		t.Fatalf("got %+v, want exactly the AndroidManifest.xml finding suppressed", suppressed)
	}
	if len(rest) != 1 || rest[0].Source != "res/other.xml" {
		t.Fatalf("got %+v, want the res/other.xml finding to remain", rest)
	}
}

func TestSplitBySuppression_NonMatchingRuleIDNeverSuppressed(t *testing.T) {
	rules := []SuppressionRule{{RuleID: "MG-007", Reason: "reviewed"}}
	findings := []Finding{{RuleID: "MG-001", Blocking: true}}
	rest, suppressed := SplitBySuppression(findings, rules)
	if len(suppressed) != 0 {
		t.Errorf("got %d suppressed, want 0: %+v", len(suppressed), suppressed)
	}
	if len(rest) != 1 {
		t.Errorf("got %+v, want the finding to remain", rest)
	}
}

func TestSplitBySuppression_NoRulesSuppressesNothing(t *testing.T) {
	findings := []Finding{{RuleID: "MG-001", Blocking: true}}
	rest, suppressed := SplitBySuppression(findings, nil)
	if len(suppressed) != 0 || len(rest) != 1 {
		t.Errorf("got rest=%+v suppressed=%+v, want everything to pass through", rest, suppressed)
	}
}

// A blocking-tier finding can be suppressed too — suppression isn't
// mode-dependent or tier-dependent, unlike baseline grandfathering.
func TestSplitBySuppression_BlockingFindingCanBeSuppressed(t *testing.T) {
	rules := []SuppressionRule{{RuleID: "MG-001", Reason: "known test fixture key, not production"}}
	findings := []Finding{{RuleID: "MG-001", Blocking: true, Source: "assets/fixture.json"}}
	rest, suppressed := SplitBySuppression(findings, rules)
	if len(rest) != 0 {
		t.Errorf("blocking finding must be removed from rest once suppressed: %+v", rest)
	}
	if len(suppressed) != 1 {
		t.Fatalf("got %d suppressed, want 1", len(suppressed))
	}
}
