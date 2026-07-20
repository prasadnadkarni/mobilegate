package core

// SuppressionRule is one policy-driven rule suppression — spec: "Rule
// suppression with mandatory justification." This package has no
// knowledge of YAML or .mobilegate.yml (internal/config owns that
// schema and its own mandatory-reason validation); it only knows how to
// match a rule against a finding, so cmd/mobilegate is what translates
// config.IgnoreRule into this type at the orchestration boundary.
type SuppressionRule struct {
	RuleID string
	Reason string
	Paths  []string // empty: suppresses RuleID everywhere; set: only findings whose Source is in this list
}

// SuppressedFinding pairs a suppressed Finding with the rule that
// suppressed it, so a caller can report WHY, not just THAT — spec:
// "Report suppressed findings in the output as suppressed-with-reason,
// never silently dropped."
type SuppressedFinding struct {
	Finding Finding
	Rule    SuppressionRule
}

// SplitBySuppression separates a finding set into what policy
// suppresses and everything else, unchanged. Unlike SplitByBaseline,
// this applies regardless of Blocking — a warning-tier finding a team
// has explicitly reviewed and suppressed should stop showing up too,
// not just stop blocking (it was never blocking in the first place).
func SplitBySuppression(findings []Finding, rules []SuppressionRule) (rest []Finding, suppressed []SuppressedFinding) {
	for _, f := range findings {
		if rule, ok := matchSuppression(f, rules); ok {
			suppressed = append(suppressed, SuppressedFinding{Finding: f, Rule: rule})
			continue
		}
		rest = append(rest, f)
	}
	return rest, suppressed
}

func matchSuppression(f Finding, rules []SuppressionRule) (SuppressionRule, bool) {
	for _, r := range rules {
		if r.RuleID != f.RuleID {
			continue
		}
		if len(r.Paths) == 0 {
			return r, true
		}
		for _, p := range r.Paths {
			if p == f.Source {
				return r, true
			}
		}
	}
	return SuppressionRule{}, false
}
