package core

// GateDecision is MobileGate's primary output — spec: "Gate decision is
// the primary output... designed to fail a CI pipeline and post a PR
// status, not to be read start-to-finish by a human." Lowercase string
// values match the JSON output contract's "gate_decision" field
// verbatim (spec's own example: "gate_decision": "blocked").
type GateDecision string

const (
	GatePass    GateDecision = "pass"
	GateBlocked GateDecision = "blocked"
)

// Decide computes the release gate decision from a set of findings:
// BLOCKED if any finding is blocking-tier, unconditionally — spec:
// "Hard rule: if any blocking rule fires (in the active policy mode),
// gate_decision is BLOCKED regardless of score."
//
// Strict-mode semantics only. Baseline mode's real behavior — block
// only on NEW blocking findings, passing pre-existing debt found via a
// stored-baseline diff — is a separate mechanism CLAUDE.md's build
// order defers to its own step (baseline mode, after this one). Until
// that exists, every blocking finding here is treated the way strict
// mode always treats it: policy_mode is reported as "strict" by the
// caller (cmd/mobilegate) regardless of what .mobilegate.yml might one
// day say, and this function does not take a mode parameter at all —
// there is only one mode it knows how to decide.
func Decide(findings []Finding) GateDecision {
	for _, f := range findings {
		if f.Blocking {
			return GateBlocked
		}
	}
	return GatePass
}
