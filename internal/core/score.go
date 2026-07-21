package core

// Score weights and bounds. Exact point values are this project's own
// choice — the spec requires the score be "deterministic and weighted,"
// "start at 100, subtract a fixed weight per confirmed finding," and be
// floored low enough that a BLOCKED build can never look healthy, but
// leaves the actual numbers unspecified. Documented here rather than
// derived from anything external, so a future change to these weights
// is a deliberate, visible diff, not an accidental drift.
const (
	startScore = 100
	minScore   = 0

	weightBlocking = 25 // per blocking-tier finding
	weightWarning  = 8  // per warning-tier finding

	// blockedScoreCeiling is the highest score a BLOCKED build may ever
	// display, regardless of how few or low-severity its blocking
	// findings were. Spec: "Floor the score low enough that a BLOCKED
	// build can never display a healthy-looking score... BLOCKED and a
	// high score must be impossible simultaneously." Chosen below any
	// band a reader could plausibly read as passing (a single 25-point
	// blocking deduction alone would otherwise leave 75, which reads as
	// healthy on a 0-100 scale) — 39 keeps every BLOCKED score in a
	// clearly failing band no matter what else is going on.
	blockedScoreCeiling = 39
)

// Score computes MobileGate's secondary output: a deterministic,
// weighted 0-100 number, never influenced by an LLM or fuzzy heuristic
// — spec: "Same weights in produce the same score out, every time."
// Never contradicts the gate: when decision is GateBlocked, the
// computed score is additionally capped at blockedScoreCeiling.
func Score(findings []Finding, decision GateDecision) int {
	score := startScore
	for _, f := range findings {
		if f.Blocking {
			score -= weightBlocking
		} else {
			score -= weightWarning
		}
	}
	if score < minScore {
		score = minScore
	}
	if decision == GateBlocked && score > blockedScoreCeiling {
		score = blockedScoreCeiling
	}
	return score
}
