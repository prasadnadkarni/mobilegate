package core

import "testing"

func TestScore_NoFindingsIsPerfect(t *testing.T) {
	if got := Score(nil, GatePass); got != 100 {
		t.Errorf("Score(nil) = %d, want 100", got)
	}
}

func TestScore_Deterministic(t *testing.T) {
	findings := []Finding{{Blocking: true}, {Blocking: false}, {Blocking: false}}
	a := Score(findings, GateBlocked)
	b := Score(findings, GateBlocked)
	if a != b {
		t.Errorf("same findings produced different scores: %d vs %d", a, b)
	}
}

func TestScore_WarningsOnlyReducesButStaysHigh(t *testing.T) {
	findings := []Finding{{Blocking: false}, {Blocking: false}}
	got := Score(findings, GatePass)
	if got != startScore-2*weightWarning {
		t.Errorf("Score(2 warnings) = %d, want %d", got, startScore-2*weightWarning)
	}
	if got <= blockedScoreCeiling {
		t.Errorf("Score(2 warnings, PASS) = %d, unexpectedly at/below the BLOCKED ceiling %d — a passing build should read healthier than a blocked one", got, blockedScoreCeiling)
	}
}

// The core acceptance requirement from spec: "BLOCKED and a high score
// must be impossible simultaneously" — even a single, otherwise-mild
// blocking finding must cap out well below anything readable as
// healthy.
func TestScore_BlockedNeverLooksHealthy(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
	}{
		{"single_blocking_finding", []Finding{{Blocking: true}}},
		{"single_blocking_plus_many_warnings", []Finding{
			{Blocking: true}, {Blocking: false}, {Blocking: false}, {Blocking: false},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := Decide(tc.findings)
			if decision != GateBlocked {
				t.Fatalf("test setup bug: expected GateBlocked, got %q", decision)
			}
			got := Score(tc.findings, decision)
			if got > blockedScoreCeiling {
				t.Errorf("Score = %d, want <= %d (blockedScoreCeiling) whenever gate_decision is blocked", got, blockedScoreCeiling)
			}
		})
	}
}

func TestScore_NeverNegative(t *testing.T) {
	var findings []Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, Finding{Blocking: true})
	}
	got := Score(findings, GateBlocked)
	if got < 0 {
		t.Errorf("Score = %d, must never be negative", got)
	}
}
