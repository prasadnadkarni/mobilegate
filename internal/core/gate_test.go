package core

import "testing"

func TestDecide_NoFindingsIsPass(t *testing.T) {
	if got := Decide(nil); got != GatePass {
		t.Errorf("Decide(nil) = %q, want %q", got, GatePass)
	}
}

func TestDecide_OnlyWarningsIsPass(t *testing.T) {
	findings := []Finding{
		{RuleID: "MG-003", Blocking: false},
		{RuleID: "MG-003", Blocking: false},
	}
	if got := Decide(findings); got != GatePass {
		t.Errorf("Decide(warnings only) = %q, want %q", got, GatePass)
	}
}

func TestDecide_OneBlockingFindingIsBlocked(t *testing.T) {
	findings := []Finding{
		{RuleID: "MG-003", Blocking: false},
		{RuleID: "MG-001", Blocking: true},
	}
	if got := Decide(findings); got != GateBlocked {
		t.Errorf("Decide(1 blocking + warnings) = %q, want %q", got, GateBlocked)
	}
}

func TestDecide_AllBlockingFindingsIsBlocked(t *testing.T) {
	findings := []Finding{
		{RuleID: "MG-001", Blocking: true},
		{RuleID: "MG-002", Blocking: true},
	}
	if got := Decide(findings); got != GateBlocked {
		t.Errorf("Decide(all blocking) = %q, want %q", got, GateBlocked)
	}
}
