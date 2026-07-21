package core

import "testing"

func TestComputeFindingHash_Deterministic(t *testing.T) {
	a := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-a")
	b := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-a")
	if a != b {
		t.Errorf("same inputs produced different hashes: %q vs %q", a, b)
	}
}

func TestComputeFindingHash_DifferentRuleIDDiffers(t *testing.T) {
	a := ComputeFindingHash("MG-001", "AndroidManifest.xml", "x", "true")
	b := ComputeFindingHash("MG-002", "AndroidManifest.xml", "x", "true")
	if a == b {
		t.Error("different rule IDs produced the same hash")
	}
}

func TestComputeFindingHash_DifferentSourceDiffers(t *testing.T) {
	a := ComputeFindingHash("MG-001", "assets/a.json", "x", "example-match-value-a")
	b := ComputeFindingHash("MG-001", "assets/b.json", "x", "example-match-value-a")
	if a == b {
		t.Error("different source files produced the same hash")
	}
}

func TestComputeFindingHash_DifferentPatternIDDiffers(t *testing.T) {
	a := ComputeFindingHash("MG-003", "AndroidManifest.xml", "allow-backup-explicit", `android:allowBackup="true"`)
	b := ComputeFindingHash("MG-003", "AndroidManifest.xml", "allow-backup-implicit-low-target-sdk", `android:allowBackup="true"`)
	if a == b {
		t.Error("different pattern IDs produced the same hash")
	}
}

func TestComputeFindingHash_DifferentMatchValueDiffers(t *testing.T) {
	a := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-a")
	b := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-b")
	if a == b {
		t.Error("different match values produced the same hash")
	}
}

// No field-boundary ambiguity: concatenation without a separator would
// make ("AB","C",...) collide with ("A","BC",...). writeField's NUL
// separator must prevent that.
func TestComputeFindingHash_NoFieldBoundaryCollision(t *testing.T) {
	a := ComputeFindingHash("AB", "C", "x", "y")
	b := ComputeFindingHash("A", "BC", "x", "y")
	if a == b {
		t.Error("field-boundary shift produced the same hash — missing separator")
	}
}

// This is the spec's literal acceptance test, at the hash-function
// level: nothing about a text line number is ever a hash input in the
// first place, so a value that "moved lines" (same rule, same file,
// same normalized match value) is definitionally identical here. The
// full end-to-end version of this test — actually moving a planted
// secret from line 14 to line 18 in a scanned asset — lives in
// internal/engine's fixture suite, where a real Line field exists to
// move.
func TestComputeFindingHash_LineNumberIsNotAnInput(t *testing.T) {
	a := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-a")
	b := ComputeFindingHash("MG-001", "assets/config.json", "aws-access-key-id", "example-match-value-a")
	if a != b {
		t.Fatal("identical rule/file/pattern/match-value inputs must hash identically regardless of any line number")
	}
}
