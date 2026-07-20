package core

import (
	"os"
	"path/filepath"
	"testing"
)

func writeBaseline(t *testing.T, path string, b *Baseline) {
	t.Helper()
	if err := b.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// --- fixture 1: a finding not in the baseline blocks ---

func TestSplitByBaseline_NewFindingBlocks(t *testing.T) {
	baseline := &Baseline{ScannerVersion: "0.1.0", RuleVersion: "2026.07.1"} // empty — nothing baselined
	findings := []Finding{
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa"},
	}
	rest, baselined := SplitByBaseline(findings, baseline)
	if len(baselined) != 0 {
		t.Fatalf("got %d baselined, want 0: %+v", len(baselined), baselined)
	}
	if len(rest) != 1 || !rest[0].Blocking {
		t.Fatalf("new finding must remain blocking in rest: %+v", rest)
	}
}

// --- fixture 2: a finding present in the baseline passes (doesn't block) ---

func TestSplitByBaseline_BaselinedFindingPasses(t *testing.T) {
	baseline := &Baseline{
		ScannerVersion: "0.1.0", RuleVersion: "2026.07.1",
		Findings: []BaselineEntry{{FindingHash: "sha256:aaa", RuleID: "MG-001"}},
	}
	findings := []Finding{
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa"},
	}
	rest, baselined := SplitByBaseline(findings, baseline)
	if len(rest) != 0 {
		t.Fatalf("baselined finding must not remain in rest: %+v", rest)
	}
	if len(baselined) != 1 || baselined[0].FindingHash != "sha256:aaa" {
		t.Fatalf("got %+v, want the one baselined finding", baselined)
	}
}

// A baselined finding must still block if the gate decision is computed
// from findings that DIDN'T go through SplitByBaseline (i.e. this is a
// property of SplitByBaseline's caller, not SplitByBaseline itself) —
// checked here structurally: Decide on "rest" alone (post-split) must
// be GatePass when the only finding was baselined away.
func TestSplitByBaseline_BaselinedFindingDoesNotAffectGate(t *testing.T) {
	baseline := &Baseline{
		ScannerVersion: "0.1.0", RuleVersion: "2026.07.1",
		Findings: []BaselineEntry{{FindingHash: "sha256:aaa", RuleID: "MG-001"}},
	}
	findings := []Finding{{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa"}}
	rest, _ := SplitByBaseline(findings, baseline)
	if got := Decide(rest); got != GatePass {
		t.Errorf("Decide(rest) = %q, want %q (the only finding was baselined)", got, GatePass)
	}
}

// Warning-tier findings are never baselined (never appear in the file
// at all — see NewBaseline) and always stay in "rest" regardless of
// whether their hash happens to appear in the baseline (it never would
// from a real write, but SplitByBaseline's own logic must not baseline
// a non-blocking finding even if asked to).
func TestSplitByBaseline_WarningFindingNeverBaselined(t *testing.T) {
	baseline := &Baseline{
		ScannerVersion: "0.1.0", RuleVersion: "2026.07.1",
		Findings: []BaselineEntry{{FindingHash: "sha256:warn", RuleID: "MG-003"}},
	}
	findings := []Finding{{RuleID: "MG-003", Blocking: false, FindingHash: "sha256:warn"}}
	rest, baselined := SplitByBaseline(findings, baseline)
	if len(baselined) != 0 {
		t.Errorf("warning-tier finding must never be baselined: %+v", baselined)
	}
	if len(rest) != 1 {
		t.Errorf("warning-tier finding must remain in rest: %+v", rest)
	}
}

// --- fixture 3: a fixed finding drops from the baseline on the next write (ratchet) ---

func TestNewBaseline_FixedFindingDropsOnRewrite(t *testing.T) {
	before := []Finding{
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/a.json"},
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "AndroidManifest.xml"},
	}
	b1 := NewBaseline("0.1.0", "2026.07.1", before)
	if len(b1.Findings) != 2 {
		t.Fatalf("initial baseline: got %d findings, want 2", len(b1.Findings))
	}

	// MG-001's finding is fixed (no longer present); MG-002's persists.
	after := []Finding{
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "AndroidManifest.xml"},
	}
	b2 := NewBaseline("0.1.0", "2026.07.1", after)
	if len(b2.Findings) != 1 {
		t.Fatalf("re-written baseline: got %d findings, want 1: %+v", len(b2.Findings), b2.Findings)
	}
	if b2.Contains("sha256:aaa") {
		t.Error("fixed finding sha256:aaa is still present after re-write — a fixed issue must not stay grandfathered")
	}
	if !b2.Contains("sha256:bbb") {
		t.Error("still-present finding sha256:bbb was dropped incorrectly")
	}
}

// Round-trip end-to-end: write b1 to disk, load it back, confirm the
// fixed finding is gone from what a fresh scan+SplitByBaseline sees
// once the baseline is re-written and re-loaded — the actual mechanism
// a real "fix a finding, re-run baseline -write" workflow depends on.
func TestBaseline_RatchetEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")

	before := []Finding{{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/a.json"}}
	writeBaseline(t, path, NewBaseline("0.1.0", "2026.07.1", before))

	// Fix it, re-write.
	writeBaseline(t, path, NewBaseline("0.1.0", "2026.07.1", nil))

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.Contains("sha256:aaa") {
		t.Error("fixed finding survived a re-write + reload — ratchet is broken")
	}
	if len(loaded.Findings) != 0 {
		t.Errorf("got %d findings after fixing the only one, want 0: %+v", len(loaded.Findings), loaded.Findings)
	}
}

// --- fixture 4: a corrupt/unreadable baseline fails closed ---

func TestLoadBaseline_MissingFileIsDistinctFromCorrupt(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadBaseline(filepath.Join(dir, "does-not-exist.yml"))
	if err == nil {
		t.Fatal("expected an error for a missing baseline file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected an os.IsNotExist error for a missing file, got: %v", err)
	}
}

func TestLoadBaseline_MalformedYAMLFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")
	if err := os.WriteFile(path, []byte("this is not: [valid yaml\n  - broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBaseline(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
	if os.IsNotExist(err) {
		t.Error("a malformed (but present) file must not look like a missing file to the caller")
	}
}

func TestLoadBaseline_SchemaMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")
	// Valid YAML, but missing scanner_version/rule_version entirely —
	// e.g. an old/foreign file that happens to parse as empty-ish.
	if err := os.WriteFile(path, []byte("findings:\n  - finding_hash: sha256:aaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBaseline(path)
	if err == nil {
		t.Fatal("expected an error for a schema-mismatched baseline (missing scanner_version/rule_version)")
	}
}

func TestLoadBaseline_EmptyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("expected an error for an empty baseline file")
	}
}

// --- round trip / determinism ---

func TestBaseline_WriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")

	findings := []Finding{
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "res/nsc.xml", Title: "Cleartext traffic permitted", Excerpt: `cleartextTrafficPermitted="true"`},
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/config.json", Title: "Hardcoded AWS Access Key ID", Excerpt: "AKIA**********"},
		{RuleID: "MG-003", Blocking: false, FindingHash: "sha256:warn", Source: "AndroidManifest.xml"}, // warning-tier — must not appear
	}
	original := NewBaseline("0.1.0", "2026.07.1", findings)
	writeBaseline(t, path, original)

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.ScannerVersion != "0.1.0" || loaded.RuleVersion != "2026.07.1" {
		t.Errorf("version mismatch after round-trip: %+v", loaded)
	}
	if len(loaded.Findings) != 2 {
		t.Fatalf("got %d findings after round-trip, want 2 (warning-tier must be excluded): %+v", len(loaded.Findings), loaded.Findings)
	}
	if !loaded.Contains("sha256:aaa") || !loaded.Contains("sha256:bbb") {
		t.Errorf("round-tripped baseline missing expected hashes: %+v", loaded.Findings)
	}
	if loaded.Contains("sha256:warn") {
		t.Error("warning-tier finding leaked into the baseline")
	}
}

// Re-writing with no underlying change must produce a byte-identical
// file — no wall-clock timestamp or other non-deterministic field.
func TestBaseline_RewriteWithNoChangeIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yml")
	findings := []Finding{
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/a.json"},
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "res/nsc.xml"},
	}
	writeBaseline(t, path, NewBaseline("0.1.0", "2026.07.1", findings))
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeBaseline(t, path, NewBaseline("0.1.0", "2026.07.1", findings))
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("re-write with no findings change produced a different file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

// Ordering is deterministic regardless of input order — a rescan that
// happens to enumerate findings in a different order must still produce
// the same sorted file.
func TestNewBaseline_DeterministicOrderRegardlessOfInputOrder(t *testing.T) {
	a := []Finding{
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "res/nsc.xml"},
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/a.json"},
	}
	b := []Finding{
		{RuleID: "MG-001", Blocking: true, FindingHash: "sha256:aaa", Source: "assets/a.json"},
		{RuleID: "MG-002", Blocking: true, FindingHash: "sha256:bbb", Source: "res/nsc.xml"},
	}
	ba := NewBaseline("0.1.0", "2026.07.1", a)
	bb := NewBaseline("0.1.0", "2026.07.1", b)
	if len(ba.Findings) != len(bb.Findings) {
		t.Fatalf("length mismatch: %d vs %d", len(ba.Findings), len(bb.Findings))
	}
	for i := range ba.Findings {
		if ba.Findings[i].FindingHash != bb.Findings[i].FindingHash {
			t.Errorf("order[%d] differs: %q vs %q", i, ba.Findings[i].FindingHash, bb.Findings[i].FindingHash)
		}
	}
}
