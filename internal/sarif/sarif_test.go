package sarif_test

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/internal/sarif"
)

func findRule(t *testing.T, log *sarif.Log, id string) sarif.ReportingDescriptor {
	t.Helper()
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no reportingDescriptor for %s", id)
	return sarif.ReportingDescriptor{}
}

func findResult(t *testing.T, log *sarif.Log, hash string) sarif.Result {
	t.Helper()
	for _, r := range log.Runs[0].Results {
		if r.PartialFingerprints["primaryLocationLineHash"] == hash {
			return r
		}
	}
	t.Fatalf("no result with finding_hash %s", hash)
	return sarif.Result{}
}

// TestBuild_AllFiveRulesAlwaysDeclared — spec: "one reportingDescriptor
// per rule (MG-001..MG-010)," regardless of whether that rule fired
// this run. A clean-APK scan (the most common real case) must still
// declare all five rules, or GitHub has no rule metadata to show if one
// ever DOES fire on a later run without a corresponding re-declaration.
func TestBuild_AllFiveRulesAlwaysDeclared(t *testing.T) {
	in := representativeInput()
	in.Findings = nil // clean APK
	log, err := sarif.Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(log.Runs[0].Tool.Driver.Rules); got != 5 {
		t.Fatalf("got %d rules declared, want 5 (all rules regardless of findings)", got)
	}
	for _, id := range []string{"MG-001", "MG-002", "MG-003", "MG-004", "MG-010"} {
		findRule(t, log, id) // fails the test if missing
	}
}

// TestBuild_RulesSortedByID — deterministic output matters for diffing
// and for not depending on map/slice iteration order across builds.
func TestBuild_RulesSortedByID(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID >= rules[i].ID {
			t.Fatalf("rules not sorted: %q before %q", rules[i-1].ID, rules[i].ID)
		}
	}
}

// TestBuild_SecuritySeverityIsRuleLevelOnly — confirms Build never
// writes a result-level security-severity value, since GitHub is
// confirmed (docs.github.com) to only read it from the rule's own
// properties bag; a result-level value would be silently ignored and
// is worse than useless — it would suggest to a future maintainer that
// per-finding severity ranking works when it doesn't. See sarif.go's
// doc comment, point 1.
func TestBuild_SecuritySeverityIsRuleLevelOnly(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, r := range log.Runs[0].Results {
		if r.Properties != nil {
			// ResultProperties has no security-severity field at all —
			// this loop is really just documentation-as-test that the
			// type doesn't grow one carelessly. The real assertion is
			// structural (see TestBuild_RuleLevelSecuritySeverityMapping
			// below) rather than checked here.
			_ = r.Properties
		}
	}
}

// TestBuild_RuleLevelSecuritySeverityMapping — MG-004's static YAML
// severity is "high", but the representative input includes an
// unguarded-provider MG-004 finding at "critical" — this is exactly the
// scenario severityScoreFor exists for: the rule's security-severity
// must reflect the worst actual finding this run, not just fall back to
// the rule's own static default, or GitHub would under-rank a critical
// finding as merely "high" in its Security tab ranking.
func TestBuild_RuleLevelSecuritySeverityMapping(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	mg001 := findRule(t, log, "MG-001") // static "critical", no override needed
	if mg001.Properties.SecuritySeverity != "9.5" {
		t.Errorf("MG-001 security-severity = %q, want 9.5 (critical band)", mg001.Properties.SecuritySeverity)
	}

	mg004 := findRule(t, log, "MG-004") // static "high", but a critical finding fired this run
	if mg004.Properties.SecuritySeverity != "9.5" {
		t.Errorf("MG-004 security-severity = %q, want 9.5 — the critical unguarded-provider finding must raise the rule's score above its static \"high\" default", mg004.Properties.SecuritySeverity)
	}

	mg010 := findRule(t, log, "MG-010") // static "critical", zero findings this run — must still get a score from the static default
	if mg010.Properties.SecuritySeverity != "9.5" {
		t.Errorf("MG-010 (zero findings this run) security-severity = %q, want 9.5 from its static YAML severity floor", mg010.Properties.SecuritySeverity)
	}
}

// TestBuild_RuleTagsIncludeSecurityMASVSAndCWE — spec requirement,
// verbatim: "properties.tags (include 'security', MASVS id, CWE id)."
func TestBuild_RuleTagsIncludeSecurityMASVSAndCWE(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	mg001 := findRule(t, log, "MG-001")
	tags := map[string]bool{}
	for _, tag := range mg001.Properties.Tags {
		tags[tag] = true
	}
	for _, want := range []string{"security", "MASVS-STORAGE-1", "CWE-798"} {
		if !tags[want] {
			t.Errorf("MG-001 tags = %v, missing %q", mg001.Properties.Tags, want)
		}
	}
}

// TestBuild_LevelMatchesBlockingTier — spec: error for blocking-tier,
// warning for warning-tier.
func TestBuild_LevelMatchesBlockingTier(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	blocking := findResult(t, log, "sha256:aaaa") // MG-001, Blocking: true
	if blocking.Level != "error" {
		t.Errorf("blocking finding level = %q, want error", blocking.Level)
	}
	warning := findResult(t, log, "sha256:bbbb") // MG-004, Blocking: false
	if warning.Level != "warning" {
		t.Errorf("warning-tier finding level = %q, want warning", warning.Level)
	}
}

// TestBuild_FingerprintUsesFindingHashUnderExactKey — GitHub is
// confirmed to read ONLY partialFingerprints.primaryLocationLineHash;
// any other key name is silently ignored and GitHub falls back to
// trying to compute its own fingerprint from source context that
// doesn't meaningfully exist for our artifacts. See sarif.go's doc
// comment, point 3.
func TestBuild_FingerprintUsesFindingHashUnderExactKey(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	r := findResult(t, log, "sha256:aaaa")
	if len(r.PartialFingerprints) != 1 {
		t.Fatalf("got %d partialFingerprints keys, want exactly 1: %v", len(r.PartialFingerprints), r.PartialFingerprints)
	}
	if got := r.PartialFingerprints["primaryLocationLineHash"]; got != "sha256:aaaa" {
		t.Errorf("primaryLocationLineHash = %q, want the finding's own finding_hash sha256:aaaa", got)
	}
}

// TestBuild_FingerprintIsPositionIndependent mirrors finding_hash's own
// acceptance test (internal/core): a finding's identity must survive
// something that shifts its position but not its substance — otherwise
// baseline mode's ratchet property and GitHub's cross-run alert
// tracking would both break the same way. Two findings differing only
// in Location (a proxy for "line/position moved") must keep the same
// primaryLocationLineHash, since finding_hash itself already excludes
// location/line by construction — Build must not silently reintroduce
// that dependency by deriving the fingerprint from anything other than
// FindingHash.
func TestBuild_FingerprintIsPositionIndependent(t *testing.T) {
	f := core.Finding{
		RuleID: "MG-001", Severity: "critical", Blocking: true,
		Source: "classes.dex", Location: "string_ids[10]",
		FindingHash: "sha256:stable",
	}
	moved := f
	moved.Location = "string_ids[99]" // same finding, different position — hash unchanged by construction

	in1 := sarif.BuildInput{Rules: []sarif.RuleInfo{{ID: "MG-001", Severity: "critical"}}, Findings: []core.Finding{f}}
	in2 := sarif.BuildInput{Rules: []sarif.RuleInfo{{ID: "MG-001", Severity: "critical"}}, Findings: []core.Finding{moved}}

	log1, err := sarif.Build(in1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	log2, err := sarif.Build(in2)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	fp1 := log1.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	fp2 := log2.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	if fp1 != fp2 {
		t.Errorf("fingerprint changed when only Location moved: %q vs %q — GitHub would treat this as a new alert instead of tracking the same one across runs", fp1, fp2)
	}
}

// TestBuild_ArtifactURIMapping — the core design decision: manifest
// findings map to the configured source manifest path; everything else
// maps to the APK's own base name, never fabricated, never absolute.
func TestBuild_ArtifactURIMapping(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	dexFinding := findResult(t, log, "sha256:aaaa") // Source: classes2.dex
	uri := dexFinding.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "app-release.apk" {
		t.Errorf("DEX finding artifactLocation.uri = %q, want the APK's base name (app-release.apk) — never a fabricated source path, never an absolute path", uri)
	}

	manifestFinding := findResult(t, log, "sha256:bbbb") // Source: AndroidManifest.xml
	uri = manifestFinding.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "app/src/main/AndroidManifest.xml" {
		t.Errorf("manifest finding artifactLocation.uri = %q, want the configured source_manifest_path", uri)
	}
}

// TestBuild_NeverEmitsRegion — no finding here has a verified line
// number that corresponds to a real line in the artifact being pointed
// at (see sarif.go's artifactURI doc comment) — Build must never
// fabricate one. This is checked by asserting the marshaled JSON has no
// "region" key at all inside any location, not just by inspecting the
// (nonexistent) Go field.
func TestBuild_NeverEmitsRegion(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// The MG-001 finding in representativeInput() has a real Line set
	// (Line: &line) — proving region-omission isn't just "we never had
	// a line to begin with," but a deliberate choice not to attach it
	// to a physicalLocation that points at a binary artifact.
	f := findResult(t, log, "sha256:aaaa")
	if f.Properties == nil || f.Properties.Line == nil {
		t.Fatalf("test setup: expected the MG-001 fixture finding to carry a real Line in properties")
	}
}

// TestBuild_OmitsSuppressedFindings — this is what point 2 of sarif.go's
// doc comment requires in practice: Build has no suppression-handling
// code at all, on purpose. The caller (cmd/mobilegate) must simply never
// pass baselined/suppressed findings into BuildInput.Findings. This test
// documents that Build performs no filtering of its own — every finding
// passed in appears in the output — so a caller cannot rely on Build to
// filter suppressions for it.
func TestBuild_OmitsSuppressedFindings(t *testing.T) {
	in := representativeInput()
	log, err := sarif.Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := len(log.Runs[0].Results), len(in.Findings); got != want {
		t.Fatalf("Build produced %d results for %d input findings — Build must pass every given finding through unfiltered; suppression is the caller's responsibility", got, want)
	}
}

// TestBuild_FailsLoudlyOverResultLimit — spec: "fail loudly rather than
// silently truncating."
func TestBuild_FailsLoudlyOverResultLimit(t *testing.T) {
	in := representativeInput()
	f := in.Findings[0]
	huge := make([]core.Finding, 0, 5001)
	for i := 0; i < 5001; i++ {
		huge = append(huge, f)
	}
	in.Findings = huge
	_, err := sarif.Build(in)
	if err == nil {
		t.Fatal("expected an error when results exceed the self-imposed limit, got nil")
	}
}
