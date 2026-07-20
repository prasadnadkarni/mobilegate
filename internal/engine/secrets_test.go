package engine

import (
	"strings"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
)

func testRule(t *testing.T) *RuleDef {
	t.Helper()
	r, err := LoadRule([]byte(`
id: MG-001
name: Hardcoded production secret
severity: critical
confidence: high
platform: android
blocking: true
masvs: MASVS-STORAGE-1
cwe: CWE-798
patterns:
  - id: aws-access-key-id
    name: AWS Access Key ID
    provider: AWS
    regex: '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
    structured: true
    confidence: high
  - id: gcp-firebase-api-key
    name: GCP / Firebase API key
    provider: Google Cloud / Firebase
    regex: '\bAIzaSy[0-9A-Za-z_\-]{33}\b'
    structured: true
    confidence: high
  - id: stripe-live-secret-key
    name: Stripe live secret key
    provider: Stripe
    regex: '\bsk_live_[0-9A-Za-z]{24,}\b'
    structured: true
    confidence: high
entropy:
  min_length: 16
exclusions:
  path_extensions:
    - .png
  value_patterns:
    - '(?i)your[_-]?api[_-]?key'
    - '(?i)(example|placeholder|changeme|dummy|xxxxx)'
`))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	return r
}

func newScanner(t *testing.T) *SecretScanner {
	t.Helper()
	s, err := NewSecretScanner(testRule(t))
	if err != nil {
		t.Fatalf("NewSecretScanner: %v", err)
	}
	return s
}

func TestScanDexStrings_MatchesUnattributedSecret(t *testing.T) {
	s := newScanner(t)
	strs := []dex.StringRef{
		{DexFile: "classes.dex", Index: 5, Value: "AKIATESTFAKEKEY12345", Usage: dex.Unattributed},
	}
	findings := s.ScanDexStrings(strs)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.PatternID != "aws-access-key-id" || f.Source != "classes.dex" || f.Location != "string_ids[5]" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestScanDexStrings_SkipsAttributedStrings(t *testing.T) {
	s := newScanner(t)
	// Same secret-shaped value, but tagged as a type/method/field name —
	// must never be scanned, per the structural exclusion.
	strs := []dex.StringRef{
		{DexFile: "classes.dex", Index: 1, Value: "AKIATESTFAKEKEY12345", Usage: dex.TypeName},
		{DexFile: "classes.dex", Index: 2, Value: "AKIATESTFAKEKEY12345", Usage: dex.MethodName},
		{DexFile: "classes.dex", Index: 3, Value: "AKIATESTFAKEKEY12345", Usage: dex.FieldName},
	}
	findings := s.ScanDexStrings(strs)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (all attributed): %+v", len(findings), findings)
	}
}

func TestScanAsset_SkipsExcludedExtension(t *testing.T) {
	s := newScanner(t)
	data := []byte("AKIATESTFAKEKEY12345") // matches, but .png must never be inspected
	findings := s.ScanAsset("assets/image.png", data)
	if len(findings) != 0 {
		t.Errorf("got %d findings for .png asset, want 0: %+v", len(findings), findings)
	}
}

func TestScanAsset_MatchesInTextFile(t *testing.T) {
	s := newScanner(t)
	data := []byte("line one\nkey=AKIATESTFAKEKEY12345\nline three")
	findings := s.ScanAsset("assets/config.txt", data)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Line == nil || *findings[0].Line != 2 {
		t.Errorf("Line = %v, want 2", findings[0].Line)
	}
	if findings[0].Location != "" {
		t.Errorf("Location = %q, want empty (Line and Location are mutually exclusive)", findings[0].Location)
	}
}

// This is the spec's literal finding_hash acceptance test: "a secret
// that moves from line 14 to line 18 in the same file, with no other
// change, must produce the same finding_hash." Same secret, same file,
// pushed from line 2 to line 5 by inserting unrelated leading lines —
// FindingHash must be identical even though Line is not.
func TestScanAsset_FindingHashSurvivesLineShift(t *testing.T) {
	s := newScanner(t)
	before := []byte("line one\nkey=AKIATESTFAKEKEY12345\nline three")
	after := []byte("line one\nline two (inserted)\nline three (inserted)\nline four (inserted)\nkey=AKIATESTFAKEKEY12345\nline six")

	findingsBefore := s.ScanAsset("assets/config.txt", before)
	findingsAfter := s.ScanAsset("assets/config.txt", after)
	if len(findingsBefore) != 1 || len(findingsAfter) != 1 {
		t.Fatalf("got %d/%d findings, want 1/1", len(findingsBefore), len(findingsAfter))
	}

	lineBefore, lineAfter := findingsBefore[0].Line, findingsAfter[0].Line
	if lineBefore == nil || lineAfter == nil || *lineBefore == *lineAfter {
		t.Fatalf("test setup bug: line numbers must actually differ (got %v vs %v)", lineBefore, lineAfter)
	}
	if findingsBefore[0].FindingHash != findingsAfter[0].FindingHash {
		t.Errorf("FindingHash changed when only the line number moved: %q (line %d) vs %q (line %d)",
			findingsBefore[0].FindingHash, *lineBefore, findingsAfter[0].FindingHash, *lineAfter)
	}
	if findingsBefore[0].FindingHash == "" {
		t.Error("FindingHash is empty, want a real hash")
	}
}

func TestScanValue_ExcludesPlaceholderByValuePattern(t *testing.T) {
	s := newScanner(t)
	// Structurally matches the GCP pattern (AIzaSy + 33 chars) but is an
	// obvious documented placeholder. Padded programmatically to the
	// exact required length rather than hand-counted, since an
	// off-by-one here would silently turn this into a non-match instead
	// of a caught-by-exclusion match (which is what this test needs to
	// exercise) — exactly the kind of fixture-construction bug worth not
	// hand-counting past.
	body := "YOUR_API_KEY_HERE_"
	body += strings.Repeat("0", 33-len(body))
	value := "AIzaSy" + body
	if len(value) != len("AIzaSy")+33 {
		t.Fatalf("test fixture value has wrong length: %d", len(value))
	}
	strs := []dex.StringRef{{DexFile: "classes.dex", Index: 0, Value: value, Usage: dex.Unattributed}}
	findings := s.ScanDexStrings(strs)
	if len(findings) != 0 {
		t.Errorf("got %d findings for documented placeholder, want 0: %+v", len(findings), findings)
	}
}

func TestScanValue_StripeTestKeyNeverMatchesLivePattern(t *testing.T) {
	s := newScanner(t)
	// sk_test_ has a different prefix than sk_live_ — must not match at
	// all, by construction, not via an exclusion list.
	strs := []dex.StringRef{{
		DexFile: "classes.dex", Index: 0,
		Value: "sk_test_" + "1234567890abcdefghijklmnopqr", Usage: dex.Unattributed,
	}}
	findings := s.ScanDexStrings(strs)
	if len(findings) != 0 {
		t.Errorf("got %d findings for sk_test_ key, want 0: %+v", len(findings), findings)
	}
}

func TestScanValue_FindsMultipleMatchesInOneValue(t *testing.T) {
	s := newScanner(t)
	value := "first=AKIATESTFAKEKEY11111 second=AKIATESTFAKEKEY22222"
	strs := []dex.StringRef{{DexFile: "classes.dex", Index: 0, Value: value, Usage: dex.Unattributed}}
	findings := s.ScanDexStrings(strs)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
}

func TestRedact(t *testing.T) {
	in := "AKIATESTFAKEKEY12345"
	got := redact(in)
	if len(got) != len(in) {
		t.Fatalf("redact changed length: got %q (%d), want length %d", got, len(got), len(in))
	}
	if got == in {
		t.Fatalf("redact did not obscure the value: %q", got)
	}
	if got[:6] != in[:6] || got[len(got)-6:] != in[len(in)-6:] {
		t.Errorf("redact should preserve first/last 6 chars: got %q, in %q", got, in)
	}
	middle := got[6 : len(got)-6]
	for _, c := range middle {
		if c != '*' {
			t.Errorf("redact middle should be all asterisks: got %q", middle)
			break
		}
	}
}

func TestRedact_ShortValueFullyMasked(t *testing.T) {
	got := redact("short")
	if got != "*****" {
		t.Errorf("redact(%q) = %q, want fully masked", "short", got)
	}
}
