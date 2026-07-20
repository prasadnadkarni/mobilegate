// This file is MG-001's acceptance-gate test: per CLAUDE.md, "A rule may
// NOT enter the blocking tier until it passes the full negative-fixture
// suite with zero false positives," and "no rule is allowed into the
// blocking tier until it produces zero false positives across the entire
// negative-fixture suite" (spec, Test Strategy). It runs the real
// rules/MG-001-hardcoded-secret.yaml through the actual apk → dex →
// engine pipeline against small synthetic APKs built in-process — not a
// simplified stand-in rule, and not unit-level string lists — so this is
// the same code path a real scan uses.
//
// Fixture APKs are built in Go rather than committed as binary .apk
// files: they're trivial to construct deterministically (a handful of
// zip entries, one of them a minimal hand-rolled DEX with no type/
// method/field tables — MG-001 fixtures only need Unattributed strings),
// and keeping them as readable Go source makes it obvious to a reviewer
// exactly what each fixture plants, which matters more for a security
// tool's test suite than it does for the parser-verification fixtures in
// testdata/real (which had to be real APKs, since the thing under test
// there was real-world binary format compliance, not rule logic).
package engine_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/rules"
)

// padDigits pads (or truncates) s to exactly n characters using '0',
// which is a valid character in every MG-001 pattern's body charset.
// Used to build fixture secrets to each pattern's exact required length
// without hand-counting characters in a literal — an easy place to get
// an off-by-one wrong and end up testing something other than what the
// fixture name claims.
func padDigits(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat("0", n-len(s))
}

// --- minimal synthetic APK builder ---

// buildMinimalDex builds a DEX file containing only a string pool: no
// type_ids/method_ids/field_ids, so every string comes back tagged
// dex.Unattributed — the realistic shape of a hardcoded data constant,
// and what MG-001 fixtures need. ASCII-only (sufficient for these
// fixtures; MUTF-8/CESU-8 edge cases are already covered in
// pkg/parser/dex's own tests).
func buildMinimalDex(t *testing.T, strs []string) []byte {
	t.Helper()
	const headerSize = 0x70
	stringIDsOff := uint32(headerSize)
	stringIDsSize := uint32(len(strs))
	dataOff := stringIDsOff + stringIDsSize*4

	var data bytes.Buffer
	offs := make([]uint32, len(strs))
	for i, s := range strs {
		for _, r := range s {
			if r > 0x7F {
				t.Fatalf("buildMinimalDex: fixture string %q must be ASCII", s)
			}
		}
		offs[i] = dataOff + uint32(data.Len())
		writeULEB128(&data, uint32(len(s))) // utf16_size == byte length for ASCII
		data.WriteString(s)
		data.WriteByte(0x00)
	}

	buf := make([]byte, dataOff)
	copy(buf[0:8], []byte("dex\n039\x00"))
	binary.LittleEndian.PutUint32(buf[40:], 0x12345678) // endian tag
	binary.LittleEndian.PutUint32(buf[56:], stringIDsSize)
	binary.LittleEndian.PutUint32(buf[60:], stringIDsOff)
	for i, off := range offs {
		binary.LittleEndian.PutUint32(buf[stringIDsOff+uint32(i)*4:], off)
	}
	return append(buf, data.Bytes()...)
}

func writeULEB128(buf *bytes.Buffer, v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

type fixture struct {
	name       string
	dexStrings []string
	assets     map[string][]byte
}

func (f fixture) build(t *testing.T) *apk.Container {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	// MG-001 doesn't scan the manifest (see engine package notes / final
	// report on scan-surface scope), so this only needs to exist for
	// apk.Open to accept the zip as a valid APK.
	w.Write([]byte("placeholder"))

	w, err = zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(buildMinimalDex(t, f.dexStrings))

	for name, content := range f.assets {
		w, err = zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(content)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "fixture.apk")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	container, err := apk.Open(path)
	if err != nil {
		t.Fatalf("apk.Open(%s): %v", f.name, err)
	}
	return container
}

func loadRealMG001(t *testing.T) *engine.SecretScanner {
	t.Helper()
	data, err := rules.FS.ReadFile("MG-001-hardcoded-secret.yaml")
	if err != nil {
		t.Fatalf("reading rules/MG-001-hardcoded-secret.yaml: %v", err)
	}
	rule, err := engine.LoadRule(data)
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	scanner, err := engine.NewSecretScanner(rule)
	if err != nil {
		t.Fatalf("NewSecretScanner: %v", err)
	}
	return scanner
}

func scanFixture(t *testing.T, s *engine.SecretScanner, c *apk.Container) []engine.Finding {
	t.Helper()
	var findings []engine.Finding
	for _, d := range c.DexFiles {
		strs, err := dex.ParseStrings(d.Name, d.Data)
		if err != nil {
			t.Fatalf("dex.ParseStrings: %v", err)
		}
		findings = append(findings, s.ScanDexStrings(strs)...)
	}
	for _, a := range c.AssetFiles {
		findings = append(findings, s.ScanAsset(a.Name, a.Data)...)
	}
	return findings
}

// --- positive fixtures: one per pattern, must produce exactly one finding ---

func TestMG001_PositiveFixtures(t *testing.T) {
	scanner := loadRealMG001(t)

	awsKey := "AKIA" + padDigits("TESTFAKEKEY", 16)                         // AKIA + exactly 16
	gcpKey := "AIzaSy" + padDigits("FAKEKEYFORTESTINGPURPOSES", 33)         // AIzaSy + exactly 33
	stripeKey := "sk_live_" + padDigits("FAKEKEYFORTESTING", 24)            // sk_live_ + at least 24
	ghClassic := "ghp_" + padDigits("FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", 36) // ghp_ + exactly 36
	ghFineGrained := "github_pat_" + padDigits("FAKEFAKEFAKEFAKEFAKE", 20)  // github_pat_ + at least 20
	slackToken := "xoxb-1234567890-1234567890123-" + padDigits("FAKEFAKEFAKEFAKE", 16)

	cases := []struct {
		fixture       fixture
		wantPatternID string
	}{
		{
			fixture{"aws_access_key_in_dex",
				[]string{"normal string", awsKey}, nil},
			"aws-access-key-id",
		},
		{
			fixture{"gcp_firebase_key_in_asset",
				nil, map[string][]byte{
					"assets/config.json": []byte(fmt.Sprintf(`{"apiKey":"%s"}`, gcpKey)),
				}},
			"gcp-firebase-api-key",
		},
		{
			fixture{"stripe_live_key_in_dex",
				[]string{stripeKey}, nil},
			"stripe-live-secret-key",
		},
		{
			fixture{"github_pat_classic_in_asset",
				nil, map[string][]byte{
					"assets/.env": []byte("GITHUB_TOKEN=" + ghClassic),
				}},
			"github-pat-classic",
		},
		{
			fixture{"github_pat_fine_grained_in_dex",
				[]string{ghFineGrained}, nil},
			"github-pat-fine-grained",
		},
		{
			fixture{"slack_token_in_asset",
				nil, map[string][]byte{
					"assets/config.txt": []byte("slack=" + slackToken),
				}},
			"slack-token",
		},
		{
			fixture{"private_key_header_in_asset",
				nil, map[string][]byte{
					"assets/certs/fake.pem": []byte("-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----"),
				}},
			"private-key-header",
		},
	}

	for _, tc := range cases {
		t.Run(tc.fixture.name, func(t *testing.T) {
			container := tc.fixture.build(t)
			findings := scanFixture(t, scanner, container)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %+v", len(findings), findings)
			}
			if findings[0].PatternID != tc.wantPatternID {
				t.Errorf("PatternID = %q, want %q", findings[0].PatternID, tc.wantPatternID)
			}
			if !findings[0].Blocking {
				t.Errorf("finding should be blocking-tier: %+v", findings[0])
			}
		})
	}
}

// --- negative fixtures: the acceptance gate. Every one of these must
// produce ZERO findings, including the deliberately tricky ones. ---

func TestMG001_NegativeFixtures(t *testing.T) {
	scanner := loadRealMG001(t)

	fixtures := []fixture{
		{
			name:       "clean_app_no_secrets",
			dexStrings: []string{"Hello, world!", "onCreate", "user_preferences", "https://example.com/api"},
			assets: map[string][]byte{
				"assets/readme.txt": []byte("Nothing sensitive here, just app copy."),
			},
		},
		{
			name:       "stripe_test_key_wrong_prefix",
			dexStrings: []string{"sk_test_1234567890abcdefghijklmnopqr"},
		},
		{
			name:       "stripe_publishable_live_key_wrong_prefix",
			dexStrings: []string{"pk_live_1234567890abcdefghijklmnopqr"},
		},
		{
			name: "documented_google_placeholder_key_in_asset",
			assets: map[string][]byte{
				// Structurally AIzaSy + 33 chars, but an obvious
				// documented placeholder — must be caught by
				// exclusions.value_patterns, not by luck.
				"assets/README.md": []byte("Set your key: AIzaSy" + padDigits("YOUR_API_KEY_HERE_", 33)),
			},
		},
		{
			name: "high_entropy_png_binary_excluded_by_extension",
			assets: map[string][]byte{
				// A real, matchable AWS-shaped key embedded inside bytes
				// with an image extension. Must be excluded purely by
				// extension — content is never even inspected. This is
				// the spec's explicit "image assets with high-entropy
				// binary data" tricky negative fixture.
				"assets/drawable/photo.png": append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0x00, 0xAB, 0xCD},
					[]byte("AKIA"+padDigits("TESTFAKEKEY", 16))...),
			},
		},
		{
			name: "lowercase_prefix_never_matches_case_sensitive_pattern",
			// AWS/GitHub/private-key prefixes are case-sensitive in real
			// life; a lowercase near-match must not fire.
			dexStrings: []string{"akia" + padDigits("testfakekey", 16), "GHP_" + padDigits("FAKE", 36)},
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			container := f.build(t)
			findings := scanFixture(t, scanner, container)
			if len(findings) != 0 {
				var summary string
				for _, fnd := range findings {
					summary += fmt.Sprintf("\n  [%s] source=%s location=%s excerpt=%s", fnd.PatternID, fnd.Source, fnd.Location, fnd.Excerpt)
				}
				t.Errorf("got %d false-positive findings, want 0:%s", len(findings), summary)
			}
		})
	}
}
