// This file is MG-003's acceptance-gate suite. Same relationship to
// StorageScanner (internal/engine/storage.go) that mg002_fixtures_test.go
// has to TransportScanner: manifest field resolution is already
// independently verified (oracle-tested against real APKs, unit-tested in
// pkg/parser/manifest), so these fixtures exercise CheckManifest's
// decision logic directly against constructed manifest.Manifest values,
// not full APK bytes.
package engine_test

import (
	"strings"
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/backuprules"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

func mg003TestRule(t *testing.T) *engine.StorageRuleDef {
	t.Helper()
	rule, err := engine.LoadStorageRule([]byte(`
id: MG-003
name: Plaintext sensitive storage (backup exposure)
severity: high
confidence: high
platform: android
blocking: true
masvs: MASVS-STORAGE-2
cwe: CWE-530
`))
	if err != nil {
		t.Fatalf("LoadStorageRule: %v", err)
	}
	return rule
}

// --- positive fixtures: one per signal subtype ---

func TestMG003_PositiveFixtures(t *testing.T) {
	cases := []struct {
		name            string
		m               *manifest.Manifest
		wantSignal      string
		wantBlocking    bool
		wantSeverity    string
		wantDetailHas   string // substring the detail text must contain
		wantDetailLacks string // substring the detail text must NOT contain
	}{
		{
			// Explicit true fires regardless of targetSdk (unlike the
			// implicit signals) — see storage.go's signal-constants comment
			// for why: the certainty/durability of the written attribute,
			// not developer intent, is what keeps this blocking at every
			// targetSdk. At high targetSdk, the detail text must name the
			// residual (cloud/D2D) risk, not claim local adb extraction.
			name:            "explicit_allow_backup_true_high_target_sdk",
			m:               &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdk(34)},
			wantSignal:      engine.SignalAllowBackupExplicit,
			wantBlocking:    true,
			wantSeverity:    "high",
			wantDetailHas:   "cloud backup",
			wantDetailLacks: "unconditionally",
		},
		{
			// At low targetSdk the local adb-extraction path is still
			// open, so the detail text must say so.
			name:          "explicit_allow_backup_true_low_target_sdk",
			m:             &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdk(23)},
			wantSignal:    engine.SignalAllowBackupExplicit,
			wantBlocking:  true,
			wantSeverity:  "high",
			wantDetailHas: "unconditionally below API 31",
		},
		{
			// Unknown targetSdk: still fires (never suppressed on unknown
			// data for the explicit signal), but must not assert either
			// extraction path is definitely open or definitely closed.
			name:          "explicit_allow_backup_true_unknown_target_sdk",
			m:             &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: nil},
			wantSignal:    engine.SignalAllowBackupExplicit,
			wantBlocking:  true,
			wantSeverity:  "high",
			wantDetailHas: "could not be determined",
		},
		{
			name:         "implicit_unset_low_target_sdk_blocking",
			m:            &manifest.Manifest{AllowBackup: manifest.Unset, TargetSdkVersion: sdk(30)},
			wantSignal:   engine.SignalAllowBackupImplicitBlock,
			wantBlocking: true,
			wantSeverity: "high",
		},
		{
			name:         "implicit_unset_at_exact_boundary_30_still_low",
			m:            &manifest.Manifest{AllowBackup: manifest.Unset, TargetSdkVersion: sdk(30)},
			wantSignal:   engine.SignalAllowBackupImplicitBlock,
			wantBlocking: true,
			wantSeverity: "high",
		},
		{
			name:         "implicit_unset_high_target_sdk_warning_tier",
			m:            &manifest.Manifest{AllowBackup: manifest.Unset, TargetSdkVersion: sdk(31)},
			wantSignal:   engine.SignalAllowBackupImplicitWarn,
			wantBlocking: false,
			wantSeverity: "medium",
		},
		{
			name:         "implicit_unset_well_above_boundary_warning_tier",
			m:            &manifest.Manifest{AllowBackup: manifest.Unset, TargetSdkVersion: sdk(34)},
			wantSignal:   engine.SignalAllowBackupImplicitWarn,
			wantBlocking: false,
			wantSeverity: "medium",
		},
	}
	scanner := engine.NewStorageScanner(mg003TestRule(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %+v", len(findings), findings)
			}
			if findings[0].PatternID != tc.wantSignal {
				t.Errorf("PatternID = %q, want %q", findings[0].PatternID, tc.wantSignal)
			}
			if findings[0].Blocking != tc.wantBlocking {
				t.Errorf("Blocking = %v, want %v: %+v", findings[0].Blocking, tc.wantBlocking, findings[0])
			}
			if findings[0].Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, tc.wantSeverity)
			}
			if tc.m.TargetSdkVersion == nil {
				if findings[0].TargetSDK != nil {
					t.Errorf("TargetSDK = %v, want nil", findings[0].TargetSDK)
				}
			} else if findings[0].TargetSDK == nil || *findings[0].TargetSDK != *tc.m.TargetSdkVersion {
				t.Errorf("TargetSDK not recorded correctly: got %v, want %v", findings[0].TargetSDK, tc.m.TargetSdkVersion)
			}
			if tc.wantDetailHas != "" && !strings.Contains(findings[0].SignalDetail, tc.wantDetailHas) {
				t.Errorf("SignalDetail = %q, want substring %q", findings[0].SignalDetail, tc.wantDetailHas)
			}
			if tc.wantDetailLacks != "" && strings.Contains(findings[0].SignalDetail, tc.wantDetailLacks) {
				t.Errorf("SignalDetail = %q, must not contain %q", findings[0].SignalDetail, tc.wantDetailLacks)
			}
		})
	}
}

// The explicit-true finding text must never claim the developer made a
// deliberate choice: android:allowBackup="true" is Android Studio's own
// new-project template default, so an explicit true is at least as often
// an untouched IDE default as a considered decision.
func TestMG003_ExplicitFindingDoesNotClaimDeliberateChoice(t *testing.T) {
	scanner := engine.NewStorageScanner(mg003TestRule(t))
	for _, sdkVal := range []*int{sdk(23), sdk(34), nil} {
		findings := scanner.CheckManifest(&manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdkVal})
		if len(findings) != 1 {
			t.Fatalf("targetSdk=%v: got %d findings, want 1", sdkVal, len(findings))
		}
		for _, banned := range []string{"deliberate", "opt-in", "opted in", "chose", "choice"} {
			if strings.Contains(strings.ToLower(findings[0].SignalDetail), banned) {
				t.Errorf("targetSdk=%v: SignalDetail contains %q, implies developer intent that isn't established: %q", sdkVal, banned, findings[0].SignalDetail)
			}
		}
	}
}

// --- negative fixtures: the acceptance gate ---

func TestMG003_NegativeFixtures(t *testing.T) {
	cases := []struct {
		name string
		m    *manifest.Manifest
	}{
		{"explicit_allow_backup_false", &manifest.Manifest{AllowBackup: manifest.False, TargetSdkVersion: sdk(23)}},
		{"unset_unknown_target_sdk_never_guessed", &manifest.Manifest{AllowBackup: manifest.Unset, TargetSdkVersion: nil}},
		{
			name: "explicit_true_but_full_backup_content_false_disabled",
			m: &manifest.Manifest{
				AllowBackup:       manifest.True,
				TargetSdkVersion:  sdk(23),
				FullBackupContent: "false",
			},
		},
		{
			name: "unset_low_sdk_but_custom_backup_agent_set",
			m: &manifest.Manifest{
				AllowBackup:      manifest.Unset,
				TargetSdkVersion: sdk(23),
				BackupAgent:      "com.example.app.MyBackupAgent",
			},
		},
		{
			// The override suppresses the implicit-low-target-sdk signal
			// too, not just the explicit one — hasBackupOverride runs
			// before the AllowBackup switch, unconditionally.
			name: "implicit_unset_low_sdk_but_full_backup_content_false_suppressed",
			m: &manifest.Manifest{
				AllowBackup:       manifest.Unset,
				TargetSdkVersion:  sdk(23),
				FullBackupContent: "false",
			},
		},
	}
	scanner := engine.NewStorageScanner(mg003TestRule(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckManifest(tc.m)
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
		})
	}
}

// fullBackupContent="true" must NOT suppress the finding — Android treats
// the literal "true" as equivalent to the unscoped default, not a real
// restriction, unlike a resource reference or the literal "false".
func TestMG003_FullBackupContentLiteralTrueIsNotAnOverride(t *testing.T) {
	scanner := engine.NewStorageScanner(mg003TestRule(t))
	m := &manifest.Manifest{
		AllowBackup:       manifest.True,
		TargetSdkVersion:  sdk(23),
		FullBackupContent: "true",
	}
	findings := scanner.CheckManifest(m)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (literal \"true\" fullBackupContent must not suppress): %+v", len(findings), findings)
	}
	if findings[0].PatternID != engine.SignalAllowBackupExplicit {
		t.Errorf("PatternID = %q, want %q", findings[0].PatternID, engine.SignalAllowBackupExplicit)
	}
}

// --- deferred override-file resolution: NeedsOverrideFileResolution / CheckOverrideFiles ---

func TestMG003_NeedsOverrideFileResolution(t *testing.T) {
	cases := []struct {
		name string
		m    *manifest.Manifest
		want bool
	}{
		{"no_override_at_all", &manifest.Manifest{AllowBackup: manifest.True}, false},
		{"full_backup_content_literal_true", &manifest.Manifest{FullBackupContent: "true"}, false},
		{"full_backup_content_literal_false", &manifest.Manifest{FullBackupContent: "false"}, false},
		{"backup_agent_only", &manifest.Manifest{BackupAgent: "com.example.app.MyBackupAgent"}, false},
		{"full_backup_content_resource_reference", &manifest.Manifest{FullBackupContent: "res/xml/backup_rules.xml"}, true},
		{"data_extraction_rules_set", &manifest.Manifest{DataExtractionRules: "res/xml/data_extraction_rules.xml"}, true},
		{
			name: "both_resource_references",
			m: &manifest.Manifest{
				FullBackupContent:   "res/xml/backup_rules.xml",
				DataExtractionRules: "res/xml/data_extraction_rules.xml",
			},
			want: true,
		},
		{
			// Resource reference takes priority even if a (largely
			// redundant) custom backupAgent is also set — the file should
			// still be checked, not silently ignored.
			name: "resource_reference_plus_backup_agent",
			m: &manifest.Manifest{
				FullBackupContent: "res/xml/backup_rules.xml",
				BackupAgent:       "com.example.app.MyBackupAgent",
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := engine.NeedsOverrideFileResolution(tc.m); got != tc.want {
				t.Errorf("NeedsOverrideFileResolution(%+v) = %v, want %v", tc.m, got, tc.want)
			}
		})
	}
}

// TestMG003_CheckOverrideFiles covers the four scenarios the suppression
// path must get right: a referenced file with real restrictions
// suppresses, an include-only file does not, an empty file does not, and
// an unresolvable/malformed file (represented here as a nil pointer —
// see cmd/mobilegate's readBackupOverrideFiles, which never propagates a
// parse/read error and returns nil in that case) does not — fail closed.
func TestMG003_CheckOverrideFiles(t *testing.T) {
	// Every case starts from a manifest that WOULD produce a blocking
	// finding absent any override — explicit allowBackup=true — so a
	// finding firing/not-firing directly reflects CheckOverrideFiles'
	// restricts decision, not some other signal.
	baseManifest := func() *manifest.Manifest {
		return &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdk(34)}
	}

	cases := []struct {
		name         string
		fbc          *backuprules.FullBackupContent
		der          *backuprules.DataExtractionRules
		wantSuppress bool
	}{
		{
			name:         "full_backup_content_has_exclude_suppresses",
			fbc:          &backuprules.FullBackupContent{HasExclude: true},
			wantSuppress: true,
		},
		{
			name:         "full_backup_content_include_only_does_not_suppress",
			fbc:          &backuprules.FullBackupContent{},
			wantSuppress: false,
		},
		{
			name:         "data_extraction_rules_disable_if_no_encryption_suppresses",
			der:          &backuprules.DataExtractionRules{CloudBackupDisableIfNoEncryption: true},
			wantSuppress: true,
		},
		{
			name:         "data_extraction_rules_empty_does_not_suppress",
			der:          &backuprules.DataExtractionRules{},
			wantSuppress: false,
		},
		{
			name:         "both_nil_unresolvable_or_malformed_does_not_suppress_fail_closed",
			fbc:          nil,
			der:          nil,
			wantSuppress: false,
		},
		{
			// One file couldn't be resolved (nil) but the other restricts —
			// OR logic, so this still suppresses.
			name:         "one_nil_one_restricts_still_suppresses",
			fbc:          nil,
			der:          &backuprules.DataExtractionRules{HasExclude: true},
			wantSuppress: true,
		},
		{
			// Both present, only one restricts — still suppresses.
			name:         "full_backup_content_restricts_data_extraction_rules_does_not",
			fbc:          &backuprules.FullBackupContent{HasRequireFlagsInclude: true},
			der:          &backuprules.DataExtractionRules{},
			wantSuppress: true,
		},
		{
			// Neither restricts — must fire.
			name:         "both_present_neither_restricts",
			fbc:          &backuprules.FullBackupContent{},
			der:          &backuprules.DataExtractionRules{},
			wantSuppress: false,
		},
	}
	scanner := engine.NewStorageScanner(mg003TestRule(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanner.CheckOverrideFiles(baseManifest(), tc.fbc, tc.der)
			gotSuppressed := len(findings) == 0
			if gotSuppressed != tc.wantSuppress {
				t.Errorf("suppressed = %v, want %v (findings: %+v)", gotSuppressed, tc.wantSuppress, findings)
			}
		})
	}
}
