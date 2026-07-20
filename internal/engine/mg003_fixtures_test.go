// This file is MG-003's acceptance-gate suite. Same relationship to
// StorageScanner (internal/engine/storage.go) that mg002_fixtures_test.go
// has to TransportScanner: manifest field resolution is already
// independently verified (oracle-tested against real APKs, unit-tested in
// pkg/parser/manifest), so these fixtures exercise CheckManifest's
// decision logic directly against constructed manifest.Manifest values,
// not full APK bytes.
package engine_test

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
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
		name         string
		m            *manifest.Manifest
		wantSignal   string
		wantBlocking bool
		wantSeverity string
	}{
		{
			name:         "explicit_allow_backup_true_high_target_sdk",
			m:            &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdk(34)},
			wantSignal:   engine.SignalAllowBackupExplicit,
			wantBlocking: true,
			wantSeverity: "high",
		},
		{
			// Explicit opt-in fires regardless of targetSdk — the API-31
			// adb-backup narrowing doesn't soften a deliberate choice.
			name:         "explicit_allow_backup_true_low_target_sdk",
			m:            &manifest.Manifest{AllowBackup: manifest.True, TargetSdkVersion: sdk(23)},
			wantSignal:   engine.SignalAllowBackupExplicit,
			wantBlocking: true,
			wantSeverity: "high",
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
			if findings[0].TargetSDK == nil || *findings[0].TargetSDK != *tc.m.TargetSdkVersion {
				t.Errorf("TargetSDK not recorded correctly: got %v, want %v", findings[0].TargetSDK, tc.m.TargetSdkVersion)
			}
		})
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
			name: "explicit_true_but_full_backup_content_resource_reference",
			m: &manifest.Manifest{
				AllowBackup:       manifest.True,
				TargetSdkVersion:  sdk(23),
				FullBackupContent: "res/xml/backup_rules.xml",
			},
		},
		{
			name: "unset_low_sdk_but_data_extraction_rules_set",
			m: &manifest.Manifest{
				AllowBackup:         manifest.Unset,
				TargetSdkVersion:    sdk(23),
				DataExtractionRules: "res/xml/data_extraction_rules.xml",
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
