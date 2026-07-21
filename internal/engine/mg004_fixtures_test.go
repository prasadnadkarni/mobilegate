// This file is MG-004's acceptance-gate suite. Same relationship to
// ExportedScanner (internal/engine/exported.go) that mg002/mg003's
// fixture suites have to their scanners: manifest field resolution
// (including the intent-filter action/category extraction and provider
// fields this rule newly depends on) is independently verified —
// oracle-tested against a real APK (tools/oracle/manifest_oracle_test.go,
// mutation-tested) — so these fixtures exercise CheckManifest's
// decision logic directly against constructed manifest.Manifest values.
package engine_test

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

func mg004TestRule(t *testing.T) *engine.ExportedRuleDef {
	t.Helper()
	rule, err := engine.LoadExportedRule([]byte(`
id: MG-004
name: Exported Android component without permission protection
severity: high
confidence: high
platform: android
blocking: true
masvs: MASVS-PLATFORM-1
cwe: CWE-926
`))
	if err != nil {
		t.Fatalf("LoadExportedRule: %v", err)
	}
	return rule
}

func mainLauncherFilter() manifest.IntentFilter {
	return manifest.IntentFilter{
		Actions:    []string{"android.intent.action.MAIN"},
		Categories: []string{"android.intent.category.LAUNCHER"},
	}
}

func appWidgetUpdateFilter() manifest.IntentFilter {
	return manifest.IntentFilter{Actions: []string{"android.appwidget.action.APPWIDGET_UPDATE"}}
}

func viewFilter() manifest.IntentFilter {
	return manifest.IntentFilter{
		Actions:    []string{"android.intent.action.VIEW"},
		Categories: []string{"android.intent.category.DEFAULT"},
	}
}

// --- positive fixtures ---

func TestMG004_PositiveFixtures(t *testing.T) {
	cases := []struct {
		name               string
		m                  *manifest.Manifest
		firstPartyPackages []string
		wantSignal         string
		wantSeverity       string
	}{
		{
			// No manifest.Manifest.PackageName set, matching the other
			// cases below — isLibraryOrigin defaults an unresolved
			// package to first-party rather than guessing.
			name: "explicit_exported_activity_no_permission",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindActivity, Name: ".ExportedActivity", Exported: manifest.True},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			name: "explicit_exported_service_no_permission",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindService, Name: ".ExportedService", Exported: manifest.True},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			name: "explicit_exported_receiver_no_permission",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindReceiver, Name: ".ExportedReceiver", Exported: manifest.True},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			name: "explicit_exported_provider_no_permission_critical",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindProvider, Name: ".ExportedProvider", Exported: manifest.True},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "critical", // provider special case — see rule YAML
		},
		{
			name: "implicit_exported_via_intent_filter",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:          manifest.KindActivity,
					Name:          ".ImplicitActivity",
					Exported:      manifest.Unset,
					IntentFilters: []manifest.IntentFilter{viewFilter()},
				},
			}, TargetSdkVersion: sdk(23)}, // implicit case structurally only occurs below API 31
			wantSignal:   engine.SignalExportedImplicitFirstParty,
			wantSeverity: "high",
		},
		{
			name: "provider_with_path_permission_severity_downgraded_not_suppressed",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindProvider, Name: ".ScopedProvider", Exported: manifest.True, HasPathPermission: true},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high", // downgraded from critical, not suppressed — must still fire
		},
		{
			// Precision check for hasLauncherFilter: MAIN and LAUNCHER in
			// TWO DIFFERENT filters must NOT be treated as a launcher
			// activity — only the same-filter combination is excluded.
			name: "main_and_launcher_in_different_filters_still_fires",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:     manifest.KindActivity,
					Name:     ".TrickyActivity",
					Exported: manifest.True,
					IntentFilters: []manifest.IntentFilter{
						{Actions: []string{"android.intent.action.MAIN"}},
						{Categories: []string{"android.intent.category.LAUNCHER"}},
					},
				},
			}},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			// Origin split, confirmed against the real corpus (e.g.
			// androidx.media.session.MediaButtonReceiver in NewPipe/VLC):
			// a component whose fully-qualified name falls outside the
			// app's own manifest package is library-origin — still
			// fires, same severity, different signal/remediation.
			name: "explicit_exported_activity_library_origin",
			m: &manifest.Manifest{
				PackageName: "com.example.app",
				Components: []manifest.Component{
					{Kind: manifest.KindReceiver, Name: "androidx.media.session.MediaButtonReceiver", Exported: manifest.True},
				},
			},
			wantSignal:   engine.SignalExportedExplicitLibrary,
			wantSeverity: "high", // library origin does not lower severity
		},
		{
			name: "implicit_exported_activity_library_origin",
			m: &manifest.Manifest{
				PackageName: "com.example.app",
				Components: []manifest.Component{
					{
						Kind:          manifest.KindService,
						Name:          "org.unifiedpush.android.connector.internal.RaiseToForegroundService",
						Exported:      manifest.Unset,
						IntentFilters: []manifest.IntentFilter{viewFilter()},
					},
				},
				TargetSdkVersion: sdk(23),
			},
			wantSignal:   engine.SignalExportedImplicitLibrary,
			wantSeverity: "high",
		},
		{
			// Boundary check the other direction: a component whose
			// fully-qualified name IS prefixed by the app's own package
			// (even in a sub-package the app didn't put the manifest
			// declaration's literal dot-shorthand in) must still resolve
			// first-party, not library, once PackageName is set.
			name: "explicit_exported_activity_first_party_with_package_set",
			m: &manifest.Manifest{
				PackageName: "com.example.app",
				Components: []manifest.Component{
					{Kind: manifest.KindActivity, Name: "com.example.app.settings.SettingsActivity", Exported: manifest.True},
				},
			},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			// 2-segment org match, confirmed against the real corpus:
			// same org ("org.videolan"), different module
			// ("org.videolan.television" vs. the app's own
			// "org.videolan.vlc") — must resolve first-party, not
			// library, unlike a full-package exact match would.
			name: "explicit_exported_activity_same_org_different_module_first_party",
			m: &manifest.Manifest{
				PackageName: "org.videolan.vlc",
				Components: []manifest.Component{
					{Kind: manifest.KindActivity, Name: "org.videolan.television.ui.DetailsActivity", Exported: manifest.True},
				},
			},
			wantSignal:   engine.SignalExportedExplicitFirstParty,
			wantSeverity: "high",
		},
		{
			// policy.first_party_packages override: a component that
			// would classify as library-origin under the 2-segment
			// heuristic (different org entirely) is forced first-party
			// because the team explicitly declared it in config — same
			// override principle as MG-002's first_party_domains.
			name: "policy_first_party_packages_override",
			m: &manifest.Manifest{
				PackageName: "com.nextcloud.client",
				Components: []manifest.Component{
					{Kind: manifest.KindActivity, Name: "com.owncloud.android.ui.activity.FileDisplayActivity", Exported: manifest.True},
				},
			},
			firstPartyPackages: []string{"com.owncloud.android"},
			wantSignal:         engine.SignalExportedExplicitFirstParty,
			wantSeverity:       "high",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := engine.NewExportedScanner(mg004TestRule(t), tc.firstPartyPackages)
			findings, exclusions := scanner.CheckManifest(tc.m)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %+v (exclusions: %+v)", len(findings), findings, exclusions)
			}
			if findings[0].PatternID != tc.wantSignal {
				t.Errorf("PatternID = %q, want %q", findings[0].PatternID, tc.wantSignal)
			}
			if findings[0].Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, tc.wantSeverity)
			}
			if !findings[0].Blocking {
				t.Errorf("finding should be blocking-tier: %+v", findings[0])
			}
			if findings[0].FindingHash == "" {
				t.Error("FindingHash is empty, want a real hash")
			}
			if len(exclusions) != 0 {
				t.Errorf("got %d exclusions, want 0 for a firing case: %+v", len(exclusions), exclusions)
			}
		})
	}
}

// --- negative fixtures: the acceptance gate ---

func TestMG004_NegativeFixtures(t *testing.T) {
	cases := []struct {
		name          string
		m             *manifest.Manifest
		wantExclusion engine.ExclusionReason
		noExclusion   bool // true for cases that are simply never reachable, so no Exclusion record is expected either
	}{
		{
			name: "launcher_activity_main_and_launcher_same_filter",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:          manifest.KindActivity,
					Name:          ".MainActivity",
					Exported:      manifest.True,
					IntentFilters: []manifest.IntentFilter{mainLauncherFilter()},
				},
			}},
			wantExclusion: engine.ExclusionLauncherActivity,
		},
		{
			name: "guarded_by_app_declared_signature_permission",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindActivity, Name: ".GuardedActivity", Exported: manifest.True, Permission: "com.example.app.permission.SIGNATURE_ONLY"},
			}},
			wantExclusion: engine.ExclusionGuardedByPermission,
		},
		{
			name: "tile_service_bind_quick_settings_tile",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:          manifest.KindService,
					Name:          ".MyTileService",
					Exported:      manifest.True,
					Permission:    "android.permission.BIND_QUICK_SETTINGS_TILE",
					IntentFilters: []manifest.IntentFilter{{Actions: []string{"android.service.quicksettings.action.QS_TILE"}}},
				},
			}},
			wantExclusion: engine.ExclusionGuardedByPermission,
		},
		{
			name: "widget_receiver_appwidget_update",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:          manifest.KindReceiver,
					Name:          ".MyWidgetProvider",
					Exported:      manifest.True,
					IntentFilters: []manifest.IntentFilter{appWidgetUpdateFilter()},
				},
			}},
			wantExclusion: engine.ExclusionWidgetUpdateReceiver,
		},
		{
			name: "exported_false_explicit",
			m: &manifest.Manifest{Components: []manifest.Component{
				{
					Kind:          manifest.KindActivity,
					Name:          ".PrivateActivity",
					Exported:      manifest.False,
					IntentFilters: []manifest.IntentFilter{viewFilter()},
				},
			}},
			noExclusion: true, // never reachable at all — exported=false wins regardless of intent-filter
		},
		{
			name: "explicit_permission_set_general_case",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindService, Name: ".ProtectedService", Exported: manifest.True, Permission: "com.example.app.permission.CUSTOM"},
			}},
			wantExclusion: engine.ExclusionGuardedByPermission,
		},
		{
			// Not in the user's explicit list, but core to the spec's own
			// detection algorithm ("no android:permission on <application>
			// that would cover it") — an application-level permission must
			// cover a component with no permission of its own.
			name: "guarded_by_application_level_permission",
			m: &manifest.Manifest{
				ApplicationPermission: "com.example.app.permission.APP_LEVEL",
				Components: []manifest.Component{
					{Kind: manifest.KindActivity, Name: ".NoOwnPermissionActivity", Exported: manifest.True},
				},
			},
			wantExclusion: engine.ExclusionGuardedByPermission,
		},
		{
			name: "unset_exported_no_intent_filter_never_reachable",
			m: &manifest.Manifest{Components: []manifest.Component{
				{Kind: manifest.KindActivity, Name: ".InternalHelperActivity", Exported: manifest.Unset},
			}},
			noExclusion: true, // not reachable at all — nothing to exclude
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := engine.NewExportedScanner(mg004TestRule(t), nil)
			findings, exclusions := scanner.CheckManifest(tc.m)
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0: %+v", len(findings), findings)
			}
			if tc.noExclusion {
				if len(exclusions) != 0 {
					t.Errorf("got %d exclusions, want 0 (component was never reachable): %+v", len(exclusions), exclusions)
				}
				return
			}
			if len(exclusions) != 1 {
				t.Fatalf("got %d exclusions, want exactly 1: %+v", len(exclusions), exclusions)
			}
			if exclusions[0].Reason != tc.wantExclusion {
				t.Errorf("exclusion reason = %q, want %q", exclusions[0].Reason, tc.wantExclusion)
			}
		})
	}
}

// --- exclusion reporting: don't silently drop ---

func TestMG004_ExclusionsReportedAlongsideFindings(t *testing.T) {
	m := &manifest.Manifest{Components: []manifest.Component{
		{Kind: manifest.KindActivity, Name: ".Launcher", Exported: manifest.True, IntentFilters: []manifest.IntentFilter{mainLauncherFilter()}},
		{Kind: manifest.KindActivity, Name: ".RealFinding", Exported: manifest.True},
		{Kind: manifest.KindReceiver, Name: ".Widget", Exported: manifest.True, IntentFilters: []manifest.IntentFilter{appWidgetUpdateFilter()}},
	}}
	scanner := engine.NewExportedScanner(mg004TestRule(t), nil)
	findings, exclusions := scanner.CheckManifest(m)
	if len(findings) != 1 || findings[0].Location != "activity .RealFinding" {
		t.Fatalf("got findings=%+v, want exactly the RealFinding activity", findings)
	}
	if len(exclusions) != 2 {
		t.Fatalf("got %d exclusions, want 2 (launcher + widget), exclusions not silently dropped: %+v", len(exclusions), exclusions)
	}
}
