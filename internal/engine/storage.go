package engine

import (
	"fmt"

	"github.com/goccy/go-yaml"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// StorageRuleDef is MG-003's rule definition — a structural manifest
// check, same shape as TransportRuleDef (MG-002): no
// patterns/exclusions/entropy, since there's nothing to regex-match.
type StorageRuleDef struct {
	RuleMeta `yaml:",inline"`
}

// LoadStorageRule parses a structural-rule definition from YAML bytes.
func LoadStorageRule(data []byte) (*StorageRuleDef, error) {
	var r StorageRuleDef
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: parse rule: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing id")
	}
	return &r, nil
}

// MG-003 signal subtypes. Three, not two: an explicit opt-in and an
// implicit default both end in the same effective exposure, but at
// different confidence-in-developer-intent and (for the implicit case)
// different severity depending on platform version — see
// minADBBackupRestrictedSDK.
const (
	SignalAllowBackupExplicit      = "allow-backup-explicit"
	SignalAllowBackupImplicitBlock = "allow-backup-implicit-low-target-sdk"
	SignalAllowBackupImplicitWarn  = "allow-backup-implicit-narrowed-by-target-sdk"
)

// minADBBackupRestrictedSDK is the targetSdkVersion at and above which
// `adb backup`/`adb restore` no longer includes app data unless the app
// is also debuggable (API 31 / Android 12). Below this line, an
// unset (implicitly-true) android:allowBackup exposes app data to local
// USB/adb extraction with no further condition. At or above it, that
// specific extraction path is closed for a non-debuggable release build
// — cloud backup and device-to-device transfer can still apply, so the
// exposure is narrowed, not eliminated, hence a warning rather than
// silence, not a block.
const minADBBackupRestrictedSDK = 31

// StorageScanner evaluates a loaded MG-003 rule against manifest data.
// It does not evaluate MODE_WORLD_READABLE/WRITEABLE, external-storage
// writes, or storage-API encryption config — see
// rules/MG-003-plaintext-storage.yaml for why: all three require DEX
// method-body/bytecode analysis this parser deliberately doesn't have,
// the same wall MG-002 hit with TrustManager.
type StorageScanner struct {
	rule *StorageRuleDef
}

// NewStorageScanner builds a scanner for rule.
func NewStorageScanner(rule *StorageRuleDef) *StorageScanner {
	return &StorageScanner{rule: rule}
}

// CheckManifest evaluates android:allowBackup and its overrides.
func (s *StorageScanner) CheckManifest(m *manifest.Manifest) []Finding {
	if hasBackupOverride(m) {
		// fullBackupContent="false" is confirmed-safe (backup affirmatively
		// disabled); a referenced XML resource or a custom backupAgent
		// means the developer took explicit action whose sufficiency this
		// tool does not verify — either way, no finding. See this
		// package's and the rule YAML's comments on why guessing wrong in
		// the blocking direction here is worse than staying silent.
		return nil
	}

	switch m.AllowBackup {
	case manifest.True:
		return []Finding{s.finding(SignalAllowBackupExplicit, s.rule.Severity, true,
			"AndroidManifest.xml", "application",
			`android:allowBackup="true"`,
			"explicit android:allowBackup=\"true\" on <application>, with no fullBackupContent/dataExtractionRules override and no custom backupAgent — app data is fully backup-extractable",
			m.TargetSdkVersion)}

	case manifest.Unset:
		if m.TargetSdkVersion == nil {
			// Can't confirm which regime applies — don't guess.
			return nil
		}
		if *m.TargetSdkVersion < minADBBackupRestrictedSDK {
			return []Finding{s.finding(SignalAllowBackupImplicitBlock, s.rule.Severity, true,
				"AndroidManifest.xml", "application",
				fmt.Sprintf("targetSdkVersion=%d (no explicit allowBackup)", *m.TargetSdkVersion),
				fmt.Sprintf("no android:allowBackup is set (default is true on every Android version), and targetSdkVersion %d is below %d, where adb backup still extracts app data unconditionally", *m.TargetSdkVersion, minADBBackupRestrictedSDK),
				m.TargetSdkVersion)}
		}
		return []Finding{s.finding(SignalAllowBackupImplicitWarn, "medium", false,
			"AndroidManifest.xml", "application",
			fmt.Sprintf("targetSdkVersion=%d (no explicit allowBackup)", *m.TargetSdkVersion),
			fmt.Sprintf("no android:allowBackup is set (default is true); targetSdkVersion %d is at or above %d, so adb backup no longer extracts app data for a non-debuggable build — narrowed, not eliminated, since cloud backup and device-to-device transfer can still apply", *m.TargetSdkVersion, minADBBackupRestrictedSDK),
			m.TargetSdkVersion)}
	}
	return nil
}

// hasBackupOverride reports whether the developer took any explicit
// backup-scoping action beyond the bare allowBackup flag.
// fullBackupContent="true" is NOT an override — Android treats it as
// equivalent to the unscoped default, not a real restriction.
func hasBackupOverride(m *manifest.Manifest) bool {
	if m.FullBackupContent == "false" {
		return true
	}
	if m.FullBackupContent != "" && m.FullBackupContent != "true" {
		return true // a resource reference, e.g. "@xml/backup_rules" (resolved to its in-APK path)
	}
	if m.DataExtractionRules != "" {
		return true // always a resource reference — no boolean literal form
	}
	if m.BackupAgent != "" {
		return true
	}
	return false
}

func (s *StorageScanner) finding(signal, severity string, blocking bool, source, location, excerpt, detail string, targetSDK *int) Finding {
	return Finding{
		RuleID:       s.rule.ID,
		PatternID:    signal,
		Title:        fmt.Sprintf("App data backup-extractable (%s)", signal),
		Severity:     severity,
		Confidence:   s.rule.Confidence,
		MASVS:        s.rule.MASVS,
		CWE:          s.rule.CWE,
		Blocking:     blocking,
		Source:       source,
		Location:     location,
		Excerpt:      excerpt,
		SignalDetail: detail,
		TargetSDK:    targetSDK,
	}
}
