package engine

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/backuprules"
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

// MG-003 signal subtypes. Three, not two: an explicit value and an
// implicit default both end in the same effective exposure, but are
// reported distinctly because the underlying manifest fact differs.
// This is NOT a claim about developer intent — android:allowBackup="true"
// is the value Android Studio's own new-project manifest template ships,
// so an explicit true is, in practice, at least as often an untouched IDE
// default as it is a considered decision, which is exactly as
// unconsidered as leaving the attribute unset. Neither signal's wording
// should say or imply "the developer chose this."
//
// The API-31 adb-backup narrowing (minADBBackupRestrictedSDK) is a
// platform property of the effective allowBackup=true state, orthogonal
// to whether the attribute is explicit or implicit: it determines which
// extraction paths (local adb vs. cloud/device-to-device only) are
// actually open, and the same targetSdk-conditional wording logic
// (explicitAllowBackupDetail below) applies to both.
//
// Blocking tier still differs by signal, but on a narrower basis than
// intent: SignalAllowBackupExplicit blocks at every targetSdk, because
// its underlying fact (the attribute IS true, unconditionally, in this
// build and every future one until someone edits the line) is more
// certain and more durable than an inherited platform default that
// could shift with a future Android release. SignalAllowBackupImplicitWarn
// downgrades specifically because it stacks two lower-certainty
// conditions at once — nothing was written down, AND the specific local-
// extraction path that made the low-targetSdk case unconditionally
// blocking is closed — not because the app "didn't mean it" any less
// than an explicit true would have.
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

// CheckManifest evaluates android:allowBackup and the overrides that
// need no file I/O to resolve (fullBackupContent="false", a custom
// backupAgent). If a resource-reference override is present
// (fullBackupContent or dataExtractionRules pointing at an XML
// resource), the decision is deferred: this returns nil, and the
// caller must check NeedsOverrideFileResolution, resolve+parse the
// referenced file(s) via pkg/parser/backuprules, and call
// CheckOverrideFiles with the result — see that method's comment for
// why file content can change the answer.
func (s *StorageScanner) CheckManifest(m *manifest.Manifest) []Finding {
	if hasFreeBackupOverride(m) {
		return nil
	}
	if NeedsOverrideFileResolution(m) {
		return nil
	}
	return s.allowBackupFinding(m)
}

// NeedsOverrideFileResolution reports whether m has a
// fullBackupContent or dataExtractionRules attribute referencing an XML
// resource (rather than being unset, "true", or the free-override
// "false") — meaning CheckManifest's decision was deferred pending that
// file's content, and the caller must resolve it before calling
// CheckOverrideRestriction. Checked independently of hasFreeBackupOverride
// so a resource reference is still flagged as needing resolution even if,
// say, a custom backupAgent is ALSO set (rare, but the file should still
// be checked rather than silently ignored).
func NeedsOverrideFileResolution(m *manifest.Manifest) bool {
	return fullBackupContentIsResourceRef(m) || m.DataExtractionRules != ""
}

// fullBackupContentIsResourceRef reports whether m.FullBackupContent
// names an XML resource rather than being unset or one of the two
// boolean literals ("true"/"false") the legacy attribute also accepts.
func fullBackupContentIsResourceRef(m *manifest.Manifest) bool {
	return m.FullBackupContent != "" && m.FullBackupContent != "true" && m.FullBackupContent != "false"
}

// CheckOverrideFiles finalizes MG-003's decision for an app whose
// CheckManifest call deferred via NeedsOverrideFileResolution, using
// the parsed content of whichever override file(s) were referenced.
// Either parameter may be nil — because that attribute wasn't a
// resource reference (see fullBackupContentIsResourceRef/
// m.DataExtractionRules), or because the caller could not read or parse
// the referenced file. A nil parameter contributes nothing toward
// suppression: fail closed, since an unresolvable or malformed override
// file is not evidence the developer scoped anything — it must not
// silently protect a finding from firing.
//
// Suppresses (no finding) if EITHER supplied file expresses a
// structural restriction, per FullBackupContent.Restricts() /
// DataExtractionRules.Restricts() — an <exclude>, a requireFlags-gated
// <include>, or disableIfNoEncryptionCapabilities="true" on
// <cloud-backup>. See this rule's YAML for a known precedence caveat:
// on API 31+ devices the platform honors dataExtractionRules and
// ignores fullBackupContent entirely, so checking both with OR can
// suppress on a fullBackupContent file the platform wouldn't actually
// consult on a modern device — conservative in the safe direction
// (never fails to suppress on the file that IS honored), not modeled
// further.
func (s *StorageScanner) CheckOverrideFiles(m *manifest.Manifest, fullBackupContent *backuprules.FullBackupContent, dataExtractionRules *backuprules.DataExtractionRules) []Finding {
	if fullBackupContent != nil && fullBackupContent.Restricts() {
		return nil
	}
	if dataExtractionRules != nil && dataExtractionRules.Restricts() {
		return nil
	}
	return s.allowBackupFinding(m)
}

// allowBackupFinding is the shared AllowBackup decision, called once
// CheckManifest or CheckOverrideRestriction has determined no override
// suppresses it.
func (s *StorageScanner) allowBackupFinding(m *manifest.Manifest) []Finding {
	switch m.AllowBackup {
	case manifest.True:
		return []Finding{s.finding(SignalAllowBackupExplicit, s.rule.Severity, true,
			"AndroidManifest.xml", "application",
			`android:allowBackup="true"`,
			explicitAllowBackupDetail(m.TargetSdkVersion),
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

// explicitAllowBackupDetail builds SignalAllowBackupExplicit's evidence
// text, selected by targetSDK the same way the implicit signals already
// are — see the const block above for why this must not, in either
// branch, describe android:allowBackup="true" as a deliberate choice.
func explicitAllowBackupDetail(targetSDK *int) string {
	switch {
	case targetSDK == nil:
		return `android:allowBackup="true" is set on <application>, with no fullBackupContent/dataExtractionRules override and no custom backupAgent. targetSdkVersion could not be determined, so it's unknown whether the API 31 adb-backup restriction (local extraction closed for non-debuggable builds) applies here — treat both local (adb backup/restore) and cloud/device-to-device backup as potential extraction paths`
	case *targetSDK < minADBBackupRestrictedSDK:
		return fmt.Sprintf(`android:allowBackup="true" is set on <application> (targetSdkVersion=%d, below %d), with no fullBackupContent/dataExtractionRules override and no custom backupAgent — app data is extractable via adb backup/restore, unconditionally below API %d, as well as via cloud backup and device-to-device transfer`, *targetSDK, minADBBackupRestrictedSDK, minADBBackupRestrictedSDK)
	default:
		return fmt.Sprintf(`android:allowBackup="true" is set on <application> (targetSdkVersion=%d, at or above %d), with no fullBackupContent/dataExtractionRules override and no custom backupAgent. Local extraction via adb backup is closed for a non-debuggable build at this targetSdk, but app data still replicates to the user's cloud backup account and via device-to-device transfer — the residual risk is off-device replication, not local USB/adb extraction`, *targetSDK, minADBBackupRestrictedSDK)
	}
}

// hasFreeBackupOverride reports whether the developer took a backup-
// scoping action that needs no file I/O to resolve: fullBackupContent
// set to the literal "false" (backup affirmatively disabled — NOT
// "true", which Android treats as equivalent to the unscoped default,
// not a real restriction), or a custom android:backupAgent class. A
// custom agent's actual behavior would need DEX method-body/bytecode
// analysis to verify — the same permanently-out-of-scope wall as
// MG-002's TrustManager gap — so its mere presence is still blindly
// trusted as an override, unlike the resource-reference case (see
// NeedsOverrideFileResolution), which this parser CAN read.
func hasFreeBackupOverride(m *manifest.Manifest) bool {
	if m.FullBackupContent == "false" {
		return true
	}
	if m.BackupAgent != "" {
		return true
	}
	return false
}

// finding builds a Finding for one of MG-003's three signals. severity/
// blocking are per-call parameters, not always s.rule.Severity/
// s.rule.Blocking, because this is the one rule with an internal
// blocking/warning split (SignalAllowBackupImplicitWarn downgrades at
// high targetSdk — see the signal-constants comment above). WhyItBlocks
// reuses detail, same reasoning as transport.go's finding — these
// signal texts are already targetSdk-accurate explanations, and a
// second static narrative risks contradicting that precision.
func (s *StorageScanner) finding(signal, severity string, blocking bool, source, location, excerpt, detail string, targetSDK *int) Finding {
	return Finding{
		RuleID:       s.rule.ID,
		RuleName:     s.rule.Name,
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
		WhyItBlocks:  detail,
		Remediation:  strings.TrimSpace(s.rule.Remediation),
		TargetSDK:    targetSDK,
		FindingHash:  core.ComputeFindingHash(s.rule.ID, source, signal, excerpt),
	}
}
