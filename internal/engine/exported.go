package engine

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// ExportedRuleDef is MG-004's rule definition — a structural manifest
// check, same shape as TransportRuleDef/StorageRuleDef/HygieneRuleDef:
// no patterns/exclusions/entropy, since there's nothing to regex-match.
type ExportedRuleDef struct {
	RuleMeta `yaml:",inline"`
}

// LoadExportedRule parses a structural-rule definition from YAML bytes.
func LoadExportedRule(data []byte) (*ExportedRuleDef, error) {
	var r ExportedRuleDef
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: parse rule: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("engine: rule is missing id")
	}
	return &r, nil
}

// MG-004 signal subtypes — four, not two. Two independent axes, each
// changing the correct remediation text, so neither collapses into the
// other (same "don't collapse subtypes" discipline as MG-002's four
// signals):
//
//  1. Reachability mechanism — explicit vs. implicit. An explicit
//     android:exported="true" is a fact the developer wrote down; an
//     unset exported relying on the pre-API-31 has-an-intent-filter
//     default is a platform default the developer never engaged with
//     at all (API 31 made stating it mandatory, so this case only
//     exists on lower-target apps).
//
//  2. Origin — first-party vs. library. Confirmed against the real
//     12-app corpus: androidx.media.session.MediaButtonReceiver,
//     org.unifiedpush.android.connector.internal's service/receiver,
//     and androidx.profileinstaller.ProfileInstallReceiver all arrive
//     via Android's build-time manifest merger, not this app's own
//     manifest source — the app developer never wrote these component
//     declarations at all, so "just add android:permission to your
//     component" is the wrong instruction; the actual remediation is a
//     manifest-merger override (tools:node) or a documented decision to
//     accept the dependency's exposure. A first-party component is the
//     opposite: the developer wrote the declaration directly, and can
//     fix it by editing this app's own manifest.
//
// Deliberately NOT a suppression: a library-origin component is not
// treated as safer or less real. It can be genuinely exploited exactly
// like a first-party one — the finding still fires, at the same
// severity. Only the remediation differs, because the fix location
// differs. See rules/MG-004-exported-component.yaml for the full
// reasoning, including why this is a different disposition than either
// MG-003's suppression or MG-004's own provider-severity downgrade.
const (
	SignalExportedExplicitFirstParty = "exported-explicit-no-permission-first-party"
	SignalExportedExplicitLibrary    = "exported-explicit-no-permission-library"
	SignalExportedImplicitFirstParty = "exported-implicit-intent-filter-no-permission-first-party"
	SignalExportedImplicitLibrary    = "exported-implicit-intent-filter-no-permission-library"
)

// reachability mechanism — internal to this file; combined with origin
// in signalFor to produce one of the four exported Signal constants.
const (
	mechanismExplicit = "explicit"
	mechanismImplicit = "implicit"
)

// Well-known intent action/category names this rule's exclusions match
// against — not a general intent-filter model, just the specific
// platform-mandated patterns spec'd for this rule.
const (
	actionMain            = "android.intent.action.MAIN"
	categoryLauncher      = "android.intent.category.LAUNCHER"
	actionAppWidgetUpdate = "android.appwidget.action.APPWIDGET_UPDATE" // #nosec G101 -- an Android platform intent-action string, not a credential; gosec's heuristic false-positives on the shape
)

// ExclusionReason names why a reachable, otherwise-candidate component
// was excluded from firing — spec: "Report exclusions applied; don't
// silently drop." Only components that clear the reachability check
// (see reachability) but then get excluded are recorded; a component
// that was never reachable at all (exported="false", or unset with no
// intent-filter) isn't a candidate in the first place, so there's
// nothing to report for it.
type ExclusionReason string

const (
	ExclusionLauncherActivity     ExclusionReason = "launcher-activity"      // MAIN+LAUNCHER in the same <intent-filter>
	ExclusionWidgetUpdateReceiver ExclusionReason = "widget-update-receiver" // <intent-filter> with APPWIDGET_UPDATE
	ExclusionGuardedByPermission  ExclusionReason = "guarded-by-permission"  // component or <application> android:permission set
)

// Exclusion pairs a component with why it didn't fire.
type Exclusion struct {
	Component manifest.Component
	Reason    ExclusionReason
}

// severity tiers — see rules/MG-004-exported-component.yaml for the
// full reasoning, including why a provider's severity is elevated and
// what <path-permission> does and doesn't do to that.
const (
	severityDefault        = "high"     // exported, unguarded activity/service/receiver
	severityProvider       = "critical" // exported, unguarded provider — direct data exposure, not just an invokable component
	severityProviderScoped = "high"     // exported, unguarded provider that DOES declare <path-permission> — partial, unverified scoping brings it back to the default tier, not below it
)

// ExportedScanner evaluates a loaded MG-004 rule against manifest data.
// Manifest-only, deterministic — no DEX/bytecode analysis, per spec:
// "no new parser packages... manifest data only."
type ExportedScanner struct {
	rule *ExportedRuleDef

	// firstPartyPackages overrides the origin heuristic (see
	// isLibraryOrigin) — same principle, and same config location
	// (policy.first_party_packages in .mobilegate.yml), as MG-002's
	// policy.first_party_domains: the team knows its own package roots
	// better than any inferred heuristic can, so a reviewed config entry
	// always wins over the default 2-segment org match.
	firstPartyPackages []string
}

// NewExportedScanner builds a scanner for rule. firstPartyPackages comes
// from policy.first_party_packages in .mobilegate.yml — may be nil, in
// which case the default 2-segment org heuristic alone decides origin.
func NewExportedScanner(rule *ExportedRuleDef, firstPartyPackages []string) *ExportedScanner {
	return &ExportedScanner{rule: rule, firstPartyPackages: firstPartyPackages}
}

// CheckManifest evaluates every component for reachability, applies the
// exclusions, and returns both the findings and the exclusions that
// were applied — the latter purely for visibility (dev-facing debug
// dump, corpus verification), never part of the gate's finding output.
func (s *ExportedScanner) CheckManifest(m *manifest.Manifest) ([]Finding, []Exclusion) {
	var findings []Finding
	var exclusions []Exclusion

	for _, c := range m.Components {
		mechanism, reachable := reachability(c)
		if !reachable {
			continue
		}

		if c.Kind == manifest.KindActivity && hasLauncherFilter(c) {
			exclusions = append(exclusions, Exclusion{Component: c, Reason: ExclusionLauncherActivity})
			continue
		}
		if c.Kind == manifest.KindReceiver && hasActionFilter(c, actionAppWidgetUpdate) {
			exclusions = append(exclusions, Exclusion{Component: c, Reason: ExclusionWidgetUpdateReceiver})
			continue
		}
		if c.Permission != "" || m.ApplicationPermission != "" {
			exclusions = append(exclusions, Exclusion{Component: c, Reason: ExclusionGuardedByPermission})
			continue
		}

		isLibrary := isLibraryOrigin(c.Name, m.PackageName, s.firstPartyPackages)
		signal := signalFor(mechanism, isLibrary)
		findings = append(findings, s.finding(signal, c, m.TargetSdkVersion))
	}

	return findings, exclusions
}

// reachability reports whether c is externally reachable at all, and
// which signal that reachability came from. Exported="false" is never
// reachable regardless of intent-filters — an explicit false always
// wins. Exported unset with no intent-filter defaults to NOT exported
// (the platform's own default for a component with no filter), so
// that's not reachable either.
func reachability(c manifest.Component) (mechanism string, reachable bool) {
	switch c.Exported {
	case manifest.True:
		return mechanismExplicit, true
	case manifest.Unset:
		if len(c.IntentFilters) > 0 {
			return mechanismImplicit, true
		}
	}
	return "", false
}

// signalFor combines the reachability mechanism with origin into one of
// the four exported Signal constants.
func signalFor(mechanism string, isLibrary bool) string {
	switch mechanism {
	case mechanismExplicit:
		if isLibrary {
			return SignalExportedExplicitLibrary
		}
		return SignalExportedExplicitFirstParty
	case mechanismImplicit:
		if isLibrary {
			return SignalExportedImplicitLibrary
		}
		return SignalExportedImplicitFirstParty
	}
	return ""
}

// isLibraryOrigin reports whether c's fully-qualified class name is
// outside the app's own org — the deterministic signal that a component
// was injected by a dependency via Android's build-time manifest merger
// rather than declared in this app's own manifest source.
//
// Two layers, config always wins:
//
//  1. firstPartyPackages (policy.first_party_packages in .mobilegate.yml,
//     same mechanism as MG-002's policy.first_party_domains): if
//     componentName falls under any configured entry, it's first-party,
//     full stop. The team knows its own package roots — forks,
//     acquisitions, renames, and white-label builds all break any
//     inferred heuristic, so a reviewed config entry is the only way to
//     close that gap completely rather than chase it with more
//     heuristic layers.
//
//  2. Default heuristic: 2-segment reverse-DNS org match (e.g.
//     "org.mozilla" from "org.mozilla.fenix.HomeActivity"), not a full
//     exact-package match. A full-package match was tried first and
//     rejected: confirmed against the real 12-app corpus that it
//     misclassifies genuinely first-party code as library in 5 of 12
//     apps, via two recurring, structural causes — Android build-flavor
//     applicationId suffixes (Fennec's manifest package is
//     org.mozilla.fennec_fdroid, an F-Droid rebrand, but its code is
//     org.mozilla.fenix.*; KeePassDX's is com.kunzisoft.keepass.libre
//     vs. code under com.kunzisoft.keepass.*) and same-org multi-module
//     package roots (VLC's Android-TV UI lives under
//     org.videolan.television.*, not org.videolan.vlc.*). The 2-segment
//     match fixes all of these while still correctly catching every
//     confirmed genuine third-party case in the corpus (androidx.*,
//     org.unifiedpush.*, com.canhub.*, com.adjust.*, mozilla.components.*
//     — none share even the org segment with any app's own identity).
//
// Design principle for anything still ambiguous after both layers: fail
// toward first-party. Mislabeling a developer's own code as "library"
// tells them to ignore a finding they own — worse than the reverse,
// where library code gets first-party remediation text and the
// developer correctly concludes on inspection that it's a dependency.
// This is why an unresolved appPackage, or a componentName with no
// dot at all, resolves to first-party rather than library.
//
// Known remaining gap, confirmed against the real corpus rather than
// theorized: this does NOT fully solve Nextcloud, whose client ships
// legacy com.owncloud.android.* classes from its fork history alongside
// its actual com.nextcloud.client package — a different org entirely,
// not fixable by any segment-count heuristic. Only
// policy.first_party_packages closes that one.
func isLibraryOrigin(componentName, appPackage string, firstPartyPackages []string) bool {
	for _, pkg := range firstPartyPackages {
		if pkg == "" {
			continue
		}
		if componentName == pkg || strings.HasPrefix(componentName, pkg+".") {
			return false
		}
	}

	if appPackage == "" {
		return false // unresolved package: don't guess, default to first-party
	}
	org := twoSegmentOrg(appPackage)
	if org == "" {
		return false
	}
	return componentName != org && !strings.HasPrefix(componentName, org+".")
}

// twoSegmentOrg returns the first two dot-segments of a package name —
// the reverse-DNS org identity, e.g. "org.mozilla" from
// "org.mozilla.fenix". Returns pkg unchanged if it has fewer than two
// segments (nothing to trim, and matching against the whole thing is
// still the most conservative available comparison).
func twoSegmentOrg(pkg string) string {
	parts := strings.SplitN(pkg, ".", 3)
	if len(parts) < 2 {
		return pkg
	}
	return parts[0] + "." + parts[1]
}

// componentPackage returns the package portion of a fully-qualified
// class name (everything before the final segment) — used only for
// library-origin remediation text, to name which dependency a finding
// came from without needing real dependency-graph resolution.
func componentPackage(componentName string) string {
	i := strings.LastIndex(componentName, ".")
	if i < 0 {
		return componentName
	}
	return componentName[:i]
}

// hasLauncherFilter reports whether any SINGLE <intent-filter> on c
// contains both MAIN and LAUNCHER — checked per-filter, not by
// flattening actions/categories across all of a component's filters,
// because that's how the platform itself decides "is this a launcher
// entry." A component with one filter carrying MAIN (for some other
// purpose) and a different filter carrying LAUNCHER (unlikely, but
// possible) is not a launcher activity, and must not be excluded as one.
func hasLauncherFilter(c manifest.Component) bool {
	for _, f := range c.IntentFilters {
		if f.HasAction(actionMain) && f.HasCategory(categoryLauncher) {
			return true
		}
	}
	return false
}

// hasActionFilter reports whether any of c's intent-filters declare the
// given action.
func hasActionFilter(c manifest.Component, action string) bool {
	for _, f := range c.IntentFilters {
		if f.HasAction(action) {
			return true
		}
	}
	return false
}

func (s *ExportedScanner) finding(signal string, c manifest.Component, targetSDK *int) Finding {
	excerpt, detail, remediation := explanationFor(signal, c)
	severity := s.severityFor(c)

	return Finding{
		RuleID:       s.rule.ID,
		RuleName:     s.rule.Name,
		PatternID:    signal,
		Title:        fmt.Sprintf("Exported %s reachable without a permission guard (%s)", c.Kind, signal),
		Severity:     severity,
		Confidence:   s.rule.Confidence,
		MASVS:        s.rule.MASVS,
		CWE:          s.rule.CWE,
		Blocking:     s.rule.Blocking,
		Source:       "AndroidManifest.xml",
		Location:     fmt.Sprintf("%s %s", c.Kind, c.Name),
		Excerpt:      excerpt,
		SignalDetail: detail,
		WhyItBlocks:  detail,
		Remediation:  remediation,
		TargetSDK:    targetSDK,
		FindingHash:  core.ComputeFindingHash(s.rule.ID, "AndroidManifest.xml", signal, excerpt),
	}
}

// severityFor implements the provider special case: a provider is
// elevated above the default tier because an unguarded exported
// ContentProvider exposes data directly, not just an invokable
// component — but if it declares <path-permission>, that's brought
// back down to the default tier, not suppressed and not below the
// default, because path-level scoping is real, unverified-for-
// completeness evidence, not proof every reachable path is covered.
// android:grantUriPermissions / <grant-uri-permission> deliberately do
// NOT affect this — see rules/MG-004-exported-component.yaml for why
// (a sharing mechanism, not an access restriction).
func (s *ExportedScanner) severityFor(c manifest.Component) string {
	if c.Kind != manifest.KindProvider {
		return severityDefault
	}
	if c.HasPathPermission {
		return severityProviderScoped
	}
	return severityProvider
}

// explanationFor builds the excerpt/detail/remediation text. Excerpt and
// the mechanical half of detail are driven by the reachability
// mechanism alone (explicit vs. implicit) — spec: "Different remediation
// text: explicit means someone wrote exported="true"; implicit means
// they relied on a platform default that changed in API 31." Detail
// additionally names the actual attack (any installed app can invoke
// this via a crafted intent), not just the config state — spec:
// "why_it_blocks text explaining the actual attack... not just the
// config state." Remediation is where origin changes the text
// completely: a first-party finding is fixed by editing this app's own
// manifest; a library-origin finding was never written by this app's
// developer at all, so "add android:permission to your component" is
// simply the wrong instruction — see the Signal constants' doc comment
// and rules/MG-004-exported-component.yaml for the full reasoning.
func explanationFor(signal string, c manifest.Component) (excerpt, detail, remediation string) {
	isLibrary := signal == SignalExportedExplicitLibrary || signal == SignalExportedImplicitLibrary
	isExplicit := signal == SignalExportedExplicitFirstParty || signal == SignalExportedExplicitLibrary

	if isExplicit {
		excerpt = fmt.Sprintf(`android:exported="true" on <%s android:name=%q>, no android:permission`, c.Kind, c.Name)
		detail = fmt.Sprintf("android:exported=\"true\" is explicitly set on this %s with no android:permission (on the %s itself or on <application>) — any app installed on the device can invoke it directly with a crafted Intent, without the user ever seeing this app's own UI, since Android's component-level access control is the only thing standing between an installed app and this %s.", c.Kind, c.Kind, c.Kind)
	} else {
		excerpt = fmt.Sprintf(`android:exported unset (has <intent-filter>) on <%s android:name=%q>, no android:permission`, c.Kind, c.Name)
		detail = fmt.Sprintf("android:exported is not set on this %s, but it has an <intent-filter> — on the targetSdkVersion this app declares, the platform's own default for that combination is exported=true, so this %s is reachable by any installed app via a crafted Intent even though nobody wrote that down. Starting at API 31, android:exported became mandatory to state explicitly whenever a component has an intent-filter, precisely because this implicit default was a common source of accidental exposure.", c.Kind, c.Kind)
	}

	if isLibrary {
		pkg := componentPackage(c.Name)
		detail += fmt.Sprintf(" This %s is declared by a third-party dependency (%s), not this app's own manifest source — it reached the merged AndroidManifest.xml via Android's build-time manifest merger. It is exploitable exactly the same way as a first-party component; only the fix location differs.", c.Kind, pkg)
		remediation = fmt.Sprintf("This %s comes from a dependency (%s), not this app's own code — editing this app's manifest source directly won't touch it. Either override it explicitly in this app's own AndroidManifest.xml with a <%s android:name=%q tools:node=\"merge\"> block that adds android:permission (or tools:node=\"remove\" if the app doesn't need the functionality), or check %s's own documentation/issue tracker for whether this exposure is intentional and, if so, accept it as a reviewed, known risk rather than an oversight.", c.Kind, pkg, c.Kind, c.Name, pkg)
		return excerpt, detail, remediation
	}

	if isExplicit {
		remediation = fmt.Sprintf("Someone explicitly wrote android:exported=\"true\" on this %s. If it genuinely needs to be reachable by other apps, add android:permission with a signature-level permission this app declares (<permission android:protectionLevel=\"signature\">) so only your own other apps can reach it — or a documented platform permission if the intent is broader. If it doesn't need to be reachable at all, set android:exported=\"false\".", c.Kind)
	} else {
		remediation = fmt.Sprintf("Nobody wrote android:exported on this %s — it's reachable only because the platform's pre-API-31 default for a component with an <intent-filter> is exported=true. Decide deliberately: if it needs to be reachable, add android:exported=\"true\" explicitly plus an android:permission guard; if not, add android:exported=\"false\". Bumping targetSdkVersion to 31+ alone does not fix this — it only makes the platform refuse to build without the attribute being stated, it doesn't choose a safe value for you.", c.Kind)
	}
	return excerpt, detail, remediation
}
