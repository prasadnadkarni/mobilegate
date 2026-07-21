// Package manifest extracts the AndroidManifest.xml fields MobileGate's
// rules need. It deliberately does not expose a general-purpose manifest
// API: only the fields MG-002 (cleartext transport), MG-003 (backup
// exposure), MG-004 (exported components), and MG-010 (debuggable/
// test-only release build) depend on.
//
// It wraps github.com/shogo82148/androidbinary rather than that library's
// own apk.Manifest struct, because apk.Manifest does not model
// android:exported, android:permission, or android:usesCleartextTraffic —
// exactly the fields this tool needs. The struct tags below follow the same
// pattern androidbinary uses internally, against its low-level XML API.
package manifest

import (
	"bytes"
	"encoding/xml"
	"fmt"

	"github.com/shogo82148/androidbinary"
)

// ComponentKind identifies which manifest element a Component came from.
type ComponentKind string

const (
	KindActivity ComponentKind = "activity"
	KindService  ComponentKind = "service"
	KindReceiver ComponentKind = "receiver"
	KindProvider ComponentKind = "provider"
)

// Manifest holds the subset of AndroidManifest.xml fields MobileGate's
// rules consume.
type Manifest struct {
	PackageName           string
	UsesCleartextTraffic  Tristate
	NetworkSecurityConfig string // resource path, e.g. "@xml/network_security_config", empty if unset
	Components            []Component

	// TargetSdkVersion is nil only if it cannot be determined at all
	// (no <uses-sdk> element, or its attributes didn't resolve).
	// Resolved the same way the Android platform itself does: an
	// explicit android:targetSdkVersion, else android:minSdkVersion,
	// else 1 — needed because MG-002 must distinguish an app that
	// permits cleartext because it explicitly opted in from one that
	// permits it only because it targets API < 28, where cleartext is
	// the platform default with no explicit config at all.
	TargetSdkVersion *int

	// AllowBackup, Debuggable, TestOnly: see MG-003/MG-010. Tri-state for
	// the same reason as UsesCleartextTraffic — AllowBackup in particular
	// defaults to true when absent, so the parser must not collapse
	// "absent" into "false" and silently hide that default.
	AllowBackup Tristate
	Debuggable  Tristate
	TestOnly    Tristate

	// FullBackupContent/DataExtractionRules/BackupAgent: empty if unset.
	// May be a literal ("true"/"false", fullBackupContent only) or a
	// resource reference (e.g. "@xml/backup_rules") — MG-003 treats a
	// resource reference or a set BackupAgent as "developer took explicit
	// action," without inspecting the referenced file's content (see that
	// rule's YAML for why).
	FullBackupContent   string
	DataExtractionRules string
	BackupAgent         string

	// ApplicationPermission is android:permission on <application> — the
	// platform-documented default required permission for every
	// component that doesn't set its own android:permission. MG-004
	// needs this because a component with no permission of its own can
	// still be guarded at the application level.
	ApplicationPermission string
}

// Component is one activity/service/receiver/provider entry.
type Component struct {
	Kind       ComponentKind
	Name       string
	Exported   Tristate
	Permission string

	// IntentFilters holds each <intent-filter>'s actions/categories,
	// kept per-filter rather than flattened across all of a component's
	// filters — MG-004's launcher-activity exclusion requires MAIN and
	// LAUNCHER to appear in the SAME filter, per the platform's own
	// launcher-matching semantics; flattening would let two unrelated
	// filters (one with MAIN, a different one with LAUNCHER) produce a
	// false match. len(IntentFilters) > 0 is what MG-002's original
	// HasIntentFilter bool meant; kept obsolete name out of this comment
	// since nothing else references it anymore.
	IntentFilters []IntentFilter

	// GrantUriPermissionsAttr/HasPathPermission/HasGrantUriPermissionElement
	// are <provider>-specific; always false/zero for other component
	// kinds. See MG-004's YAML for why only HasPathPermission (not the
	// other two) factors into that rule's severity handling —
	// grantUriPermissions and <grant-uri-permission> are a sharing
	// mechanism, not an access *restriction*, so their presence doesn't
	// change whether the provider itself is guarded.
	GrantUriPermissionsAttr      bool
	HasPathPermission            bool
	HasGrantUriPermissionElement bool
}

// IntentFilter is one <intent-filter> block's actions and categories —
// only what MG-004's exclusions need (the launcher MAIN+LAUNCHER
// pattern, the widget-provider APPWIDGET_UPDATE pattern), not a general
// intent-filter model (no data/scheme/mimeType).
type IntentFilter struct {
	Actions    []string
	Categories []string
}

// HasAction reports whether this filter declares the given action name.
func (f IntentFilter) HasAction(name string) bool {
	for _, a := range f.Actions {
		if a == name {
			return true
		}
	}
	return false
}

// HasCategory reports whether this filter declares the given category name.
func (f IntentFilter) HasCategory(name string) bool {
	for _, c := range f.Categories {
		if c == name {
			return true
		}
	}
	return false
}

// Tristate distinguishes "attribute absent" from an explicit true/false,
// because Android's own default for android:exported depends on whether
// the component has an intent-filter — that decision belongs to the rule
// engine (step 2+), not the parser, so the parser must not collapse
// "absent" into "false".
type Tristate int

const (
	Unset Tristate = iota
	True
	False
)

func tristateFrom(b optionalBool) Tristate {
	if !b.set {
		return Unset
	}
	v, err := b.Bool.Bool()
	if err != nil {
		// Malformed or unresolved reference: treat as unset rather than
		// guessing — a rule that depends on this must know it couldn't be
		// determined, not silently see "false".
		return Unset
	}
	if v {
		return True
	}
	return False
}

// optionalBool wraps androidbinary.Bool to record whether the attribute
// was present at all. androidbinary.Bool.Bool() alone conflates "absent"
// and "explicit false" (both parse to false, nil), which is exactly the
// distinction Android's own exported-default logic needs upstream.
type optionalBool struct {
	androidbinary.Bool
	set bool
}

func (v *optionalBool) UnmarshalXMLAttr(attr xml.Attr) error {
	v.set = true
	return v.Bool.UnmarshalXMLAttr(attr)
}

// optionalInt32 is optionalBool's counterpart for integer attributes —
// same reasoning: androidbinary.Int32 alone can't distinguish "absent"
// from "explicitly 0".
type optionalInt32 struct {
	androidbinary.Int32
	set bool
}

func (v *optionalInt32) UnmarshalXMLAttr(attr xml.Attr) error {
	v.set = true
	return v.Int32.UnmarshalXMLAttr(attr)
}

// nameAttrXML is the shared shape of <action>/<category>: just a single
// android:name attribute, nothing else MG-004 needs.
type nameAttrXML struct {
	Name androidbinary.String `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

type intentFilterXML struct {
	Actions    []nameAttrXML `xml:"action"`
	Categories []nameAttrXML `xml:"category"`
}

// pathPermissionXML/grantUriPermissionXML: presence-only for MG-004 (see
// Component.HasPathPermission's doc comment) — no attributes read off
// them, so these are deliberately empty structs; encoding/xml still
// counts elements into a slice regardless of the element type.
type pathPermissionXML struct{}
type grantUriPermissionXML struct{}

type activityXML struct {
	Name          androidbinary.String `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      optionalBool         `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    androidbinary.String `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []intentFilterXML    `xml:"intent-filter"`

	// <provider>-only attributes/elements — absent (zero value) on
	// activity/service/receiver XML, since those elements never carry
	// them; sharing one struct across all four kinds (see
	// applicationXML below) is harmless because of that, and avoids a
	// parallel providerXML type plus a second populate function for a
	// handful of fields.
	GrantUriPermissions optionalBool            `xml:"http://schemas.android.com/apk/res/android grantUriPermissions,attr"`
	PathPermissions     []pathPermissionXML     `xml:"path-permission"`
	GrantUriPermission  []grantUriPermissionXML `xml:"grant-uri-permission"`
}

type applicationXML struct {
	UsesCleartextTraffic  optionalBool         `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	NetworkSecurityConfig androidbinary.String `xml:"http://schemas.android.com/apk/res/android networkSecurityConfig,attr"`
	AllowBackup           optionalBool         `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
	Debuggable            optionalBool         `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	TestOnly              optionalBool         `xml:"http://schemas.android.com/apk/res/android testOnly,attr"`
	FullBackupContent     androidbinary.String `xml:"http://schemas.android.com/apk/res/android fullBackupContent,attr"`
	DataExtractionRules   androidbinary.String `xml:"http://schemas.android.com/apk/res/android dataExtractionRules,attr"`
	BackupAgent           androidbinary.String `xml:"http://schemas.android.com/apk/res/android backupAgent,attr"`
	Permission            androidbinary.String `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	Activities            []activityXML        `xml:"activity"`
	Services              []activityXML        `xml:"service"`
	Receivers             []activityXML        `xml:"receiver"`
	Providers             []activityXML        `xml:"provider"`
}

type usesSDKXML struct {
	MinSdkVersion    optionalInt32 `xml:"http://schemas.android.com/apk/res/android minSdkVersion,attr"`
	TargetSdkVersion optionalInt32 `xml:"http://schemas.android.com/apk/res/android targetSdkVersion,attr"`
}

type manifestXML struct {
	Package androidbinary.String `xml:"package,attr"`
	App     applicationXML       `xml:"application"`
	UsesSDK usesSDKXML           `xml:"uses-sdk"`
}

// Parse extracts manifest fields from raw AndroidManifest.xml bytes.
// resourcesArsc may be nil; if so, attributes expressed as resource
// references (rather than literal values) resolve as unset instead of
// erroring the whole parse.
func Parse(manifestBytes, resourcesArsc []byte) (*Manifest, error) {
	xf, err := androidbinary.NewXMLFile(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("manifest: parse binary XML: %w", err)
	}

	var table *androidbinary.TableFile
	if len(resourcesArsc) > 0 {
		table, err = androidbinary.NewTableFile(bytes.NewReader(resourcesArsc))
		if err != nil {
			// Degrade gracefully: literal (non-reference) attribute values,
			// the overwhelming majority in practice, still resolve fine.
			table = nil
		}
	}

	var raw manifestXML
	if err := xf.Decode(&raw, table, nil); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}

	m := &Manifest{
		PackageName:           mustString(raw.Package),
		UsesCleartextTraffic:  tristateFrom(raw.App.UsesCleartextTraffic),
		NetworkSecurityConfig: mustString(raw.App.NetworkSecurityConfig),
		TargetSdkVersion:      resolveTargetSdk(raw.UsesSDK),
		AllowBackup:           tristateFrom(raw.App.AllowBackup),
		Debuggable:            tristateFrom(raw.App.Debuggable),
		TestOnly:              tristateFrom(raw.App.TestOnly),
		FullBackupContent:     mustString(raw.App.FullBackupContent),
		DataExtractionRules:   mustString(raw.App.DataExtractionRules),
		BackupAgent:           mustString(raw.App.BackupAgent),
		ApplicationPermission: mustString(raw.App.Permission),
	}

	m.Components = append(m.Components, componentsFrom(KindActivity, raw.App.Activities)...)
	m.Components = append(m.Components, componentsFrom(KindService, raw.App.Services)...)
	m.Components = append(m.Components, componentsFrom(KindReceiver, raw.App.Receivers)...)
	m.Components = append(m.Components, componentsFrom(KindProvider, raw.App.Providers)...)

	return m, nil
}

func componentsFrom(kind ComponentKind, xs []activityXML) []Component {
	out := make([]Component, 0, len(xs))
	for _, x := range xs {
		grantUriAttr, _ := x.GrantUriPermissions.Bool.Bool()
		out = append(out, Component{
			Kind:                         kind,
			Name:                         mustString(x.Name),
			Exported:                     tristateFrom(x.Exported),
			Permission:                   mustString(x.Permission),
			IntentFilters:                intentFiltersFrom(x.IntentFilters),
			GrantUriPermissionsAttr:      x.GrantUriPermissions.set && grantUriAttr,
			HasPathPermission:            len(x.PathPermissions) > 0,
			HasGrantUriPermissionElement: len(x.GrantUriPermission) > 0,
		})
	}
	return out
}

func intentFiltersFrom(xs []intentFilterXML) []IntentFilter {
	out := make([]IntentFilter, 0, len(xs))
	for _, x := range xs {
		out = append(out, IntentFilter{
			Actions:    namesFrom(x.Actions),
			Categories: namesFrom(x.Categories),
		})
	}
	return out
}

func namesFrom(xs []nameAttrXML) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s := mustString(x.Name); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// resolveTargetSdk mirrors the Android platform's own fallback: an
// explicit targetSdkVersion, else minSdkVersion, else 1 (the platform
// default when neither is present — vanishingly rare in a real APK, but
// this is what the OS itself does, so replicated for correctness rather
// than assumed away).
func resolveTargetSdk(sdk usesSDKXML) *int {
	if v, ok := optionalInt32Value(sdk.TargetSdkVersion); ok {
		return &v
	}
	if v, ok := optionalInt32Value(sdk.MinSdkVersion); ok {
		return &v
	}
	one := 1
	return &one
}

func optionalInt32Value(v optionalInt32) (int, bool) {
	if !v.set {
		return 0, false
	}
	n, err := v.Int32.Int32()
	if err != nil {
		return 0, false
	}
	return int(n), true
}

func mustString(s androidbinary.String) string {
	v, err := s.String()
	if err != nil {
		return ""
	}
	return v
}
