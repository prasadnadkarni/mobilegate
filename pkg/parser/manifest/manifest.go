// Package manifest extracts the AndroidManifest.xml fields MobileGate's
// rules need. It deliberately does not expose a general-purpose manifest
// API: only the fields MG-002 (cleartext transport) and MG-004 (exported
// components) depend on.
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

const androidNS = "http://schemas.android.com/apk/res/android"

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
}

// Component is one activity/service/receiver/provider entry.
type Component struct {
	Kind            ComponentKind
	Name            string
	Exported        Tristate
	Permission      string
	HasIntentFilter bool
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

type intentFilterXML struct{}

type activityXML struct {
	Name          androidbinary.String `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      optionalBool         `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    androidbinary.String `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []intentFilterXML    `xml:"intent-filter"`
}

type applicationXML struct {
	UsesCleartextTraffic  optionalBool         `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	NetworkSecurityConfig androidbinary.String `xml:"http://schemas.android.com/apk/res/android networkSecurityConfig,attr"`
	Activities            []activityXML        `xml:"activity"`
	Services              []activityXML        `xml:"service"`
	Receivers             []activityXML        `xml:"receiver"`
	Providers             []activityXML        `xml:"provider"`
}

type manifestXML struct {
	Package androidbinary.String `xml:"package,attr"`
	App     applicationXML       `xml:"application"`
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
		out = append(out, Component{
			Kind:            kind,
			Name:            mustString(x.Name),
			Exported:        tristateFrom(x.Exported),
			Permission:      mustString(x.Permission),
			HasIntentFilter: len(x.IntentFilters) > 0,
		})
	}
	return out
}

func mustString(s androidbinary.String) string {
	v, err := s.String()
	if err != nil {
		return ""
	}
	return v
}
