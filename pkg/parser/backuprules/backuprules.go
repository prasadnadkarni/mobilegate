// Package backuprules parses android:fullBackupContent (legacy Auto
// Backup) and android:dataExtractionRules (API 31+) resource files far
// enough to answer MG-003's structural question: does the referenced
// file express ANY restriction on backup content at all? It does not
// evaluate whether that restriction is sufficient for a given app's
// actual sensitive data — see rules/MG-003-plaintext-storage.yaml for
// why that judgment is deliberately out of scope.
//
// Every fact this package needs lives in element attributes
// (domain/path/requireFlags/disableIfNoEncryptionCapabilities), not
// element text — confirmed against Android's own schema docs
// (developer.android.com/guide/topics/data/autobackup). Unlike
// network_security_config.xml (pkg/parser/nsc), which needed a custom
// CDATA-aware tree walker because <domain> text is the one thing
// androidbinary's own reader silently drops, this package reuses
// androidbinary's struct-tag XML decode directly — the same mechanism
// pkg/parser/manifest already uses — with no custom binary-XML-walking
// code required.
//
// Schema attributes covered, per the docs above (checked deliberately,
// after MG-003's Conversations corpus case showed the "any <exclude>"
// signal alone false-positives on a real app that restricts backup
// entirely through requireFlags/disableIfNoEncryptionCapabilities
// instead):
//
//   - <full-backup-content>: <include>/<exclude domain= path=>, plus
//     <include requireFlags="clientSideEncryption|deviceToDeviceTransfer">
//     (API 28+) — a documented, structural restriction mechanism
//     distinct from <exclude>.
//   - <data-extraction-rules>: <cloud-backup
//     disableIfNoEncryptionCapabilities="true|false">,
//     <device-transfer>, and <cross-platform-transfer platform="ios">
//     (all API 31+), each containing <include>/<exclude domain= path=>.
//     requireFlags is NOT part of this schema — cloud-backup vs.
//     device-transfer vs. cross-platform-transfer already splits what
//     requireFlags used to gate in the legacy schema.
package backuprules

import (
	"bytes"
	"fmt"

	"github.com/shogo82148/androidbinary"
)

// includeExcludeXML models the attributes shared by <include>/<exclude>
// in both schemas. RequireFlags is legacy-only (fullBackupContent), but
// declaring it here too is harmless: it simply resolves empty for a
// dataExtractionRules file, which never sets it.
type includeExcludeXML struct {
	RequireFlags androidbinary.String `xml:"requireFlags,attr"`
}

type fullBackupContentXML struct {
	Includes []includeExcludeXML `xml:"include"`
	Excludes []includeExcludeXML `xml:"exclude"`
}

// FullBackupContent is the structural facts extracted from a legacy
// android:fullBackupContent resource file.
type FullBackupContent struct {
	HasExclude             bool
	HasRequireFlagsInclude bool
}

// Restricts reports whether the file expresses any restriction at all:
// an <exclude> element, or an <include> gated by requireFlags (e.g.
// requireFlags="clientSideEncryption") — both are documented,
// structural restriction mechanisms. Neither element's path/domain
// content is inspected for sufficiency.
func (f FullBackupContent) Restricts() bool {
	return f.HasExclude || f.HasRequireFlagsInclude
}

// ParseFullBackupContent extracts structural facts from a compiled
// full-backup-content XML resource. resourcesArsc may be nil.
func ParseFullBackupContent(data, resourcesArsc []byte) (FullBackupContent, error) {
	var raw fullBackupContentXML
	if err := decode(data, resourcesArsc, &raw); err != nil {
		return FullBackupContent{}, fmt.Errorf("backuprules: parse full-backup-content: %w", err)
	}
	out := FullBackupContent{HasExclude: len(raw.Excludes) > 0}
	for _, inc := range raw.Includes {
		if flags, _ := inc.RequireFlags.String(); flags != "" {
			out.HasRequireFlagsInclude = true
			break
		}
	}
	return out, nil
}

type cloudBackupXML struct {
	DisableIfNoEncryptionCapabilities androidbinary.Bool  `xml:"disableIfNoEncryptionCapabilities,attr"`
	Excludes                          []includeExcludeXML `xml:"exclude"`
}

type deviceTransferXML struct {
	Excludes []includeExcludeXML `xml:"exclude"`
}

type crossPlatformTransferXML struct {
	Excludes []includeExcludeXML `xml:"exclude"`
}

type dataExtractionRulesXML struct {
	CloudBackup           *cloudBackupXML           `xml:"cloud-backup"`
	DeviceTransfer        *deviceTransferXML        `xml:"device-transfer"`
	CrossPlatformTransfer *crossPlatformTransferXML `xml:"cross-platform-transfer"`
}

// DataExtractionRules is the structural facts extracted from an
// android:dataExtractionRules (API 31+) resource file.
type DataExtractionRules struct {
	HasExclude                       bool
	CloudBackupDisableIfNoEncryption bool
}

// Restricts reports whether the file expresses any restriction at all:
// an <exclude> element anywhere (cloud-backup, device-transfer, or
// cross-platform-transfer), or disableIfNoEncryptionCapabilities="true"
// on <cloud-backup> — both documented, structural restriction
// mechanisms.
func (d DataExtractionRules) Restricts() bool {
	return d.HasExclude || d.CloudBackupDisableIfNoEncryption
}

// ParseDataExtractionRules extracts structural facts from a compiled
// data-extraction-rules XML resource. resourcesArsc may be nil.
func ParseDataExtractionRules(data, resourcesArsc []byte) (DataExtractionRules, error) {
	var raw dataExtractionRulesXML
	if err := decode(data, resourcesArsc, &raw); err != nil {
		return DataExtractionRules{}, fmt.Errorf("backuprules: parse data-extraction-rules: %w", err)
	}
	var out DataExtractionRules
	if raw.CloudBackup != nil {
		if len(raw.CloudBackup.Excludes) > 0 {
			out.HasExclude = true
		}
		if b, err := raw.CloudBackup.DisableIfNoEncryptionCapabilities.Bool(); err == nil && b {
			out.CloudBackupDisableIfNoEncryption = true
		}
	}
	if raw.DeviceTransfer != nil && len(raw.DeviceTransfer.Excludes) > 0 {
		out.HasExclude = true
	}
	if raw.CrossPlatformTransfer != nil && len(raw.CrossPlatformTransfer.Excludes) > 0 {
		out.HasExclude = true
	}
	return out, nil
}

func decode(data, resourcesArsc []byte, v interface{}) error {
	xf, err := androidbinary.NewXMLFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse binary XML: %w", err)
	}
	var table *androidbinary.TableFile
	if len(resourcesArsc) > 0 {
		table, err = androidbinary.NewTableFile(bytes.NewReader(resourcesArsc))
		if err != nil {
			// Degrade gracefully, same as pkg/parser/manifest: literal
			// (non-reference) attribute values still resolve fine.
			table = nil
		}
	}
	return xf.Decode(v, table, nil)
}
