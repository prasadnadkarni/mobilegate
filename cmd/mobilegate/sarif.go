package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/internal/sarif"
	"github.com/prasadnadkarni/mobilegate/rules"
)

// defaultSourceManifestPath is where -sarif output points a manifest-
// based finding's artifactLocation.uri, absent a
// policy.source_manifest_path in .mobilegate.yml — the standard Gradle
// app-module layout. See internal/config.Policy.SourceManifestPath's
// doc comment for why this is a default applied here, at the CLI layer,
// not hardcoded into internal/config or internal/sarif.
const defaultSourceManifestPath = "app/src/main/AndroidManifest.xml"

// repoInformationURI is MobileGate's own repo — tool.driver.informationUri.
const repoInformationURI = "https://github.com/prasadnadkarni/mobilegate"

// sarifResultLimitMB is the byte size (gzip-compressed, matching what
// upload-sarif actually compresses before sending) above which
// writeSarifFile refuses to write the file — see internal/sarif's
// maxResults doc comment for the parallel results-count guard. GitHub's
// documented limit is 10MB compressed; MobileGate's own finding volumes
// are nowhere near this, so hitting it at all would mean something is
// badly wrong, and failing loudly beats uploading a file GitHub will
// reject anyway with a less specific error.
const sarifMaxCompressedBytes = 10 * 1024 * 1024

// loadAllRuleInfo loads every embedded rule's static metadata for
// tool.driver.rules — spec: "one reportingDescriptor per rule
// (MG-001..MG-010)," regardless of whether it fired this run. Loaded
// independently of scanMG001..scanMG010 (which only return findings)
// rather than threading RuleMeta out of each of those — five small YAML
// reads is cheap, and keeps this SARIF-only concern from changing the
// existing scan-function signatures.
func loadAllRuleInfo() ([]sarif.RuleInfo, error) {
	type loader struct {
		file string
		meta func([]byte) (engine.RuleMeta, error)
	}
	loaders := []loader{
		{"MG-001-hardcoded-secret.yaml", func(d []byte) (engine.RuleMeta, error) {
			r, err := engine.LoadRule(d)
			if r == nil {
				return engine.RuleMeta{}, err
			}
			return r.RuleMeta, err
		}},
		{"MG-002-cleartext-transport.yaml", func(d []byte) (engine.RuleMeta, error) {
			r, err := engine.LoadTransportRule(d)
			if r == nil {
				return engine.RuleMeta{}, err
			}
			return r.RuleMeta, err
		}},
		{"MG-003-plaintext-storage.yaml", func(d []byte) (engine.RuleMeta, error) {
			r, err := engine.LoadStorageRule(d)
			if r == nil {
				return engine.RuleMeta{}, err
			}
			return r.RuleMeta, err
		}},
		{"MG-004-exported-component.yaml", func(d []byte) (engine.RuleMeta, error) {
			r, err := engine.LoadExportedRule(d)
			if r == nil {
				return engine.RuleMeta{}, err
			}
			return r.RuleMeta, err
		}},
		{"MG-010-debug-build-artifact.yaml", func(d []byte) (engine.RuleMeta, error) {
			r, err := engine.LoadHygieneRule(d)
			if r == nil {
				return engine.RuleMeta{}, err
			}
			return r.RuleMeta, err
		}},
	}

	out := make([]sarif.RuleInfo, 0, len(loaders))
	for _, l := range loaders {
		data, err := rules.FS.ReadFile(l.file)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", l.file, err)
		}
		meta, err := l.meta(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", l.file, err)
		}
		out = append(out, sarif.RuleInfo{
			ID:          meta.ID,
			Name:        meta.Name,
			Description: meta.Description,
			Remediation: meta.Remediation,
			Severity:    meta.Severity,
			MASVS:       meta.MASVS,
			CWE:         meta.CWE,
		})
	}
	return out, nil
}

// buildSarifLog assembles a SARIF log for one scan. allFindings must
// already exclude baselined and policy-suppressed findings — see
// internal/sarif's package doc comment, point 2, for why those must
// never reach SARIF output (GitHub doesn't honor results[].suppressions,
// so a "suppressed" finding uploaded there would show as a normal,
// active alert — worse than just leaving it out of this specific
// output format, since every OTHER MobileGate output still shows it
// as suppressed-with-reason).
func buildSarifLog(apkPath, packageName string, allFindings []core.Finding, sourceManifestPath string) (*sarif.Log, error) {
	ruleInfo, err := loadAllRuleInfo()
	if err != nil {
		return nil, err
	}
	if sourceManifestPath == "" {
		sourceManifestPath = defaultSourceManifestPath
	}

	automationID := "mobilegate"
	if packageName != "" {
		automationID = "mobilegate/" + packageName
	}

	return sarif.Build(sarif.BuildInput{
		ToolVersion:        scannerVersion,
		RepoURI:            repoInformationURI,
		AutomationID:       automationID,
		Rules:              ruleInfo,
		Findings:           allFindings,
		APKPath:            apkPath,
		SourceManifestPath: sourceManifestPath,
	})
}

// writeSarifFile marshals log and writes it to path, refusing (loudly,
// per spec) rather than writing a file GitHub would reject or silently
// truncate — see sarifMaxCompressedBytes' doc comment. Uses the same
// 2-space-indent, unescaped-HTML JSON style as printContractJSON, for
// the same reason: this is inspected by humans and CI logs, not
// embedded in an HTML page.
func writeSarifFile(path string, log *sarif.Log) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("checking SARIF size: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("checking SARIF size: %w", err)
	}
	if gz.Len() > sarifMaxCompressedBytes {
		return fmt.Errorf("SARIF output is %d bytes gzip-compressed, over GitHub's documented 10MB upload limit (%d bytes) — refusing to write a file the upload step would reject; this should never happen at MobileGate's normal finding volumes, so if it does, something upstream produced far more findings than expected", gz.Len(), sarifMaxCompressedBytes)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
