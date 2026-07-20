package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// maxSampleStrings caps how many example strings per dex file the text
// report prints, to keep the eyeball-check output readable on a real APK
// with tens of thousands of strings.
const maxSampleStrings = 15

// printDebugDump is the full parser-state dump used through build-order
// steps 1-2, before there was a gate decision to report at all. Kept
// behind -debug for development/troubleshooting: it shows manifest
// fields and DEX string samples that have nothing to do with the actual
// product output (spec: "Emits PASS or BLOCKED, not a findings report")
// but are useful for verifying the parser against a new APK by eye.
func printDebugDump(apkPath string, m *manifest.Manifest, results []dexFileResult, mg001Findings, mg002Findings, mg003Findings, mg010Findings []engine.Finding, surface scanSurfaceCounts) {
	fmt.Printf("APK: %s\n\n", apkPath)

	fmt.Println("== MG-001: Hardcoded production secret ==")
	fmt.Printf("scan surface: %d DEX strings (unattributed only), %d resources.arsc strings, %d AndroidManifest.xml strings, %d asset files\n",
		surface.dexStrings, surface.resourceStrings, surface.manifestStrings, surface.assetFiles)
	printFindings(mg001Findings)
	fmt.Println()

	fmt.Println("== MG-002: Cleartext / accept-all transport ==")
	fmt.Printf("networkSecurityConfig: %s\n", orNone(m.NetworkSecurityConfig))
	printFindings(mg002Findings)
	fmt.Println()

	fmt.Println("== MG-003: Plaintext sensitive storage (backup exposure) ==")
	fmt.Printf("allowBackup: %s   targetSdkVersion: %s\n", tristateLabel(m.AllowBackup), targetSdkLabel(m.TargetSdkVersion))
	printFindings(mg003Findings)
	fmt.Println()

	fmt.Println("== MG-010: Debug/test build artifact ==")
	fmt.Printf("debuggable: %s   testOnly: %s\n", tristateLabel(m.Debuggable), tristateLabel(m.TestOnly))
	printFindings(mg010Findings)
	fmt.Println()

	fmt.Println("== Manifest ==")
	fmt.Printf("package:                 %s\n", m.PackageName)
	fmt.Printf("usesCleartextTraffic:    %s\n", tristateLabel(m.UsesCleartextTraffic))
	fmt.Printf("networkSecurityConfig:   %s\n", orNone(m.NetworkSecurityConfig))
	fmt.Printf("allowBackup:             %s\n", tristateLabel(m.AllowBackup))
	fmt.Printf("debuggable:              %s\n", tristateLabel(m.Debuggable))
	fmt.Printf("testOnly:                %s\n", tristateLabel(m.TestOnly))
	fmt.Printf("fullBackupContent:       %s\n", orNone(m.FullBackupContent))
	fmt.Printf("dataExtractionRules:     %s\n", orNone(m.DataExtractionRules))
	fmt.Printf("backupAgent:             %s\n", orNone(m.BackupAgent))
	fmt.Printf("components:              %d\n", len(m.Components))
	for _, c := range m.Components {
		fmt.Printf("  [%-9s] %-60s exported=%-6s permission=%-30s intent-filter=%v\n",
			c.Kind, c.Name, tristateLabel(c.Exported), orNone(c.Permission), c.HasIntentFilter)
	}

	fmt.Println()
	fmt.Println("== DEX ==")
	for _, r := range results {
		typeN, methodN, fieldN, unattrN := 0, 0, 0, 0
		for _, s := range r.strings {
			switch s.Usage {
			case dex.TypeName:
				typeN++
			case dex.MethodName:
				methodN++
			case dex.FieldName:
				fieldN++
			default:
				unattrN++
			}
		}
		fmt.Printf("%s: %d strings (type=%d method=%d field=%d unattributed=%d)\n",
			r.name, len(r.strings), typeN, methodN, fieldN, unattrN)

		fmt.Printf("  sample:\n")
		for i, s := range r.strings {
			if i >= maxSampleStrings {
				fmt.Printf("  ... (%d more)\n", len(r.strings)-maxSampleStrings)
				break
			}
			label := s.Usage.String()
			if s.ClassType != "" {
				label = fmt.Sprintf("%s of %s", label, s.ClassType)
			}
			fmt.Printf("  [%5d] (%s) %q\n", s.Index, label, truncate(s.Value, 80))
		}
	}
}

func printFindings(findings []engine.Finding) {
	if len(findings) == 0 {
		fmt.Println("no findings")
		return
	}
	for _, f := range findings {
		blockLabel := "WARNING"
		if f.Blocking {
			blockLabel = "BLOCKING"
		}
		fmt.Printf("[%s] %s (%s)\n", blockLabel, f.Title, f.PatternID)
		fmt.Printf("  source:     %s\n", f.Source)
		if f.Line != nil {
			fmt.Printf("  line:       %d\n", *f.Line)
		} else {
			fmt.Printf("  location:   %s\n", f.Location)
		}
		fmt.Printf("  excerpt:    %s\n", f.Excerpt)
		fmt.Printf("  confidence: %s   severity: %s   masvs: %s   cwe: %s\n", f.Confidence, f.Severity, f.MASVS, f.CWE)
		fmt.Printf("  signal:     %s\n", f.SignalDetail)
		fmt.Printf("  hash:       %s\n", f.FindingHash)
		if f.TargetSDK != nil {
			fmt.Printf("  targetSdkVersion: %d\n", *f.TargetSDK)
		}
	}
}

func tristateLabel(t manifest.Tristate) string {
	switch t {
	case manifest.True:
		return "true"
	case manifest.False:
		return "false"
	default:
		return "unset"
	}
}

func targetSdkLabel(v *int) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- JSON dump (dev-only debug format, not the step-3 gate output contract) ---

type debugJSONReport struct {
	PackageName           string               `json:"package_name"`
	UsesCleartextTraffic  string               `json:"uses_cleartext_traffic"`
	NetworkSecurityConfig string               `json:"network_security_config"`
	AllowBackup           string               `json:"allow_backup"`
	Debuggable            string               `json:"debuggable"`
	TestOnly              string               `json:"test_only"`
	FullBackupContent     string               `json:"full_backup_content,omitempty"`
	DataExtractionRules   string               `json:"data_extraction_rules,omitempty"`
	BackupAgent           string               `json:"backup_agent,omitempty"`
	TargetSdkVersion      *int                 `json:"target_sdk_version,omitempty"`
	Components            []debugJSONComponent `json:"components"`
	Dex                   []debugJSONDexFile   `json:"dex"`
	ScanSurface           debugJSONScanSurface `json:"scan_surface"`
	MG001Findings         []debugJSONFinding   `json:"mg001_findings"`
	MG002Findings         []debugJSONFinding   `json:"mg002_findings"`
	MG003Findings         []debugJSONFinding   `json:"mg003_findings"`
	MG010Findings         []debugJSONFinding   `json:"mg010_findings"`
}

type debugJSONScanSurface struct {
	DexStringsUnattributed int `json:"dex_strings_unattributed"`
	ResourceStrings        int `json:"resource_strings"`
	ManifestStrings        int `json:"manifest_strings"`
	AssetFiles             int `json:"asset_files"`
}

type debugJSONFinding struct {
	RuleID       string `json:"rule_id"`
	PatternID    string `json:"pattern_id"`
	Title        string `json:"title"`
	Blocking     bool   `json:"blocking"`
	Confidence   string `json:"confidence"`
	Severity     string `json:"severity"`
	MASVS        string `json:"masvs"`
	CWE          string `json:"cwe"`
	Source       string `json:"source"`
	Location     string `json:"location"`
	Excerpt      string `json:"excerpt"`
	SignalDetail string `json:"signal_detail"`
	TargetSDK    *int   `json:"target_sdk_version,omitempty"`
}

type debugJSONComponent struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Exported        string `json:"exported"`
	Permission      string `json:"permission"`
	HasIntentFilter bool   `json:"has_intent_filter"`
}

type debugJSONDexFile struct {
	File        string               `json:"file"`
	StringCount int                  `json:"string_count"`
	Strings     []debugJSONStringRef `json:"strings"`
}

type debugJSONStringRef struct {
	Index     int    `json:"index"`
	Value     string `json:"value"`
	Usage     string `json:"usage"`
	ClassType string `json:"class_type,omitempty"`
}

func toDebugJSONFindings(findings []engine.Finding) []debugJSONFinding {
	out := make([]debugJSONFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, debugJSONFinding{
			RuleID:       f.RuleID,
			PatternID:    f.PatternID,
			Title:        f.Title,
			Blocking:     f.Blocking,
			Confidence:   f.Confidence,
			Severity:     f.Severity,
			MASVS:        f.MASVS,
			CWE:          f.CWE,
			Source:       f.Source,
			Location:     f.Location,
			Excerpt:      f.Excerpt,
			SignalDetail: f.SignalDetail,
			TargetSDK:    f.TargetSDK,
		})
	}
	return out
}

func printDebugJSON(m *manifest.Manifest, results []dexFileResult, mg001Findings, mg002Findings, mg003Findings, mg010Findings []engine.Finding, surface scanSurfaceCounts) {
	rep := debugJSONReport{
		PackageName:           m.PackageName,
		UsesCleartextTraffic:  tristateLabel(m.UsesCleartextTraffic),
		NetworkSecurityConfig: m.NetworkSecurityConfig,
		AllowBackup:           tristateLabel(m.AllowBackup),
		Debuggable:            tristateLabel(m.Debuggable),
		TestOnly:              tristateLabel(m.TestOnly),
		FullBackupContent:     m.FullBackupContent,
		DataExtractionRules:   m.DataExtractionRules,
		BackupAgent:           m.BackupAgent,
		TargetSdkVersion:      m.TargetSdkVersion,
		ScanSurface: debugJSONScanSurface{
			DexStringsUnattributed: surface.dexStrings,
			ResourceStrings:        surface.resourceStrings,
			ManifestStrings:        surface.manifestStrings,
			AssetFiles:             surface.assetFiles,
		},
		MG001Findings: toDebugJSONFindings(mg001Findings),
		MG002Findings: toDebugJSONFindings(mg002Findings),
		MG003Findings: toDebugJSONFindings(mg003Findings),
		MG010Findings: toDebugJSONFindings(mg010Findings),
	}
	for _, c := range m.Components {
		rep.Components = append(rep.Components, debugJSONComponent{
			Kind:            string(c.Kind),
			Name:            c.Name,
			Exported:        tristateLabel(c.Exported),
			Permission:      c.Permission,
			HasIntentFilter: c.HasIntentFilter,
		})
	}
	for _, r := range results {
		df := debugJSONDexFile{File: r.name, StringCount: len(r.strings)}
		for _, s := range r.strings {
			df.Strings = append(df.Strings, debugJSONStringRef{
				Index:     s.Index,
				Value:     s.Value,
				Usage:     s.Usage.String(),
				ClassType: s.ClassType,
			})
		}
		rep.Dex = append(rep.Dex, df)
	}

	sort.Slice(rep.Components, func(i, j int) bool { return rep.Components[i].Name < rep.Components[j].Name })

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // this JSON is CI/log output, not embedded in HTML — escaping "<application>" to "\\u003capplication\\u003e" only hurts human readability and grep
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: encode json: %v\n", err)
		os.Exit(1)
	}
}

// --- the actual product output: gate report (terminal) + contract JSON ---
//
// This is what build-order step 3 is actually for. Spec: "Emits PASS or
// BLOCKED, not a findings report" / "MobSF says here are 150 findings.
// This tool says your release is blocked because these 3 controls
// failed." Everything above this line (printDebugDump, printDebugJSON)
// is a development aid from earlier build-order steps, not part of the
// product's real output — gated behind -debug for that reason.

// scannerVersion/ruleVersion are this build's own identity, reported in
// the JSON contract so a consumer can tell which detection logic
// produced a given result. No real release-versioning process exists
// yet (pre-1.0, single-developer build) — bump these by hand when rule
// logic changes meaningfully, the same discipline PERFORMANCE.md's
// table already asks for on the performance side. ruleVersion is also
// what a baseline file records and compares against on load — see
// core.LoadBaseline and runGate's staleness check.
const (
	scannerVersion = "0.1.0"
	ruleVersion    = "2026.07.1"

	// modeStrict/modeBaseline are policy_mode's two possible values —
	// spec's own example shows "strict"; modeBaseline is this build's
	// own baseline-mode addition, selected at runtime by whether -baseline
	// was passed and loaded successfully (see runGate), not hardcoded.
	modeStrict   = "strict"
	modeBaseline = "baseline"
)

// contractReport is the spec's output contract: scanner_version,
// rule_version, artifact_type, platform, gate_decision, policy_mode,
// score, summary_counts, and findings buckets with structured evidence
// arrays. baselined_findings/baseline_notice are this build's own
// baseline-mode addition, not in the spec's original example — omitted
// entirely (via omitempty) in strict mode, so a strict-mode JSON
// document is byte-for-byte what the spec shows.
type contractReport struct {
	ScannerVersion    string                `json:"scanner_version"`
	RuleVersion       string                `json:"rule_version"`
	ArtifactType      string                `json:"artifact_type"`
	Platform          string                `json:"platform"`
	GateDecision      core.GateDecision     `json:"gate_decision"`
	PolicyMode        string                `json:"policy_mode"`
	Score             int                   `json:"score"`
	SummaryCounts     contractSummaryCounts `json:"summary_counts"`
	BlockingFindings  []contractFinding     `json:"blocking_findings"`
	Warnings          []contractFinding     `json:"warnings"`
	Info              []contractFinding     `json:"info"`
	BaselinedFindings []contractFinding     `json:"baselined_findings,omitempty"`
	BaselineNotice    string                `json:"baseline_notice,omitempty"`
}

type contractSummaryCounts struct {
	Blocking  int `json:"blocking"`
	Warning   int `json:"warning"`
	Info      int `json:"info"`
	Baselined int `json:"baselined,omitempty"`
}

// contractFinding is one entry in blocking_findings/warnings/info.
// "id" is the RULE's id (spec's own example: "id": "MG-001") — a
// per-finding unique identifier is finding_hash, not this field.
// Evidence reuses core.Evidence directly (already carries its own json
// tags — see that type's doc comment) rather than a redundant DTO.
type contractFinding struct {
	ID          string          `json:"id"`
	FindingHash string          `json:"finding_hash"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	Confidence  string          `json:"confidence"`
	MASVS       string          `json:"masvs"`
	CWE         string          `json:"cwe"`
	Evidence    []core.Evidence `json:"evidence"`
	WhyItBlocks string          `json:"why_it_blocks"`
	Remediation string          `json:"remediation"`
}

func toContractFindings(findings []core.Finding) []contractFinding {
	out := make([]contractFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, contractFinding{
			ID:          f.RuleID,
			FindingHash: f.FindingHash,
			Title:       f.Title,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			MASVS:       f.MASVS,
			CWE:         f.CWE,
			Evidence:    f.EvidenceChain(),
			WhyItBlocks: f.WhyItBlocks,
			Remediation: f.Remediation,
		})
	}
	return out
}

// printContractJSON emits the spec's machine-readable output contract.
// mode is "strict" or "baseline" (see modeStrict/modeBaseline); baselined
// is empty in strict mode, and baselineNotice is empty unless baseline
// mode degraded (missing/corrupt file, stale rule_version).
func printContractJSON(mode string, decision core.GateDecision, score int, blocking, warning, info, baselined []core.Finding, baselineNotice string) {
	rep := contractReport{
		ScannerVersion: scannerVersion,
		RuleVersion:    ruleVersion,
		ArtifactType:   "apk",
		Platform:       "android",
		GateDecision:   decision,
		PolicyMode:     mode,
		Score:          score,
		SummaryCounts: contractSummaryCounts{
			Blocking:  len(blocking),
			Warning:   len(warning),
			Info:      len(info),
			Baselined: len(baselined),
		},
		BlockingFindings:  toContractFindings(blocking),
		Warnings:          toContractFindings(warning),
		Info:              toContractFindings(info),
		BaselinedFindings: toContractFindings(baselined),
		BaselineNotice:    baselineNotice,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // this JSON is CI/log output, not embedded in HTML — escaping "<application>" to "\\u003capplication\\u003e" only hurts human readability and grep
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: encode json: %v\n", err)
		os.Exit(1)
	}
}

// printGateReport is the default human-readable output — spec: "lead
// with RELEASE STATUS: BLOCKED and the failed controls. Warnings
// collapsed by default." Not read start-to-finish; a CI log viewer or a
// developer glancing at a failed pipeline step needs the verdict in the
// first line, not buried under a manifest dump. mode is "strict" or
// "baseline"; baselined is the pre-existing debt a baseline grandfathered
// (always empty in strict mode) — shown so nothing is silently hidden,
// matching the baseline file's own "auditable, not opaque" requirement.
func printGateReport(apkPath, mode string, decision core.GateDecision, score int, blocking, warning, info, baselined []core.Finding, showWarnings bool) {
	status := "PASS"
	if decision == core.GateBlocked {
		status = "BLOCKED"
	}
	fmt.Printf("RELEASE STATUS: %s\n", status)
	fmt.Printf("apk:   %s\n", apkPath)
	fmt.Printf("mode:  %s\n", mode)
	fmt.Printf("score: %d/100 (secondary to the release status above — see internal/core.Score)\n", score)
	fmt.Println()

	if len(blocking) == 0 {
		fmt.Println("No blocking findings.")
	} else {
		fmt.Println("Failed controls:")
		printControls(blocking, "  ")
	}
	fmt.Println()

	if len(baselined) > 0 {
		fmt.Printf("%d pre-existing finding(s) grandfathered by baseline (not blocking):\n", len(baselined))
		printControls(baselined, "  ")
		fmt.Println()
	}

	switch {
	case len(warning) == 0:
		fmt.Println("0 warnings.")
	case showWarnings:
		fmt.Printf("Warnings (%d):\n", len(warning))
		printControls(warning, "  ")
	default:
		fmt.Printf("%d warning(s) not shown — rerun with -warnings to see details.\n", len(warning))
	}

	// info is always empty in this build (see core.Finding.Blocking's
	// doc comment) — nothing to print, kept as a parameter for symmetry
	// with the JSON contract and so this signature doesn't need to
	// change when a real info-tier rule eventually exists.
	_ = info
}

// printControls groups findings by rule (spec: "the specific controls
// that failed" — a control is a rule, not an individual finding) and
// prints each finding's evidence chain underneath its rule header.
func printControls(findings []core.Finding, indent string) {
	order, byRule := groupByRule(findings)
	for _, ruleID := range order {
		fs := byRule[ruleID]
		fmt.Printf("%s%s — %s (%d finding%s)\n", indent, ruleID, fs[0].RuleName, len(fs), plural(len(fs)))
		for _, f := range fs {
			fmt.Printf("%s  [%s] %s\n", indent, f.Source, f.Excerpt)
			if f.Line != nil {
				fmt.Printf("%s    line: %d\n", indent, *f.Line)
			} else if f.Location != "" {
				fmt.Printf("%s    location: %s\n", indent, f.Location)
			}
			fmt.Printf("%s    why it blocks: %s\n", indent, f.WhyItBlocks)
			fmt.Printf("%s    remediation:   %s\n", indent, f.Remediation)
			fmt.Printf("%s    masvs: %s   cwe: %s   confidence: %s\n", indent, f.MASVS, f.CWE, f.Confidence)
			fmt.Printf("%s    finding_hash: %s\n", indent, f.FindingHash)
		}
	}
}

// groupByRule buckets findings by RuleID, preserving first-seen order
// (deterministic given findings itself is produced in a fixed rule
// evaluation order by main.go, not e.g. from map iteration).
func groupByRule(findings []core.Finding) (order []string, byRule map[string][]core.Finding) {
	byRule = map[string][]core.Finding{}
	for _, f := range findings {
		if _, seen := byRule[f.RuleID]; !seen {
			order = append(order, f.RuleID)
		}
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}
	return order, byRule
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
