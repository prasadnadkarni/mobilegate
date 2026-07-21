// Command mobilegate is the MobileGate CLI entrypoint.
//
// It runs four rules — MG-001 (hardcoded secrets), MG-002 (cleartext
// transport), MG-003 (backup exposure), MG-010 (debug/test build
// artifact) — and emits the release gate's actual product output: a
// PASS/BLOCKED decision, the failed controls, a secondary score, and
// (with -json) the spec's machine-readable output contract.
//
// Three subcommands:
//
//	mobilegate [-mode strict|baseline] [-baseline path] [-json] [-debug] [-warnings] [-config path] <apk>
//	mobilegate baseline -write [-baseline path] [-config path] <apk>
//	mobilegate version
//
// Policy (mode, baseline file, first-party domains, rule suppression)
// lives in .mobilegate.yml — a file a team reviews and commits — not in
// whoever's CI invocation happens to pass which flags. -mode/-baseline
// CLI flags override the file when explicitly passed (so CI can force
// strict for one run regardless of what's committed); config wins
// otherwise. A missing or invalid config, or a missing or corrupt
// baseline, falls back to safe defaults (strict mode, no suppressions)
// with a loud warning — never a silent pass. Spec: "fail closed."
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prasadnadkarni/mobilegate/internal/config"
	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/backuprules"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/nsc"
	"github.com/prasadnadkarni/mobilegate/rules"
)

// defaultBaselinePath is where `mobilegate baseline -write` writes and
// where baseline mode looks, absent a policy.baseline_file in
// .mobilegate.yml or a -baseline CLI override — dot-prefixed to match
// .mobilegate.yml's convention, meant to be committed to the project's
// repo.
const defaultBaselinePath = ".mobilegate-baseline.yml"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "baseline":
			runBaseline(os.Args[2:])
			return
		case "version":
			// scanner_version + rule_version, same identity the JSON
			// contract and baseline files carry — lets CI (and a human)
			// confirm what a downloaded release binary actually is
			// before trusting anything it says. Deliberately plain text,
			// not JSON: this is a quick human/shell smoke check, not
			// another output contract to keep stable.
			fmt.Printf("mobilegate %s (rules %s)\n", scannerVersion, ruleVersion)
			return
		}
	}
	runGate(os.Args[1:])
}

// loadConfig loads .mobilegate.yml with the fail-closed fallback spec
// asks for: a missing file is a legitimate default (config.LoadFile
// itself returns an empty Config, no warning needed — see that
// function's doc comment), but an invalid one (bad YAML, bad
// policy.mode, an ignore_rules entry missing its reason) must not
// silently proceed as if the file said nothing. The caller gets safe
// defaults (strict mode, no suppressions, no first-party domains) plus
// a non-empty notice to surface loudly, exactly like a corrupt baseline
// file falls back rather than crashing outright.
func loadConfig(path string) (*config.Config, string) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return &config.Config{}, fmt.Sprintf("config file %s is invalid (%v) — falling back to default policy: strict mode, no rule suppressions, no first-party domains. Fix the file and re-run", path, err)
	}
	return cfg, ""
}

func runGate(args []string) {
	fs := flag.NewFlagSet("mobilegate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the machine-readable JSON output contract instead of the human-readable gate report")
	debug := fs.Bool("debug", false, "emit the full parser-state dump (manifest fields, DEX string samples) instead of the gate report — development/troubleshooting only, not the product output")
	markdownOut := fs.Bool("markdown", false, "emit a GitHub/GitLab-flavored Markdown PR comment instead of the human-readable gate report")
	showWarnings := fs.Bool("warnings", false, "show full warning-tier finding details in the terminal gate report (collapsed to a count by default)")
	modeFlag := fs.String("mode", "", "override policy.mode from .mobilegate.yml: \"strict\" or \"baseline\". Unset (default): use the config file, defaulting to strict if it doesn't specify one — pass this explicitly to force a mode regardless of what's committed (e.g. CI forcing strict)")
	baselinePath := fs.String("baseline", "", "override policy.baseline_file from .mobilegate.yml. Passing this alone (without -mode) also selects baseline mode, as a shorthand. Unset: use the config file's baseline_file, or this tool's own default path")
	configPath := fs.String("config", ".mobilegate.yml", "path to .mobilegate.yml; a missing file is not an error, an invalid one falls back to safe defaults with a loud warning")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mobilegate [-mode strict|baseline] [-baseline path] [-json|-markdown] [-debug] [-warnings] [-config path] <path-to-apk>")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	apkPath := fs.Arg(0)

	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	cfg, configNotice := loadConfig(*configPath)
	if configNotice != "" {
		fmt.Fprintf(os.Stderr, "mobilegate: %s\n", configNotice)
	}

	mode := cfg.Policy.Mode
	if mode == "" {
		mode = config.ModeStrict
	}
	if explicit["baseline"] && !explicit["mode"] {
		mode = config.ModeBaseline // shorthand: -baseline alone implies baseline mode
	}
	if explicit["mode"] {
		mode = *modeFlag
		if mode != config.ModeStrict && mode != config.ModeBaseline {
			fmt.Fprintf(os.Stderr, "mobilegate: -mode must be %q or %q, got %q\n", config.ModeStrict, config.ModeBaseline, mode)
			os.Exit(2)
		}
	}

	baselineFile := cfg.Policy.BaselineFile
	if baselineFile == "" {
		baselineFile = defaultBaselinePath
	}
	if explicit["baseline"] {
		baselineFile = *baselinePath
	}

	res, err := scanAPK(apkPath, cfg.Policy.FirstPartyDomains)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	if *debug {
		if *jsonOut {
			printDebugJSON(res.m, res.dexResults, res.mg001, res.mg002, res.mg003, res.mg010, res.surface)
			return
		}
		printDebugDump(apkPath, res.m, res.dexResults, res.mg001, res.mg002, res.mg003, res.mg010, res.surface)
		return
	}

	allFindings := res.allFindings()

	allFindings, suppressed := core.SplitBySuppression(allFindings, suppressionRules(cfg.IgnoreRules))

	var baselined []core.Finding
	var baselineNotice string
	if mode == config.ModeBaseline {
		b, loadErr := core.LoadBaseline(baselineFile)
		switch {
		case loadErr == nil:
			if b.RuleVersion != ruleVersion {
				baselineNotice = fmt.Sprintf("baseline %s was written with rule_version %s; this build is %s — findings may have shifted since the baseline was written; review the result before trusting a clean scan", baselineFile, b.RuleVersion, ruleVersion)
			}
			allFindings, baselined = core.SplitByBaseline(allFindings, b)
		case os.IsNotExist(loadErr):
			mode = config.ModeStrict
			baselineNotice = fmt.Sprintf("no baseline file found at %s — running in STRICT mode (write one with: mobilegate baseline -write -baseline %s %s)", baselineFile, baselineFile, apkPath)
		default:
			mode = config.ModeStrict
			baselineNotice = fmt.Sprintf("baseline file %s is corrupt or unreadable (%v) — falling back to STRICT mode; ALL existing findings are treated as new", baselineFile, loadErr)
		}
	}

	decision := core.Decide(allFindings)
	score := core.Score(allFindings, decision)
	blocking, warning, info := core.Buckets(allFindings)

	switch {
	case *jsonOut:
		printContractJSON(mode, decision, score, blocking, warning, info, baselined, suppressed, baselineNotice)
	case *markdownOut:
		if baselineNotice != "" {
			fmt.Fprintf(os.Stderr, "mobilegate: %s\n", baselineNotice)
		}
		fmt.Print(markdownReport(apkPath, mode, decision, score, blocking, warning, info, baselined, suppressed))
	default:
		if baselineNotice != "" {
			fmt.Fprintf(os.Stderr, "mobilegate: %s\n", baselineNotice)
		}
		printGateReport(apkPath, mode, decision, score, blocking, warning, info, baselined, suppressed, *showWarnings)
	}

	if decision == core.GateBlocked {
		os.Exit(1)
	}
}

// suppressionRules translates config.IgnoreRule (the YAML schema) into
// core.SuppressionRule (the matching logic's own type) — kept as a
// small conversion at this orchestration boundary rather than making
// internal/core depend on internal/config, or vice versa.
func suppressionRules(rules []config.IgnoreRule) []core.SuppressionRule {
	out := make([]core.SuppressionRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, core.SuppressionRule{RuleID: r.ID, Reason: r.Reason, Paths: r.Paths})
	}
	return out
}

// runBaseline implements `mobilegate baseline -write <apk>`: runs the
// same scan pipeline as the gate command, then writes a full snapshot
// of its blocking-tier findings — replacing whatever baseline file was
// there before, not merging with it, which is what makes the ratchet
// property (a fixed finding drops out on the next write) hold with no
// extra bookkeeping — see core.NewBaseline's doc comment. Suppressed
// findings (ignore_rules) are excluded before the snapshot, same as the
// gate command: a policy-suppressed finding isn't debt to grandfather,
// it's explicitly excluded, and should reappear immediately as a real
// finding if the suppression is ever removed from the config.
func runBaseline(args []string) {
	fs := flag.NewFlagSet("mobilegate baseline", flag.ExitOnError)
	write := fs.Bool("write", false, "write/replace the baseline file with the blocking findings from a fresh scan of the given APK (required — the only supported baseline operation right now)")
	baselinePath := fs.String("baseline", "", "override policy.baseline_file from .mobilegate.yml. Unset: use the config file's baseline_file, or this tool's own default path")
	configPath := fs.String("config", ".mobilegate.yml", "path to .mobilegate.yml")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mobilegate baseline -write [-baseline path] [-config path] <path-to-apk>")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if !*write {
		fmt.Fprintln(os.Stderr, "mobilegate baseline: -write is required")
		fs.Usage()
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	apkPath := fs.Arg(0)

	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	cfg, configNotice := loadConfig(*configPath)
	if configNotice != "" {
		fmt.Fprintf(os.Stderr, "mobilegate: %s\n", configNotice)
	}

	baselineFile := cfg.Policy.BaselineFile
	if baselineFile == "" {
		baselineFile = defaultBaselinePath
	}
	if explicit["baseline"] {
		baselineFile = *baselinePath
	}

	res, err := scanAPK(apkPath, cfg.Policy.FirstPartyDomains)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	allFindings, _ := core.SplitBySuppression(res.allFindings(), suppressionRules(cfg.IgnoreRules))

	b := core.NewBaseline(scannerVersion, ruleVersion, allFindings)
	if err := b.WriteFile(baselineFile); err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote baseline: %d blocking finding(s) captured to %s\n", len(b.Findings), baselineFile)
}

// scanResult is the full parser + rule-evaluation output for one APK —
// shared by both runGate and runBaseline so the scan pipeline itself is
// written and verified in exactly one place.
type scanResult struct {
	m          *manifest.Manifest
	dexResults []dexFileResult
	mg001      []core.Finding
	mg002      []core.Finding
	mg003      []core.Finding
	mg010      []core.Finding
	surface    scanSurfaceCounts
}

func (r *scanResult) allFindings() []core.Finding {
	var out []core.Finding
	out = append(out, r.mg001...)
	out = append(out, r.mg002...)
	out = append(out, r.mg003...)
	out = append(out, r.mg010...)
	return out
}

func scanAPK(apkPath string, firstPartyDomains []string) (*scanResult, error) {
	container, err := apk.Open(apkPath)
	if err != nil {
		return nil, err
	}
	defer container.Close()

	m, err := manifest.Parse(container.Manifest, container.ResourcesArsc)
	if err != nil {
		return nil, err
	}

	var dexResults []dexFileResult
	var dexStrings []dex.StringRef
	for _, entry := range container.DexFiles {
		strs, err := dex.ParseStrings(entry.Name, entry.Data)
		if err != nil {
			return nil, err
		}
		dexResults = append(dexResults, dexFileResult{name: entry.Name, strings: strs})
		dexStrings = append(dexStrings, strs...)
	}

	resourceStrings, err := arsc.ExtractGlobalStringPool(container.ResourcesArsc)
	if err != nil {
		return nil, err
	}

	manifestStrings, err := arsc.ExtractGlobalStringPool(container.Manifest)
	if err != nil {
		return nil, err
	}

	mg001Findings, err := scanMG001(dexStrings, resourceStrings, manifestStrings, container.AssetFiles)
	if err != nil {
		return nil, err
	}

	mg002Findings, err := scanMG002(container, m, firstPartyDomains)
	if err != nil {
		return nil, err
	}

	mg003Findings, err := scanMG003(container, m)
	if err != nil {
		return nil, err
	}

	mg010Findings, err := scanMG010(m)
	if err != nil {
		return nil, err
	}

	var dexUnattributed int
	for _, s := range dexStrings {
		if s.Usage == dex.Unattributed {
			dexUnattributed++
		}
	}

	return &scanResult{
		m:          m,
		dexResults: dexResults,
		mg001:      mg001Findings,
		mg002:      mg002Findings,
		mg003:      mg003Findings,
		mg010:      mg010Findings,
		surface: scanSurfaceCounts{
			dexStrings:      dexUnattributed, // only Unattributed strings are actually scanned — see ScanDexStrings
			resourceStrings: len(resourceStrings),
			manifestStrings: len(manifestStrings),
			assetFiles:      len(container.AssetFiles),
		},
	}, nil
}

// scanMG001 loads the embedded MG-001 rule and runs it against the
// parser output.
func scanMG001(dexStrings []dex.StringRef, resourceStrings, manifestStrings []arsc.PoolString, assets []apk.AssetEntry) ([]engine.Finding, error) {
	data, err := rules.FS.ReadFile("MG-001-hardcoded-secret.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading MG-001 rule: %w", err)
	}
	rule, err := engine.LoadRule(data)
	if err != nil {
		return nil, fmt.Errorf("MG-001: %w", err)
	}
	scanner, err := engine.NewSecretScanner(rule)
	if err != nil {
		return nil, fmt.Errorf("MG-001: %w", err)
	}

	var findings []engine.Finding
	findings = append(findings, scanner.ScanDexStrings(dexStrings)...)
	findings = append(findings, scanner.ScanResourceStrings(resourceStrings)...)
	findings = append(findings, scanner.ScanManifestStrings(manifestStrings)...)
	for _, a := range assets {
		findings = append(findings, scanner.ScanAsset(a.Name, a.Data)...)
	}
	return findings, nil
}

// scanMG002 loads the embedded MG-002 rule and runs it against the
// already-parsed manifest, plus network_security_config.xml if the
// manifest references one and it resolves to a real in-APK file.
func scanMG002(container *apk.Container, m *manifest.Manifest, firstPartyDomains []string) ([]engine.Finding, error) {
	data, err := rules.FS.ReadFile("MG-002-cleartext-transport.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading MG-002 rule: %w", err)
	}
	rule, err := engine.LoadTransportRule(data)
	if err != nil {
		return nil, fmt.Errorf("MG-002: %w", err)
	}
	scanner := engine.NewTransportScanner(rule, firstPartyDomains)

	findings := scanner.CheckManifest(m, m.NetworkSecurityConfig != "")

	if m.NetworkSecurityConfig == "" {
		return findings, nil
	}
	nscData, found, err := container.ReadFile(m.NetworkSecurityConfig)
	if err != nil {
		return nil, fmt.Errorf("MG-002: reading %s: %w", m.NetworkSecurityConfig, err)
	}
	if !found {
		return findings, nil
	}
	configs, err := nsc.Parse(nscData)
	if err != nil {
		return nil, fmt.Errorf("MG-002: parsing %s: %w", m.NetworkSecurityConfig, err)
	}
	findings = append(findings, scanner.CheckNetworkSecurityConfig(m.NetworkSecurityConfig, configs, m.TargetSdkVersion)...)
	return findings, nil
}

// scanMG003 loads the embedded MG-003 rule and runs it against the
// already-parsed manifest. If android:fullBackupContent or
// android:dataExtractionRules references an XML resource,
// StorageScanner defers its decision until that file's content is
// resolved — see engine.StorageScanner.NeedsOverrideFileResolution.
func scanMG003(container *apk.Container, m *manifest.Manifest) ([]engine.Finding, error) {
	data, err := rules.FS.ReadFile("MG-003-plaintext-storage.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading MG-003 rule: %w", err)
	}
	rule, err := engine.LoadStorageRule(data)
	if err != nil {
		return nil, fmt.Errorf("MG-003: %w", err)
	}
	scanner := engine.NewStorageScanner(rule)

	if !engine.NeedsOverrideFileResolution(m) {
		return scanner.CheckManifest(m), nil
	}
	fbc, der := readBackupOverrideFiles(container, m)
	return scanner.CheckOverrideFiles(m, fbc, der), nil
}

// readBackupOverrideFiles resolves and parses whichever of
// fullBackupContent/dataExtractionRules names an XML resource. A
// returned pointer is nil if that attribute isn't a resource reference,
// or if the referenced file could not be found, read, or parsed — fail
// closed, same as an unresolved network_security_config.xml reference
// in scanMG002: this never returns an error, since a broken override
// file must not abort the whole scan, only leave
// engine.StorageScanner.CheckOverrideFiles unable to treat it as a
// suppression.
func readBackupOverrideFiles(container *apk.Container, m *manifest.Manifest) (*backuprules.FullBackupContent, *backuprules.DataExtractionRules) {
	var fbc *backuprules.FullBackupContent
	if m.FullBackupContent != "" && m.FullBackupContent != "true" && m.FullBackupContent != "false" {
		if data, found, err := container.ReadFile(m.FullBackupContent); err == nil && found {
			if parsed, perr := backuprules.ParseFullBackupContent(data, container.ResourcesArsc); perr == nil {
				fbc = &parsed
			}
		}
	}
	var der *backuprules.DataExtractionRules
	if m.DataExtractionRules != "" {
		if data, found, err := container.ReadFile(m.DataExtractionRules); err == nil && found {
			if parsed, perr := backuprules.ParseDataExtractionRules(data, container.ResourcesArsc); perr == nil {
				der = &parsed
			}
		}
	}
	return fbc, der
}

// scanMG010 loads the embedded MG-010 rule and runs it against the
// already-parsed manifest.
func scanMG010(m *manifest.Manifest) ([]engine.Finding, error) {
	data, err := rules.FS.ReadFile("MG-010-debug-build-artifact.yaml")
	if err != nil {
		return nil, fmt.Errorf("loading MG-010 rule: %w", err)
	}
	rule, err := engine.LoadHygieneRule(data)
	if err != nil {
		return nil, fmt.Errorf("MG-010: %w", err)
	}
	scanner := engine.NewHygieneScanner(rule)
	return scanner.CheckManifest(m), nil
}

// scanSurfaceCounts is reported alongside findings so "zero findings" can
// be told apart from "nothing was scanned."
type scanSurfaceCounts struct {
	dexStrings      int
	resourceStrings int
	manifestStrings int
	assetFiles      int
}

type dexFileResult struct {
	name    string
	strings []dex.StringRef
}
