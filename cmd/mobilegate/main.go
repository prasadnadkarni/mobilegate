// Command mobilegate is the MobileGate CLI entrypoint.
//
// It runs four rules — MG-001 (hardcoded secrets), MG-002 (cleartext
// transport), MG-003 (backup exposure), MG-010 (debug/test build
// artifact) — and emits the release gate's actual product output: a
// PASS/BLOCKED decision, the failed controls, a secondary score, and
// (with -json) the spec's machine-readable output contract.
//
// Two subcommands:
//
//	mobilegate [-baseline path] [-json] [-debug] [-warnings] [-config path] <apk>
//	mobilegate baseline -write [-baseline path] [-config path] <apk>
//
// Strict mode (default, no -baseline flag) blocks on any blocking-tier
// finding. Baseline mode (-baseline path) blocks only on findings not
// present in that file — see internal/core.SplitByBaseline. A missing
// or corrupt baseline falls back to strict mode with a loud warning,
// never a silent pass — spec: "fail closed."
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
// `mobilegate -baseline` (with no explicit path) looks, absent an
// override — dot-prefixed to match .mobilegate.yml's convention, meant
// to be committed to the project's repo.
const defaultBaselinePath = ".mobilegate-baseline.yml"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "baseline" {
		runBaseline(os.Args[2:])
		return
	}
	runGate(os.Args[1:])
}

func runGate(args []string) {
	fs := flag.NewFlagSet("mobilegate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the machine-readable JSON output contract instead of the human-readable gate report")
	debug := fs.Bool("debug", false, "emit the full parser-state dump (manifest fields, DEX string samples) instead of the gate report — development/troubleshooting only, not the product output")
	showWarnings := fs.Bool("warnings", false, "show full warning-tier finding details in the terminal gate report (collapsed to a count by default)")
	baselinePath := fs.String("baseline", "", "path to a baseline file (see 'mobilegate baseline -write'); if set, run in baseline mode — findings already present in the baseline don't block. Unset (default): strict mode, every blocking finding blocks")
	configPath := fs.String("config", ".mobilegate.yml", "path to .mobilegate.yml (currently just policy.first_party_domains, used by MG-002); a missing file is not an error")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mobilegate [-json] [-debug] [-warnings] [-baseline path] [-config path] <path-to-apk>")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	apkPath := fs.Arg(0)

	res, err := scanAPK(apkPath, *configPath)
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

	mode := modeStrict
	var baselined []core.Finding
	var baselineNotice string
	if *baselinePath != "" {
		b, loadErr := core.LoadBaseline(*baselinePath)
		switch {
		case loadErr == nil:
			mode = modeBaseline
			if b.RuleVersion != ruleVersion {
				baselineNotice = fmt.Sprintf("baseline %s was written with rule_version %s; this build is %s — findings may have shifted since the baseline was written; review the result before trusting a clean scan", *baselinePath, b.RuleVersion, ruleVersion)
			}
			allFindings, baselined = core.SplitByBaseline(allFindings, b)
		case os.IsNotExist(loadErr):
			baselineNotice = fmt.Sprintf("no baseline file found at %s — running in STRICT mode (write one with: mobilegate baseline -write -baseline %s %s)", *baselinePath, *baselinePath, apkPath)
		default:
			baselineNotice = fmt.Sprintf("baseline file %s is corrupt or unreadable (%v) — falling back to STRICT mode; ALL existing findings are treated as new", *baselinePath, loadErr)
		}
	}

	decision := core.Decide(allFindings)
	score := core.Score(allFindings, decision)
	blocking, warning, info := core.Buckets(allFindings)

	if *jsonOut {
		printContractJSON(mode, decision, score, blocking, warning, info, baselined, baselineNotice)
	} else {
		if baselineNotice != "" {
			fmt.Fprintf(os.Stderr, "mobilegate: %s\n", baselineNotice)
		}
		printGateReport(apkPath, mode, decision, score, blocking, warning, info, baselined, *showWarnings)
	}

	if decision == core.GateBlocked {
		os.Exit(1)
	}
}

// runBaseline implements `mobilegate baseline -write <apk>`: runs the
// same scan pipeline as the gate command, then writes a full snapshot
// of its blocking-tier findings — replacing whatever baseline file was
// there before, not merging with it, which is what makes the ratchet
// property (a fixed finding drops out on the next write) hold with no
// extra bookkeeping — see core.NewBaseline's doc comment.
func runBaseline(args []string) {
	fs := flag.NewFlagSet("mobilegate baseline", flag.ExitOnError)
	write := fs.Bool("write", false, "write/replace the baseline file with the blocking findings from a fresh scan of the given APK (required — the only supported baseline operation right now)")
	baselinePath := fs.String("baseline", defaultBaselinePath, "path to the baseline file to write")
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

	res, err := scanAPK(apkPath, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	b := core.NewBaseline(scannerVersion, ruleVersion, res.allFindings())
	if err := b.WriteFile(*baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote baseline: %d blocking finding(s) captured to %s\n", len(b.Findings), *baselinePath)
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

func scanAPK(apkPath, configPath string) (*scanResult, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, err
	}

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

	mg002Findings, err := scanMG002(container, m, cfg.Policy.FirstPartyDomains)
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
