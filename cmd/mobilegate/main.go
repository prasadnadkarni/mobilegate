// Command mobilegate is the MobileGate CLI entrypoint.
//
// It runs four rules — MG-001 (hardcoded secrets), MG-002 (cleartext
// transport), MG-003 (backup exposure), MG-010 (debug/test build
// artifact) — and emits the release gate's actual product output: a
// PASS/BLOCKED decision, the failed controls, a secondary score, and
// (with -json) the spec's machine-readable output contract. Baseline
// mode (comparing against a stored baseline to block only on
// regressions) is a later build-order step and not implemented here —
// every blocking finding is currently evaluated as if in strict mode.
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

func main() {
	jsonOut := flag.Bool("json", false, "emit the machine-readable JSON output contract instead of the human-readable gate report")
	debug := flag.Bool("debug", false, "emit the full parser-state dump (manifest fields, DEX string samples) instead of the gate report — development/troubleshooting only, not the product output")
	showWarnings := flag.Bool("warnings", false, "show full warning-tier finding details in the terminal gate report (collapsed to a count by default)")
	configPath := flag.String("config", ".mobilegate.yml", "path to .mobilegate.yml (currently just policy.first_party_domains, used by MG-002); a missing file is not an error")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mobilegate [-json] [-debug] [-warnings] [-config path] <path-to-apk>")
		os.Exit(2)
	}
	apkPath := flag.Arg(0)

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}
	defer container.Close()

	m, err := manifest.Parse(container.Manifest, container.ResourcesArsc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	var dexResults []dexFileResult
	var dexStrings []dex.StringRef
	for _, entry := range container.DexFiles {
		strs, err := dex.ParseStrings(entry.Name, entry.Data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
			os.Exit(1)
		}
		dexResults = append(dexResults, dexFileResult{name: entry.Name, strings: strs})
		dexStrings = append(dexStrings, strs...)
	}

	resourceStrings, err := arsc.ExtractGlobalStringPool(container.ResourcesArsc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	manifestStrings, err := arsc.ExtractGlobalStringPool(container.Manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	mg001Findings, err := scanMG001(dexStrings, resourceStrings, manifestStrings, container.AssetFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	mg002Findings, err := scanMG002(container, m, cfg.Policy.FirstPartyDomains)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	mg003Findings, err := scanMG003(container, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	mg010Findings, err := scanMG010(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

	var dexUnattributed int
	for _, s := range dexStrings {
		if s.Usage == dex.Unattributed {
			dexUnattributed++
		}
	}
	scanSurface := scanSurfaceCounts{
		dexStrings:      dexUnattributed, // only Unattributed strings are actually scanned — see ScanDexStrings
		resourceStrings: len(resourceStrings),
		manifestStrings: len(manifestStrings),
		assetFiles:      len(container.AssetFiles),
	}

	if *debug {
		if *jsonOut {
			printDebugJSON(m, dexResults, mg001Findings, mg002Findings, mg003Findings, mg010Findings, scanSurface)
			return
		}
		printDebugDump(apkPath, m, dexResults, mg001Findings, mg002Findings, mg003Findings, mg010Findings, scanSurface)
		return
	}

	var allFindings []core.Finding
	allFindings = append(allFindings, mg001Findings...)
	allFindings = append(allFindings, mg002Findings...)
	allFindings = append(allFindings, mg003Findings...)
	allFindings = append(allFindings, mg010Findings...)

	decision := core.Decide(allFindings)
	score := core.Score(allFindings, decision)
	blocking, warning, info := core.Buckets(allFindings)

	if *jsonOut {
		printContractJSON(decision, score, blocking, warning, info)
	} else {
		printGateReport(apkPath, decision, score, blocking, warning, info, *showWarnings)
	}

	if decision == core.GateBlocked {
		os.Exit(1)
	}
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
