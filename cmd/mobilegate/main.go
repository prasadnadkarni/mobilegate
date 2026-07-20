// Command mobilegate is the MobileGate CLI entrypoint.
//
// At this build-order step it exercises the parser (unzip, manifest, DEX
// string extraction) and one rule, MG-001 (hardcoded secrets). There is
// no scoring or gate decision (PASS/BLOCKED) yet, and no other rules —
// those are later build-order steps. Findings are reported for review,
// not enforced.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/prasadnadkarni/mobilegate/rules"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit machine-readable parser dump instead of the human-readable report")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mobilegate [-json] <path-to-apk>")
		os.Exit(2)
	}
	apkPath := flag.Arg(0)

	container, err := apk.Open(apkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
		os.Exit(1)
	}

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

	findings, err := scanMG001(dexStrings, resourceStrings, container.AssetFiles)
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
		assetFiles:      len(container.AssetFiles),
	}

	if *jsonOut {
		printJSON(m, dexResults, findings, scanSurface)
		return
	}
	printText(apkPath, m, dexResults, findings, scanSurface)
}

// scanMG001 loads the embedded MG-001 rule and runs it against the
// parser output. The only rule wired in at this build-order step.
func scanMG001(dexStrings []dex.StringRef, resourceStrings []arsc.PoolString, assets []apk.AssetEntry) ([]engine.Finding, error) {
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
	for _, a := range assets {
		findings = append(findings, scanner.ScanAsset(a.Name, a.Data)...)
	}
	return findings, nil
}

// scanSurfaceCounts is reported alongside findings so "zero findings" can
// be told apart from "nothing was scanned."
type scanSurfaceCounts struct {
	dexStrings      int
	resourceStrings int
	assetFiles      int
}

type dexFileResult struct {
	name    string
	strings []dex.StringRef
}
