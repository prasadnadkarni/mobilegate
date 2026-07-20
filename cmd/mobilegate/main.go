// Command mobilegate is the MobileGate CLI entrypoint.
//
// At this build-order step it only exercises the parser: unzip, manifest,
// and DEX string extraction. There is no rule engine, scoring, or gate
// decision yet — those are later build-order steps.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
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
	for _, entry := range container.DexFiles {
		strs, err := dex.ParseStrings(entry.Name, entry.Data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mobilegate: %v\n", err)
			os.Exit(1)
		}
		dexResults = append(dexResults, dexFileResult{name: entry.Name, strings: strs})
	}

	if *jsonOut {
		printJSON(m, dexResults)
		return
	}
	printText(apkPath, m, dexResults)
}

type dexFileResult struct {
	name    string
	strings []dex.StringRef
}
