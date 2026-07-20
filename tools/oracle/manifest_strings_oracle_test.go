//go:build oracle

// Development-time correctness check for pkg/parser/arsc's other
// container format: AndroidManifest.xml's own binary-XML string pool
// (RES_XML_TYPE), as opposed to resources.arsc's resource table
// (RES_TABLE_TYPE) — see that package's doc comment for why the same
// reader handles both. `aapt2 dump xmlstrings` is the independent,
// from-scratch oracle for this container, the XML-specific sibling of
// `aapt2 dump strings` used in arsc_oracle_test.go; reuses that file's
// parseAapt2DumpStrings/diffMultiset helpers since the output format and
// multiset-not-index comparison rationale are identical.
//
// Same rules as the other oracles: oracle-tagged, never ships, never
// runs in plain `go test ./...`, skips cleanly if aapt2 isn't found.
package oracle

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
)

func TestManifestStringPoolAgainstAapt2(t *testing.T) {
	primary := os.Getenv("MOBILEGATE_ORACLE_APK")
	if primary == "" {
		t.Skip("MOBILEGATE_ORACLE_APK not set; run via `make oracle` — see tools/oracle/README.md")
	}
	t.Run(filepath.Base(primary), func(t *testing.T) { checkManifestStrings(t, primary) })

	if multi := os.Getenv("MOBILEGATE_ORACLE_MULTIDEX_APK"); multi != "" {
		t.Run(filepath.Base(multi), func(t *testing.T) { checkManifestStrings(t, multi) })
	}
}

func checkManifestStrings(t *testing.T, apkPath string) {
	aapt2Path, err := findTool("aapt2")
	if err != nil {
		t.Skipf("aapt2 not available: %v (install Android SDK build-tools, or set ANDROID_HOME)", err)
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("apk.Open: %v", err)
	}
	if len(container.Manifest) == 0 {
		t.Fatalf("%s: no AndroidManifest.xml found", apkPath)
	}

	ours, err := arsc.ExtractGlobalStringPool(container.Manifest)
	if err != nil {
		t.Fatalf("arsc.ExtractGlobalStringPool(manifest): %v", err)
	}
	ourValues := make([]string, len(ours))
	for i, s := range ours {
		ourValues[i] = s.Value
	}

	out, err := exec.Command(aapt2Path, "dump", "xmlstrings", apkPath, "--file", "AndroidManifest.xml").Output()
	if err != nil {
		t.Fatalf("aapt2 dump xmlstrings: %v", err)
	}
	theirValues := parseAapt2DumpStrings(out)

	t.Logf("%s: ours=%d strings, aapt2=%d strings", filepath.Base(apkPath), len(ourValues), len(theirValues))

	if len(ourValues) != len(theirValues) {
		t.Errorf("string count mismatch: ours=%d aapt2=%d", len(ourValues), len(theirValues))
	}

	sort.Strings(ourValues)
	sort.Strings(theirValues)

	onlyOurs, onlyTheirs := diffMultiset(ourValues, theirValues)
	const maxShown = 10
	for i, s := range onlyOurs {
		if i >= maxShown {
			t.Errorf("... and %d more strings only in our extraction", len(onlyOurs)-maxShown)
			break
		}
		t.Errorf("only in our extraction: %q", truncate(s, 120))
	}
	for i, s := range onlyTheirs {
		if i >= maxShown {
			t.Errorf("... and %d more strings only in aapt2's dump", len(onlyTheirs)-maxShown)
			break
		}
		t.Errorf("only in aapt2's dump: %q", truncate(s, 120))
	}
}
