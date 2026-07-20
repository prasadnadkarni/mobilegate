//go:build oracle

// Development-time correctness check for pkg/parser/dex, the hand-rolled
// string-pool extractor — the highest-risk parser code in step 1 since,
// unlike the manifest path, it has no maintained library backing it to
// lean on. dexdump (Android SDK build-tools) is a from-scratch
// implementation of the DEX format independent of ours; cross-checking
// our extracted string count against its reported string_ids_size for
// every classes*.dex in a real APK catches offset/bounds mistakes that a
// "parses without crashing" smoke test would miss entirely.
//
// Same rules as manifest_oracle_test.go: oracle-tagged, never ships,
// never runs in plain `go test ./...`, requires the Android SDK
// build-tools on PATH/$ANDROID_HOME/$ANDROID_SDK_ROOT and skips cleanly
// if absent.
package oracle

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
)

func TestDexStringCountAgainstDexdump(t *testing.T) {
	primary := os.Getenv("MOBILEGATE_ORACLE_APK")
	if primary == "" {
		t.Skip("MOBILEGATE_ORACLE_APK not set; run via `make oracle` — see tools/oracle/README.md")
	}
	t.Run(filepath.Base(primary), func(t *testing.T) {
		checkDexStringCounts(t, primary)
	})

	// Optional: a multi-dex APK, to exercise classes2.dex+ against real
	// input rather than only the synthetic multi-dex unit test.
	if multi := os.Getenv("MOBILEGATE_ORACLE_MULTIDEX_APK"); multi != "" {
		t.Run(filepath.Base(multi), func(t *testing.T) {
			checkDexStringCounts(t, multi)
		})
	}
}

func checkDexStringCounts(t *testing.T, apkPath string) {
	dexdumpPath, err := findTool("dexdump")
	if err != nil {
		t.Skipf("dexdump not available: %v (install Android SDK build-tools, or set ANDROID_HOME)", err)
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("apk.Open: %v", err)
	}
	if len(container.DexFiles) == 0 {
		t.Fatalf("%s: no classes*.dex found", apkPath)
	}
	t.Logf("%s: %d dex file(s)", filepath.Base(apkPath), len(container.DexFiles))

	tmpDir := t.TempDir()
	for _, entry := range container.DexFiles {
		got, err := dex.ParseStrings(entry.Name, entry.Data)
		if err != nil {
			t.Fatalf("dex.ParseStrings(%s): %v", entry.Name, err)
		}

		// dexdump needs a real file on disk; hand it the raw dex bytes we
		// already extracted rather than the apk, so this test exercises
		// exactly the same bytes our parser saw, one dex file at a time
		// with no ambiguity about which entry dexdump is reading.
		dexPath := filepath.Join(tmpDir, entry.Name)
		if err := os.WriteFile(dexPath, entry.Data, 0o644); err != nil {
			t.Fatalf("writing %s to temp dir: %v", entry.Name, err)
		}

		want, err := dexdumpStringIDsSize(dexdumpPath, dexPath)
		if err != nil {
			t.Fatalf("dexdump(%s): %v", entry.Name, err)
		}

		if len(got) != want {
			t.Errorf("%s: string count parser=%d dexdump string_ids_size=%d", entry.Name, len(got), want)
			continue
		}
		t.Logf("%s: string_ids_size=%d matches parser", entry.Name, want)
	}
}

var stringIDsSizeRE = regexp.MustCompile(`string_ids_size\s*:\s*(\d+)`)

func dexdumpStringIDsSize(dexdumpPath, dexFilePath string) (int, error) {
	// dexdump -f still emits a full class listing after the header on
	// some SDK versions; we only need the header line, so run it and
	// regex out string_ids_size rather than depending on -f fully
	// suppressing the rest.
	out, cmdErr := exec.Command(dexdumpPath, "-f", dexFilePath).CombinedOutput()
	m := stringIDsSizeRE.FindSubmatch(out)
	if m == nil {
		if cmdErr != nil {
			return 0, fmt.Errorf("dexdump -f %s: %w\n%s", dexFilePath, cmdErr, out)
		}
		return 0, fmt.Errorf("could not find string_ids_size in dexdump output for %s:\n%s", dexFilePath, out)
	}
	return strconv.Atoi(string(m[1]))
}
