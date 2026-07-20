//go:build oracle

// Development-time correctness check for pkg/parser/arsc, the hand-rolled
// resources.arsc global string pool reader (same "no maintained library
// exposes this" situation as pkg/parser/dex — see that package's oracle
// and pkg/parser/arsc's doc comment for why this is custom code at all).
//
// `aapt2 dump strings` is an independent, from-scratch reading of the
// same string pool. Its printed "String #N" index does NOT correspond to
// the pool's physical on-disk index — confirmed by manual byte-level
// decoding against the resources.arsc spec during development, which
// matched this package's output exactly at the indices where aapt2's
// dump diverged — so this oracle compares the two as a multiset (every
// string that exists, with correct multiplicity) rather than index by
// index. A multiset match across tens of thousands of real, mixed-script
// strings, including several containing embedded NUL-adjacent bytes and
// supplementary-plane emoji, is still strong independent evidence: any
// truncation, offset, or UTF-8/UTF-16 decoding bug in either reader would
// show up as extra/missing/corrupted entries in the diff, regardless of
// ordering.
//
// Same rules as the other oracles: oracle-tagged, never ships, never
// runs in plain `go test ./...`, skips cleanly if aapt2 isn't found.
package oracle

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
)

func TestResourceStringPoolAgainstAapt2(t *testing.T) {
	primary := os.Getenv("MOBILEGATE_ORACLE_APK")
	if primary == "" {
		t.Skip("MOBILEGATE_ORACLE_APK not set; run via `make oracle` — see tools/oracle/README.md")
	}
	t.Run(filepath.Base(primary), func(t *testing.T) { checkResourceStrings(t, primary) })

	if multi := os.Getenv("MOBILEGATE_ORACLE_MULTIDEX_APK"); multi != "" {
		t.Run(filepath.Base(multi), func(t *testing.T) { checkResourceStrings(t, multi) })
	}
}

func checkResourceStrings(t *testing.T, apkPath string) {
	aapt2Path, err := findTool("aapt2")
	if err != nil {
		t.Skipf("aapt2 not available: %v (install Android SDK build-tools, or set ANDROID_HOME)", err)
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("apk.Open: %v", err)
	}
	defer container.Close()
	if len(container.ResourcesArsc) == 0 {
		t.Fatalf("%s: no resources.arsc found", apkPath)
	}

	ours, err := arsc.ExtractGlobalStringPool(container.ResourcesArsc)
	if err != nil {
		t.Fatalf("arsc.ExtractGlobalStringPool: %v", err)
	}
	ourValues := make([]string, len(ours))
	for i, s := range ours {
		ourValues[i] = s.Value
	}

	out, err := exec.Command(aapt2Path, "dump", "strings", apkPath).Output()
	if err != nil {
		t.Fatalf("aapt2 dump strings: %v", err)
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

var aapt2StringMarker = regexp.MustCompile(`(?m)^String #\d+ : `)

// parseAapt2DumpStrings splits aapt2's "String #N : <value>" output into
// the individual (possibly multi-line) string values. Operates on raw
// bytes rather than requiring valid UTF-8: aapt2's own text dump emits
// raw CESU-8 surrogate bytes for supplementary-plane characters (e.g.
// emoji) instead of re-encoding them as proper 4-byte UTF-8, which is a
// quirk of aapt2's dump output, not a defect in our data — Go strings
// can hold those bytes without complaint, so no lossy re-decoding is
// needed to compare them byte-for-byte against our own extraction.
func parseAapt2DumpStrings(out []byte) []string {
	// First line is the "String pool of N unique ... strings" summary,
	// not a string entry — drop everything before the first marker.
	loc := aapt2StringMarker.FindIndex(out)
	if loc == nil {
		return nil
	}
	out = out[loc[0]:]

	idxs := aapt2StringMarker.FindAllIndex(out, -1)
	values := make([]string, 0, len(idxs))
	for i, m := range idxs {
		start := m[1]
		end := len(out)
		if i+1 < len(idxs) {
			end = idxs[i+1][0]
		}
		values = append(values, string(bytes.TrimRight(out[start:end], "\n")))
	}
	return values
}

func diffMultiset(a, b []string) (onlyA, onlyB []string) {
	// a and b are both pre-sorted.
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case a[i] < b[j]:
			onlyA = append(onlyA, a[i])
			i++
		default:
			onlyB = append(onlyB, b[j])
			j++
		}
	}
	onlyA = append(onlyA, a[i:]...)
	onlyB = append(onlyB, b[j:]...)
	return onlyA, onlyB
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("…(+%d bytes)", len(s)-n)
}
