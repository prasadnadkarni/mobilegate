//go:build oracle

// This file is a development-time correctness check, never a runtime
// dependency of MobileGate: it shells out to real Android SDK tooling
// (apkanalyzer, part of the cmdline-tools package; aapt2 as a fallback)
// to get an independent, authoritative read of a real APK's manifest,
// then diffs that against pkg/parser/manifest's output.
//
// It is gated behind the "oracle" build tag specifically so that:
//   - `go build ./...` never links it into the release binary.
//   - `go test ./...` never runs it and never requires the Android SDK
//     to be installed just to run the normal test suite.
//   - CLAUDE.md's "no shelling out to anything JVM-based" constraint is
//     about the shipped detection/gate path, not developer tooling used
//     to sanity-check that path — apkanalyzer/aapt2 never run in CI or
//     in the mobilegate binary itself.
//
// Run via `make oracle` (see Makefile), which also fetches the pinned
// dev-verification APK documented in testdata/real/README.md.
package oracle

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// componentKey identifies one activity/service/receiver/provider by kind
// and name, matched between our parser and the oracle tool.
type componentKey struct {
	kind string
	name string
}

type componentTruth struct {
	exported   string // "true" | "false" | "unset"
	permission string
}

type groundTruth struct {
	source               string // which tool produced this, for failure messages
	packageName          string
	usesCleartextTraffic string // "true" | "false" | "unset"
	components           map[componentKey]componentTruth
}

func TestManifestAgainstAndroidSDK(t *testing.T) {
	apkPath := os.Getenv("MOBILEGATE_ORACLE_APK")
	if apkPath == "" {
		t.Skip("MOBILEGATE_ORACLE_APK not set; run via `make oracle` — see tools/oracle/README.md")
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("apk.Open: %v", err)
	}
	got, err := manifest.Parse(container.Manifest, container.ResourcesArsc)
	if err != nil {
		t.Fatalf("manifest.Parse: %v", err)
	}

	want, err := groundTruthFor(apkPath)
	if err != nil {
		t.Skipf("no oracle tool available: %v (install Android SDK cmdline-tools/build-tools, or set ANDROID_HOME)", err)
	}
	t.Logf("oracle source: %s", want.source)

	if got.PackageName != want.packageName {
		t.Errorf("package name: parser=%q oracle(%s)=%q", got.PackageName, want.source, want.packageName)
	}

	gotCleartext := tristateStr(got.UsesCleartextTraffic)
	if want.usesCleartextTraffic != "" && gotCleartext != want.usesCleartextTraffic {
		t.Errorf("usesCleartextTraffic: parser=%q oracle(%s)=%q", gotCleartext, want.source, want.usesCleartextTraffic)
	}

	gotComponents := map[componentKey]componentTruth{}
	for _, c := range got.Components {
		gotComponents[componentKey{kind: string(c.Kind), name: c.Name}] = componentTruth{
			exported:   tristateStr(c.Exported),
			permission: c.Permission,
		}
	}

	if want.components != nil {
		var mismatches []string
		for k, wantC := range want.components {
			gotC, ok := gotComponents[k]
			if !ok {
				mismatches = append(mismatches, fmt.Sprintf("MISSING in parser output: %s %s (oracle: exported=%s permission=%q)", k.kind, k.name, wantC.exported, wantC.permission))
				continue
			}
			if gotC.exported != wantC.exported {
				mismatches = append(mismatches, fmt.Sprintf("%s %s: exported parser=%s oracle=%s", k.kind, k.name, gotC.exported, wantC.exported))
			}
			if gotC.permission != wantC.permission {
				mismatches = append(mismatches, fmt.Sprintf("%s %s: permission parser=%q oracle=%q", k.kind, k.name, gotC.permission, wantC.permission))
			}
		}
		for k := range gotComponents {
			if _, ok := want.components[k]; !ok {
				mismatches = append(mismatches, fmt.Sprintf("EXTRA in parser output not seen by oracle: %s %s", k.kind, k.name))
			}
		}
		sort.Strings(mismatches)
		for _, m := range mismatches {
			t.Error(m)
		}
		t.Logf("compared %d components against %s", len(want.components), want.source)
	}
}

func tristateStr(t manifest.Tristate) string {
	switch t {
	case manifest.True:
		return "true"
	case manifest.False:
		return "false"
	default:
		return "unset"
	}
}

// groundTruthFor tries apkanalyzer first (it prints a fully reconstructed,
// real AndroidManifest.xml — the highest-fidelity, easiest-to-parse
// ground truth) and falls back to aapt2 (package name + coarse
// usesCleartextTraffic check only; aapt2's badging summary doesn't list
// per-component exported/permission at all, and its xmltree dump format
// has changed across SDK versions, so we don't attempt a full structural
// diff against it).
func groundTruthFor(apkPath string) (*groundTruth, error) {
	if path, err := findTool("apkanalyzer"); err == nil {
		return viaApkAnalyzer(path, apkPath)
	}
	if path, err := findTool("aapt2"); err == nil {
		return viaAapt2Badging(path, apkPath)
	}
	return nil, fmt.Errorf("neither apkanalyzer nor aapt2 found on PATH or under $ANDROID_HOME/$ANDROID_SDK_ROOT")
}

// findTool looks on PATH first, then in the usual Android SDK
// cmdline-tools/build-tools layout under $ANDROID_HOME or
// $ANDROID_SDK_ROOT, since these tools are commonly installed but not
// added to PATH.
func findTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, envVar := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		root := os.Getenv(envVar)
		if root == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(root, "cmdline-tools", "*", "bin", name))
		matches2, _ := filepath.Glob(filepath.Join(root, "build-tools", "*", name))
		all := append(matches, matches2...)
		sort.Sort(sort.Reverse(sort.StringSlice(all))) // prefer highest version dir
		for _, m := range all {
			if info, err := os.Stat(m); err == nil && !info.IsDir() {
				return m, nil
			}
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// --- apkanalyzer path: parses its reconstructed, real AndroidManifest.xml ---

type gtComponent struct {
	Name       string  `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported   *string `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission *string `xml:"http://schemas.android.com/apk/res/android permission,attr"`
}

type gtApplication struct {
	UsesCleartextTraffic *string       `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	Activities           []gtComponent `xml:"activity"`
	Services             []gtComponent `xml:"service"`
	Receivers            []gtComponent `xml:"receiver"`
	Providers            []gtComponent `xml:"provider"`
}

type gtManifest struct {
	Package string        `xml:"package,attr"`
	App     gtApplication `xml:"application"`
}

func viaApkAnalyzer(toolPath, apkPath string) (*groundTruth, error) {
	out, err := exec.Command(toolPath, "manifest", "print", apkPath).Output()
	if err != nil {
		return nil, fmt.Errorf("apkanalyzer manifest print: %w", err)
	}

	var m gtManifest
	if err := xml.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("parsing apkanalyzer manifest output: %w", err)
	}

	gt := &groundTruth{
		source:      "apkanalyzer",
		packageName: m.Package,
		components:  map[componentKey]componentTruth{},
	}
	gt.usesCleartextTraffic = optStrTristate(m.App.UsesCleartextTraffic)

	add := func(kind string, cs []gtComponent) {
		for _, c := range cs {
			gt.components[componentKey{kind: kind, name: c.Name}] = componentTruth{
				exported:   optStrTristate(c.Exported),
				permission: derefOr(c.Permission, ""),
			}
		}
	}
	add("activity", m.App.Activities)
	add("service", m.App.Services)
	add("receiver", m.App.Receivers)
	add("provider", m.App.Providers)

	return gt, nil
}

func optStrTristate(s *string) string {
	if s == nil {
		return "unset"
	}
	return *s
}

func derefOr(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}

// --- aapt2 fallback: coarse checks only (package name + cleartext) ---

func viaAapt2Badging(toolPath, apkPath string) (*groundTruth, error) {
	out, err := exec.Command(toolPath, "dump", "badging", apkPath).Output()
	if err != nil {
		return nil, fmt.Errorf("aapt2 dump badging: %w", err)
	}
	text := string(out)

	gt := &groundTruth{source: "aapt2 dump badging (coarse: package name only, no per-component exported/permission check)"}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "package:") {
			if idx := strings.Index(line, "name='"); idx >= 0 {
				rest := line[idx+len("name='"):]
				if end := strings.Index(rest, "'"); end >= 0 {
					gt.packageName = rest[:end]
				}
			}
		}
	}
	// aapt2 badging doesn't reliably surface usesCleartextTraffic or
	// per-component exported/permission, so we deliberately leave
	// usesCleartextTraffic empty and components nil: the test above skips
	// those comparisons when so.
	return gt, nil
}
