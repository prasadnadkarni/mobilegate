package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/prasadnadkarni/mobilegate/internal/engine"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// maxSampleStrings caps how many example strings per dex file the text
// report prints, to keep the eyeball-check output readable on a real APK
// with tens of thousands of strings.
const maxSampleStrings = 15

func printText(apkPath string, m *manifest.Manifest, results []dexFileResult, findings []engine.Finding) {
	fmt.Printf("APK: %s\n\n", apkPath)

	fmt.Println("== MG-001: Hardcoded production secret ==")
	if len(findings) == 0 {
		fmt.Println("no findings")
	}
	for _, f := range findings {
		blockLabel := "WARNING"
		if f.Blocking {
			blockLabel = "BLOCKING"
		}
		fmt.Printf("[%s] %s (%s)\n", blockLabel, f.Title, f.PatternID)
		fmt.Printf("  source:     %s\n", f.Source)
		fmt.Printf("  location:   %s\n", f.Location)
		fmt.Printf("  excerpt:    %s\n", f.Excerpt)
		fmt.Printf("  confidence: %s   severity: %s   masvs: %s   cwe: %s\n", f.Confidence, f.Severity, f.MASVS, f.CWE)
		fmt.Printf("  signal:     %s\n", f.SignalDetail)
	}
	fmt.Println()

	fmt.Println("== Manifest ==")
	fmt.Printf("package:                 %s\n", m.PackageName)
	fmt.Printf("usesCleartextTraffic:    %s\n", tristateLabel(m.UsesCleartextTraffic))
	fmt.Printf("networkSecurityConfig:   %s\n", orNone(m.NetworkSecurityConfig))
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

type jsonReport struct {
	PackageName           string          `json:"package_name"`
	UsesCleartextTraffic  string          `json:"uses_cleartext_traffic"`
	NetworkSecurityConfig string          `json:"network_security_config"`
	Components            []jsonComponent `json:"components"`
	Dex                   []jsonDexFile   `json:"dex"`
	Findings              []jsonFinding   `json:"findings"`
}

type jsonFinding struct {
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
}

type jsonComponent struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Exported        string `json:"exported"`
	Permission      string `json:"permission"`
	HasIntentFilter bool   `json:"has_intent_filter"`
}

type jsonDexFile struct {
	File        string          `json:"file"`
	StringCount int             `json:"string_count"`
	Strings     []jsonStringRef `json:"strings"`
}

type jsonStringRef struct {
	Index     int    `json:"index"`
	Value     string `json:"value"`
	Usage     string `json:"usage"`
	ClassType string `json:"class_type,omitempty"`
}

func printJSON(m *manifest.Manifest, results []dexFileResult, findings []engine.Finding) {
	rep := jsonReport{
		PackageName:           m.PackageName,
		UsesCleartextTraffic:  tristateLabel(m.UsesCleartextTraffic),
		NetworkSecurityConfig: m.NetworkSecurityConfig,
	}
	for _, f := range findings {
		rep.Findings = append(rep.Findings, jsonFinding{
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
		})
	}
	for _, c := range m.Components {
		rep.Components = append(rep.Components, jsonComponent{
			Kind:            string(c.Kind),
			Name:            c.Name,
			Exported:        tristateLabel(c.Exported),
			Permission:      c.Permission,
			HasIntentFilter: c.HasIntentFilter,
		})
	}
	for _, r := range results {
		df := jsonDexFile{File: r.name, StringCount: len(r.strings)}
		for _, s := range r.strings {
			df.Strings = append(df.Strings, jsonStringRef{
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
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(os.Stderr, "mobilegate: encode json: %v\n", err)
		os.Exit(1)
	}
}
