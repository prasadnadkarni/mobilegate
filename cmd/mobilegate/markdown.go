package main

import (
	"fmt"
	"strings"

	"github.com/prasadnadkarni/mobilegate/internal/core"
)

// markdownReport renders the gate result as GitHub/GitLab-flavored
// Markdown for a PR comment — spec: "Provide a Markdown formatter for
// the GitHub/GitLab PR comment." Deliberately a third VIEW over exactly
// the same finding buckets (blocking/warning/baselined/suppressed) the
// terminal and JSON reports already compute in runGate, not a separate
// code path that could drift from what actually gates the release.
//
// Failed controls are always fully visible; baselined/suppressed/
// warning findings are wrapped in <details> (GitHub and GitLab both
// render this natively in Markdown) so a PR comment on a mostly-clean
// change doesn't bury the one thing that matters under grandfathered
// debt — the same "warnings collapsed by default" principle the
// terminal report follows, extended to the other two collapsible
// buckets this format supports that the terminal doesn't bother
// collapsing (a terminal isn't collaboratively read by a whole team the
// way a PR thread is, so the terminal report just always shows them).
func markdownReport(apkPath, mode string, decision core.GateDecision, score int, blocking, warning, info, baselined []core.Finding, suppressed []core.SuppressedFinding) string {
	var b strings.Builder

	status := "PASS"
	if decision == core.GateBlocked {
		status = "BLOCKED"
	}
	fmt.Fprintf(&b, "## MobileGate — %s\n\n", status)
	fmt.Fprintf(&b, "**APK:** `%s`  \n", apkPath)
	fmt.Fprintf(&b, "**Mode:** %s  \n", mode)
	fmt.Fprintf(&b, "**Score:** %d/100 _(secondary to the release status above)_\n\n", score)

	if len(blocking) == 0 {
		b.WriteString("No blocking findings.\n\n")
	} else {
		fmt.Fprintf(&b, "### Failed controls (%d)\n\n", len(blocking))
		writeMarkdownControls(&b, blocking)
	}

	if len(baselined) > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>%d pre-existing finding(s) grandfathered by baseline (not blocking)</summary>\n\n", len(baselined))
		writeMarkdownControls(&b, baselined)
		b.WriteString("</details>\n\n")
	}

	if len(suppressed) > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>%d finding(s) suppressed by policy (.mobilegate.yml ignore_rules)</summary>\n\n", len(suppressed))
		writeMarkdownSuppressed(&b, suppressed)
		b.WriteString("</details>\n\n")
	}

	if len(warning) > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>%d warning(s)</summary>\n\n", len(warning))
		writeMarkdownControls(&b, warning)
		b.WriteString("</details>\n\n")
	}

	// info is always empty in this build (see core.Finding.Blocking's
	// doc comment) — kept as a parameter for symmetry with the terminal
	// and JSON reports so this signature doesn't need to change when a
	// real info-tier rule eventually exists.
	_ = info

	return b.String()
}

func writeMarkdownControls(b *strings.Builder, findings []core.Finding) {
	order, byRule := groupByRule(findings)
	for _, ruleID := range order {
		fs := byRule[ruleID]
		fmt.Fprintf(b, "**%s — %s** (%d finding%s)\n\n", ruleID, fs[0].RuleName, len(fs), plural(len(fs)))
		for _, f := range fs {
			b.WriteString("- `")
			b.WriteString(f.Source)
			b.WriteString("`")
			if f.Line != nil {
				fmt.Fprintf(b, " (line %d)", *f.Line)
			} else if f.Location != "" {
				fmt.Fprintf(b, " (%s)", f.Location)
			}
			fmt.Fprintf(b, ": `%s`\n", f.Excerpt)
			fmt.Fprintf(b, "  - **Why it blocks:** %s\n", f.WhyItBlocks)
			fmt.Fprintf(b, "  - **Remediation:** %s\n", f.Remediation)
			fmt.Fprintf(b, "  - MASVS: `%s` · CWE: `%s` · confidence: %s\n", f.MASVS, f.CWE, f.Confidence)
			fmt.Fprintf(b, "  - `finding_hash: %s`\n", f.FindingHash)
		}
		b.WriteString("\n")
	}
}

func writeMarkdownSuppressed(b *strings.Builder, suppressed []core.SuppressedFinding) {
	order, byRule := groupSuppressedByRule(suppressed)
	for _, ruleID := range order {
		items := byRule[ruleID]
		fmt.Fprintf(b, "**%s — %s** (%d finding%s)\n\n", ruleID, items[0].Finding.RuleName, len(items), plural(len(items)))
		for _, s := range items {
			fmt.Fprintf(b, "- `%s`: `%s`\n", s.Finding.Source, s.Finding.Excerpt)
			fmt.Fprintf(b, "  - **Reason:** %s\n", s.Rule.Reason)
			fmt.Fprintf(b, "  - `finding_hash: %s`\n", s.Finding.FindingHash)
		}
		b.WriteString("\n")
	}
}
