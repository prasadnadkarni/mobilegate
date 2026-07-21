// Package sarif converts MobileGate's own finding model
// (internal/core.Finding) into a SARIF 2.1.0 log, so findings can flow
// into GitHub Code Scanning's Security tab alongside CodeQL and other
// tools.
//
// SARIF assumes findings live in source files. MobileGate's don't — they
// live inside a binary APK (a compiled AndroidManifest.xml, a DEX string
// pool, resources.arsc, an asset file). GitHub only renders a finding
// inline on a PR diff when artifactLocation.uri resolves to a real repo
// path; everything here is built around being honest about when that is
// and isn't true, rather than fabricating a location that looks
// plausible but isn't verified — see artifactURI's doc comment.
//
// Three facts about GitHub's actual SARIF ingestion, confirmed against
// docs.github.com and a May-2025 GitHub-staff reply on
// github.com/orgs/community/discussions/156737 (not assumed — verified,
// since getting any of these wrong means a feature silently doesn't
// work on GitHub's side even though the file is schema-valid):
//
//  1. security-severity (the numeric score that drives GitHub's
//     Critical/High/Medium/Low ranking) is read ONLY from
//     reportingDescriptor.properties["security-severity"] — the RULE,
//     not the result. A result-level value is simply never read. See
//     severityScoreFor's doc comment for how this rule builds one
//     number per rule id despite some rules (MG-004) producing findings
//     at more than one severity.
//
//  2. results[].suppressions — SARIF's own native suppression
//     mechanism — is NOT implemented by GitHub's code-scanning
//     ingestion as of the discussion above ("we promise to do our best
//     to address this in the future" — i.e., not yet). A suppressed
//     result uploaded there would NOT show as suppressed; it would show
//     as a normal, active, alerting result — the opposite of what
//     suppression is for. So Build deliberately omits baselined and
//     policy-suppressed findings from the SARIF output entirely, rather
//     than emitting a suppressions[] array GitHub will silently ignore.
//     Suppressed findings remain fully visible in every OTHER MobileGate
//     output format (JSON, terminal, Markdown) — this is SARIF-specific,
//     not a product-wide suppression change.
//
//  3. partialFingerprints — used for alert identity across runs — is
//     only honored under the exact key "primaryLocationLineHash". A
//     tool-provided value under any other key is ignored, and if the
//     whole partialFingerprints object is empty/absent, upload-sarif
//     tries to compute its own fingerprint from surrounding SOURCE
//     LINES — meaningless (and unstable) for an artifactLocation that
//     points at an APK or a merged manifest with no verified line. So
//     this package puts our own stable finding_hash under exactly that
//     key, even though "line hash" doesn't literally describe it — it's
//     the only key GitHub will actually use.
package sarif

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prasadnadkarni/mobilegate/internal/core"
)

const schemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

// maxResults is a conservative, self-imposed hard limit — well below
// GitHub's own documented 25,000-results-per-run ceiling, and at the
// 5,000 mark GitHub's own docs say only the top 5,000 (by severity) are
// even guaranteed to be included in a run above that count. Rather than
// rely on GitHub's own truncation-by-severity behavor (which is silent
// from this tool's side — we'd have no way to tell the user which
// findings got dropped), Build refuses outright once results would
// exceed this, so the failure is loud and attributable to MobileGate,
// not a silent gap discovered later in the Security tab. MobileGate's
// real-world finding counts (worst case seen: ~19 for one rule on one
// APK in the reference corpus) are nowhere near this ceiling in
// practice.
const maxResults = 5000

// severityScore maps MobileGate's severity vocabulary to GitHub's
// documented security-severity bands: "over 9.0 is critical, from 7.0
// to 8.9 is high, from 4.0 to 6.9 is medium and from 0.1 to 3.9 is low"
// (docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
// Picked mid-band, not at an edge, so a future off-by-one in either this
// table or GitHub's own band boundaries doesn't silently cross into the
// wrong tier.
var severityScore = map[string]string{
	"critical": "9.5",
	"high":     "7.5",
	"medium":   "5.5",
	"low":      "2.5",
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// RuleInfo is the static, per-rule metadata Build needs for
// tool.driver.rules — deliberately a plain struct rather than importing
// internal/engine's rule-definition types, so this package only depends
// on internal/core, matching the project's existing layering (rule
// engines construct core.Finding; nothing downstream of core should need
// to know about rule-loading machinery).
type RuleInfo struct {
	ID          string
	Name        string
	Description string
	Remediation string

	// Severity is the rule's own static, YAML-declared severity — used
	// as the FLOOR for this rule's security-severity score when no
	// finding for it appears in the current run, and as the starting
	// point when some do (see severityScoreFor). Not necessarily the
	// only severity this rule can produce — MG-004's static severity is
	// "high", but an unguarded exported <provider> finding is
	// "critical"; see severityScoreFor's doc comment.
	Severity string
	MASVS    string
	CWE      string
}

// BuildInput is everything Build needs. APKPath and SourceManifestPath
// are already the caller's fully-resolved values (default applied, if
// any) — this package doesn't know about .mobilegate.yml or CLI flags.
type BuildInput struct {
	ToolVersion string // scannerVersion
	RepoURI     string // tool.driver.informationUri

	// AutomationID distinguishes this run's results from another scan
	// (e.g. a different APK variant) in GitHub's automationDetails — see
	// the "runs[].automationDetails.id" requirement. Does not replace
	// upload-sarif's own `category` input, which is the actual mechanism
	// GitHub uses to keep multiple SARIF uploads for the same commit
	// from overwriting each other; this is SARIF-level identification
	// only. Caller's responsibility to pass something meaningful (see
	// cmd/mobilegate's automationID, built from the app's own package
	// name).
	AutomationID string

	// Rules is every rule MobileGate ships, regardless of whether it
	// produced a finding in this run — spec: "one reportingDescriptor
	// per rule (MG-001..MG-010)."
	Rules []RuleInfo

	// Findings is every non-suppressed, non-baselined finding from this
	// run (i.e. exactly what the terminal/JSON/Markdown reports show as
	// blocking+warning — NOT info, which doesn't exist in this build;
	// see core.Finding.Blocking's doc comment). Baselined and
	// policy-suppressed findings must NOT be passed here — see this
	// package's doc comment, point 2.
	Findings []core.Finding

	// APKPath is used only for its base name (see artifactURI) — never
	// embedded as an absolute path, which would leak the build
	// machine's filesystem layout into a file that may end up in a
	// public repo's Security tab.
	APKPath string

	// SourceManifestPath is policy.source_manifest_path from
	// .mobilegate.yml, already defaulted by the caller (see
	// cmd/mobilegate's defaultSourceManifestPath) if unset.
	SourceManifestPath string
}

// Build converts in into a SARIF 2.1.0 log. Returns an error if the
// result count would exceed maxResults — see that constant's doc
// comment for why this fails loudly instead of truncating.
func Build(in BuildInput) (*Log, error) {
	if len(in.Findings) > maxResults {
		return nil, fmt.Errorf("sarif: %d results exceeds this tool's self-imposed limit of %d (GitHub's own documented ceiling is higher, but only the top 5,000 results by severity are guaranteed inclusion above that — refusing to build a SARIF file that could be silently truncated on upload; see internal/sarif.maxResults)", len(in.Findings), maxResults)
	}

	rules := make([]ReportingDescriptor, 0, len(in.Rules))
	sortedRules := append([]RuleInfo(nil), in.Rules...)
	sort.Slice(sortedRules, func(i, j int) bool { return sortedRules[i].ID < sortedRules[j].ID })
	for _, r := range sortedRules {
		rules = append(rules, reportingDescriptorFor(r, in.Findings))
	}

	apkBase := filepath.Base(in.APKPath)
	sourceManifestPath := in.SourceManifestPath

	results := make([]Result, 0, len(in.Findings))
	for _, f := range in.Findings {
		results = append(results, resultFor(f, apkBase, sourceManifestPath))
	}

	return &Log{
		Schema:  schemaURI,
		Version: sarifVersion,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: ToolComponent{
						Name:           "MobileGate",
						Version:        in.ToolVersion,
						InformationURI: in.RepoURI,
						Rules:          rules,
					},
				},
				Results:           results,
				AutomationDetails: &AutomationDetails{ID: in.AutomationID},
			},
		},
	}, nil
}

// reportingDescriptorFor builds one rule's static metadata plus its
// security-severity score.
func reportingDescriptorFor(r RuleInfo, findings []core.Finding) ReportingDescriptor {
	tags := []string{"security"}
	if r.MASVS != "" {
		tags = append(tags, r.MASVS)
	}
	if r.CWE != "" {
		tags = append(tags, r.CWE)
	}

	help := r.Description
	if r.Remediation != "" {
		help = strings.TrimSpace(help) + "\n\n**Remediation:** " + strings.TrimSpace(r.Remediation)
	}

	return ReportingDescriptor{
		ID:               r.ID,
		Name:             r.Name,
		ShortDescription: MultiformatMessage{Text: r.Name},
		FullDescription:  MultiformatMessage{Text: strings.TrimSpace(r.Description)},
		Help:             MultiformatMessage{Text: strings.TrimSpace(help), Markdown: strings.TrimSpace(help)},
		Properties: &ReportingDescriptorProperties{
			Tags:             tags,
			SecuritySeverity: severityScoreFor(r, findings),
		},
	}
}

// severityScoreFor computes ONE security-severity number for a rule,
// because that's all GitHub reads (see this package's doc comment,
// point 1) even though a single rule id can produce findings at more
// than one MobileGate severity (MG-004: "high" by default, "critical"
// for an unguarded exported <provider> — see
// rules/MG-004-exported-component.yaml). Starts from the rule's own
// static YAML severity (so a rule that fired zero times this run still
// gets a sensible score), then raises it if any ACTUAL finding this run
// is more severe — never lowers it. This means MG-004 correctly reports
// as "critical" in GitHub's ranking on any run where an unguarded
// provider actually fired, without this package hardcoding
// MG-004-specific knowledge; it falls out of the real data.
func severityScoreFor(r RuleInfo, findings []core.Finding) string {
	worst := r.Severity
	worstRank := severityRank[worst]
	for _, f := range findings {
		if f.RuleID != r.ID {
			continue
		}
		if rank := severityRank[f.Severity]; rank > worstRank {
			worst = f.Severity
			worstRank = rank
		}
	}
	if score, ok := severityScore[worst]; ok {
		return score
	}
	return "" // unknown severity string: omit rather than guess a number
}

// resultFor converts one finding into a SARIF result.
func resultFor(f core.Finding, apkBase, sourceManifestPath string) Result {
	return Result{
		RuleID:  f.RuleID,
		Level:   levelFor(f),
		Message: Message{Text: messageFor(f)},
		Locations: []Location{
			{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: artifactURI(f, apkBase, sourceManifestPath)}}},
		},
		// primaryLocationLineHash is the only key GitHub's fingerprint
		// matching actually reads (see this package's doc comment,
		// point 3) — not a literal line hash, but the only way to make
		// GitHub track this finding's identity using OUR finding_hash
		// instead of trying (and failing) to compute its own from
		// source context that doesn't meaningfully exist here.
		PartialFingerprints: map[string]string{"primaryLocationLineHash": f.FindingHash},
		Properties:          resultPropertiesFor(f),
	}
}

// levelFor maps MobileGate's Blocking bool to SARIF's level vocabulary.
// Only error/warning are reachable today — core.Finding has no info
// tier yet (see that type's doc comment) — but this is written as a
// real mapping, not a ternary, so a future info tier is a one-line
// addition here rather than a design change.
func levelFor(f core.Finding) string {
	if f.Blocking {
		return "error"
	}
	return "warning"
}

// messageFor builds the per-result alert text. Always names the real
// in-artifact location (dex file, string pool index, manifest element)
// explicitly in the message body — not just in properties — because
// message.text is what's actually shown in GitHub's alert view; a
// properties bag is easy to miss. This is what makes a
// coarse/APK-mapped finding still useful: even when artifactLocation.uri
// can't point GitHub at a real line, the text says exactly where inside
// the APK the finding actually is.
func messageFor(f core.Finding) string {
	detail := f.WhyItBlocks
	if detail == "" {
		detail = f.SignalDetail
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(detail))
	fmt.Fprintf(&b, "\n\nIn-APK location: %s — %s", f.Source, f.Location)
	if f.Excerpt != "" {
		fmt.Fprintf(&b, "\nExcerpt: %s", f.Excerpt)
	}
	if f.Remediation != "" {
		b.WriteString("\n\nRemediation: " + strings.TrimSpace(f.Remediation))
	}
	return b.String()
}

// artifactURI decides whether a finding's location can honestly be
// mapped to a real source file in the scanned repo, or must fall back
// to the APK itself.
//
//   - AndroidManifest.xml findings (MG-002's manifest signal, MG-003,
//     MG-004, MG-010) map to sourceManifestPath — policy.
//     source_manifest_path, defaulting to
//     app/src/main/AndroidManifest.xml. This is the one case where a
//     real repo file plausibly exists at that path. It is still the
//     COMPILED, MERGED manifest that was actually scanned, not that
//     source file's own text — attribute values match (the merger
//     doesn't rewrite android:exported or android:allowBackup), but
//     line numbers do not, and are never fabricated here (see Result's
//     doc comment: no region is ever set).
//   - Everything else (MG-001's DEX/resources.arsc/asset findings,
//     MG-002's network_security_config.xml-based findings) has no
//     source-repo equivalent at all — an APK's compiled string pools
//     and merged resources don't correspond to any single file a
//     developer edited. Mapping these to a plausible-looking source
//     path would be worse than mapping them honestly to the APK itself:
//     a wrong location actively misleads triage ("I checked that file,
//     there's nothing there"), while an APK-mapped finding is honest
//     about being un-locatable in source and relies on message.text
//     (see messageFor) to say where it actually is.
//
// apkBase is always just filepath.Base(apkPath) — never the full path,
// which could be absolute and would leak the build machine's directory
// layout into output that may be uploaded to a public repo.
func artifactURI(f core.Finding, apkBase, sourceManifestPath string) string {
	if f.Source == "AndroidManifest.xml" {
		return sourceManifestPath
	}
	return apkBase
}

// resultPropertiesFor carries the finding's true severity (which,
// unlike security-severity, IS accurate per-result — see this package's
// doc comment, point 1) plus the real in-artifact location fields, so
// they're machine-readable even for tools that read the properties bag
// instead of parsing message.text.
func resultPropertiesFor(f core.Finding) *ResultProperties {
	return &ResultProperties{
		PatternID:   f.PatternID,
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		MASVS:       f.MASVS,
		CWE:         f.CWE,
		Source:      f.Source,
		Location:    f.Location,
		Line:        f.Line,
		Excerpt:     f.Excerpt,
		FindingHash: f.FindingHash,
	}
}
