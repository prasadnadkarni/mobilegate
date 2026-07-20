// Package core holds MobileGate's shared finding model plus the logic
// that consumes it across every rule: finding_hash, the gate decision,
// and the score (spec's deliverable structure: "internal/core — shared
// finding model, hashing (finding_hash), baseline diff, scoring").
// internal/engine stays focused on rule evaluation (matchers, signal
// logic) and constructs Finding values from here; baseline diff is a
// build-order-step-5 concern (baseline mode) and is not implemented in
// this package yet.
package core

// Finding is MobileGate's canonical representation of one confirmed
// rule hit. internal/engine.Finding is a type alias to this (not a
// separate type) so the rule scanners and their existing fixture tests
// don't need mechanical call-site updates for the model to live here.
type Finding struct {
	RuleID string

	// RuleName is the rule's own name (e.g. "Hardcoded production
	// secret"), distinct from Title (a per-signal title, e.g. "Hardcoded
	// AWS Access Key ID"). Needed because the gate report groups and
	// names "failed controls" by rule identity — spec: "your release is
	// blocked because these 3 controls failed" — not by individual
	// finding title.
	RuleName   string
	PatternID  string
	Title      string
	Provider   string // MG-001 only; empty for structural (manifest-only) rules
	Severity   string // critical/high/medium/low — MASVS-adjacent severity, a different axis from Blocking (see below)
	Confidence string
	MASVS      string
	CWE        string

	// Blocking is true for the blocking tier, false for the warning
	// tier. No info-tier rule exists yet in this build (MG-005+ are a
	// later build-order step) — see Score's doc comment for how a real
	// info tier would need more than this bool once one exists.
	Blocking bool

	Source string // e.g. "classes.dex", "assets/config.json", "AndroidManifest.xml"

	// Location is a non-line location descriptor — a string pool index
	// ("string_ids[1042]"), a structural path ("application",
	// "domain-config[example.com]") — set whenever Line is nil. Line and
	// Location are mutually exclusive by construction: only a real text
	// asset (MG-001's ScanAsset) has an actual line number; DEX/resource
	// string pools and binary XML have no line concept to report.
	Location string
	Line     *int

	Excerpt      string // redacted where the underlying value could be sensitive (see MG-001)
	SignalDetail string // the mechanical "what matched and why this counts" explanation

	// WhyItBlocks is the human-facing, business-impact explanation the
	// spec calls out as where "pentest judgment becomes product value"
	// — distinct from SignalDetail, which explains the detection
	// mechanism, not the consequence. For MG-002/003/010, whose
	// SignalDetail text was already written in an explanatory,
	// consequence-aware style (and, for MG-003 in particular, carefully
	// tuned to be targetSdk-accurate after a real corpus bug — see
	// rules/MG-003-plaintext-storage.yaml), this deliberately reuses
	// SignalDetail rather than risk a second, independently-drifting
	// narrative that could contradict it. Only MG-001 gets genuinely
	// distinct text, since its SignalDetail is a terse detection-
	// mechanism note ("matched pattern X; outside exclusion zone") that
	// was never written to carry business-impact framing.
	WhyItBlocks string

	Remediation string // copied from the rule's own metadata at construction time

	// TargetSDK is the app's resolved targetSdkVersion, recorded when
	// relevant evidence for the finding (MG-002, MG-003). Nil otherwise.
	TargetSDK *int

	// FindingHash is this finding's stable identity — see
	// ComputeFindingHash. Deliberately excludes Line/Location: baseline
	// mode (build-order step 5) depends on this hash surviving unrelated
	// changes that shift a finding's position without changing the
	// finding itself.
	FindingHash string
}

// Evidence is one entry in a Finding's structured evidence array — spec:
// "evidence is a structured array, not a single string, so file/line/
// source/signal parse cleanly."
type Evidence struct {
	Source   string `json:"source"`
	Line     *int   `json:"line,omitempty"`
	Location string `json:"location,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// EvidenceChain returns f's evidence as the spec's two-entry shape: a
// "where" entry (source file, a real line number when this finding has
// one, a non-line location descriptor otherwise, and the excerpt) and a
// "signal" entry carrying the multi-signal reasoning — matching the
// spec's own JSON example exactly (an evidence[0] with source/line/
// excerpt, an evidence[1] with source:"signal"/detail).
func (f Finding) EvidenceChain() []Evidence {
	where := Evidence{Source: f.Source, Excerpt: f.Excerpt}
	if f.Line != nil {
		where.Line = f.Line
	} else {
		where.Location = f.Location
	}
	return []Evidence{
		where,
		{Source: "signal", Detail: f.SignalDetail},
	}
}

// Buckets splits findings into the tiers the output contract requires.
// info is always empty in this build — see Finding.Blocking's doc
// comment on why a real info tier isn't modeled yet.
func Buckets(findings []Finding) (blocking, warning, info []Finding) {
	for _, f := range findings {
		if f.Blocking {
			blocking = append(blocking, f)
		} else {
			warning = append(warning, f)
		}
	}
	return blocking, warning, nil
}
