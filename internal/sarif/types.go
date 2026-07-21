package sarif

// This file models only the subset of the SARIF 2.1.0 object graph
// GitHub Code Scanning actually reads (per its documented
// "supported SARIF output properties" — see sarif.go's doc comment),
// plus whatever the formal schema requires for validity even where
// GitHub itself ignores a field. It is not a general-purpose SARIF
// library: no code flows, no nested rule extensions, no baseline-state
// tracking. If a future need requires more of the spec, extend this
// file rather than reaching for a third-party SARIF package — the
// subset in active use has stayed small and is exercised end-to-end by
// this package's own tests plus schema validation.

// Log is the SARIF root object (sarifLog in the schema).
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool invocation's results.
type Run struct {
	Tool              Tool               `json:"tool"`
	Results           []Result           `json:"results"`
	AutomationDetails *AutomationDetails `json:"automationDetails,omitempty"`
}

// AutomationDetails distinguishes this run from another (e.g. a
// different APK variant scanned in the same workflow) — see
// BuildInput.AutomationID's doc comment.
type AutomationDetails struct {
	ID string `json:"id"`
}

// Tool wraps the driver component. SARIF supports tool.extensions[]
// (other analyzers a driver delegates to) — not used here, MobileGate
// has exactly one analysis component.
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent describes MobileGate itself and declares every rule it
// can produce.
type ToolComponent struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor is one rule's static metadata — MG-001..MG-010,
// one entry each, regardless of whether that rule fired this run.
type ReportingDescriptor struct {
	ID               string                         `json:"id"`
	Name             string                         `json:"name,omitempty"`
	ShortDescription MultiformatMessage             `json:"shortDescription"`
	FullDescription  MultiformatMessage             `json:"fullDescription"`
	Help             MultiformatMessage             `json:"help"`
	Properties       *ReportingDescriptorProperties `json:"properties,omitempty"`
}

// MultiformatMessage is SARIF's { text, markdown } message shape, used
// both for rule descriptions/help and result messages (though results
// here only ever set Text — see Message below, which is the same shape
// but kept as a distinct type for clarity at call sites).
type MultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// ReportingDescriptorProperties carries GitHub-specific rule metadata:
// tags (must include "security" for GitHub to treat this as a security
// rule at all, plus the MASVS/CWE identifiers) and security-severity
// (the numeric score GitHub's ranking reads — rule-level only, see
// sarif.go's doc comment point 1).
type ReportingDescriptorProperties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

// Result is one finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level,omitempty"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          *ResultProperties `json:"properties,omitempty"`
}

// Message is a result's alert text — see sarif.go's messageFor.
type Message struct {
	Text string `json:"text"`
}

// Location wraps PhysicalLocation — SARIF also supports logicalLocations
// and a location-level message, neither used here.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation deliberately never sets Region — see sarif.go's
// artifactURI doc comment: no finding here has a verified line number
// that corresponds to anything in the artifactLocation being pointed
// at, so no region is ever fabricated. artifactLocation.uri alone
// (pointing at a file, not a line within it) is a complete, valid SARIF
// location.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation.URI is always a relative path — either
// policy.source_manifest_path or the APK's own base name, never an
// absolute local filesystem path (see BuildInput.APKPath's doc comment).
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// ResultProperties carries the finding's true per-result severity
// (accurate, unlike the rule-level security-severity — see sarif.go's
// doc comment point 1) and the real in-artifact location, so both
// remain machine-readable even for a consumer that doesn't parse
// message.text.
type ResultProperties struct {
	PatternID   string `json:"pattern_id,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	MASVS       string `json:"masvs,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Source      string `json:"source,omitempty"`
	Location    string `json:"location,omitempty"`
	Line        *int   `json:"line,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
	FindingHash string `json:"finding_hash,omitempty"`
}
