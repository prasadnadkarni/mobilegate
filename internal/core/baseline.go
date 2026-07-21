package core

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/go-yaml"
)

// baselineHeader is prepended to every written baseline file as a
// literal YAML comment — Marshal doesn't carry Go doc comments, so a
// reviewer opening this file in a PR diff needs the explanation right
// there in the file itself, not in this tool's own source. Spec:
// "producing something human-readable and diffable... auditable in
// code review, not an opaque blob."
const baselineHeader = `# MobileGate baseline — pre-existing blocking findings grandfathered
# as of this snapshot. A blocking finding whose finding_hash is NOT
# listed below still blocks the release; one that IS listed below is
# treated as known debt and passes.
#
# This file is a full snapshot, not an append-only log: regenerating it
# (mobilegate baseline -write <apk>) REPLACES it entirely with whatever
# the tool currently finds. A finding that was fixed and no longer
# appears in a scan drops out on the next write — it does not stay
# grandfathered forever under a stale entry.
#
# Do not hand-edit finding_hash values; they must match what the
# scanner itself computes (rule ID + file path + normalized match
# value — see internal/core.ComputeFindingHash, and note it deliberately
# excludes line numbers) or the entry will simply never match and that
# finding will block anyway.
`

// Baseline is a snapshot of the blocking-tier findings a team has
// reviewed and deliberately chosen not to block on yet — spec: "the
// tool compares current findings against a stored baseline and blocks
// only on regressions (new blocking findings), passing pre-existing
// debt." Only blocking-tier findings are ever captured: warning/info
// findings never affect the gate decision regardless of policy mode
// (see Decide), so baselining them would be file noise, not a real
// grandfather clause.
type Baseline struct {
	ScannerVersion string          `yaml:"scanner_version"`
	RuleVersion    string          `yaml:"rule_version"`
	Findings       []BaselineEntry `yaml:"findings"`
}

// BaselineEntry carries enough context for a human reviewing a PR that
// touches this file to recognize WHAT is being grandfathered without
// re-running the scanner. FindingHash is the actual identity used for
// comparison (SplitByBaseline); every other field here is display-only
// and never consulted for matching.
type BaselineEntry struct {
	FindingHash string `yaml:"finding_hash"`
	RuleID      string `yaml:"rule_id"`
	Title       string `yaml:"title"`
	Source      string `yaml:"source"`
	Excerpt     string `yaml:"excerpt"`
}

// NewBaseline snapshots findings' blocking-tier subset into a Baseline
// ready to write. Sorted by (rule ID, source, hash) — not insertion
// order, not raw hash order — so a re-write with no real change
// produces a byte-identical file (no wall-clock timestamp is recorded
// anywhere in this type, for the same reason: a field that changes on
// every write regardless of content would make every re-run touch the
// file, which defeats "diffable") and a re-write with a real change
// produces a minimal, readable diff grouped by rule rather than a
// reshuffled file.
func NewBaseline(scannerVersion, ruleVersion string, findings []Finding) *Baseline {
	b := &Baseline{ScannerVersion: scannerVersion, RuleVersion: ruleVersion}
	for _, f := range findings {
		if !f.Blocking {
			continue
		}
		b.Findings = append(b.Findings, BaselineEntry{
			FindingHash: f.FindingHash,
			RuleID:      f.RuleID,
			Title:       f.Title,
			Source:      f.Source,
			Excerpt:     f.Excerpt,
		})
	}
	sort.Slice(b.Findings, func(i, j int) bool {
		a, c := b.Findings[i], b.Findings[j]
		if a.RuleID != c.RuleID {
			return a.RuleID < c.RuleID
		}
		if a.Source != c.Source {
			return a.Source < c.Source
		}
		return a.FindingHash < c.FindingHash
	})
	return b
}

// Contains reports whether hash is grandfathered by this baseline.
func (b *Baseline) Contains(hash string) bool {
	for _, e := range b.Findings {
		if e.FindingHash == hash {
			return true
		}
	}
	return false
}

// WriteFile serializes b as YAML, with the leading explanatory header,
// to path.
func (b *Baseline) WriteFile(path string) error {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Errorf("core: marshal baseline: %w", err)
	}
	out := append([]byte(baselineHeader), data...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("core: writing baseline %s: %w", path, err)
	}
	return nil
}

// LoadBaseline reads and parses a baseline file. The returned error is
// os.IsNotExist-checkable, so callers can distinguish "no baseline
// written yet" (expected and quiet on a first run) from "the file
// exists but is corrupt, unreadable, or schema-mismatched" — spec:
// "fail closed... never silently pass because the baseline couldn't be
// read." LoadBaseline itself only reports which case occurred; it does
// not decide policy (falling back to strict mode and saying so loudly
// is the caller's job — see cmd/mobilegate).
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a local CLI flag/default (-baseline), chosen by the person running the binary, not remote/attacker-supplied input
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("core: parse baseline %s: %w", path, err)
	}
	if b.ScannerVersion == "" || b.RuleVersion == "" {
		return nil, fmt.Errorf("core: baseline %s is missing scanner_version/rule_version — schema mismatch or corrupt file", path)
	}
	return &b, nil
}

// SplitByBaseline separates a finding set into the findings a stored
// baseline grandfathers (blocking-tier, hash present in baseline) and
// everything else, unchanged. Only blocking-tier findings are ever
// grandfathered — warning/info findings never affect the gate decision
// in the first place, baseline or not, so they always end up in rest.
func SplitByBaseline(findings []Finding, baseline *Baseline) (rest, baselined []Finding) {
	for _, f := range findings {
		if f.Blocking && baseline.Contains(f.FindingHash) {
			baselined = append(baselined, f)
			continue
		}
		rest = append(rest, f)
	}
	return rest, baselined
}
