package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/dex"
)

// Finding is one MG-001 hit: a pattern match that survived every
// exclusion check.
type Finding struct {
	RuleID       string
	PatternID    string
	Title        string
	Provider     string
	Severity     string
	Confidence   string
	MASVS        string
	CWE          string
	Blocking     bool
	Source       string // e.g. "classes.dex", "assets/config.json"
	Location     string // e.g. "string_ids[1042]", "line 14"
	Excerpt      string // redacted matched value — enough to verify, not a second copy of the secret
	SignalDetail string
}

type compiledPattern struct {
	def PatternDef
	re  *regexp.Regexp
}

// SecretScanner evaluates a loaded MG-001 RuleDef against parser output.
type SecretScanner struct {
	rule           *RuleDef
	patterns       []compiledPattern
	excludeExt     map[string]bool
	excludeValueRe []*regexp.Regexp
}

// NewSecretScanner compiles a rule's patterns and exclusion regexes once,
// so bad YAML data fails loudly at load time rather than on the first
// scanned string.
func NewSecretScanner(rule *RuleDef) (*SecretScanner, error) {
	s := &SecretScanner{rule: rule, excludeExt: map[string]bool{}}

	for _, p := range rule.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("engine: rule %s: pattern %s: bad regex: %w", rule.ID, p.ID, err)
		}
		s.patterns = append(s.patterns, compiledPattern{def: p, re: re})
	}
	for _, ext := range rule.Exclusions.PathExtensions {
		s.excludeExt[strings.ToLower(ext)] = true
	}
	for _, vp := range rule.Exclusions.ValuePatterns {
		re, err := regexp.Compile(vp)
		if err != nil {
			return nil, fmt.Errorf("engine: rule %s: value_pattern %q: bad regex: %w", rule.ID, vp, err)
		}
		s.excludeValueRe = append(s.excludeValueRe, re)
	}
	return s, nil
}

// ScanDexStrings scans one dex file's extracted string pool. Strings
// used as a type/method/field name (dex.Usage != Unattributed) are
// skipped: they're syntactically-constrained identifiers, not data, and
// this exclusion is structural (enforced here, not policy-configurable
// in the rule YAML) — see MG-001-hardcoded-secret.yaml's header comment.
func (s *SecretScanner) ScanDexStrings(strs []dex.StringRef) []Finding {
	var out []Finding
	for _, sr := range strs {
		if sr.Usage != dex.Unattributed {
			continue
		}
		out = append(out, s.scanValue(sr.Value, sr.DexFile, fmt.Sprintf("string_ids[%d]", sr.Index))...)
	}
	return out
}

// ScanResourceStrings scans resources.arsc's global string pool — the
// most common real-world location for a hardcoded Google/Firebase key:
// the Google Services Gradle plugin generates google_api_key,
// google_app_id, and gcm_defaultSenderId as string resources, and the
// Maps SDK convention (@string/google_maps_key) is the same pattern.
// Every entry is a resource *value* (see pkg/parser/arsc's doc comment
// for why this reads only the global pool, not per-package type/key
// names), so — unlike ScanDexStrings — there's no identifier-vs-data
// distinction to filter on here.
func (s *SecretScanner) ScanResourceStrings(strs []arsc.PoolString) []Finding {
	var out []Finding
	for _, ps := range strs {
		out = append(out, s.scanValue(ps.Value, "resources.arsc", fmt.Sprintf("string_pool[%d]", ps.Index))...)
	}
	return out
}

// ScanManifestStrings scans AndroidManifest.xml's own binary-XML string
// pool — the other place a hardcoded key shows up alongside
// resources.arsc: a literal <meta-data android:value="AIzaSy…"/> (common
// for Maps API keys) puts the key straight into the manifest's own pool,
// not resources.arsc, since it's never routed through a @string/
// reference. Same pool format as ScanResourceStrings reads
// (pkg/parser/arsc handles both container types with one reader), same
// lack of an identifier-vs-data distinction to filter on.
func (s *SecretScanner) ScanManifestStrings(strs []arsc.PoolString) []Finding {
	var out []Finding
	for _, ps := range strs {
		out = append(out, s.scanValue(ps.Value, "AndroidManifest.xml", fmt.Sprintf("string_pool[%d]", ps.Index))...)
	}
	return out
}

// ScanAsset scans one assets/ file's raw content, unless its extension is
// in the rule's binary-asset exclusion zone — those are never inspected
// at all, not matched-then-discarded.
//
// Scans the whole file as a single candidate, not line by line: a
// multi-line credential block (e.g. a PEM key checked in as its own
// .pem asset, header on one line and base64 body on the next) has to be
// visible to the pattern as one unit, or a header-then-body pattern like
// private-key-header can never match content whose header and body land
// on different lines. Evidence still reports a line number, computed
// from each match's byte offset after the fact, so this costs nothing
// on the evidence side.
func (s *SecretScanner) ScanAsset(path string, data []byte) []Finding {
	if s.excludeExt[strings.ToLower(extOf(path))] {
		return nil
	}
	content := string(data)
	var out []Finding
	for _, cp := range s.patterns {
		for _, loc := range cp.re.FindAllStringIndex(content, -1) {
			matched := content[loc[0]:loc[1]]
			if s.isExcludedValue(matched) {
				continue
			}
			line := 1 + strings.Count(content[:loc[0]], "\n")
			out = append(out, s.newFinding(cp, matched, path, fmt.Sprintf("line %d", line)))
		}
	}
	return out
}

func (s *SecretScanner) scanValue(value, source, location string) []Finding {
	var out []Finding
	for _, cp := range s.patterns {
		for _, loc := range cp.re.FindAllStringIndex(value, -1) {
			matched := value[loc[0]:loc[1]]
			if s.isExcludedValue(matched) {
				continue
			}
			out = append(out, s.newFinding(cp, matched, source, location))
		}
	}
	return out
}

func (s *SecretScanner) newFinding(cp compiledPattern, matched, source, location string) Finding {
	return Finding{
		RuleID:       s.rule.ID,
		PatternID:    cp.def.ID,
		Title:        fmt.Sprintf("Hardcoded %s", cp.def.Name),
		Provider:     cp.def.Provider,
		Severity:     s.rule.Severity,
		Confidence:   cp.def.Confidence,
		MASVS:        s.rule.MASVS,
		CWE:          s.rule.CWE,
		Blocking:     s.rule.Blocking,
		Source:       source,
		Location:     location,
		Excerpt:      redact(matched),
		SignalDetail: fmt.Sprintf("matched pattern %s (%s); outside exclusion zone", cp.def.ID, cp.def.Provider),
	}
}

func (s *SecretScanner) isExcludedValue(v string) bool {
	for _, re := range s.excludeValueRe {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func extOf(path string) string {
	i := strings.LastIndexByte(path, '.')
	if i < 0 {
		return ""
	}
	return path[i:]
}

// redact shows enough of a matched credential to let a human verify the
// hit without the scan output itself becoming a second copy of the
// secret.
func redact(s string) string {
	const keep = 6
	if len(s) <= keep*2 {
		return strings.Repeat("*", len(s))
	}
	return s[:keep] + strings.Repeat("*", len(s)-keep*2) + s[len(s)-keep:]
}
