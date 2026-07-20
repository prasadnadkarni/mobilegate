package core

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// ComputeFindingHash computes a Finding's stable identity hash — spec:
// "Compute it from: rule ID + file path + normalized match value. Do
// NOT include the line number... The line number stays in the evidence
// array for humans; it stays out of the identity hash." This is the
// mechanism baseline mode (build-order step 5) will diff against, so a
// finding that only moves position in an otherwise-unchanged file must
// hash identically — see the acceptance test in engine's fixture suite
// (a secret moved from line 14 to line 18 with no other change) and
// TestComputeFindingHash_* in this package.
//
// patternID (which signal within the rule fired) is folded into the
// hash input alongside the spec's three named components, not treated
// as a fourth independent one: the spec's "rule ID" names the rule as a
// whole, but a rule with multiple signal subtypes (MG-002's four,
// MG-003's three, MG-010's two) needs those subtypes distinguished too,
// or two different signals that happen to produce the same normalized
// match value in the same file would collide into one identity. No
// currently-shipped rule can actually produce that collision (checked
// case by case when each rule's signals were built), but folding
// patternID in is cheap, avoids a whole latent-bug class for future
// signals, and doesn't contradict the spec's formula — it's still
// exactly rule ID + file path + normalized match value, just with the
// signal identity treated as part of what "the rule" and "the match
// value" mean together.
//
// normalizedMatchValue must never be a REDACTED value for a secret
// (MG-001): two different secrets that happen to redact to the same
// display string (same length, same first/last N characters, different
// middle) would otherwise collide into one identity hash, silently
// merging two distinct leaked credentials under baseline diffing. The
// hash's own preimage resistance is what keeps the raw secret out of
// the output — hashing it directly is safe; hashing its redacted
// display form is not.
func ComputeFindingHash(ruleID, filePath, patternID, normalizedMatchValue string) string {
	h := sha256.New()
	writeField(h, ruleID)
	writeField(h, filePath)
	writeField(h, patternID)
	writeField(h, normalizedMatchValue)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// writeField writes s followed by a NUL separator, so e.g. ("AB", "C")
// and ("A", "BC") never hash identically just because naive
// concatenation would have made them the same byte string.
func writeField(w io.Writer, s string) {
	w.Write([]byte(s))
	w.Write([]byte{0})
}
