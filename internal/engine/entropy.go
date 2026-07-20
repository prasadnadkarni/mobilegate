package engine

import "math"

// ShannonEntropy returns the Shannon entropy of s, in bits per character,
// over the distribution of byte values in s.
//
// This is the length-gated "signal 2" from MG-001: per spec, entropy math
// applies only to long unstructured candidates (no recognizable provider
// prefix) — never to short strings, and never as a substitute for a
// prefix match on structured credential formats, where it would just be
// noise. Callers are responsible for the length gate; this function
// itself has no opinion on what counts as "long."
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
