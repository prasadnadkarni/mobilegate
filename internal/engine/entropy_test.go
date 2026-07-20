package engine

import "testing"

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want float64
	}{
		{"empty", "", 0},
		{"single repeated char has zero entropy", "aaaaaaaa", 0},
		{"two equally frequent symbols is 1 bit", "abababab", 1},
		{"four equally frequent symbols is 2 bits", "abcdabcdabcd", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.in)
			if diff := got - tt.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("ShannonEntropy(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestShannonEntropy_MonotonicWithRandomness documents the property the
// length-gated signal actually depends on: more distinct, more evenly
// distributed characters should never produce lower entropy than a more
// repetitive string of the same length.
func TestShannonEntropy_MonotonicWithRandomness(t *testing.T) {
	low := ShannonEntropy("aaaaaaaaaaaaaaaa")  // 16 chars, 1 symbol
	mid := ShannonEntropy("ababababababacac")  // 16 chars, few symbols
	high := ShannonEntropy("Tx9!qL2vZmR7pKdW") // 16 chars, high variety
	if !(low < mid && mid < high) {
		t.Errorf("expected low < mid < high entropy, got low=%v mid=%v high=%v", low, mid, high)
	}
}
