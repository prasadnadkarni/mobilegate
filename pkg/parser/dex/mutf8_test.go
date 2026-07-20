package dex

import "testing"

// TestDecodeMUTF8_EdgeCases targets the exact cases where a hand-rolled
// MUTF-8 decoder diverges from standard UTF-8 (and where a silent
// corruption would otherwise hide): the two-byte NUL encoding Android
// uses in place of a bare 0x00 byte, and CESU-8 surrogate pairs for
// characters outside the Basic Multilingual Plane. Expected byte
// sequences are hand-computed against the DEX/CESU-8 spec, not produced
// by this package's own toMUTF8 test helper — round-tripping through our
// own encoder would let a symmetric encode/decode bug cancel itself out
// and pass silently.
func TestDecodeMUTF8_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "empty string",
			in:   []byte{},
			want: "",
		},
		{
			name: "embedded NUL encoded as 0xC0 0x80",
			// Android's MUTF-8 never puts a bare 0x00 inside string data
			// (0x00 is the terminator), so U+0000 mid-string must appear
			// as the overlong 2-byte form 0xC0 0x80.
			in:   []byte{'a', 0xC0, 0x80, 'b'},
			want: "a\x00b",
		},
		{
			name: "ASCII",
			in:   []byte("hello"),
			want: "hello",
		},
		{
			name: "BMP 3-byte character (EURO SIGN, U+20AC)",
			in:   []byte{0xE2, 0x82, 0xAC},
			want: "€",
		},
		{
			name: "supplementary-plane character via CESU-8 surrogate pair (GRINNING FACE, U+1F600)",
			// U+1F600 is above the BMP, so standard UTF-8 would encode it
			// as one 4-byte sequence (F0 9F 98 80). MUTF-8/CESU-8 instead
			// encodes the UTF-16 surrogate pair (high D83D, low DE00) as
			// two independent 3-byte sequences — this is the case a
			// decoder that just special-cases NUL and otherwise defers
			// to stdlib UTF-8 rules would get wrong, because a bare
			// stdlib UTF-8 decoder run over these bytes sees two lone
			// surrogates (invalid in real UTF-8), not one character.
			in:   []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80},
			want: "\U0001F600",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeMUTF8(tt.in)
			if err != nil {
				t.Fatalf("decodeMUTF8(%v): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("decodeMUTF8(% X) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDecodeMUTF8_RejectsBareFourByteUTF8 documents that MUTF-8 never
// uses standard UTF-8's 4-byte lead bytes (0xF0-0xF7) — supplementary
// characters only ever appear as a surrogate pair of 3-byte sequences —
// so a real 4-byte UTF-8 lead byte in DEX string data is malformed input,
// not a valid encoding this decoder should silently accept.
func TestDecodeMUTF8_RejectsBareFourByteUTF8(t *testing.T) {
	// Standard UTF-8 for U+1F600, which MUTF-8 must never produce.
	in := []byte{0xF0, 0x9F, 0x98, 0x80}
	if _, err := decodeMUTF8(in); err == nil {
		t.Fatalf("decodeMUTF8(% X): expected error for bare 4-byte UTF-8 lead byte, got nil", in)
	}
}
