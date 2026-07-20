package arsc

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildTable constructs a minimal resources.arsc: a RES_TABLE_TYPE header
// immediately followed by one RES_STRING_POOL_TYPE chunk containing
// strs, encoded UTF-8 or UTF-16 per utf8. No packages — this package
// never reads them.
func buildTable(t *testing.T, strs []string, utf8 bool) []byte {
	t.Helper()

	const tableHeaderSize = 12 // chunk header(8) + packageCount(4)
	const poolHeaderSize = 28
	poolOff := uint32(tableHeaderSize)
	offsetTableStart := poolOff + poolHeaderSize
	stringsStart := offsetTableStart + uint32(len(strs))*4 - poolOff // relative to poolOff

	var data []byte
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(len(data))
		if utf8 {
			data = append(data, encode8BitLength(len(utf16.Encode([]rune(s))))...)
			data = append(data, encode8BitLength(len(s))...)
			data = append(data, []byte(s)...)
		} else {
			units := utf16.Encode([]rune(s))
			data = append(data, encode16BitLength(len(units))...)
			for _, u := range units {
				var b [2]byte
				binary.LittleEndian.PutUint16(b[:], u)
				data = append(data, b[:]...)
			}
		}
	}

	poolChunkSize := poolHeaderSize + uint32(len(strs))*4 + uint32(len(data))
	tableSize := tableHeaderSize + poolChunkSize

	buf := make([]byte, tableSize)
	// table header
	binary.LittleEndian.PutUint16(buf[0:], resTableType)
	binary.LittleEndian.PutUint16(buf[2:], tableHeaderSize)
	binary.LittleEndian.PutUint32(buf[4:], tableSize)
	// pool chunk header
	binary.LittleEndian.PutUint16(buf[poolOff:], resStringPoolType)
	binary.LittleEndian.PutUint16(buf[poolOff+2:], poolHeaderSize)
	binary.LittleEndian.PutUint32(buf[poolOff+4:], poolChunkSize)
	binary.LittleEndian.PutUint32(buf[poolOff+8:], uint32(len(strs))) // stringCount
	// styleCount (poolOff+12) left 0
	var flags uint32
	if utf8 {
		flags = utf8Flag
	}
	binary.LittleEndian.PutUint32(buf[poolOff+16:], flags)
	binary.LittleEndian.PutUint32(buf[poolOff+20:], stringsStart)
	// stylesStart (poolOff+24) left 0

	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[offsetTableStart+uint32(i)*4:], off)
	}
	copy(buf[poolOff+stringsStart:], data)

	return buf
}

func encode8BitLength(n int) []byte {
	if n <= 0x7F {
		return []byte{byte(n)}
	}
	return []byte{byte((n>>8)&0x7F) | 0x80, byte(n & 0xFF)}
}

func encode16BitLength(n int) []byte {
	if n <= 0x7FFF {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(n))
		return b
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:], uint16((n>>16)&0x7FFF)|0x8000)
	binary.LittleEndian.PutUint16(b[2:], uint16(n&0xFFFF))
	return b
}

func TestExtractGlobalStringPool_UTF8(t *testing.T) {
	strs := []string{"", "hello", "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", "emoji:\U0001F600", "unicode: café résumé"}
	data := buildTable(t, strs, true)

	got, err := ExtractGlobalStringPool(data)
	if err != nil {
		t.Fatalf("ExtractGlobalStringPool: %v", err)
	}
	assertStringsMatch(t, got, strs)
}

func TestExtractGlobalStringPool_UTF16(t *testing.T) {
	strs := []string{"", "hello", "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", "emoji:\U0001F600", "unicode: café résumé"}
	data := buildTable(t, strs, false)

	got, err := ExtractGlobalStringPool(data)
	if err != nil {
		t.Fatalf("ExtractGlobalStringPool: %v", err)
	}
	assertStringsMatch(t, got, strs)
}

func TestExtractGlobalStringPool_LongStringOver127Bytes(t *testing.T) {
	// Exercises the 2-byte length-prefix path (values > 0x7F) in both
	// the UTF-8 byte-length and UTF-16 char-count encodings.
	long := ""
	for i := 0; i < 40; i++ {
		long += "0123456789" // 400 chars/bytes, well past the 1-byte (0x7F) length threshold
	}
	for _, utf8 := range []bool{true, false} {
		data := buildTable(t, []string{long}, utf8)
		got, err := ExtractGlobalStringPool(data)
		if err != nil {
			t.Fatalf("utf8=%v: ExtractGlobalStringPool: %v", utf8, err)
		}
		assertStringsMatch(t, got, []string{long})
	}
}

func assertStringsMatch(t *testing.T, got []PoolString, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d strings, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Value != w {
			t.Errorf("strings[%d] = %q, want %q", i, got[i].Value, w)
		}
		if got[i].Index != i {
			t.Errorf("strings[%d].Index = %d, want %d", i, got[i].Index, i)
		}
	}
}

func TestExtractGlobalStringPool_RejectsTruncatedHeader(t *testing.T) {
	if _, err := ExtractGlobalStringPool([]byte("short")); err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

func TestExtractGlobalStringPool_RejectsWrongChunkType(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:], 0x0003) // not RES_TABLE_TYPE
	binary.LittleEndian.PutUint16(buf[2:], 12)
	binary.LittleEndian.PutUint32(buf[4:], 16)
	if _, err := ExtractGlobalStringPool(buf); err == nil {
		t.Fatal("expected error for wrong top-level chunk type, got nil")
	}
}

func TestExtractGlobalStringPool_RejectsOversizedDeclaredStringCount(t *testing.T) {
	data := buildTable(t, []string{"a"}, true)
	// Corrupt stringCount to claim far more entries than fit in the file.
	binary.LittleEndian.PutUint32(data[12+8:], 0xFFFFFF)
	if _, err := ExtractGlobalStringPool(data); err == nil {
		t.Fatal("expected error for out-of-bounds declared string count, got nil")
	}
}

func TestExtractGlobalStringPool_NoStringPoolChunkIsNotAnError(t *testing.T) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint16(buf[0:], resTableType)
	binary.LittleEndian.PutUint16(buf[2:], 12)
	binary.LittleEndian.PutUint32(buf[4:], 12) // table with no chunks after the header at all
	got, err := ExtractGlobalStringPool(buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d strings", len(got))
	}
}
