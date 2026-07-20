// Package arsc extracts resources.arsc's global string pool — the one
// place every string-typed resource *value* lives (e.g. the literal text
// of a <string name="google_api_key">AIzaSy…</string> resource), as
// opposed to resource type/key *names*, which live in separate per-package
// string pools this package does not read.
//
// github.com/shogo82148/androidbinary (used for AndroidManifest.xml
// parsing) has no public API to enumerate resources.arsc's string pool:
// TableFile only exposes GetResource(id, config) and GetString(ref), both
// of which require already knowing a specific ID — there is no
// enumerator, and the fields that hold the parsed packages/pools are
// unexported. Confirmed via `go doc` on the installed package before
// writing this. Everything else about resources.arsc (per-package type
// tables, resource ID resolution, configuration qualifiers) is
// deliberately NOT reimplemented here — this package reads exactly one
// chunk, the same discipline pkg/parser/dex applies to the DEX string
// pool: minimal custom code for the one well-isolated structure a
// maintained library's public API doesn't reach, not a second resource
// table parser.
package arsc

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// MaxDecodedStringBytes bounds the total bytes this package will decode
// out of the global string pool, guarding against a crafted
// resources.arsc whose declared string count/lengths are designed to
// blow up memory. Same budget as pkg/parser/dex, for the same reason.
const MaxDecodedStringBytes = 50 * 1024 * 1024

const (
	chunkHeaderSize      = 8 // type(2) + headerSize(2) + size(4)
	resTableType         = 0x0002
	resStringPoolType    = 0x0001
	utf8Flag             = 0x100
	stringPoolHeaderSize = 28      // chunk header(8) + stringCount(4) + styleCount(4) + flags(4) + stringsStart(4) + stylesStart(4)
	maxTopLevelChunks    = 1 << 20 // sanity cap on the outer scan loop, not a real-world limit
)

// PoolString is one entry from the global string pool.
type PoolString struct {
	Index int
	Value string
}

// ExtractGlobalStringPool reads resources.arsc's top-level string pool —
// the chunk immediately following the RES_TABLE_TYPE header — and
// returns every string in it. Returns an empty, non-error result if the
// file has no such chunk (a resource table with no string-valued
// resources at all is unusual but not invalid).
func ExtractGlobalStringPool(data []byte) ([]PoolString, error) {
	if len(data) < chunkHeaderSize+4 { // chunk header + packageCount
		return nil, fmt.Errorf("arsc: file too small to contain a table header (%d bytes)", len(data))
	}

	typ, headerSize, size, err := readChunkHeader(data, 0)
	if err != nil {
		return nil, fmt.Errorf("arsc: %w", err)
	}
	if typ != resTableType {
		return nil, fmt.Errorf("arsc: not a resource table (chunk type 0x%04X, want 0x%04X)", typ, resTableType)
	}
	tableEnd := size
	if tableEnd > uint32(len(data)) {
		tableEnd = uint32(len(data))
	}

	// Scan top-level chunks for the first RES_STRING_POOL_TYPE. In every
	// resources.arsc this library or the author has seen it's the very
	// next chunk after the table header, but we scan rather than assume,
	// since nothing requires that ordering and a misread offset here
	// would silently skip the entire scan surface.
	offset := headerSize
	for i := 0; i < maxTopLevelChunks && offset < tableEnd; i++ {
		ctyp, cheaderSize, csize, err := readChunkHeader(data, offset)
		if err != nil {
			return nil, fmt.Errorf("arsc: reading chunk at offset %d: %w", offset, err)
		}
		if csize == 0 {
			return nil, fmt.Errorf("arsc: zero-size chunk at offset %d", offset)
		}
		if ctyp == resStringPoolType {
			return parseStringPool(data, offset, cheaderSize, csize)
		}
		offset += csize
	}

	return nil, nil
}

// readChunkHeader reads a ResChunkHeader at off, bounds-checked against
// len(data) before returning.
func readChunkHeader(data []byte, off uint32) (typ, headerSize, size uint32, err error) {
	if uint64(off)+chunkHeaderSize > uint64(len(data)) {
		return 0, 0, 0, fmt.Errorf("chunk header at offset %d out of bounds", off)
	}
	typ = uint32(binary.LittleEndian.Uint16(data[off:]))
	headerSize = uint32(binary.LittleEndian.Uint16(data[off+2:]))
	size = binary.LittleEndian.Uint32(data[off+4:])
	if headerSize < chunkHeaderSize {
		return 0, 0, 0, fmt.Errorf("chunk at offset %d has invalid header_size %d", off, headerSize)
	}
	if uint64(off)+uint64(size) > uint64(len(data)) {
		return 0, 0, 0, fmt.Errorf("chunk at offset %d has size %d extending past end of file", off, size)
	}
	return typ, headerSize, size, nil
}

func parseStringPool(data []byte, poolOff, headerSize, chunkSize uint32) ([]PoolString, error) {
	if uint64(poolOff)+stringPoolHeaderSize > uint64(len(data)) {
		return nil, fmt.Errorf("arsc: string pool header at offset %d out of bounds", poolOff)
	}
	stringCount := binary.LittleEndian.Uint32(data[poolOff+8:])
	flags := binary.LittleEndian.Uint32(data[poolOff+16:])
	stringsStart := binary.LittleEndian.Uint32(data[poolOff+20:])

	// Bounds-check the offset table BEFORE allocating anything sized by
	// the attacker-controlled stringCount.
	offsetTableStart := poolOff + headerSize
	offsetTableBytes := uint64(stringCount) * 4
	if uint64(offsetTableStart)+offsetTableBytes > uint64(poolOff)+uint64(chunkSize) ||
		uint64(offsetTableStart)+offsetTableBytes > uint64(len(data)) {
		return nil, fmt.Errorf("arsc: string pool at offset %d declares %d strings, offset table exceeds chunk/file bounds", poolOff, stringCount)
	}

	poolEnd := uint64(poolOff) + uint64(chunkSize)
	if poolEnd > uint64(len(data)) {
		poolEnd = uint64(len(data))
	}

	isUTF8 := flags&utf8Flag != 0

	out := make([]PoolString, stringCount)
	var budget int64
	for i := uint32(0); i < stringCount; i++ {
		relOff := binary.LittleEndian.Uint32(data[offsetTableStart+i*4:])
		absOff := uint64(poolOff) + uint64(stringsStart) + uint64(relOff)
		if absOff >= poolEnd {
			return nil, fmt.Errorf("arsc: string %d offset %d out of bounds", i, absOff)
		}

		var s string
		var err error
		if isUTF8 {
			s, err = readUTF8String(data, absOff, poolEnd)
		} else {
			s, err = readUTF16String(data, absOff, poolEnd)
		}
		if err != nil {
			return nil, fmt.Errorf("arsc: string %d: %w", i, err)
		}

		budget += int64(len(s))
		if budget > MaxDecodedStringBytes {
			return nil, fmt.Errorf("arsc: string pool exceeds %d byte decode budget — refusing to continue", MaxDecodedStringBytes)
		}
		out[i] = PoolString{Index: int(i), Value: s}
	}
	return out, nil
}

// read8BitLength reads AOSP's variable-length encoding used for both the
// (ignored) UTF-16 char count and the UTF-8 byte count in UTF-8 mode
// strings: one byte normally, or two bytes (high bit of the first set)
// combining 7+8 bits for lengths above 0x7F.
func read8BitLength(data []byte, off uint64) (length int, next uint64, err error) {
	if off >= uint64(len(data)) {
		return 0, off, fmt.Errorf("truncated length prefix at %d", off)
	}
	first := data[off]
	if first&0x80 != 0 {
		if off+1 >= uint64(len(data)) {
			return 0, off, fmt.Errorf("truncated 2-byte length prefix at %d", off)
		}
		second := data[off+1]
		return (int(first&0x7F) << 8) | int(second), off + 2, nil
	}
	return int(first), off + 1, nil
}

// read16BitLength is the UTF-16 mode equivalent: one uint16 normally, or
// two (high bit of the first set) combining 15+16 bits.
func read16BitLength(data []byte, off uint64) (length int, next uint64, err error) {
	if off+2 > uint64(len(data)) {
		return 0, off, fmt.Errorf("truncated length prefix at %d", off)
	}
	first := binary.LittleEndian.Uint16(data[off:])
	if first&0x8000 != 0 {
		if off+4 > uint64(len(data)) {
			return 0, off, fmt.Errorf("truncated 4-byte length prefix at %d", off)
		}
		second := binary.LittleEndian.Uint16(data[off+2:])
		return (int(first&0x7FFF) << 16) | int(second), off + 4, nil
	}
	return int(first), off + 2, nil
}

func readUTF8String(data []byte, off, limit uint64) (string, error) {
	// Skip the UTF-16 character count; only the UTF-8 byte count that
	// follows determines how much data to read.
	_, off, err := read8BitLength(data, off)
	if err != nil {
		return "", err
	}
	byteLen, off, err := read8BitLength(data, off)
	if err != nil {
		return "", err
	}
	if off+uint64(byteLen) > limit {
		return "", fmt.Errorf("string data (%d bytes at %d) extends past pool bounds", byteLen, off)
	}
	return string(data[off : off+uint64(byteLen)]), nil
}

func readUTF16String(data []byte, off, limit uint64) (string, error) {
	charLen, off, err := read16BitLength(data, off)
	if err != nil {
		return "", err
	}
	byteLen := uint64(charLen) * 2
	if off+byteLen > limit {
		return "", fmt.Errorf("string data (%d chars at %d) extends past pool bounds", charLen, off)
	}
	units := make([]uint16, charLen)
	for i := 0; i < charLen; i++ {
		units[i] = binary.LittleEndian.Uint16(data[off+uint64(i)*2:])
	}
	return string(utf16.Decode(units)), nil
}
