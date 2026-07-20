// Package arsc extracts the global string pool from Android's
// chunk-based binary resource format — the one place every string-typed
// resource *value* lives (e.g. the literal text of a
// <string name="google_api_key">AIzaSy…</string> resource), as opposed
// to resource type/key *names*, which live in separate per-package
// string pools this package does not read.
//
// Despite the package name, this reads two container formats, not just
// resources.arsc: a resources.arsc resource table (leading chunk type
// RES_TABLE_TYPE) and a compiled binary XML document such as
// AndroidManifest.xml (leading chunk type RES_XML_TYPE) — e.g. a literal
// <meta-data android:value="AIzaSy…"/>, as opposed to the
// @string/google_maps_key reference form resources.arsc covers. Both
// container formats are immediately followed by the identical
// ResChunkHeader/ResStringPool sub-format, so the same reader below
// handles both; there is no second parser for the manifest's string
// pool, deliberately, per the same "verify before reimplementing"
// reasoning that produced this package in the first place (below).
//
// github.com/shogo82148/androidbinary (used for AndroidManifest.xml's
// structured-field parsing elsewhere in this codebase) has no public API
// to enumerate either container's string pool: TableFile only exposes
// GetResource(id, config) and GetString(ref), both of which require
// already knowing a specific ID — there is no enumerator, and the fields
// that hold the parsed packages/pools are unexported. Confirmed via
// `go doc` on the installed package before writing this. Everything else
// about these formats (per-package resource type tables, resource ID
// resolution, configuration qualifiers, the actual XML element/attribute
// tree) is deliberately NOT reimplemented here — this package reads
// exactly one chunk, the same discipline pkg/parser/dex applies to the
// DEX string pool: minimal custom code for the one well-isolated
// structure a maintained library's public API doesn't reach, not a
// second resource table or XML parser.
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
	chunkHeaderSize      = 8      // type(2) + headerSize(2) + size(4)
	resTableType         = 0x0002 // resources.arsc: ResTable_header (chunk header + packageCount)
	resXMLType           = 0x0003 // compiled binary XML (e.g. AndroidManifest.xml): ResXMLTree_header (just the chunk header)
	resStringPoolType    = 0x0001
	utf8Flag             = 0x100
	stringPoolHeaderSize = 28      // chunk header(8) + stringCount(4) + styleCount(4) + flags(4) + stringsStart(4) + stylesStart(4)
	maxTopLevelChunks    = 1 << 20 // sanity cap on the outer scan loop, not a real-world limit
)

// Exported chunk-type/size constants — pkg/parser/nsc walks the same
// binary-XML container beyond the leading string pool (element/attribute/
// CDATA chunks this package doesn't read), and reuses ReadChunkHeader/
// ParseStringPool below rather than duplicating string-pool decoding.
const (
	ChunkHeaderSize  = chunkHeaderSize
	ChunkTypeXML     = resXMLType
	ChunkTypeTable   = resTableType
	ChunkTypeStrPool = resStringPoolType
)

// PoolString is one entry from the global string pool.
type PoolString struct {
	Index int
	Value string
}

// ExtractGlobalStringPool reads the top-level string pool — the chunk
// immediately following the outer container header — from either a
// resources.arsc resource table or a compiled binary XML document (e.g.
// AndroidManifest.xml), and returns every string in it. Returns an
// empty, non-error result if the file has no such chunk (unusual but not
// invalid: a resource table with no string-valued resources, or an XML
// document with no strings at all).
func ExtractGlobalStringPool(data []byte) ([]PoolString, error) {
	if len(data) < chunkHeaderSize {
		return nil, fmt.Errorf("arsc: file too small to contain a container header (%d bytes)", len(data))
	}

	typ, headerSize, size, err := ReadChunkHeader(data, 0)
	if err != nil {
		return nil, fmt.Errorf("arsc: %w", err)
	}
	if typ != resTableType && typ != resXMLType {
		return nil, fmt.Errorf("arsc: not a resource table or binary XML document (chunk type 0x%04X, want 0x%04X or 0x%04X)", typ, resTableType, resXMLType)
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
		ctyp, cheaderSize, csize, err := ReadChunkHeader(data, offset)
		if err != nil {
			return nil, fmt.Errorf("arsc: reading chunk at offset %d: %w", offset, err)
		}
		if csize == 0 {
			return nil, fmt.Errorf("arsc: zero-size chunk at offset %d", offset)
		}
		if ctyp == resStringPoolType {
			return ParseStringPool(data, offset, cheaderSize, csize)
		}
		offset += csize
	}

	return nil, nil
}

// ReadChunkHeader reads a ResChunkHeader (type, headerSize, size) at off,
// bounds-checked against len(data) before returning. Exported for
// pkg/parser/nsc, which walks the same chunk sequence this package does
// but continues past the leading string pool into element/attribute/
// CDATA chunks.
func ReadChunkHeader(data []byte, off uint32) (typ, headerSize, size uint32, err error) {
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

// ParseStringPool parses a single RES_STRING_POOL_TYPE chunk starting at
// poolOff (chunk header already read into headerSize/chunkSize by the
// caller, typically via ReadChunkHeader). Exported for pkg/parser/nsc —
// see ReadChunkHeader's doc comment.
func ParseStringPool(data []byte, poolOff, headerSize, chunkSize uint32) ([]PoolString, error) {
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
