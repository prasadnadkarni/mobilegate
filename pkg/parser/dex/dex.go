// Package dex extracts the string pool from a DEX file, tagging each
// string with best-effort class/method/field attribution derived purely
// from the fixed-size id tables (string_ids, type_ids, method_ids,
// field_ids). It does not parse class_data_item or code_item — no
// bytecode, no instruction decoding, no decompilation. A string used only
// as a data constant (e.g. a hardcoded secret baked in via const-string)
// has no reliable attribution at this level without disassembling code
// that references it, which is out of scope by design.
package dex

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// MaxDecodedStringBytes bounds the total bytes this package will decode
// out of a single DEX file's string table, guarding against a crafted DEX
// whose declared string count/lengths are designed to blow up memory
// (the DEX analogue of a zip decompression bomb). Mirrors the budget
// avast/apkparser applies to resources.arsc string pools.
const MaxDecodedStringBytes = 50 * 1024 * 1024

const headerSize = 0x70

// Header field byte offsets (see dex-format spec: header_item).
const (
	offEndianTag     = 40
	offStringIDsSize = 56
	offStringIDsOff  = 60
	offTypeIDsSize   = 64
	offTypeIDsOff    = 68
	offFieldIDsSize  = 80
	offFieldIDsOff   = 84
	offMethodIDsSize = 88
	offMethodIDsOff  = 92
)

const endianTagValue = 0x12345678

const (
	stringIDEntrySize = 4
	typeIDEntrySize   = 4
	fieldIDEntrySize  = 8
	methodIDEntrySize = 8
)

// Usage records what an id-table entry a string was found in implies
// about its role, derived without any bytecode parsing.
type Usage int

const (
	Unattributed Usage = iota
	TypeName
	MethodName
	FieldName
)

func (u Usage) String() string {
	switch u {
	case TypeName:
		return "type"
	case MethodName:
		return "method"
	case FieldName:
		return "field"
	default:
		return "unattributed"
	}
}

// StringRef is one entry from a DEX file's string pool.
type StringRef struct {
	DexFile   string // e.g. "classes2.dex" — required for stable finding_hash file paths across multi-dex APKs
	Index     int    // index into this dex file's string_ids table
	Value     string
	Usage     Usage
	ClassType string // owning class descriptor (e.g. "Lcom/example/Foo;") when Usage != Unattributed
}

// ParseStrings extracts and attributes every string in a single DEX
// file's string pool. dexFileName is recorded on every returned StringRef
// verbatim (e.g. "classes.dex", "classes2.dex") since string_ids indices
// are only meaningful within their own dex file — merging strings from
// multiple dex files without that tag would make finding evidence point
// at the wrong file.
func ParseStrings(dexFileName string, data []byte) ([]StringRef, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("dex: %s: file too small to contain a header (%d bytes)", dexFileName, len(data))
	}
	if len(data) < 8 || string(data[0:4]) != "dex\n" {
		return nil, fmt.Errorf("dex: %s: bad magic", dexFileName)
	}
	if endian := binary.LittleEndian.Uint32(data[offEndianTag:]); endian != endianTagValue {
		return nil, fmt.Errorf("dex: %s: unsupported endian tag 0x%08X (big-endian DEX is not supported)", dexFileName, endian)
	}

	stringIDsSize := binary.LittleEndian.Uint32(data[offStringIDsSize:])
	stringIDsOff := binary.LittleEndian.Uint32(data[offStringIDsOff:])
	typeIDsSize := binary.LittleEndian.Uint32(data[offTypeIDsSize:])
	typeIDsOff := binary.LittleEndian.Uint32(data[offTypeIDsOff:])
	fieldIDsSize := binary.LittleEndian.Uint32(data[offFieldIDsSize:])
	fieldIDsOff := binary.LittleEndian.Uint32(data[offFieldIDsOff:])
	methodIDsSize := binary.LittleEndian.Uint32(data[offMethodIDsSize:])
	methodIDsOff := binary.LittleEndian.Uint32(data[offMethodIDsOff:])

	stringDataOffs, err := readUint32Table(data, stringIDsOff, stringIDsSize, stringIDEntrySize, 0, dexFileName, "string_ids")
	if err != nil {
		return nil, err
	}
	typeDescriptorIdx, err := readUint32Table(data, typeIDsOff, typeIDsSize, typeIDEntrySize, 0, dexFileName, "type_ids")
	if err != nil {
		return nil, err
	}

	values := make([]string, len(stringDataOffs))
	var budget int64
	for i, off := range stringDataOffs {
		s, err := decodeStringDataItem(data, off)
		if err != nil {
			return nil, fmt.Errorf("dex: %s: string_ids[%d]: %w", dexFileName, i, err)
		}
		budget += int64(len(s))
		if budget > MaxDecodedStringBytes {
			return nil, fmt.Errorf("dex: %s: string table exceeds %d byte decode budget — refusing to continue", dexFileName, MaxDecodedStringBytes)
		}
		values[i] = s
	}

	usage := make([]Usage, len(values))
	classType := make([]string, len(values))

	// type_ids: every descriptor string is a type name.
	for _, strIdx := range typeDescriptorIdx {
		if int(strIdx) >= len(values) {
			return nil, fmt.Errorf("dex: %s: type_ids references out-of-range string index %d", dexFileName, strIdx)
		}
		usage[strIdx] = TypeName
		classType[strIdx] = values[strIdx]
	}

	descriptorForType := func(typeIdx uint32) (string, bool) {
		if int(typeIdx) >= len(typeDescriptorIdx) {
			return "", false
		}
		strIdx := typeDescriptorIdx[typeIdx]
		if int(strIdx) >= len(values) {
			return "", false
		}
		return values[strIdx], true
	}

	// method_ids: method_id_item is { ushort class_idx; ushort proto_idx; uint name_idx }.
	if err := attributeMembers(data, methodIDsOff, methodIDsSize, methodIDEntrySize, dexFileName, "method_ids", func(rec []byte) error {
		classIdx := uint32(binary.LittleEndian.Uint16(rec[0:2]))
		nameIdx := binary.LittleEndian.Uint32(rec[4:8])
		if int(nameIdx) >= len(values) {
			return fmt.Errorf("name_idx out of range: %d", nameIdx)
		}
		if usage[nameIdx] == Unattributed {
			usage[nameIdx] = MethodName
			if d, ok := descriptorForType(classIdx); ok {
				classType[nameIdx] = d
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("dex: %s: %w", dexFileName, err)
	}

	// field_ids: field_id_item is { ushort class_idx; ushort type_idx; uint name_idx }.
	if err := attributeMembers(data, fieldIDsOff, fieldIDsSize, fieldIDEntrySize, dexFileName, "field_ids", func(rec []byte) error {
		classIdx := uint32(binary.LittleEndian.Uint16(rec[0:2]))
		nameIdx := binary.LittleEndian.Uint32(rec[4:8])
		if int(nameIdx) >= len(values) {
			return fmt.Errorf("name_idx out of range: %d", nameIdx)
		}
		if usage[nameIdx] == Unattributed {
			usage[nameIdx] = FieldName
			if d, ok := descriptorForType(classIdx); ok {
				classType[nameIdx] = d
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("dex: %s: %w", dexFileName, err)
	}

	out := make([]StringRef, len(values))
	for i, v := range values {
		out[i] = StringRef{
			DexFile:   dexFileName,
			Index:     i,
			Value:     v,
			Usage:     usage[i],
			ClassType: classType[i],
		}
	}
	return out, nil
}

// readUint32Table reads a table of size fixed-width entries starting at
// off, returning the first uint32 field of each entry (entries where the
// field of interest isn't the first 4 bytes aren't handled by this
// helper — string_ids and type_ids both are). fieldByteOffset lets a
// caller pick a field other than the first if needed; both current
// callers use 0.
func readUint32Table(data []byte, off, size uint32, entrySize, fieldByteOffset int, dexFileName, tableName string) ([]uint32, error) {
	end := uint64(off) + uint64(size)*uint64(entrySize)
	if size > 0 && (off == 0 || end > uint64(len(data))) {
		return nil, fmt.Errorf("dex: %s: %s table out of bounds (off=%d size=%d entrySize=%d filelen=%d)", dexFileName, tableName, off, size, entrySize, len(data))
	}
	out := make([]uint32, size)
	for i := uint32(0); i < size; i++ {
		recOff := off + i*uint32(entrySize) + uint32(fieldByteOffset)
		out[i] = binary.LittleEndian.Uint32(data[recOff : recOff+4])
	}
	return out, nil
}

// attributeMembers walks a fixed-size id table (method_ids or field_ids)
// and invokes fn with each raw entry's bytes.
func attributeMembers(data []byte, off, size uint32, entrySize int, dexFileName, tableName string, fn func(rec []byte) error) error {
	end := uint64(off) + uint64(size)*uint64(entrySize)
	if size > 0 && (off == 0 || end > uint64(len(data))) {
		return fmt.Errorf("%s table out of bounds (off=%d size=%d entrySize=%d filelen=%d)", tableName, off, size, entrySize, len(data))
	}
	for i := uint32(0); i < size; i++ {
		recOff := off + i*uint32(entrySize)
		if err := fn(data[recOff : recOff+uint32(entrySize)]); err != nil {
			return fmt.Errorf("%s[%d]: %w", tableName, i, err)
		}
	}
	return nil
}

// decodeStringDataItem reads one string_data_item at byte offset off:
// a ULEB128 utf16_size followed by MUTF-8 bytes terminated by a single
// 0x00 byte.
func decodeStringDataItem(data []byte, off uint32) (string, error) {
	if int(off) >= len(data) {
		return "", fmt.Errorf("string_data_off %d out of bounds", off)
	}
	_, next, err := readULEB128(data, int(off))
	if err != nil {
		return "", fmt.Errorf("reading utf16_size: %w", err)
	}

	termRel := indexByte(data[next:], 0x00)
	if termRel < 0 {
		return "", fmt.Errorf("unterminated string_data_item at offset %d", off)
	}
	return decodeMUTF8(data[next : next+termRel])
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// readULEB128 reads an unsigned LEB128 value starting at off, returning
// the value and the offset just past it.
func readULEB128(data []byte, off int) (value uint32, next int, err error) {
	var shift uint
	for {
		if off >= len(data) {
			return 0, off, fmt.Errorf("truncated uleb128")
		}
		b := data[off]
		off++
		if shift >= 32 {
			return 0, off, fmt.Errorf("uleb128 too long")
		}
		value |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return value, off, nil
}

// decodeMUTF8 decodes Android's Modified UTF-8 (MUTF-8 / CESU-8): like
// UTF-8 but NUL is encoded as the two-byte sequence 0xC0 0x80 (since a
// single 0x00 byte is reserved as the string terminator), and characters
// outside the Basic Multilingual Plane are encoded as a surrogate pair of
// 3-byte sequences rather than a single 4-byte UTF-8 sequence. Decoding
// each MUTF-8 character to its raw UTF-16 code unit and handing the whole
// sequence to unicode/utf16.Decode reuses the stdlib's surrogate-pairing
// logic instead of reimplementing it, and degrades safely (U+FFFD) on
// malformed/lone surrogates rather than panicking on adversarial input.
func decodeMUTF8(b []byte) (string, error) {
	units := make([]uint16, 0, len(b))
	i := 0
	for i < len(b) {
		b0 := b[i]
		switch {
		case b0 < 0x80:
			units = append(units, uint16(b0))
			i++
		case b0&0xE0 == 0xC0:
			if i+1 >= len(b) || b[i+1]&0xC0 != 0x80 {
				return "", fmt.Errorf("invalid MUTF-8 2-byte sequence at %d", i)
			}
			units = append(units, uint16(b0&0x1F)<<6|uint16(b[i+1]&0x3F))
			i += 2
		case b0&0xF0 == 0xE0:
			if i+2 >= len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 {
				return "", fmt.Errorf("invalid MUTF-8 3-byte sequence at %d", i)
			}
			units = append(units, uint16(b0&0x0F)<<12|uint16(b[i+1]&0x3F)<<6|uint16(b[i+2]&0x3F))
			i += 3
		default:
			return "", fmt.Errorf("invalid MUTF-8 lead byte 0x%02X at %d", b0, i)
		}
	}
	return string(utf16.Decode(units)), nil
}
