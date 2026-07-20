package dex

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// buildDex constructs a minimal synthetic DEX file containing only the
// sections this package reads (string_ids, type_ids, method_ids,
// field_ids) — no proto_ids, class_defs, or code, since ParseStrings
// never touches them. methods/fields are (classIdx, nameStrIdx) pairs,
// where classIdx indexes into typeDescIdx.
func buildDex(t *testing.T, strings []string, typeDescIdx []uint32, methods, fields [][2]uint32) []byte {
	t.Helper()

	stringIDsOff := uint32(0x70)
	stringIDsSize := uint32(len(strings))
	typeIDsOff := stringIDsOff + stringIDsSize*4
	typeIDsSize := uint32(len(typeDescIdx))
	methodIDsOff := typeIDsOff + typeIDsSize*4
	methodIDsSize := uint32(len(methods))
	fieldIDsOff := methodIDsOff + methodIDsSize*8
	fieldIDsSize := uint32(len(fields))
	dataOff := fieldIDsOff + fieldIDsSize*8

	var data bytes.Buffer
	stringDataOffs := make([]uint32, len(strings))
	for i, s := range strings {
		stringDataOffs[i] = dataOff + uint32(data.Len())
		writeULEB128(&data, uint32(len(utf16.Encode([]rune(s)))))
		data.Write(toMUTF8(s))
		data.WriteByte(0x00)
	}

	buf := make([]byte, dataOff)
	copy(buf[0:8], []byte("dex\n039\x00"))
	binary.LittleEndian.PutUint32(buf[offEndianTag:], endianTagValue)
	binary.LittleEndian.PutUint32(buf[offStringIDsSize:], stringIDsSize)
	binary.LittleEndian.PutUint32(buf[offStringIDsOff:], stringIDsOff)
	binary.LittleEndian.PutUint32(buf[offTypeIDsSize:], typeIDsSize)
	binary.LittleEndian.PutUint32(buf[offTypeIDsOff:], typeIDsOff)
	binary.LittleEndian.PutUint32(buf[offFieldIDsSize:], fieldIDsSize)
	binary.LittleEndian.PutUint32(buf[offFieldIDsOff:], fieldIDsOff)
	binary.LittleEndian.PutUint32(buf[offMethodIDsSize:], methodIDsSize)
	binary.LittleEndian.PutUint32(buf[offMethodIDsOff:], methodIDsOff)

	for i, off := range stringDataOffs {
		binary.LittleEndian.PutUint32(buf[stringIDsOff+uint32(i)*4:], off)
	}
	for i, idx := range typeDescIdx {
		binary.LittleEndian.PutUint32(buf[typeIDsOff+uint32(i)*4:], idx)
	}
	for i, m := range methods {
		binary.LittleEndian.PutUint16(buf[methodIDsOff+uint32(i)*8:], uint16(m[0]))
		binary.LittleEndian.PutUint32(buf[methodIDsOff+uint32(i)*8+4:], m[1])
	}
	for i, f := range fields {
		binary.LittleEndian.PutUint16(buf[fieldIDsOff+uint32(i)*8:], uint16(f[0]))
		binary.LittleEndian.PutUint32(buf[fieldIDsOff+uint32(i)*8+4:], f[1])
	}

	return append(buf, data.Bytes()...)
}

func writeULEB128(buf *bytes.Buffer, v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

// toMUTF8 is the encode-side inverse of decodeMUTF8, used only to build
// test fixtures.
func toMUTF8(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		switch {
		case u == 0:
			out = append(out, 0xC0, 0x80)
		case u <= 0x7F:
			out = append(out, byte(u))
		case u <= 0x7FF:
			out = append(out, 0xC0|byte(u>>6), 0x80|byte(u&0x3F))
		default:
			out = append(out, 0xE0|byte(u>>12), 0x80|byte((u>>6)&0x3F), 0x80|byte(u&0x3F))
		}
	}
	return out
}

func TestParseStrings_AttributionAndDecoding(t *testing.T) {
	strings := []string{
		"Lcom/example/Foo;",                   // 0: type descriptor
		"doSecret",                            // 1: method name
		"apiKey",                              // 2: field name
		"sk_live_FAKEKEYFORTESTING1234567890", // 3: unattributed data string
		"\x00embedded-null",                   // 4: literal NUL mid-string (MUTF-8 0xC0 0x80 case)
		"emoji:\U0001F600",                    // 5: supplementary-plane char (CESU-8 surrogate pair case)
	}
	data := buildDex(t, strings,
		[]uint32{0},         // type_ids[0] -> string 0
		[][2]uint32{{0, 1}}, // method_ids[0]: class_idx=0, name_idx=1
		[][2]uint32{{0, 2}}, // field_ids[0]: class_idx=0, name_idx=2
	)

	refs, err := ParseStrings("classes.dex", data)
	if err != nil {
		t.Fatalf("ParseStrings: %v", err)
	}
	if len(refs) != len(strings) {
		t.Fatalf("got %d string refs, want %d", len(refs), len(strings))
	}

	for i, want := range strings {
		if refs[i].Value != want {
			t.Errorf("refs[%d].Value = %q, want %q", i, refs[i].Value, want)
		}
		if refs[i].DexFile != "classes.dex" {
			t.Errorf("refs[%d].DexFile = %q, want classes.dex", i, refs[i].DexFile)
		}
		if refs[i].Index != i {
			t.Errorf("refs[%d].Index = %d, want %d", i, refs[i].Index, i)
		}
	}

	if refs[0].Usage != TypeName || refs[0].ClassType != "Lcom/example/Foo;" {
		t.Errorf("refs[0] = %+v, want Usage=TypeName ClassType=Lcom/example/Foo;", refs[0])
	}
	if refs[1].Usage != MethodName || refs[1].ClassType != "Lcom/example/Foo;" {
		t.Errorf("refs[1] = %+v, want Usage=MethodName ClassType=Lcom/example/Foo;", refs[1])
	}
	if refs[2].Usage != FieldName || refs[2].ClassType != "Lcom/example/Foo;" {
		t.Errorf("refs[2] = %+v, want Usage=FieldName ClassType=Lcom/example/Foo;", refs[2])
	}
	if refs[3].Usage != Unattributed {
		t.Errorf("refs[3].Usage = %v, want Unattributed", refs[3].Usage)
	}
}

// TestParseStrings_MultiDexAttribution proves a string hit is tagged with
// the dex file it actually came from, and that indices in one dex file's
// string pool are never confused with another's — the requirement behind
// stable finding_hash file paths across multi-dex APKs.
func TestParseStrings_MultiDexAttribution(t *testing.T) {
	strings := []string{"sk_live_FAKEKEYFORTESTING1234567890"}
	data := buildDex(t, strings, nil, nil, nil)

	refsA, err := ParseStrings("classes.dex", data)
	if err != nil {
		t.Fatalf("ParseStrings(classes.dex): %v", err)
	}
	refsB, err := ParseStrings("classes7.dex", data)
	if err != nil {
		t.Fatalf("ParseStrings(classes7.dex): %v", err)
	}

	if refsA[0].DexFile != "classes.dex" {
		t.Errorf("refsA[0].DexFile = %q, want classes.dex", refsA[0].DexFile)
	}
	if refsB[0].DexFile != "classes7.dex" {
		t.Errorf("refsB[0].DexFile = %q, want classes7.dex", refsB[0].DexFile)
	}
	if refsA[0].Value != refsB[0].Value || refsA[0].Index != refsB[0].Index {
		t.Errorf("same string content/index should decode identically regardless of source file: got %+v vs %+v", refsA[0], refsB[0])
	}
}

func TestParseStrings_RejectsTruncatedHeader(t *testing.T) {
	if _, err := ParseStrings("classes.dex", []byte("too short")); err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

func TestParseStrings_RejectsOutOfBoundsTable(t *testing.T) {
	data := buildDex(t, []string{"a"}, nil, nil, nil)
	// Corrupt string_ids_size to claim far more entries than actually fit.
	binary.LittleEndian.PutUint32(data[offStringIDsSize:], 0xFFFFFF)
	if _, err := ParseStrings("classes.dex", data); err == nil {
		t.Fatal("expected error for out-of-bounds string_ids table, got nil")
	}
}
