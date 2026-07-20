package backuprules

import (
	"encoding/binary"
	"testing"
)

// --- minimal binary-XML tree builder, scoped to full-backup-content's
// and data-extraction-rules' small element vocabulary. Adapted from
// pkg/parser/nsc's test builder (same real on-disk format, duplicated
// rather than imported since it's a test-only helper unexported from
// that package). Unlike nsc's CDATA-driven schema, none of these
// elements carry text content — every fact lives in attributes — so
// this omits the cdata() helper nsc_test.go needed.

type xmlBuilder struct {
	strings []string
	index   map[string]uint32
	chunks  [][]byte
}

func newXMLBuilder() *xmlBuilder {
	return &xmlBuilder{index: map[string]uint32{}}
}

func (b *xmlBuilder) intern(s string) uint32 {
	if idx, ok := b.index[s]; ok {
		return idx
	}
	idx := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.index[s] = idx
	return idx
}

type attr struct {
	name, value string
}

const nilStringRef = 0xFFFFFFFF

func (b *xmlBuilder) startElement(name string, attrs ...attr) {
	nameRef := b.intern(name)
	const nodeSize = 16
	const extSize = 20
	const attrRecSize = 20
	total := uint32(nodeSize+extSize) + uint32(len(attrs))*attrRecSize

	buf := make([]byte, total)
	binary.LittleEndian.PutUint16(buf[0:], uint16(0x0102)) // ResXMLStartElementType
	binary.LittleEndian.PutUint16(buf[2:], uint16(nodeSize))
	binary.LittleEndian.PutUint32(buf[4:], total)
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], nilStringRef)

	extOff := nodeSize
	binary.LittleEndian.PutUint32(buf[extOff:], nilStringRef) // NS
	binary.LittleEndian.PutUint32(buf[extOff+4:], nameRef)
	binary.LittleEndian.PutUint16(buf[extOff+8:], uint16(extSize))
	binary.LittleEndian.PutUint16(buf[extOff+10:], uint16(attrRecSize))
	binary.LittleEndian.PutUint16(buf[extOff+12:], uint16(len(attrs)))

	attrOff := nodeSize + extSize
	for i, a := range attrs {
		off := attrOff + i*attrRecSize
		nameRef := b.intern(a.name)
		valRef := b.intern(a.value)
		binary.LittleEndian.PutUint32(buf[off:], nilStringRef) // NS
		binary.LittleEndian.PutUint32(buf[off+4:], nameRef)
		binary.LittleEndian.PutUint32(buf[off+8:], valRef) // RawValue: literal string
		binary.LittleEndian.PutUint16(buf[off+12:], 8)
		buf[off+14] = 0
		buf[off+15] = 0x03 // dataType = TYPE_STRING
		binary.LittleEndian.PutUint32(buf[off+16:], valRef)
	}
	b.chunks = append(b.chunks, buf)
}

func (b *xmlBuilder) endElement(name string) {
	nameRef := b.intern(name)
	const size = 16 + 8
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:], uint16(0x0103)) // ResXMLEndElementType
	binary.LittleEndian.PutUint16(buf[2:], 16)
	binary.LittleEndian.PutUint32(buf[4:], size)
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], nilStringRef)
	binary.LittleEndian.PutUint32(buf[16:], nilStringRef) // NS
	binary.LittleEndian.PutUint32(buf[20:], nameRef)
	b.chunks = append(b.chunks, buf)
}

func (b *xmlBuilder) build(t *testing.T) []byte {
	t.Helper()
	const poolHeaderSize = 28
	poolOff := uint32(8)
	offsetTableStart := poolOff + poolHeaderSize
	stringsStart := offsetTableStart + uint32(len(b.strings))*4 - poolOff

	var data []byte
	offsets := make([]uint32, len(b.strings))
	for i, s := range b.strings {
		offsets[i] = uint32(len(data))
		data = append(data, encLen(len(s))...)
		data = append(data, encLen(len(s))...)
		data = append(data, []byte(s)...)
	}
	poolChunkSize := poolHeaderSize + uint32(len(b.strings))*4 + uint32(len(data))

	pool := make([]byte, poolChunkSize)
	binary.LittleEndian.PutUint16(pool[0:], uint16(0x0001)) // ResStringPoolChunkType
	binary.LittleEndian.PutUint16(pool[2:], poolHeaderSize)
	binary.LittleEndian.PutUint32(pool[4:], poolChunkSize)
	binary.LittleEndian.PutUint32(pool[8:], uint32(len(b.strings)))
	binary.LittleEndian.PutUint32(pool[16:], 0x100) // UTF8_FLAG
	binary.LittleEndian.PutUint32(pool[20:], stringsStart)
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(pool[offsetTableStart-poolOff+uint32(i)*4:], off)
	}
	copy(pool[stringsStart:], data)

	var body []byte
	body = append(body, pool...)
	for _, c := range b.chunks {
		body = append(body, c...)
	}

	total := uint32(8) + uint32(len(body))
	out := make([]byte, 8, total)
	binary.LittleEndian.PutUint16(out[0:], uint16(0x0003)) // ResXMLChunkType
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], total)
	out = append(out, body...)
	return out
}

func encLen(n int) []byte {
	if n <= 0x7F {
		return []byte{byte(n)}
	}
	return []byte{byte((n>>8)&0x7F) | 0x80, byte(n & 0xFF)}
}

// --- full-backup-content tests ---

func TestParseFullBackupContent_ExcludeRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("full-backup-content")
	b.startElement("include", attr{"domain", "sharedpref"}, attr{"path", "."})
	b.endElement("include")
	b.startElement("exclude", attr{"domain", "sharedpref"}, attr{"path", "device.xml"})
	b.endElement("exclude")
	b.endElement("full-backup-content")

	got, err := ParseFullBackupContent(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseFullBackupContent: %v", err)
	}
	if !got.HasExclude || got.HasRequireFlagsInclude {
		t.Fatalf("got %+v, want HasExclude=true HasRequireFlagsInclude=false", got)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (has an <exclude>)")
	}
}

func TestParseFullBackupContent_RequireFlagsIncludeRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("full-backup-content")
	b.startElement("include", attr{"domain", "sharedpref"}, attr{"path", "."}, attr{"requireFlags", "clientSideEncryption"})
	b.endElement("include")
	b.endElement("full-backup-content")

	got, err := ParseFullBackupContent(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseFullBackupContent: %v", err)
	}
	if got.HasExclude || !got.HasRequireFlagsInclude {
		t.Fatalf("got %+v, want HasExclude=false HasRequireFlagsInclude=true", got)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (requireFlags-gated include)")
	}
}

// An include-only file with no requireFlags restricts nothing — it's
// functionally identical to no override at all. This is the exact case
// MG-003's Conversations corpus finding showed cannot be assumed just
// from "no <exclude>" — but a plain include-only file (no requireFlags
// either) really doesn't restrict anything, so this must NOT suppress.
func TestParseFullBackupContent_IncludeOnlyDoesNotRestrict(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("full-backup-content")
	b.startElement("include", attr{"domain", "sharedpref"}, attr{"path", "."})
	b.endElement("include")
	b.endElement("full-backup-content")

	got, err := ParseFullBackupContent(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseFullBackupContent: %v", err)
	}
	if got.Restricts() {
		t.Errorf("Restricts() = true, want false (include-only, no requireFlags): %+v", got)
	}
}

func TestParseFullBackupContent_EmptyDoesNotRestrict(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("full-backup-content")
	b.endElement("full-backup-content")

	got, err := ParseFullBackupContent(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseFullBackupContent: %v", err)
	}
	if got.Restricts() {
		t.Errorf("Restricts() = true, want false (empty file): %+v", got)
	}
}

func TestParseFullBackupContent_MalformedIsError(t *testing.T) {
	if _, err := ParseFullBackupContent([]byte("not a binary xml file"), nil); err == nil {
		t.Fatal("expected error for malformed input, got nil")
	}
}

// --- data-extraction-rules tests ---

func TestParseDataExtractionRules_CloudBackupExcludeRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.startElement("cloud-backup")
	b.startElement("exclude", attr{"domain", "sharedpref"})
	b.endElement("exclude")
	b.endElement("cloud-backup")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if !got.HasExclude {
		t.Errorf("got %+v, want HasExclude=true", got)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (cloud-backup has an <exclude>)")
	}
}

func TestParseDataExtractionRules_DisableIfNoEncryptionRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.startElement("cloud-backup", attr{"disableIfNoEncryptionCapabilities", "true"})
	b.startElement("include", attr{"domain", "sharedpref"})
	b.endElement("include")
	b.endElement("cloud-backup")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if got.HasExclude || !got.CloudBackupDisableIfNoEncryption {
		t.Fatalf("got %+v, want HasExclude=false CloudBackupDisableIfNoEncryption=true", got)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (disableIfNoEncryptionCapabilities=true, include-only)")
	}
}

func TestParseDataExtractionRules_DeviceTransferExcludeRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.startElement("device-transfer")
	b.startElement("exclude", attr{"domain", "file"})
	b.endElement("exclude")
	b.endElement("device-transfer")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (device-transfer has an <exclude>)")
	}
}

func TestParseDataExtractionRules_CrossPlatformTransferExcludeRestricts(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.startElement("cross-platform-transfer", attr{"platform", "ios"})
	b.startElement("exclude", attr{"domain", "database"})
	b.endElement("exclude")
	b.endElement("cross-platform-transfer")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if !got.Restricts() {
		t.Error("Restricts() = false, want true (cross-platform-transfer has an <exclude>)")
	}
}

// Include-only cloud-backup, no disableIfNoEncryptionCapabilities and
// no excludes anywhere: restricts nothing.
func TestParseDataExtractionRules_IncludeOnlyDoesNotRestrict(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.startElement("cloud-backup")
	b.startElement("include", attr{"domain", "sharedpref"})
	b.endElement("include")
	b.endElement("cloud-backup")
	b.startElement("device-transfer")
	b.startElement("include", attr{"domain", "sharedpref"})
	b.endElement("include")
	b.endElement("device-transfer")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if got.Restricts() {
		t.Errorf("Restricts() = true, want false (include-only, no disableIfNoEncryptionCapabilities): %+v", got)
	}
}

func TestParseDataExtractionRules_EmptyDoesNotRestrict(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("data-extraction-rules")
	b.endElement("data-extraction-rules")

	got, err := ParseDataExtractionRules(b.build(t), nil)
	if err != nil {
		t.Fatalf("ParseDataExtractionRules: %v", err)
	}
	if got.Restricts() {
		t.Errorf("Restricts() = true, want false (empty file): %+v", got)
	}
}

func TestParseDataExtractionRules_MalformedIsError(t *testing.T) {
	if _, err := ParseDataExtractionRules([]byte("not a binary xml file"), nil); err == nil {
		t.Fatal("expected error for malformed input, got nil")
	}
}
