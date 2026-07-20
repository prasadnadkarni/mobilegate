package nsc

import (
	"encoding/binary"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
)

// --- minimal binary-XML tree builder, scoped to network-security-config's
// small element vocabulary. Not a general AXML writer. ---

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

func (b *xmlBuilder) startElement(name string, attrs ...attr) {
	nameRef := b.intern(name)
	const nodeSize = 16 // ResXMLTree_node only — the chunk's headerSize field is THIS, not node+ext; the ext struct always starts right after it regardless of the field's value (matches androidbinary's own readStartElement: seek to headerSize, then read the ext struct from there)
	const extSize = 20
	const attrRecSize = 20
	total := uint32(nodeSize+extSize) + uint32(len(attrs))*attrRecSize

	buf := make([]byte, total)
	binary.LittleEndian.PutUint16(buf[0:], chunkStartElement)
	binary.LittleEndian.PutUint16(buf[2:], uint16(nodeSize))
	binary.LittleEndian.PutUint32(buf[4:], total)
	binary.LittleEndian.PutUint32(buf[8:], 0)             // lineNumber
	binary.LittleEndian.PutUint32(buf[12:], nilStringRef) // comment

	extOff := nodeSize
	binary.LittleEndian.PutUint32(buf[extOff:], nilStringRef) // NS
	binary.LittleEndian.PutUint32(buf[extOff+4:], nameRef)
	binary.LittleEndian.PutUint16(buf[extOff+8:], uint16(extSize)) // AttributeStart, relative to extOff
	binary.LittleEndian.PutUint16(buf[extOff+10:], uint16(attrRecSize))
	binary.LittleEndian.PutUint16(buf[extOff+12:], uint16(len(attrs)))

	attrOff := nodeSize + extSize
	for i, a := range attrs {
		off := attrOff + i*attrRecSize
		nameRef := b.intern(a.name)
		valRef := b.intern(a.value)
		binary.LittleEndian.PutUint32(buf[off:], nilStringRef) // NS
		binary.LittleEndian.PutUint32(buf[off+4:], nameRef)
		binary.LittleEndian.PutUint32(buf[off+8:], valRef) // RawValue: always literal string for these tests
		binary.LittleEndian.PutUint16(buf[off+12:], 8)     // typedValue.Size
		buf[off+14] = 0                                    // res0
		buf[off+15] = 0x03                                 // dataType = TYPE_STRING (unused when RawValue set, but filled for realism)
		binary.LittleEndian.PutUint32(buf[off+16:], valRef)
	}
	b.chunks = append(b.chunks, buf)
}

func (b *xmlBuilder) endElement(name string) {
	nameRef := b.intern(name)
	const size = 16 + 8
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:], chunkEndElement)
	binary.LittleEndian.PutUint16(buf[2:], 16)
	binary.LittleEndian.PutUint32(buf[4:], size)
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], nilStringRef)
	binary.LittleEndian.PutUint32(buf[16:], nilStringRef) // NS
	binary.LittleEndian.PutUint32(buf[20:], nameRef)
	b.chunks = append(b.chunks, buf)
}

func (b *xmlBuilder) cdata(text string) {
	ref := b.intern(text)
	const size = 16 + 12
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:], chunkCData)
	binary.LittleEndian.PutUint16(buf[2:], 16)
	binary.LittleEndian.PutUint32(buf[4:], size)
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], nilStringRef)
	binary.LittleEndian.PutUint32(buf[16:], ref) // data
	binary.LittleEndian.PutUint16(buf[20:], 8)
	buf[22] = 0
	buf[23] = 0x03
	binary.LittleEndian.PutUint32(buf[24:], ref)
	b.chunks = append(b.chunks, buf)
}

func (b *xmlBuilder) build(t *testing.T) []byte {
	t.Helper()
	// String pool chunk, UTF-8 mode (mirrors pkg/parser/arsc/arsc_test.go's buildContainer, duplicated
	// rather than imported since it's a test-only helper unexported from that package).
	const poolHeaderSize = 28
	poolOff := uint32(8) // right after the outer RES_XML_TYPE chunk header (headerSize=8, no packageCount)
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
	binary.LittleEndian.PutUint16(pool[0:], uint16(chunkTypeStrPoolForTest))
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
	binary.LittleEndian.PutUint16(out[0:], chunkTypeXMLForTest)
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], total)
	out = append(out, body...)
	return out
}

const (
	chunkTypeXMLForTest     = 0x0003
	chunkTypeStrPoolForTest = 0x0001
)

func encLen(n int) []byte {
	if n <= 0x7F {
		return []byte{byte(n)}
	}
	return []byte{byte((n>>8)&0x7F) | 0x80, byte(n & 0xFF)}
}

// --- tests ---

func TestParse_DomainConfigWithCleartextAndDomain(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("network-security-config")
	b.startElement("domain-config", attr{"cleartextTrafficPermitted", "true"})
	b.startElement("domain", attr{"includeSubdomains", "true"})
	b.cdata("example.com")
	b.endElement("domain")
	b.endElement("domain-config")
	b.endElement("network-security-config")

	configs, err := Parse(b.build(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1: %+v", len(configs), configs)
	}
	c := configs[0]
	if c.Kind != KindDomainConfig || c.CleartextPermitted != manifest.True {
		t.Errorf("unexpected config: %+v", c)
	}
	if len(c.Domains) != 1 || c.Domains[0].Name != "example.com" || !c.Domains[0].IncludeSubdomains {
		t.Errorf("unexpected domains: %+v", c.Domains)
	}
}

func TestParse_BaseConfigNoDomains(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("network-security-config")
	b.startElement("base-config", attr{"cleartextTrafficPermitted", "false"})
	b.startElement("trust-anchors")
	b.startElement("certificates", attr{"src", "system"})
	b.endElement("certificates")
	b.endElement("trust-anchors")
	b.endElement("base-config")
	b.endElement("network-security-config")

	configs, err := Parse(b.build(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1: %+v", len(configs), configs)
	}
	c := configs[0]
	if c.Kind != KindBaseConfig || c.CleartextPermitted != manifest.False {
		t.Errorf("unexpected config: %+v", c)
	}
	if len(c.Domains) != 0 {
		t.Errorf("base-config should have no domains, got %+v", c.Domains)
	}
}

func TestParse_MultipleDomainsAndConfigs(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("network-security-config")
	b.startElement("base-config", attr{"cleartextTrafficPermitted", "false"})
	b.endElement("base-config")
	b.startElement("domain-config", attr{"cleartextTrafficPermitted", "true"})
	b.startElement("domain", attr{"includeSubdomains", "true"})
	b.cdata("first-party.example")
	b.endElement("domain")
	b.startElement("domain", attr{"includeSubdomains", "false"})
	b.cdata("second.example")
	b.endElement("domain")
	b.endElement("domain-config")
	b.endElement("network-security-config")

	configs, err := Parse(b.build(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d configs, want 2: %+v", len(configs), configs)
	}
	if configs[0].Kind != KindBaseConfig {
		t.Errorf("configs[0] = %+v, want base-config first", configs[0])
	}
	dc := configs[1]
	if dc.Kind != KindDomainConfig || len(dc.Domains) != 2 {
		t.Fatalf("configs[1] = %+v, want domain-config with 2 domains", dc)
	}
	if dc.Domains[0].Name != "first-party.example" || dc.Domains[0].IncludeSubdomains != true {
		t.Errorf("domains[0] = %+v", dc.Domains[0])
	}
	if dc.Domains[1].Name != "second.example" || dc.Domains[1].IncludeSubdomains != false {
		t.Errorf("domains[1] = %+v", dc.Domains[1])
	}
}

func TestParse_MissingCleartextAttrIsUnset(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("network-security-config")
	b.startElement("domain-config")
	b.startElement("domain", attr{"includeSubdomains", "true"})
	b.cdata("example.com")
	b.endElement("domain")
	b.endElement("domain-config")
	b.endElement("network-security-config")

	configs, err := Parse(b.build(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(configs) != 1 || configs[0].CleartextPermitted != manifest.Unset {
		t.Fatalf("got %+v, want CleartextPermitted=Unset", configs)
	}
}

func TestParse_RejectsTruncatedHeader(t *testing.T) {
	if _, err := Parse([]byte("short")); err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

func TestParse_RejectsWrongChunkType(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:], 0x0002) // RES_TABLE_TYPE, not RES_XML_TYPE
	binary.LittleEndian.PutUint16(buf[2:], 8)
	binary.LittleEndian.PutUint32(buf[4:], 16)
	if _, err := Parse(buf); err == nil {
		t.Fatal("expected error for wrong container type, got nil")
	}
}

func TestParse_NoElementsIsEmptyNotError(t *testing.T) {
	b := newXMLBuilder()
	b.startElement("network-security-config")
	b.endElement("network-security-config")
	configs, err := Parse(b.build(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0", len(configs))
	}
}
