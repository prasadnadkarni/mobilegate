// Package nsc parses a compiled network_security_config.xml enough to
// answer MG-002's question: which domains (if any) does this app permit
// cleartext traffic to, and under what kind of config block.
//
// github.com/shogo82148/androidbinary's XMLFile cannot do this: its
// reader never handles RES_XML_CDATA_TYPE chunks (the constant is
// defined in the package but never referenced in its chunk-type switch),
// so a <domain>example.com</domain> element's text — the domain name,
// the one fact this whole file exists to express — is silently dropped.
// Confirmed empirically before writing this package: decoding a real
// network_security_config.xml from the MG-002 corpus (Tusky) through
// androidbinary.NewXMLFile().Reader() produced
// "<domain includeSubdomains=\"true\"></domain>" — the element, no text.
// Also confirmed via `go doc`: ResXMLCDataType is declared but never
// appears in the library's own chunk-handling switch.
//
// This package does not reimplement general binary-XML parsing. It
// reuses pkg/parser/arsc's already-verified ReadChunkHeader/
// ParseStringPool for the leading string pool (the same
// ResChunkHeader/ResStringPool sub-format arsc already handles), and
// adds just enough of a tree walk — start element, end element, CDATA,
// skip everything else — to track domain-config/base-config nesting and
// their cleartextTrafficPermitted attribute plus child <domain> text.
// It reuses github.com/shogo82148/androidbinary's exported
// ResXMLTreeAttrExt/ResXMLTreeAttribute/ResXMLTreeEndElementExt/ResValue
// struct layouts and DataType constants rather than redefining them,
// since those are public and byte-layout-correct — only the missing
// CDATA handling and the tree-walk logic are new.
package nsc

import (
	"encoding/binary"
	"fmt"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/arsc"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/shogo82148/androidbinary"
)

// Chunk types beyond what pkg/parser/arsc already exports (that package
// only names the string-pool and container types it itself reads).
const (
	chunkStartNamespace = 0x0100
	chunkEndNamespace   = 0x0101
	chunkStartElement   = 0x0102
	chunkEndElement     = 0x0103
	chunkCData          = 0x0104

	nilStringRef = 0xFFFFFFFF // androidbinary.NilResStringPoolRef, as a raw uint32 for direct field comparison

	maxChunks = 1 << 20 // sanity cap on the walk, not a real-world limit
)

// ConfigKind distinguishes a domain-scoped block from the global default.
type ConfigKind string

const (
	KindDomainConfig ConfigKind = "domain-config"
	KindBaseConfig   ConfigKind = "base-config"
)

// Domain is one <domain> entry inside a <domain-config> block.
type Domain struct {
	Name              string
	IncludeSubdomains bool
}

// Config is one <domain-config> or <base-config> block.
type Config struct {
	Kind               ConfigKind
	CleartextPermitted manifest.Tristate // reuses manifest's tri-state: an explicit attribute is required to know either way
	Domains            []Domain          // empty for base-config
}

// Parse extracts every <domain-config>/<base-config> block's
// cleartextTrafficPermitted setting (and, for domain-config, its
// <domain> children) from a compiled network_security_config.xml.
func Parse(data []byte) ([]Config, error) {
	if len(data) < arsc.ChunkHeaderSize {
		return nil, fmt.Errorf("nsc: file too small to contain a container header (%d bytes)", len(data))
	}
	typ, headerSize, size, err := arsc.ReadChunkHeader(data, 0)
	if err != nil {
		return nil, fmt.Errorf("nsc: %w", err)
	}
	if typ != arsc.ChunkTypeXML {
		return nil, fmt.Errorf("nsc: not a binary XML document (chunk type 0x%04X, want 0x%04X)", typ, arsc.ChunkTypeXML)
	}
	end := size
	if end > uint32(len(data)) {
		end = uint32(len(data))
	}

	var pool []string
	var configs []*Config // pointers: appended into as they're discovered, mutated in place while open

	// One stack of frames, exactly one push per start-element and one pop
	// per end-element regardless of element name — a single, always-
	// balanced stack, rather than two parallel stacks that need to agree
	// on when each pushes, which is easy to get subtly out of sync (an
	// earlier draft of this function did).
	type frame struct {
		name string
		cfg  *Config // nearest enclosing domain-config/base-config, or nil
	}
	var stack []frame
	var pendingDomain *Domain // set while inside <domain>, attached to the enclosing config on </domain>

	offset := headerSize
	for i := 0; i < maxChunks && offset < end; i++ {
		ctyp, cheaderSize, csize, err := arsc.ReadChunkHeader(data, offset)
		if err != nil {
			return nil, fmt.Errorf("nsc: reading chunk at offset %d: %w", offset, err)
		}
		if csize == 0 {
			return nil, fmt.Errorf("nsc: zero-size chunk at offset %d", offset)
		}

		switch ctyp {
		case uint32(arsc.ChunkTypeStrPool):
			strs, err := arsc.ParseStringPool(data, offset, cheaderSize, csize)
			if err != nil {
				return nil, fmt.Errorf("nsc: %w", err)
			}
			pool = make([]string, len(strs))
			for _, s := range strs {
				pool[s.Index] = s.Value
			}

		case chunkStartElement:
			name, attrs, err := readStartElement(data, offset, cheaderSize, pool)
			if err != nil {
				return nil, fmt.Errorf("nsc: start element at offset %d: %w", offset, err)
			}

			cfg := (*Config)(nil)
			if len(stack) > 0 {
				cfg = stack[len(stack)-1].cfg // inherit enclosing config by default
			}
			switch name {
			case string(KindDomainConfig), string(KindBaseConfig):
				newCfg := &Config{Kind: ConfigKind(name)}
				if v, ok := attrs["cleartextTrafficPermitted"]; ok {
					newCfg.CleartextPermitted = tristateFromAttr(v)
				}
				configs = append(configs, newCfg)
				cfg = newCfg
			case "domain":
				d := Domain{}
				if v, ok := attrs["includeSubdomains"]; ok {
					d.IncludeSubdomains = v == "true"
				}
				pendingDomain = &d
			}
			stack = append(stack, frame{name: name, cfg: cfg})

		case chunkEndElement:
			name, err := readEndElement(data, offset, cheaderSize, pool)
			if err != nil {
				return nil, fmt.Errorf("nsc: end element at offset %d: %w", offset, err)
			}
			if len(stack) > 0 && stack[len(stack)-1].name == name {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if name == "domain" && pendingDomain != nil {
					if top.cfg != nil {
						top.cfg.Domains = append(top.cfg.Domains, *pendingDomain)
					}
					pendingDomain = nil
				}
			}

		case chunkCData:
			text, err := readCData(data, offset, cheaderSize, pool)
			if err != nil {
				return nil, fmt.Errorf("nsc: cdata at offset %d: %w", offset, err)
			}
			if pendingDomain != nil {
				pendingDomain.Name = text
			}

		default:
			// RES_XML_START_NAMESPACE_TYPE / END_NAMESPACE_TYPE /
			// RES_XML_RESOURCE_MAP_TYPE, or anything else: irrelevant to
			// domain-config/base-config extraction, skip by size.
		}

		offset += csize
	}

	out := make([]Config, len(configs))
	for i, c := range configs {
		out[i] = *c
	}
	return out, nil
}

func tristateFromAttr(v string) manifest.Tristate {
	switch v {
	case "true":
		return manifest.True
	case "false":
		return manifest.False
	default:
		return manifest.Unset
	}
}

// readStartElement reads a RES_XML_START_ELEMENT_TYPE chunk: the element
// name and its attributes (name -> normalized string value), resolving
// resource-string refs via pool and typed boolean/int values the same
// way androidbinary's own (CDATA-blind) reader does for attributes.
func readStartElement(data []byte, chunkOff, headerSize uint32, pool []string) (string, map[string]string, error) {
	extOff := chunkOff + headerSize
	const extSize = 20 // NS(4)+Name(4)+AttributeStart(2)+AttributeSize(2)+AttributeCount(2)+IDIndex(2)+ClassIndex(2)+StyleIndex(2)
	if uint64(extOff)+extSize > uint64(len(data)) {
		return "", nil, fmt.Errorf("attrExt out of bounds")
	}
	var ext androidbinary.ResXMLTreeAttrExt
	ext.NS = androidbinary.ResStringPoolRef(binary.LittleEndian.Uint32(data[extOff:]))
	ext.Name = androidbinary.ResStringPoolRef(binary.LittleEndian.Uint32(data[extOff+4:]))
	ext.AttributeStart = binary.LittleEndian.Uint16(data[extOff+8:])
	ext.AttributeSize = binary.LittleEndian.Uint16(data[extOff+10:])
	ext.AttributeCount = binary.LittleEndian.Uint16(data[extOff+12:])

	name, err := poolString(pool, uint32(ext.Name))
	if err != nil {
		return "", nil, err
	}

	attrs := make(map[string]string, ext.AttributeCount)
	attrOff := uint64(extOff) + uint64(ext.AttributeStart)
	for i := 0; i < int(ext.AttributeCount); i++ {
		recOff := attrOff + uint64(i)*uint64(ext.AttributeSize)
		if recOff+20 > uint64(len(data)) {
			return "", nil, fmt.Errorf("attribute %d out of bounds", i)
		}
		attrNameRef := binary.LittleEndian.Uint32(data[recOff+4:])
		rawValueRef := binary.LittleEndian.Uint32(data[recOff+8:])
		typedSize := binary.LittleEndian.Uint16(data[recOff+12:])
		_ = typedSize
		dataType := data[recOff+15]
		typedData := binary.LittleEndian.Uint32(data[recOff+16:])

		attrName, err := poolString(pool, attrNameRef)
		if err != nil {
			continue // unresolvable attribute name isn't fatal to the whole element
		}

		var value string
		if rawValueRef != nilStringRef {
			value, err = poolString(pool, rawValueRef)
			if err != nil {
				continue
			}
		} else {
			switch androidbinary.DataType(dataType) {
			case androidbinary.TypeNull:
				value = ""
			case androidbinary.TypeIntBoolean:
				if typedData != 0 {
					value = "true"
				} else {
					value = "false"
				}
			default:
				value = fmt.Sprintf("0x%08X", typedData)
			}
		}
		attrs[attrName] = value
	}

	return name, attrs, nil
}

func readEndElement(data []byte, chunkOff, headerSize uint32, pool []string) (string, error) {
	extOff := chunkOff + headerSize
	if uint64(extOff)+8 > uint64(len(data)) {
		return "", fmt.Errorf("endElementExt out of bounds")
	}
	nameRef := binary.LittleEndian.Uint32(data[extOff+4:])
	return poolString(pool, nameRef)
}

func readCData(data []byte, chunkOff, headerSize uint32, pool []string) (string, error) {
	extOff := chunkOff + headerSize
	if uint64(extOff)+4 > uint64(len(data)) {
		return "", fmt.Errorf("cdataExt out of bounds")
	}
	dataRef := binary.LittleEndian.Uint32(data[extOff:])
	return poolString(pool, dataRef)
}

func poolString(pool []string, ref uint32) (string, error) {
	if ref == nilStringRef {
		return "", nil
	}
	if int(ref) >= len(pool) {
		return "", fmt.Errorf("string pool ref %d out of range (pool size %d)", ref, len(pool))
	}
	return pool[ref], nil
}
