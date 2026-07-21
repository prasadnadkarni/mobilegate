// Package apk opens an APK's zip container and extracts the files the rest
// of the parser needs: AndroidManifest.xml, resources.arsc, the DEX files,
// and the assets/ directory. It does not interpret their contents.
package apk

import (
	"archive/zip"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// MaxUncompressedTotalBytes bounds the total bytes read out of the zip
// across all extracted entries, guarding against decompression-bomb APKs
// (a small zip that expands to gigabytes on inflate).
const MaxUncompressedTotalBytes int64 = 512 * 1024 * 1024

// MaxSingleEntryBytes bounds any one extracted entry.
const MaxSingleEntryBytes int64 = 256 * 1024 * 1024

var classesDexPattern = regexp.MustCompile(`^classes[0-9]*\.dex$`)

// Container holds the raw bytes of the files needed from an APK.
// DexFiles is ordered: classes.dex first, then classes2.dex, classes3.dex, …
//
// A Container returned by Open holds the underlying zip file open for
// ReadFile's on-demand lookups (see below) — call Close when done with
// it. A Container built in-process from an in-memory zip.Reader (as the
// test suites do) needs no such cleanup; Close is a no-op for those.
type Container struct {
	Manifest      []byte // AndroidManifest.xml, may be nil if absent
	ResourcesArsc []byte // resources.arsc, may be nil if absent
	DexFiles      []DexEntry
	AssetFiles    []AssetEntry // everything under the top-level assets/ directory

	zr    *zip.ReadCloser
	files map[string]*zip.File // every entry, for ReadFile's on-demand lookups
}

// DexEntry is one classes*.dex file extracted from the APK.
type DexEntry struct {
	Name string // e.g. "classes.dex", "classes2.dex"
	Data []byte
}

// AssetEntry is one file under the APK's assets/ directory — arbitrary
// bundled files (config JSON, certs, etc.), distinct from compiled res/
// resources. Name is the full in-APK path, e.g. "assets/config.json".
type AssetEntry struct {
	Name string
	Data []byte
}

// Open extracts AndroidManifest.xml, resources.arsc, and all classes*.dex
// entries from the APK at path. The returned Container holds the file
// open for ReadFile; call Close when done with it.
func Open(path string) (*Container, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("apk: open zip: %w", err)
	}
	c, err := read(&r.Reader)
	if err != nil {
		_ = r.Close() // best-effort cleanup on the error path; the read error above is what's returned
		return nil, err
	}
	c.zr = r
	return c, nil
}

// Close releases the underlying zip file, if Open opened one. Safe to
// call on a Container built in-process (a no-op in that case).
func (c *Container) Close() error {
	if c.zr != nil {
		return c.zr.Close()
	}
	return nil
}

// ReadFile fetches an arbitrary entry by its exact in-APK path, subject
// to the same per-entry size cap as the entries extracted eagerly by
// Open. For paths resolved from a resources.arsc file-based resource —
// e.g. AndroidManifest.xml's android:networkSecurityConfig attribute,
// which resolves to something like "res/xml/network_security_config.xml"
// or, under resource shrinking, an arbitrary short name with no
// recognizable pattern — since that resolved path can be anything, this
// is a genuine lookup, not a pre-filtered category like AssetFiles.
// Returns found=false, not an error, if no such entry exists.
func (c *Container) ReadFile(name string) (data []byte, found bool, err error) {
	f, ok := c.files[name]
	if !ok {
		return nil, false, nil
	}
	var budget uint64 // fresh per-call budget; this is an on-demand single-file fetch, not part of Open's eager-extraction total
	data, err = extract(f, &budget)
	if err != nil {
		return nil, true, err
	}
	return data, true, nil
}

func read(zr *zip.Reader) (*Container, error) {
	c := &Container{files: make(map[string]*zip.File, len(zr.File))}
	var totalRead uint64

	var dexNames []string
	dexData := map[string][]byte{}

	for _, f := range zr.File {
		c.files[f.Name] = f
		switch {
		case f.Name == "AndroidManifest.xml":
			data, err := extract(f, &totalRead)
			if err != nil {
				return nil, fmt.Errorf("apk: extract AndroidManifest.xml: %w", err)
			}
			c.Manifest = data
		case f.Name == "resources.arsc":
			data, err := extract(f, &totalRead)
			if err != nil {
				return nil, fmt.Errorf("apk: extract resources.arsc: %w", err)
			}
			c.ResourcesArsc = data
		case classesDexPattern.MatchString(f.Name):
			data, err := extract(f, &totalRead)
			if err != nil {
				return nil, fmt.Errorf("apk: extract %s: %w", f.Name, err)
			}
			dexNames = append(dexNames, f.Name)
			dexData[f.Name] = data
		case strings.HasPrefix(f.Name, "assets/") && !strings.HasSuffix(f.Name, "/"):
			data, err := extract(f, &totalRead)
			if err != nil {
				return nil, fmt.Errorf("apk: extract %s: %w", f.Name, err)
			}
			c.AssetFiles = append(c.AssetFiles, AssetEntry{Name: f.Name, Data: data})
		}
	}

	if c.Manifest == nil {
		return nil, fmt.Errorf("apk: AndroidManifest.xml not found — not a valid APK")
	}

	sort.Slice(dexNames, func(i, j int) bool { return dexSortKey(dexNames[i]) < dexSortKey(dexNames[j]) })
	for _, name := range dexNames {
		c.DexFiles = append(c.DexFiles, DexEntry{Name: name, Data: dexData[name]})
	}

	sort.Slice(c.AssetFiles, func(i, j int) bool { return c.AssetFiles[i].Name < c.AssetFiles[j].Name })

	return c, nil
}

// dexSortKey orders "classes.dex" before "classes2.dex" before "classes10.dex".
// name is always pre-validated by classesDexPattern at the only call site
// (dexNames is only ever populated with matches), so the Sscanf below can
// never actually fail on the input it receives here.
func dexSortKey(name string) int {
	if name == "classes.dex" {
		return 1
	}
	var n int
	_, _ = fmt.Sscanf(name, "classes%d.dex", &n)
	return n
}

func extract(f *zip.File, totalRead *uint64) ([]byte, error) {
	// f.UncompressedSize64 is attacker-controlled zip metadata and is kept
	// in its native uint64 throughout both checks below (totalRead is
	// uint64 for the same reason) rather than ever narrowed to int64: a
	// value near uint64's max would wrap to a negative (or otherwise
	// wrong) int64 and could defeat a naively-converted comparison. The
	// budget check is subtraction-based rather than "*totalRead + size >
	// max" specifically to avoid summing a trusted-but-bounded value with
	// an untrusted, potentially-huge one — *totalRead never exceeds
	// MaxUncompressedTotalBytes (that's this same check's own invariant),
	// so the subtraction below can't underflow.
	if f.UncompressedSize64 > uint64(MaxSingleEntryBytes) {
		return nil, fmt.Errorf("entry %s exceeds max single-entry size (%d > %d)", f.Name, f.UncompressedSize64, MaxSingleEntryBytes)
	}
	if f.UncompressedSize64 > uint64(MaxUncompressedTotalBytes)-*totalRead {
		return nil, fmt.Errorf("extracting %s would exceed total uncompressed budget (%d bytes)", f.Name, MaxUncompressedTotalBytes)
	}

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	// Close() here can't mask a checksum-mismatch bug: archive/zip surfaces
	// ErrChecksum from Read() itself at EOF, not from Close() — verified
	// against the stdlib source, not assumed.
	defer func() { _ = rc.Close() }()

	// LimitReader as a second guard: UncompressedSize64 is attacker-controlled
	// zip metadata and is not guaranteed to match what actually inflates.
	limited := io.LimitReader(rc, MaxSingleEntryBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxSingleEntryBytes {
		return nil, fmt.Errorf("entry %s inflated past max single-entry size", f.Name)
	}

	*totalRead += uint64(len(data))
	return data, nil
}
