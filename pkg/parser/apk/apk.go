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
type Container struct {
	Manifest      []byte // AndroidManifest.xml, may be nil if absent
	ResourcesArsc []byte // resources.arsc, may be nil if absent
	DexFiles      []DexEntry
	AssetFiles    []AssetEntry // everything under the top-level assets/ directory
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
// entries from the APK at path.
func Open(path string) (*Container, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("apk: open zip: %w", err)
	}
	defer r.Close()
	return read(&r.Reader)
}

func read(zr *zip.Reader) (*Container, error) {
	c := &Container{}
	var totalRead int64

	var dexNames []string
	dexData := map[string][]byte{}

	for _, f := range zr.File {
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
func dexSortKey(name string) int {
	if name == "classes.dex" {
		return 1
	}
	var n int
	fmt.Sscanf(name, "classes%d.dex", &n)
	return n
}

func extract(f *zip.File, totalRead *int64) ([]byte, error) {
	if int64(f.UncompressedSize64) > MaxSingleEntryBytes {
		return nil, fmt.Errorf("entry %s exceeds max single-entry size (%d > %d)", f.Name, f.UncompressedSize64, MaxSingleEntryBytes)
	}
	if *totalRead+int64(f.UncompressedSize64) > MaxUncompressedTotalBytes {
		return nil, fmt.Errorf("extracting %s would exceed total uncompressed budget (%d bytes)", f.Name, MaxUncompressedTotalBytes)
	}

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

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

	*totalRead += int64(len(data))
	return data, nil
}
