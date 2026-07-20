package apk

import (
	"archive/zip"
	"bytes"
	"testing"
)

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zw.Create(%s): %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}
	return buf.Bytes()
}

func TestRead_ExtractsAssets(t *testing.T) {
	data := buildZip(t, map[string]string{
		"AndroidManifest.xml":   "manifest-placeholder",
		"classes.dex":           "dex-placeholder",
		"assets/config.json":    `{"key":"value"}`,
		"assets/sub/nested.txt": "nested content",
		"res/drawable/icon.png": "not-an-asset",
	})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}

	c, err := read(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(c.AssetFiles) != 2 {
		t.Fatalf("got %d asset files, want 2: %+v", len(c.AssetFiles), c.AssetFiles)
	}
	want := map[string]string{
		"assets/config.json":    `{"key":"value"}`,
		"assets/sub/nested.txt": "nested content",
	}
	for _, a := range c.AssetFiles {
		wantContent, ok := want[a.Name]
		if !ok {
			t.Errorf("unexpected asset file %s", a.Name)
			continue
		}
		if string(a.Data) != wantContent {
			t.Errorf("asset %s content = %q, want %q", a.Name, a.Data, wantContent)
		}
	}
}

func TestRead_IgnoresAssetDirectoryEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("AndroidManifest.xml"); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Create("assets/"); err != nil { // explicit directory entry, no content
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	c, err := read(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(c.AssetFiles) != 0 {
		t.Errorf("got %d asset files, want 0 (directory entry should be skipped): %+v", len(c.AssetFiles), c.AssetFiles)
	}
}
