package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_MissingFileIsEmptyNotError(t *testing.T) {
	c, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(c.Policy.FirstPartyDomains) != 0 {
		t.Errorf("expected no first-party domains, got %v", c.Policy.FirstPartyDomains)
	}
}

func TestLoadFile_ParsesFirstPartyDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mobilegate.yml")
	content := "policy:\n  first_party_domains:\n    - example.com\n    - api.example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := []string{"example.com", "api.example.com"}
	if len(c.Policy.FirstPartyDomains) != len(want) {
		t.Fatalf("got %v, want %v", c.Policy.FirstPartyDomains, want)
	}
	for i, d := range want {
		if c.Policy.FirstPartyDomains[i] != d {
			t.Errorf("domains[%d] = %q, want %q", i, c.Policy.FirstPartyDomains[i], d)
		}
	}
}

func TestLoadFile_RejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mobilegate.yml")
	if err := os.WriteFile(path, []byte("policy: [this is not a map"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}
