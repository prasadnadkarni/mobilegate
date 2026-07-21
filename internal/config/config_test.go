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

func TestLoadFile_ParsesFirstPartyPackages(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mobilegate.yml")
	content := "policy:\n  first_party_packages:\n    - com.owncloud.android\n    - com.example.legacy\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := []string{"com.owncloud.android", "com.example.legacy"}
	if len(c.Policy.FirstPartyPackages) != len(want) {
		t.Fatalf("got %v, want %v", c.Policy.FirstPartyPackages, want)
	}
	for i, p := range want {
		if c.Policy.FirstPartyPackages[i] != p {
			t.Errorf("packages[%d] = %q, want %q", i, c.Policy.FirstPartyPackages[i], p)
		}
	}
}

func TestLoadFile_ParsesSourceManifestPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mobilegate.yml")
	content := "policy:\n  source_manifest_path: mobile/src/main/AndroidManifest.xml\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if c.Policy.SourceManifestPath != "mobile/src/main/AndroidManifest.xml" {
		t.Errorf("SourceManifestPath = %q, want %q", c.Policy.SourceManifestPath, "mobile/src/main/AndroidManifest.xml")
	}
}

func TestLoadFile_UnsetSourceManifestPathIsEmpty(t *testing.T) {
	c, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if c.Policy.SourceManifestPath != "" {
		t.Errorf("SourceManifestPath = %q, want empty (caller applies its own default)", c.Policy.SourceManifestPath)
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

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".mobilegate.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFile_ParsesModeAndBaselineFile(t *testing.T) {
	path := writeConfig(t, "policy:\n  mode: baseline\n  baseline_file: custom-baseline.yml\n")
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if c.Policy.Mode != ModeBaseline {
		t.Errorf("Mode = %q, want %q", c.Policy.Mode, ModeBaseline)
	}
	if c.Policy.BaselineFile != "custom-baseline.yml" {
		t.Errorf("BaselineFile = %q, want %q", c.Policy.BaselineFile, "custom-baseline.yml")
	}
}

func TestLoadFile_UnsetModeIsNotAnError(t *testing.T) {
	path := writeConfig(t, "policy:\n  first_party_domains: [example.com]\n")
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if c.Policy.Mode != "" {
		t.Errorf("Mode = %q, want empty (caller defaults to strict)", c.Policy.Mode)
	}
}

func TestLoadFile_RejectsInvalidMode(t *testing.T) {
	path := writeConfig(t, "policy:\n  mode: yolo\n")
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error for an invalid policy.mode value, got nil")
	}
}

func TestLoadFile_ParsesIgnoreRulesWithReason(t *testing.T) {
	path := writeConfig(t, `ignore_rules:
  - id: "MG-007"
    reason: "Background location required for core delivery-tracking feature."
    paths: ["AndroidManifest.xml"]
`)
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(c.IgnoreRules) != 1 {
		t.Fatalf("got %d ignore_rules, want 1", len(c.IgnoreRules))
	}
	r := c.IgnoreRules[0]
	if r.ID != "MG-007" || r.Reason == "" || len(r.Paths) != 1 || r.Paths[0] != "AndroidManifest.xml" {
		t.Errorf("unexpected ignore rule: %+v", r)
	}
}

// This is the spec's explicit acceptance requirement: "Suppression
// without a reason is a config validation error." Not a warning, not a
// skipped entry — the whole load fails.
func TestLoadFile_RejectsIgnoreRuleMissingReason(t *testing.T) {
	path := writeConfig(t, `ignore_rules:
  - id: "MG-007"
    paths: ["AndroidManifest.xml"]
`)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error for an ignore_rules entry with no reason, got nil")
	}
}

func TestLoadFile_RejectsIgnoreRuleWithBlankReason(t *testing.T) {
	path := writeConfig(t, `ignore_rules:
  - id: "MG-007"
    reason: "   "
`)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error for an ignore_rules entry with a whitespace-only reason, got nil")
	}
}

func TestLoadFile_RejectsIgnoreRuleMissingID(t *testing.T) {
	path := writeConfig(t, `ignore_rules:
  - reason: "some reason"
`)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error for an ignore_rules entry with no id, got nil")
	}
}

// One bad entry invalidates the WHOLE file, not just itself — a config
// validation error must not let the rest of a broken file quietly load.
func TestLoadFile_OneBadIgnoreRuleFailsWholeConfig(t *testing.T) {
	path := writeConfig(t, `policy:
  first_party_domains: [example.com]
ignore_rules:
  - id: "MG-005"
    reason: "reviewed and accepted"
  - id: "MG-007"
`)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected the whole config load to fail when any ignore_rules entry is invalid")
	}
}
