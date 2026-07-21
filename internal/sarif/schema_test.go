package sarif_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/prasadnadkarni/mobilegate/internal/core"
	"github.com/prasadnadkarni/mobilegate/internal/sarif"
)

// schemaJSON is the official SARIF 2.1.0 JSON Schema, vendored at
// testdata/sarif-schema-2.1.0.json (fetched from
// github.com/oasis-tcs/sarif-spec, the OASIS TC's own repo) rather than
// fetched at test time — this test must run offline, the same as every
// other test in this module (only tools/oracle's *_test.go files shell
// out to external tooling, and only under an explicit build tag). If
// the vendored copy ever needs updating, re-fetch from
// raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json.
//
//go:embed testdata/sarif-schema-2.1.0.json
var schemaJSON []byte

// TestBuild_ValidatesAgainstSARIFSchema is the acceptance test CLAUDE.md
// implicitly demands for anything claiming spec compliance: don't
// eyeball it, validate it. Builds a representative log — multiple
// rules, both artifactLocation cases (manifest-mapped and
// APK-mapped), a critical-severity provider finding — and asserts the
// marshaled JSON validates against the real SARIF 2.1.0 schema, not
// just "this package's own Go structs looked right."
func TestBuild_ValidatesAgainstSARIFSchema(t *testing.T) {
	log, err := sarif.Build(representativeInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		t.Fatalf("unmarshal vendored schema: %v", err)
	}
	if err := compiler.AddResource("sarif-schema-2.1.0.json", schemaDoc); err != nil {
		t.Fatalf("AddResource: %v", err)
	}
	schema, err := compiler.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal built SARIF output: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("Build output does not validate against SARIF 2.1.0 schema:\n%v\n\nfull output:\n%s", err, raw)
	}
}

// TestBuild_ValidatesWithZeroFindings — a clean APK (zero findings) is
// the most common real case, and is exactly the shape most likely to
// leave an empty-array vs. omitted-field bug unnoticed if only the
// "lots of findings" case is schema-tested.
func TestBuild_ValidatesWithZeroFindings(t *testing.T) {
	in := representativeInput()
	in.Findings = nil
	log, err := sarif.Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		t.Fatalf("unmarshal vendored schema: %v", err)
	}
	if err := compiler.AddResource("sarif-schema-2.1.0.json", schemaDoc); err != nil {
		t.Fatalf("AddResource: %v", err)
	}
	schema, err := compiler.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal built SARIF output: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("zero-findings Build output does not validate:\n%v\n\nfull output:\n%s", err, raw)
	}
}

func representativeInput() sarif.BuildInput {
	line := 42
	return sarif.BuildInput{
		ToolVersion:  "v0.2.0",
		RepoURI:      "https://github.com/prasadnadkarni/mobilegate",
		AutomationID: "mobilegate/com.example.app",
		Rules: []sarif.RuleInfo{
			{ID: "MG-001", Name: "Hardcoded production secret", Description: "desc", Remediation: "remediate", Severity: "critical", MASVS: "MASVS-STORAGE-1", CWE: "CWE-798"},
			{ID: "MG-002", Name: "Cleartext transport", Description: "desc", Remediation: "remediate", Severity: "critical", MASVS: "MASVS-NETWORK-1", CWE: "CWE-319"},
			{ID: "MG-003", Name: "Backup exposure", Description: "desc", Remediation: "remediate", Severity: "high", MASVS: "MASVS-STORAGE-2", CWE: "CWE-530"},
			{ID: "MG-004", Name: "Exported component", Description: "desc", Remediation: "remediate", Severity: "high", MASVS: "MASVS-PLATFORM-1", CWE: "CWE-926"},
			{ID: "MG-010", Name: "Debug build artifact", Description: "desc", Remediation: "remediate", Severity: "critical", MASVS: "MASVS-RESILIENCE-2", CWE: "CWE-489"},
		},
		Findings: []core.Finding{
			{
				RuleID: "MG-001", RuleName: "Hardcoded production secret", PatternID: "aws-access-key",
				Title: "Hardcoded AWS Access Key ID", Severity: "critical", Confidence: "high",
				MASVS: "MASVS-STORAGE-1", CWE: "CWE-798", Blocking: true,
				Source: "classes2.dex", Location: "string_ids[1042]", Line: &line,
				Excerpt: "AKIA[redacted]", SignalDetail: "matched AWS access key pattern",
				WhyItBlocks: "Anyone who downloads this APK can extract this key.",
				Remediation: "Rotate the key and remove it from the binary.",
				FindingHash: "sha256:aaaa",
			},
			{
				RuleID: "MG-004", RuleName: "Exported component", PatternID: "exported-explicit-no-permission-first-party",
				Title: "Exported provider reachable without a permission guard", Severity: "critical", Confidence: "high",
				MASVS: "MASVS-PLATFORM-1", CWE: "CWE-926", Blocking: false,
				Source: "AndroidManifest.xml", Location: "provider com.example.app.FileProvider",
				Excerpt: `android:exported="true" on <provider ...>`, SignalDetail: "unguarded exported provider",
				WhyItBlocks: "Any installed app can query this provider directly.",
				Remediation: "Add android:permission or set exported=false.",
				FindingHash: "sha256:bbbb",
			},
		},
		APKPath:            "/home/runner/work/build/outputs/apk/release/app-release.apk",
		SourceManifestPath: "app/src/main/AndroidManifest.xml",
	}
}
