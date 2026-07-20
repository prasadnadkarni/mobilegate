# MobileGate — project context

An Android APK release gate for CI/CD. Emits PASS or BLOCKED, not a findings report.

**Full spec: `./mobile-security-release-gate-build-prompt-v2.1.md` — read it before doing any work in this repo.**

## Product thesis (do not drift from this)

The promise is precision, not coverage. A clean APK must produce zero blocking findings. A blocking rule that fires on a clean app is a worse failure than one that misses a real issue: the first gets the tool disabled, the second is caught by the human review that still exists alongside this gate.

This is not a MobSF clone. MobSF says "here are 150 findings." This says "your release is blocked because these 3 controls failed."

## Hard constraints (never violate)

- **Go only.** Single static binary. No runtime dependency on the CI runner.
- **No shelling out** to apktool, jadx, androguard, dex2jar, or anything JVM-based. If a runner needs Java, adoption dies.
- **No LLM in the detection or gate-decision path.** Deterministic rules only. LLM use is permitted *only* for writing the human-readable remediation text of a finding a deterministic rule already confirmed.
- **Android APK only.** iOS is v2. Do not implement it, do not scaffold for it, do not build abstractions "so iOS slots in later."
- **`finding_hash` excludes line numbers.** Compute from rule id + file path + normalized match value. Line numbers shift on unrelated code changes and produce phantom regressions that break baseline mode.
- **A rule may NOT enter the blocking tier** until it passes the full negative-fixture suite with zero false positives.
- **Test fixtures are synthetic and self-authored.** Never use real client APKs, real client findings, or any data from a prior security engagement. Not even anonymized.
- **Verify every third-party library on pkg.go.dev** before depending on it — that it exists, is maintained, and parses what's needed. The DEX space in particular has misleadingly named packages.

## Parser strategy

The parser is an implementation detail, not the moat. The moat is the rules, evidence model, and confidence engine. Do not reimplement apktool.

- APK container → stdlib `archive/zip`
- Binary AndroidManifest.xml + resources.arsc → maintained library, thin wrapper
- DEX string extraction → minimal custom parser (~150 LOC): read header, seek `string_ids`, read MUTF-8 string table. No decompilation to Smali. Do not let this grow into a decompiler.

## Definition of done for any rule

Positive fixture detects it **AND** every negative fixture stays clean. Both, or it ships as a warning instead of a blocker.

## Build order — do not skip ahead

1. Parser: unzip + manifest parse + DEX string extractor, verified against a real APK
2. MG-001 (secrets) with multi-signal evidence + exclusion zones
3. Scoring + gate decision + finding_hash + JSON/terminal output
4. Negative-fixture suite green — this is the acceptance gate
5. Baseline mode + PR-comment Markdown formatter
6. Only then: promote MG-004 if it passes negatives, add warning-tier rules

Finish and test each step before starting the next. Do not write MG-001, MG-002, and MG-003 in one pass before any of them has fixtures.

## Scope discipline

If a change isn't in the current build-order step, don't make it. Ask first. Common drift to resist: adding iOS scaffolding, adding a fourth blocking rule, adding config options not in the spec, building a web dashboard.
