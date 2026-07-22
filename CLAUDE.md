# MobileGate — project context

An Android APK release gate for CI/CD. Emits PASS or BLOCKED, not a findings report.

**This file and `DESIGN.md` are the authoritative description of the
project — read them before doing any work here.**
`./mobile-security-release-gate-build-prompt-v2.1.md` is the original
pre-implementation spec, kept unmodified as historical context (it now
carries its own header explaining exactly where it and reality
diverged) — not current instructions, and not a substitute for this
file or `DESIGN.md`.

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

- APK container → stdlib `archive/zip`.
- Binary AndroidManifest.xml structural fields (`exported`, `permission`, `allowBackup`, intent-filter actions/categories, etc.) → `pkg/parser/manifest`, a thin wrapper over the maintained `github.com/shogo82148/androidbinary` library's own XML-decode engine, with custom Go struct tags selecting which fields to pull out. This is the one case that actually looks like the original "maintained library, thin wrapper" plan.
- `resources.arsc` / `AndroidManifest.xml` string-pool enumeration → `pkg/parser/arsc`, hand-rolled. `androidbinary`'s `TableFile` has no public way to enumerate the string pool at all — confirmed via `go doc` before writing any custom code, not assumed. MG-001's secret-scanning signal needs every string in the pool, not just resolved attribute values, which the library doesn't expose.
- `network_security_config.xml` → `pkg/parser/nsc`, hand-rolled. `androidbinary`'s `XMLFile` silently drops CDATA text (`RES_XML_CDATA_TYPE` is declared but never handled in its chunk-type switch) — confirmed empirically (decoding a real config through it dropped the actual domain name, not just inferred from reading the source) before writing a replacement.
- DEX string extraction → `pkg/parser/dex`, hand-rolled: header → `string_ids` → MUTF-8 table, plus enough class/method/field structure to attribute a string to its declaring type. No decompilation to Smali. Do not let this grow into a decompiler.

**The standard for writing a custom parser instead of using a library: a demonstrated, verified gap in the maintained library, plus an oracle once it's written** — not "the library looked complicated" or "our own would be cleaner." Verify the gap with `go doc` and/or a real decoded APK before writing any replacement code, the way `pkg/parser/arsc` and `pkg/parser/nsc`'s own package doc comments record. See "Constraints established since initial build" below for the oracle requirement.

## Definition of done for any rule

Positive fixture detects it **AND** every negative fixture stays clean. Both, or it ships as a warning instead of a blocker.

## Current state (as of v0.4.3)

The build-order plan this file used to carry is finished. This section
describes what actually exists, so a new session extends it correctly
instead of re-deriving or re-litigating decisions already made.

**Five rules, wired into the CLI:**

- **MG-001** (hardcoded secrets) — blocking.
- **MG-002** (cleartext/accept-all transport) — blocking.
- **MG-003** (plaintext sensitive storage / backup exposure) — blocking (one signal is warning-tier; see `rules/MG-003-plaintext-storage.yaml`).
- **MG-004** (exported Android component without permission protection) — **warning-tier**. It passed its own negative-fixture suite with zero false positives — the same technical bar every blocking rule clears — and was deliberately NOT promoted anyway: a 12-app real corpus found every app firing, and a follow-up investigation into the narrowest defensible blocking subset (first-party service/provider findings only) still narrowed to roughly 3-5 real findings concentrated in a single app. **This is a settled decision, not an outstanding to-do.** Full reasoning is in `DESIGN.md`'s "MG-004: why it isn't blocking" and in `rules/MG-004-exported-component.yaml`'s own header. Do not read the warning-tier status as unfinished work, and do not promote it on the reasoning "it passed the fixture suite so it should be blocking" — that reasoning was already considered and rejected. Revisiting it needs a genuinely new input (e.g. a materially wider corpus with different results), not a re-read of the same 12 apps.
- **MG-010** (debug/test build artifact) — blocking.

`MG-005` through `MG-009` are the spec's remaining catalog entries —
considered and deliberately deferred, not unbuilt oversights. See
`DESIGN.md`'s "Rules considered and not built" for the specific reason
each one was scoped out.

**Also shipped, end to end:**

- **Baseline mode** (`-baseline`, `mobilegate baseline -write`) — grandfathers pre-existing findings, blocks only on regressions.
- **SARIF 2.1.0 output** (`-sarif`) — see "Constraints established since initial build" below for what it deliberately does and doesn't do.
- **GitHub Action** (`action.yml`) — composite action: downloads a pinned, checksum-verified release binary, posts/updates a PR comment, optional SARIF upload.
- **Four distribution paths**: Homebrew tap (`prasadnadkarni/tap/mobilegate`), Docker (`ghcr.io/prasadnadkarni/mobilegate`, multi-arch amd64/arm64), goreleaser release binaries (what the Action fetches), and `go install` (works, but unversioned — documented as such, not a full parity path).
- **`.mobilegate.yml` policy config** — mode (strict/baseline), baseline file path, first-party domain/package allowlists, rule suppression with mandatory reasons.
- **`golangci-lint` in CI** (the default five linters plus `gosec`, pinned version) and **parser oracles** for manifest/DEX/ARSC/NSC — see the constraint below.

## Constraints established since initial build

These weren't known or decided when the rest of this file was written.
Treat them as binding, same as "Hard constraints" above.

- **SARIF omits suppressed/baselined findings instead of emitting `results[].suppressions`.** Confirmed against GitHub's own docs (and a May 2025 GitHub-staff reply on a public discussion) that GitHub's SARIF ingestion does not honor `suppressions[]` — a suppressed finding uploaded there would show as a normal, active, open alert, not as suppressed. Emitting it anyway would ship something that looks like it works but silently doesn't. Suppressed/baselined findings stay fully visible, with their reason, in every OTHER output format (terminal, `-json`, `-markdown`) — this is SARIF-specific. See `DESIGN.md`'s SARIF section.
- **Every hand-rolled parser needs an oracle, or a documented reason it doesn't have one.** `pkg/parser/manifest`, `pkg/parser/dex`, `pkg/parser/arsc`, and `pkg/parser/nsc` each have a corresponding `tools/oracle/*_test.go` cross-checking against independent, from-scratch Android tooling (`aapt2`, `apkanalyzer`, `dexdump`) on a real APK, and each has been mutation-tested (a bug deliberately introduced, confirmed the oracle catches it with a precise diff, reverted). `pkg/parser/backuprules` is the one exception, and it's a documented one, not an oversight — verified via synthetic binary-XML unit tests plus manual cross-checking against `aapt2 dump xmltree` during development, noted explicitly in `DESIGN.md` rather than left to look covered. A new hand-rolled parser with neither an oracle nor an equivalent documented reason is not done.
- **`release.yml` gates on doc version pins matching the tag being released.** Every `prasadnadkarni/mobilegate@vX.Y.Z` reference in `README.md`/`CONTRIBUTING.md` is hand-written prose, not generated from the tag — a stale one slipped through three times before this was automated. The release now fails outright, before goreleaser runs anything, if any reference doesn't match the tag just pushed. See `CONTRIBUTING.md`'s "Cutting a release."

## Scope discipline

If a change isn't part of what you're actually doing, don't make it — ask first. Common drift to resist: adding iOS scaffolding, promoting MG-004 to blocking without a genuinely new reason (see "Current state" above — this was already investigated and settled), adding config options not reflected in `.mobilegate.yml`'s documented schema, building a web dashboard.
