# Build Prompt: Mobile App Security Release Gate — v2.1 (Android-only MVP)

Paste this into Claude Code as the initial spec. This is the final spec before implementation — do not keep refining it, build it. Scope is deliberately narrow and the precision bar is deliberately high. Do not re-expand scope.

The open questions left are empirical, not editorial: whether real mobile teams trust the red/green decision in their own CI. You answer those with a running binary, not more spec revisions.

---

## Role

You are building a CLI tool + CI/CD integration that acts as a **release gate** for Android APKs. It is not a general-purpose scanner and not a report generator. When a build runs through it, engineering gets a single answer — **PASS** or **BLOCKED** — plus the specific controls that failed, in under 90 seconds, with near-zero false positives on the blocking checks.

The product promise is precision, not coverage. A clean APK must produce zero blocking findings. That property is the product. A blocking rule that fires on a clean app is a worse failure than a blocking rule that misses a real issue, because the first one gets the tool disabled and the second one is caught by the human review that still exists alongside this gate.

## Product framing (do not deviate)

This is explicitly **not** a MobSF clone. MobSF says "here are 150 findings." This tool says "your release is blocked because these 3 controls failed." That difference is the entire value proposition.

1. **Gate decision is the primary output.** `BLOCKED` / `PASS`, followed by the list of failed controls. Designed to fail a CI pipeline and post a PR status, not to be read start-to-finish by a human.
2. **A tiny, high-precision blocking ruleset.** Three blocking rules in v1. Everything else is a warning until it proves near-100% precision on real samples.
3. **Near-zero false positives on blocking checks is a formal acceptance gate, not an aspiration.** No rule enters the blocking tier until it passes the negative-fixture suite (see Test Strategy).

## Target buyer (ICP — build for this user, not "all mobile devs")

Regulated orgs shipping Android apps on a weekly/monthly cadence that already have an AppSec function but lack scalable mobile review: banking, healthcare, insurance, fintech, enterprise SaaS with a mobile app. A startup shipping a hobby app does not care. A bank shipping a mobile banking APK cannot ship without knowing this is green. Every design tradeoff resolves in favor of that second user.

## Scope — v1 is Android APK only

iOS is out of scope for v1. It is not "later in the same sprint," it is a separate version. Do not add iOS parsing, do not add iOS rules, do not design abstractions "so iOS slots in later." Designing for parity before Android is reliable is the failure mode to avoid. iOS notes live in the v2 appendix at the end of this doc and nowhere else in the executable code.

No dynamic/runtime analysis in v1 (no Frida, no emulator, no traffic capture). Pure static analysis on the APK so it runs in CI with no device.

## Tech stack — pure Go, zero external process dependencies

**Language: Go.** Non-negotiable. Single static binary, no runtime to install on the CI runner, fast startup, easy concurrency for parallel rule evaluation. This is what lets you hit 90 seconds and get adopted in locked-down enterprise CI.

**No shelling out to external CLI tools. This is a hard constraint.** Do NOT invoke `apktool`, `androguard`, `jadx`, `dex2jar`, or anything JVM-based. If a runner has to install Java to run this gate, adoption dies and the 90-second budget is blown. Everything is parsed in-process.

**The parser is not your moat — the rules, evidence model, and confidence engine are.** Do not reimplement apktool. Use a maintained library where one exists and is solid; write minimal custom code only where the library ecosystem is weak. The split:

- **APK container:** standard library `archive/zip`. No dependency needed.
- **Binary `AndroidManifest.xml` + `resources.arsc`:** use a maintained pure-Go library (e.g. `github.com/appflight/apkparser` — verify it before committing, see below). Binary XML and ARSC are fiddly formats and MG-002/MG-004 both depend on reading the manifest reliably, so do not hand-roll this. Reuse proven code.
- **DEX string extraction:** write a minimal custom parser here. This is the one place where the Go library ecosystem is thin and mostly abandoned, and the format is stable and simple enough that custom code is safer than an unmaintained dependency. You do NOT need decompilation to Smali. You need the string pool: read the DEX header, seek to the `string_ids` offset, read the MUTF-8 string table, and keep enough class/method structure to attribute a finding. This is roughly 150 lines of Go, not a decompiler project. Do not let it grow into one.

**Library verification (implementation note):** before depending on any third-party Go library, confirm on pkg.go.dev that it exists, is maintained, and parses what you need. The DEX space in particular is full of misleadingly named packages (several "dexparser" libraries are Solana trading parsers, not Android DEX). Verify, don't trust the name.

**Secret detection patterns:** reuse proven pattern sets (e.g. the rule sets behind gitleaks / trufflehog) and document their provenance in the repo. Do not hand-roll credential regexes from scratch when vetted sets exist.

**No LLM in the blocking-check path.** Detection that gates a release is 100% deterministic. An LLM that hallucinates a hardcoded secret, or misses a real one, destroys trust on day one. The only permitted LLM use is generating the human-readable *remediation explanation* for a finding that a deterministic rule has already confirmed — never detection, never the gate decision.

## Blocking rules — three release-blocking gates in v1

Framing note: these are three release-blocking *gates*, each a category with real depth underneath, not "three checks." MG-001 covers cloud keys, provider PATs, private keys, and OAuth tokens; MG-002 covers cleartext config, accept-all trust managers, and hostname-verifier bypass; MG-003 covers world-readable modes and unencrypted external storage. Present it externally as three security gates with depth, never as "only three things," so it doesn't read as thin to a security buyer.

Every blocking rule must satisfy **multi-signal evidence**: a single weak signal never blocks. Each rule below specifies the signals required.

### MG-001 — Hardcoded production secret
Block when a credential is found in the APK (string pool, resources, assets, manifest) AND it clears the multi-signal bar:
- Signal 1: matches a known credential pattern (AWS, GCP/Firebase `AIza…`, Stripe `sk_live`, GitHub PAT `ghp_`/`github_pat_`, Slack, private key headers, etc.).
- Signal 2 (length-gated entropy): compute Shannon entropy ONLY for long unstructured candidates (length > ~16 chars). For structurally distinctive patterns (`AIzaSy…`, `sk_live_…`, `ghp_…`), the prefix regex plus exclusion-zone check IS the signal — skip entropy math entirely, because entropy on a short structured key is noise and produces erratic thresholds. Entropy is a signal for the long-random-blob case, not the known-prefix case.
- Signal 3: is NOT in an exclusion zone. Exclusion zones are mandatory to hit acceptable precision: ignore image/asset binary blobs (`.png`, `.jpg`, `.svg`, `.webp`), known-SDK package identifiers, resource IDs, tracking/analytics IDs, and test/example key patterns (`sk_test`, documented placeholder keys).
- Prefer `sk_live`-class / provider-scoped-live patterns for the highest-confidence blocks; ambiguous generic high-entropy strings are a **warning**, not a block.
- Active credential validation (calling the provider to confirm the key is live) is **off by default**, available behind an explicit `--validate-secrets` flag only. Many CI runners have no egress, and firing requests at a live production key from inside CI creates its own risk and noise.

### MG-002 — Cleartext / accept-all transport
Block on deterministic transport-security failures:
- `android:usesCleartextTraffic="true"` in the manifest, OR a `network_security_config.xml` that permits cleartext for first-party domains, OR
- a custom `TrustManager` / `HostnameVerifier` that accepts all certificates/hosts (accept-all `checkServerTrusted` with empty body, `ALLOW_ALL_HOSTNAME_VERIFIER`, etc.).
- First-party domains come from the config file's allowlist, not from inferred runtime behavior. Do not flag third-party SDK hosts.

### MG-003 — Plaintext sensitive storage (config-based, not content-inference)
Block on the **storage configuration** being unsafe, not on trying to statically prove the written data is sensitive (that inference is false-positive-prone and is explicitly out of scope for blocking):
- `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` usage,
- writes to external/shared storage of app-private data,
- explicitly disabled encryption on a storage API that offers it.
- Content-based "this looks like a token being written to SharedPreferences" detection is a **warning**, never a block, in v1.

### Blocking-set candidate for early promotion: MG-004 — Exported components without permission protection
Exported `activity` / `service` / `receiver` / `provider` in the manifest with `android:exported="true"` and no `android:permission` guard. This is deterministic, high-confidence, reads straight from the manifest, and is a classic real finding. Ship it as blocking **if** it passes the negative-fixture suite cleanly; if any false positive shows up (e.g. launcher activity legitimately exported), demote to warning until the exclusion logic is tight (launcher/main activity is expected-exported and must be excluded).

## Warning rules (v1 — informational, never block)

- MG-005 Weak/missing certificate pinning — block ONLY is not permitted in v1; warn. For pinning, restrict any high-confidence signal to the native `network_security_config.xml` `<pin-set>`; code-level pinning (OkHttp `CertificatePinner`, TrustKit) is warning-only because static detection is unreliable.
- MG-006 Insecure WebView config — `setJavaScriptEnabled(true)` combined with file access / untrusted content loading. Warn.
- MG-007 Excessive/dangerous permissions relative to declared app category — warn; too subjective for blocking without carefully defined category baselines.
- MG-008 Weak root/jailbreak detection — warn. This is a runtime-defense concern, not a release-security gate concern, and "weak" is a judgment call. Do not block.
- MG-009 Third-party SDK inventory + known-CVE flagging — informational.
- Flutter / React Native architecture detection — informational.

## Baseline mode (critical for enterprise adoption)

Enterprises have existing debt. A gate that blocks on pre-existing findings gets disabled immediately. Support a baseline:

```yaml
policy:
  mode: baseline          # or "strict"
  new_findings_only: true  # in baseline mode, only NEW blocking findings block the release
```

- In `strict` mode, any blocking finding blocks.
- In `baseline` mode, the tool compares current findings against a stored baseline and blocks only on **regressions** (new blocking findings), passing pre-existing debt. This lets a team adopt the gate on a legacy app without a wall of red on day one, then ratchet down.
- Baseline comparison depends on stable finding identity — see `finding_hash` in the output contract.

## Config file (`.mobilegate.yml`)

Must support from day one:
- `policy.mode` and `new_findings_only`.
- First-party domain allowlist (for MG-002 / MG-005).
- Rule suppression **with mandatory justification**:
  ```yaml
  ignore_rules:
    - id: "MG-007"
      reason: "Background location required for core delivery-tracking feature."
      paths: ["AndroidManifest.xml"]
  ```
- Score threshold override.

Suppression without a `reason` is a config validation error. This keeps the audit trail honest.

## Scoring model (secondary to the gate, and deterministic)

The score exists only for executive trend-tracking. It must never contradict the gate.
- Hard rule: if any blocking rule fires (in the active policy mode), `gate_decision` is `BLOCKED` regardless of score.
- Score is deterministic and weighted: start at 100, subtract a fixed weight per confirmed finding by severity (blocking > warning > info).
- Floor the score low enough that a BLOCKED build can never display a "healthy-looking" score. `BLOCKED` and a high score must be impossible simultaneously.
- No LLM, no fuzzy heuristic in the score. Same weights in produce the same score out, every time.

## Output contract

Always emit both machine-readable JSON and a human-readable summary.

```json
{
  "scanner_version": "0.1.0",
  "rule_version": "2026.02.1",
  "artifact_type": "apk",
  "platform": "android",
  "gate_decision": "blocked",
  "policy_mode": "strict",
  "score": 20,
  "summary_counts": { "blocking": 2, "warning": 3, "info": 5 },
  "blocking_findings": [
    {
      "id": "MG-001",
      "finding_hash": "sha256:…",
      "title": "Hardcoded production Google API key",
      "severity": "critical",
      "confidence": "high",
      "masvs": "MASVS-STORAGE-1",
      "cwe": "CWE-798",
      "evidence": [
        { "source": "assets/config.json", "line": 14, "excerpt": "AIzaSy… (redacted)" },
        { "source": "signal", "detail": "matched GCP key pattern + entropy 4.7 + outside exclusion zone" }
      ],
      "why_it_blocks": "Anyone who downloads this APK can extract this key from the assets bundle. It is a live production Google API credential.",
      "remediation": "Remove the key from the bundle, inject it at build time via the CI secret store, and rotate the exposed key immediately."
    }
  ],
  "warnings": [ ... ],
  "info": [ ... ]
}
```

Contract requirements:
- `evidence` is a **structured array**, not a single string, so file/line/source/signal parse cleanly.
- `finding_hash` is a stable content hash that drives baseline comparison and dedup across CI runs. **Compute it from: rule ID + file path + normalized match value. Do NOT include the line number.** This is critical: line numbers shift when unrelated code changes or when compiler/obfuscation settings change, and a hash that includes them produces phantom "new" findings that block unchanged builds — which breaks baseline mode, which was the entire enterprise-adoption mechanism. The line number stays in the `evidence` array for humans; it stays out of the identity hash. Acceptance test: a secret that moves from line 14 to line 18 in the same file, with no other change, must produce the same `finding_hash` and therefore must NOT register as a regression. Two scans of the same unchanged APK must produce byte-identical hashes.
- `why_it_blocks` is the human-facing explanation — this is where your pentest judgment becomes product value. "Hardcoded secret found" is worthless. "Anyone who downloads this app can extract this production key" is the reason a release manager acts.
- `masvs` / `cwe` mapping on every finding makes the output enterprise- and compliance-friendly with near-zero cost.

Human-readable output: lead with `RELEASE STATUS: BLOCKED` and the failed controls. Warnings collapsed by default. Provide a Markdown formatter for the GitHub/GitLab PR comment.

## Rules as data, not hardcoded logic

Rule definitions live as data files, not buried in Go:

```
/rules
  MG-001-hardcoded-secret.yaml
  MG-002-cleartext-transport.yaml
  MG-003-plaintext-storage.yaml
  MG-004-exported-component.yaml
  ...
```

```yaml
id: MG-004
name: Exported Android component without permission protection
severity: high
confidence: high
platform: android
blocking: true
masvs: MASVS-PLATFORM-1
cwe: CWE-926
signals_required: [manifest_exported_true, no_permission_guard, not_launcher_activity]
remediation: Set android:exported="false" unless the component must be externally reachable; if it must, protect it with a signature-level permission.
```

The Go engine evaluates these; adding or tuning a rule is a data change. This is the foundation for customer-specific policy and compliance mapping when this becomes a hosted product.

## Test strategy (this is a precision product — the tests ARE the spec)

Build a regression suite with **synthetic fixtures you author yourself**. Do NOT use findings, binaries, or data from any real client engagement, even anonymized — that is a confidentiality exposure and it does not belong anywhere near a public repo. Build purpose-made test APKs instead:

- **Positive fixtures:** minimal APKs each deliberately planted with one known issue (a fake-but-pattern-valid `sk_live`-shaped test key, `usesCleartextTraffic=true`, an unprotected exported activity, a `MODE_WORLD_READABLE` write). Each has a documented expected finding.
- **Negative fixtures (the important ones):** clean APKs that must produce **zero** blocking findings — including deliberately tricky ones: an app with a launcher activity legitimately exported, image assets with high-entropy binary data, `sk_test` placeholder keys, third-party SDK hosts using cleartext (must NOT be flagged as first-party).

Formal acceptance gate (precision): **no rule is allowed into the blocking tier until it produces zero false positives across the entire negative-fixture suite.** Passing the negative suite is a harder requirement than passing the positive suite, because "clean APK → PASS" is the product promise. If a candidate blocking rule can't hit that, it ships as a warning until it can.

Formal acceptance gate (performance): the 90-second budget is a measured test, not a slogan. Enterprise CI runners are resource-constrained. Assert as CI-enforced targets on a representative APK:
- Scan time P95 < 90 seconds on an APK up to 100 MB.
- Peak memory < 1 GB.
- Cold start (single static binary, no runtime install) — the binary runs on a scratch/minimal container with no Java, no Python, nothing pre-installed.

If a parsing approach can't hit these, that's a signal to fix the parser, not to relax the target.

## Deliverable structure

```
/cmd/mobilegate        — CLI entrypoint + config parsing
/pkg/parser
  /apk                 — zip container handling (stdlib archive/zip)
  /manifest            — binary XML + resources.arsc via maintained library (thin wrapper)
  /dex                 — minimal custom DEX string-pool extractor (~150 LOC, no decompiler)
/internal/engine       — rule runner, regex matchers, entropy checks, exclusion zones, signal evaluation
/internal/core         — shared finding model, hashing (finding_hash), baseline diff, scoring
/internal/report       — JSON, terminal, Markdown PR-comment formatters
/rules                 — YAML rule definitions
/testdata
  /positive            — planted-issue synthetic APKs + expected findings
  /negative            — clean + tricky synthetic APKs, expected zero blocking
```

## Build order (ship end-to-end before adding breadth)

1. APK unzip (stdlib) + manifest parse (library) + minimal custom DEX string extractor, verified against a real-world APK. Get raw manifest fields and the DEX string pool out reliably before writing any rule.
2. MG-001, MG-002, MG-003 with full multi-signal evidence + exclusion zones.
3. Scoring + gate decision + `finding_hash` + JSON/terminal output.
4. Negative-fixture suite green (zero false positives) — this is the acceptance gate.
5. Baseline mode + PR-comment Markdown formatter.
6. Only then: promote MG-004 to blocking if it passes the negative suite, and add the warning-tier rules.

One reliable Android gate beats two half-finished platforms. Do not touch iOS until this is trusted in a real pipeline.

---

## Appendix: iOS (v2 — do NOT implement now)

Recorded only so it isn't redesigned from scratch later. Parse `Info.plist` / entitlements with a pure-Go plist decoder; extract Mach-O strings via stdlib `debug/macho` (`__cstring` section) rather than shelling out to `otool`/`strings`. iOS transport rules key off `NSAppTransportSecurity` (`NSAllowsArbitraryLoads`, `NSPinnedDomains`). None of this belongs in the v1 codebase.
