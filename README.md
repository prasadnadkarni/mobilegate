# MobileGate

An Android APK release gate for CI/CD. It answers one question — **PASS**
or **BLOCKED** — and lists the specific controls that failed. It is not
a findings report, and it does not try to be comprehensive.

Single static Go binary, no runtime dependencies, no JVM. Pure static
analysis: no device, no emulator, no network access required to run a
scan.

```
$ mobilegate app-release.apk
RELEASE STATUS: BLOCKED
apk:   app-release.apk
mode:  strict
score: 39/100 (secondary to the release status above)

Failed controls:
  MG-003 — Plaintext sensitive storage (backup exposure) (1 finding)
    [AndroidManifest.xml] android:allowBackup="true"
      why it blocks: android:allowBackup="true" is set on <application> ...
      remediation:   Set android:allowBackup="false" on <application> unless ...
```

**Ships as a GitHub Action** — no build step, no Go toolchain on your
runner, a pinned/checksum-verified release binary fetched at run time:

```yaml
- uses: prasadnadkarni/mobilegate@v0.1.0
  with:
    apk-path: app/build/outputs/apk/release/app-release-unsigned.apk
```

Full inputs, permissions, and the exit-code/PR-comment behavior are in
[GitHub Action](#github-action) below.

## Why this isn't MobSF

MobSF says "here are 150 findings." MobileGate says "your release is
blocked because these controls failed." That's the entire product
difference, and it's deliberate, not a limitation of a smaller tool.

The promise is precision, not coverage. A clean APK must produce zero
blocking findings — that property *is* the product. A blocking rule
that fires on a clean app is a worse failure than one that misses a
real issue: the false positive gets the tool disabled; the miss is
caught by the human review that still exists alongside this gate. Every
design decision in this repo resolves in favor of that tradeoff, which
is why the rule set below is short and each rule's YAML documents what
it deliberately does *not* detect as carefully as what it does.

## The rules

Four rules exist today. Each rule requires multiple corroborating
signals before it fires — no rule blocks on a single weak signal.

| Rule | Detects | Blocking tier |
|---|---|---|
| **MG-001** — Hardcoded production secret | AWS access keys, GCP/Firebase API keys, Stripe live secret keys, GitHub PATs (classic + fine-grained), Slack tokens, PEM private-key blocks with an actual key body — in the DEX string pool, `resources.arsc`, `AndroidManifest.xml`, and `assets/**`. Provider-prefix patterns adapted from gitleaks/trufflehog's public rule sets. | Blocking |
| **MG-002** — Cleartext / accept-all transport | `android:usesCleartextTraffic="true"` (explicit, or implicit via `targetSdkVersion < 28`), and `network_security_config.xml` `<base-config>`/`<domain-config>` blocks permitting cleartext — domain-scoped matches only fire against a first-party domain allowlist you configure, never inferred. | Blocking |
| **MG-003** — Plaintext sensitive storage (backup exposure) | `android:allowBackup="true"` (explicit, or implicit via `targetSdkVersion < 31`) with no `fullBackupContent`/`dataExtractionRules` override that actually restricts something, and no custom `backupAgent`. Implicit-and-narrowed-by-`targetSdkVersion≥31` is warning-tier, not blocking — the primary local-extraction path is closed on modern targets, cloud/D2D backup remain a residual risk. | Blocking (one signal is warning-tier) |
| **MG-004** — Exported Android component without permission protection | `android:exported="true"` (explicit) or an unset `android:exported` with an `<intent-filter>` (implicit, pre-API-31 platform default) on an activity/service/receiver/provider, with no covering `android:permission`. Splits first-party vs. library-injected-via-manifest-merger origin (same finding, different remediation) — see `rules/MG-004-exported-component.yaml`. | Warning (see below) |
| **MG-010** — Debug/test build artifact | `android:debuggable="true"` and `android:testOnly="true"` on the release candidate. Not in the original spec's MG-001–MG-009 catalog — split out from MG-003 deliberately: build-artifact hygiene is a different threat model and a different remediation owner than storage exposure. | Blocking |

Each rule's YAML (`rules/*.yaml`) documents its exact signal logic,
what it excludes and why, and the corpus evidence behind blocking-tier
status. That documentation is the actual spec — this table is a
summary of it, not the other way around.

**MG-004** is written into the spec as a blocking-tier promotion
candidate and passes its own negative-fixture suite with zero false
positives — this project's technical acceptance gate. It ships
warning-tier anyway: the 12-app real corpus found every single app
firing (even after splitting first-party from library-origin
components and tightening the origin heuristic — see
`rules/MG-004-exported-component.yaml`'s "BLOCKING STATUS" note for the
exact numbers and reasoning). CLAUDE.md: *"A blocking rule that fires
on a clean app is a worse failure than one that misses a real issue."*
Revisit once there's more signal on how much of that volume is real
vs. common boilerplate this tool hasn't learned to recognize yet.

## Scope limits — stated plainly

These are architectural decisions, not gaps waiting to be filled by the
next PR. Read them before assuming a finding you expected is missing
because of a bug.

**No DEX bytecode analysis.** The DEX parser reads the string pool
(header → `string_ids` → MUTF-8 table) and enough class/method/field
structure to attribute a string to its declaring type. It does not
decompile, and it does not walk method bodies. This is a hard
architectural line, not a missing feature — see `CLAUDE.md`:
*"You do NOT need decompilation to Smali... do not let it grow into
one."* Concretely, this means MobileGate cannot and does not detect:

- An accept-all `TrustManager`/`HostnameVerifier` (an empty
  `checkServerTrusted` body). A class *referencing*
  `X509TrustManager` is not evidence of an accept-all implementation —
  legitimate implementations are common — and there is no
  string-pool-only way to tell them apart. This is spec'd as MG-002's
  third signal and is not built.
- `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` at `openFileOutput`/
  `getSharedPreferences` call sites — these are integer constants at a
  call site, invisible without reading the method body they're passed
  into.
- Whether a storage API's encryption was explicitly disabled in code.

**No `lib/*.so` (native/NDK) parsing.** Developers do embed secrets in
native code on the mistaken belief it's harder to extract — it isn't,
`strings libfoo.so` finds the same bytes just as easily — but `.so` is
ELF, not an Android chunk format, and needs its own reader (ELF section
parsing, then the same pattern-matching signals). That's new parser
surface that hasn't been built, not a decompiler extension.

**No content-inference blocking.** MG-003 blocks on storage
*configuration* (`allowBackup`), never on statically guessing that a
particular write looks like it contains a token. That inference is
false-positive-prone and is explicitly out of scope for the blocking
tier per the spec.

**Android APK only.** No iOS. Not "later in this sprint" — a separate
version, with no shared abstractions pre-built for it in this codebase.

**No LLM in the detection or gate-decision path.** Every signal above
is deterministic regex/structural matching over parsed data. The only
place an LLM is even permitted (not currently used) is generating the
human-readable remediation text for a finding a deterministic rule has
already confirmed — never detection, never the gate decision itself.

If a class of bug needs bytecode analysis to catch reliably, the
honest answer is that MobileGate doesn't catch it yet, not that it's
"probably fine." Revisiting any of these requires a deliberate decision
to add bytecode-analysis capability generally, not a one-off carve-out
for a single rule.

## Baseline mode: adopt without a wall of red

Enterprises have existing debt. A gate that blocks on every
pre-existing finding on day one gets disabled, not fixed. Baseline mode
snapshots current findings and blocks only on *regressions* — new
blocking findings not present in that snapshot — while pre-existing
debt passes silently... except it isn't silent: every grandfathered
finding is still shown in the report, just not counted toward the gate
decision.

```sh
# Adopt on a legacy app: snapshot what's already there.
mobilegate baseline -write app-release.apk
# wrote baseline: 2 blocking finding(s) captured to .mobilegate-baseline.yml

# From then on, scan against it.
mobilegate -baseline .mobilegate-baseline.yml app-release.apk
```

**The demo that proves the mechanism, not just describes it:** VLC's
corpus scan (see below) has two pre-existing findings — an embedded RSA
private key and an explicit cleartext-traffic flag. After writing a
baseline from that state:

```
$ mobilegate -baseline vlc-baseline.yml app.apk
RELEASE STATUS: PASS
score: 100/100

No blocking findings.

2 pre-existing finding(s) grandfathered by baseline (not blocking):
  MG-001 — Hardcoded production secret (1 finding)
  MG-002 — Cleartext / accept-all transport (1 finding)
```

Then a fresh secret was planted in the same APK (a Stripe-key-shaped
string in a new asset file) and scanned against the *same, unmodified*
baseline:

```
$ mobilegate -baseline vlc-baseline.yml app-with-planted-secret.apk
RELEASE STATUS: BLOCKED
score: 39/100

Failed controls:
  MG-001 — Hardcoded production secret (1 finding)
    [assets/planted_secret.txt] sk_liv********************STUVWX

2 pre-existing finding(s) grandfathered by baseline (not blocking):
  MG-001 — Hardcoded production secret (1 finding)
  MG-002 — Cleartext / accept-all transport (1 finding)
```

The new finding blocked. The two pre-existing ones didn't. That's the
whole mechanism.

The baseline file (`.mobilegate-baseline.yml`) is plain, sorted, diffable
YAML meant to be committed and reviewed like any other config change —
not an opaque cache:

```yaml
scanner_version: 0.1.0
rule_version: 2026.07.1
findings:
- finding_hash: sha256:42d42e9a...
  rule_id: MG-001
  title: Hardcoded Private key block header
  source: classes4.dex
  excerpt: -----B********...d6gaWp
```

**Identity is `finding_hash` — rule ID + file path + normalized match
value, deliberately excluding line number.** A finding that moves lines
in an otherwise-unchanged file (a refactor, a compiler/obfuscation
setting change) must not register as "new." That's tested directly: a
secret moved from one line to another in the same file produces an
identical hash.

**Ratchet, not amnesty:** `baseline -write` always replaces the file
with a full snapshot of what's currently found — it never merges with
what was there before. A finding that gets fixed simply isn't in the
next scan, so it isn't in the next write. It cannot silently stay
grandfathered under a stale entry once it's actually gone.

**Fails closed.** A missing baseline file falls back to strict mode
with an explanatory message (expected on first use). A baseline file
that's corrupt, unreadable, or schema-mismatched *also* falls back to
strict — loudly, on stderr, with every existing finding treated as new
— never a silent pass. Same discipline applies to `.mobilegate.yml`
itself: a missing config is a legitimate default; an invalid one falls
back to safe defaults (strict mode, no suppressions) with a loud
warning, not a crash and not a silent pass.

## Policy: `.mobilegate.yml`

Policy lives in a file your team reviews and commits, not in whoever's
CI invocation happens to pass which flags.

```yaml
policy:
  mode: baseline                 # or "strict" (default)
  baseline_file: .mobilegate-baseline.yml
  first_party_domains:
    - example.com                # MG-002's domain-config allowlist
  first_party_packages:
    - com.example.legacy         # MG-004's origin-heuristic override — see below
  source_manifest_path: app/src/main/AndroidManifest.xml   # -sarif output's manifest-finding location — see "SARIF" below

ignore_rules:
  - id: "MG-002"
    reason: "Required — suppression without a reason is a config load error, not a warning."
    paths: ["AndroidManifest.xml"]   # omit to suppress the rule everywhere
```

`first_party_packages` overrides MG-004's exported-component origin classification (first-party vs. library-injected-via-dependency). The default heuristic compares a component's fully-qualified class name against your app's manifest package at the reverse-DNS org level (2 segments — e.g. `org.mozilla` covers both `org.mozilla.fenix.*` and an F-Droid rebuild's `org.mozilla.fennec_fdroid` applicationId), which handles common cases like build-flavor `applicationId` suffixes and same-org multi-module code. It can't know about a package inherited from a fork, an acquisition, or a rename with a genuinely different org name — list those explicitly here and they're always treated as first-party regardless of what the heuristic would guess.

CLI flags (`-mode`, `-baseline`) override the committed file only when
explicitly passed, so CI can force strict mode for one run without
touching what's checked in. Suppressed findings are never dropped
silently — they show up in every output format as
suppressed-with-reason, the same visibility principle baseline mode
applies to grandfathered debt.

## Corpus results

Twelve real, open-source F-Droid APKs — not synthetic fixtures, not a
client engagement (see `testdata/real/README.md` for exactly which apps
and how to fetch them yourself).

**Strict mode: 8 BLOCKED / 4 PASS.**

| Outcome | Apps |
|---|---|
| BLOCKED | Nextcloud, AntennaPod, Conversations, Fennec (MG-002 — permissive `network_security_config` base-config); Simple Flashlight, NewPipe (MG-003 — `allowBackup`); Material Files (both); VLC (MG-001 + MG-002) |
| PASS | Tusky, KeePassDX, Termux, Dolphin |

**Baseline mode, after writing a baseline from that same state: 12/12
PASS** — every pre-existing finding shown as grandfathered, none
dropped, none silently hidden.

**The one finding on this corpus that's a genuine credential, not a
config default:** VLC's `classes4.dex` contains a complete RSA private
key and its self-signed certificate (`CN=example.com`) — MG-001's
`private-key-header` pattern requires an actual base64 key body after
the PEM marker specifically to avoid firing on bare boundary constants
every TLS library ships (this rule hit that false positive twice in
early corpus runs — Nextcloud, KeePassDX — before the body-length
requirement existed). The `CN=example.com` strongly suggests this is a
bundled example/test certificate rather than a live production key, but
MobileGate reports the configuration fact and stops there — it does
not attempt to guess intent, that's exactly the kind of judgment call
that belongs to the human reviewing the finding.

Full performance numbers (P95 scan time, peak RSS across the corpus,
tracked as rules are added) are in `PERFORMANCE.md` — the worst
observed case with all four rules active is well inside the spec's
90-second / 1 GB targets.

## Verification: parser oracles

Five parser oracles (`tools/oracle/*_test.go`, `make oracle`, gated
behind a build tag so they never compile into the shipped binary or run
in CI) cross-check MobileGate's own parsers against independent,
from-scratch Android tooling — `aapt2`, `apkanalyzer`, `dexdump` — on
real APKs:

| Oracle | Cross-checks against | What it verifies |
|---|---|---|
| Manifest | `apkanalyzer manifest print` (falls back to `aapt2 dump badging`) | package name, `usesCleartextTraffic`, every component's `exported`/`permission` |
| DEX string count | `dexdump -f` | `string_ids_size` matches exactly, on single- and multi-dex APKs |
| `resources.arsc` string pool | `aapt2 dump strings` | full multiset match (order-independent — see the oracle's own doc comment for why) |
| `network_security_config.xml` | `aapt2 dump xmltree` | domain names and `includeSubdomains`, the one oracle that checks CDATA text specifically |
| `AndroidManifest.xml` string pool | `aapt2 dump xmlstrings` | same multiset check, plus the only oracle that exercises the UTF-16 pool-encoding path against real input |

Every oracle is mutation-tested, not just written and trusted: each
one's own doc comment in `tools/oracle/README.md` records the specific
bug that was temporarily introduced, the exact diff the oracle produced
when it caught it, and confirmation the bug was reverted before
committing.

Not every parser has a dedicated oracle. `pkg/parser/backuprules`
(`fullBackupContent`/`dataExtractionRules` XML) is verified by synthetic
binary-XML unit tests plus real-corpus cross-checking against `aapt2
dump xmltree` output done manually during development, not an automated
oracle test in this suite — noted here rather than left to look covered
by the table above.

## Quickstart

**Build:**

```sh
git clone <this-repo>
cd mobilegate
go build -o mobilegate ./cmd/mobilegate
```

Requires Go 1.26+. No other runtime dependency — the built binary is
static and self-contained.

**Scan an APK:**

```sh
./mobilegate app-release.apk                 # human-readable gate report
./mobilegate -json app-release.apk            # machine-readable output contract
./mobilegate -markdown app-release.apk        # GitHub/GitLab PR-comment Markdown
./mobilegate -sarif out.sarif app-release.apk # also write SARIF 2.1.0 (combine with any of the above)
```

Exit code is `1` on `BLOCKED`, `0` on `PASS` — designed to fail a CI
step directly.

**Adopt on an existing app (baseline mode):**

```sh
./mobilegate baseline -write app-release.apk
git add .mobilegate-baseline.yml
git commit -m "Adopt MobileGate: baseline existing findings"
```

Then set `policy.mode: baseline` in `.mobilegate.yml` (or pass
`-baseline .mobilegate-baseline.yml` on the command line) so future
scans only block on regressions.

## GitHub Action

`prasadnadkarni/mobilegate@v0.1.0` is a composite action: it downloads
the pinned release binary (checksum-verified, no build step, no Go
toolchain needed on your runner), runs it against an APK, fails the
workflow on `BLOCKED`, and posts or updates a PR comment with the
Markdown report.

The realistic case — the APK is a build artifact from an earlier step
in the *same job*, not a file committed to the repo:

```yaml
name: MobileGate release gate

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # required to post/update the PR comment — see "Permissions" below

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"

      - name: Build release APK
        run: ./gradlew assembleRelease

      - uses: prasadnadkarni/mobilegate@v0.1.0
        with:
          apk-path: app/build/outputs/apk/release/app-release-unsigned.apk
          # config-path: .mobilegate.yml        # optional, this is already the default
          # baseline-path: .mobilegate-baseline.yml  # optional — omit to let policy.mode in .mobilegate.yml decide
```

If the APK is built in a **different job** (a separate build job feeding
a separate gate job), it has to cross the job boundary explicitly —
each job is a clean filesystem:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./gradlew assembleRelease
      - uses: actions/upload-artifact@v4
        with:
          name: release-apk
          path: app/build/outputs/apk/release/app-release-unsigned.apk

  gate:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: release-apk
      - uses: prasadnadkarni/mobilegate@v0.1.0
        with:
          apk-path: app-release-unsigned.apk
```

### Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `apk-path` | yes | — | Fails the action immediately (before downloading anything) if the file doesn't exist. |
| `config-path` | no | *(unset — MobileGate's own default, `.mobilegate.yml`)* | |
| `baseline-path` | no | *(unset — mode/path come from `.mobilegate.yml`'s `policy.mode`)* | Setting this alone also switches to baseline mode, same shorthand as the CLI's `-baseline` flag. |
| `version` | no | `latest` | Pin an exact tag (`v0.1.0`) for a reproducible pipeline — `latest` can change under you between runs. |
| `comment-on-pr` | no | `true` | No-op (not an error) on any event that isn't a pull request. |
| `comment-marker` | no | `default` | Change only if one workflow scans multiple APKs and needs a separate comment per APK. |
| `fail-on-comment-error` | no | `true` | See "Permissions" below. |
| `github-token` | no | `${{ github.token }}` | |
| `sarif-file` | no | *(unset — no SARIF output, no upload)* | See "SARIF / GitHub Code Scanning" below. Needs `security-events: write`. |

### Outputs

`gate-decision` (`pass`/`blocked`) and `score`, for a downstream step
that wants to branch on the result beyond the action's own exit code.

### Exit code and the PR comment: order of operations

A `BLOCKED` result must still get its PR comment posted — that's the
whole point, that's when the comment matters most. The action runs the
scan, posts/updates the comment regardless of the result, and *only
then* exits with the scan's real exit code as its last step. A workflow
step failure from `BLOCKED` always shows up after the comment step has
had its chance to run, never instead of it.

### Sticky comment, not a stack

Every comment the action posts carries a hidden marker
(`<!-- mobilegate-report:default -->` by default). On each run, the
action lists existing PR comments, and if one already carries that
marker, it's **updated in place** — re-running the workflow (a new
commit, a manual re-run) never produces a second comment.

### Permissions

Posting or updating the PR comment needs **`pull-requests: write`** on
the token the workflow gives the action. Many orgs now default
`GITHUB_TOKEN` to read-only, in which case you need the explicit block
shown in the examples above:

```yaml
permissions:
  pull-requests: write
```

**What happens if that permission is missing:** the action does **not**
silently skip the comment and report success. `fail-on-comment-error`
defaults to `true` — a permissions failure posting the comment fails
the action with a message telling you exactly what to add, even if the
scan itself was a clean `PASS`. Set `fail-on-comment-error: false` only
if you'd rather the scan result alone govern the action's outcome and
you're fine with comments silently not appearing when permissions are
wrong — that's an explicit opt-out, not the default, on purpose.

### SARIF / GitHub Code Scanning

`-sarif <path>` (CLI) / `sarif-file` (action input) writes a SARIF
2.1.0 file and, via the action, uploads it with
`github/codeql-action/upload-sarif@v3` so findings show up in the repo's
**Security → Code scanning** tab alongside CodeQL and any other SARIF
producer:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write   # required for the SARIF upload — see below

steps:
  - uses: prasadnadkarni/mobilegate@v0.1.0
    with:
      apk-path: app/build/outputs/apk/release/app-release-unsigned.apk
      sarif-file: mobilegate.sarif
```

**Read this before relying on where alerts appear to point.** SARIF
assumes a finding lives in a source file GitHub can check out and
diff. MobileGate's findings live inside a *compiled binary APK* —
there is no source file for a DEX string pool index or a merged
resources.arsc entry, and even the manifest MobileGate actually parses
is the compiled, **merged** `AndroidManifest.xml`, not the source file
you edit. Rather than fabricate a plausible-but-wrong location (worse
than an honest one — it actively misleads triage: "I checked that
file, there's nothing there"), MobileGate maps locations honestly:

- **Manifest findings** (MG-002's manifest signal, MG-003, MG-004,
  MG-010) map to `policy.source_manifest_path` in `.mobilegate.yml`
  (default: `app/src/main/AndroidManifest.xml`, the standard Gradle
  module layout — override it if your manifest lives elsewhere). This
  is the one case a real repo file is being pointed at. Attribute
  values match what MobileGate actually saw (the manifest merger
  doesn't rewrite `android:exported` or `android:allowBackup`), but
  **line numbers do not correspond** to anything in that file — the
  merged manifest MobileGate parses has different line numbers, if it
  has recognizable lines at all. MobileGate never fabricates a line
  number it can't verify; alerts point at the file, not a specific
  line.
- **Everything else** — MG-001 (DEX strings, `resources.arsc`, asset
  files) and MG-002's `network_security_config.xml`-based signal — has
  **no source-repo equivalent at all**. These map `artifactLocation.uri`
  to the APK file's own name. GitHub will list these alerts in the
  Security tab, but cannot render an inline PR diff annotation for
  them, because there genuinely isn't a diffable source location. The
  real in-artifact location (which DEX file, which string pool index,
  which manifest element) is always in the alert's message text and in
  its `properties`, specifically so it's still useful even when the
  physical location is coarse.

```yaml
policy:
  source_manifest_path: mobile/src/main/AndroidManifest.xml  # only if not app/src/main
```

**Severity ranking.** GitHub's Critical/High/Medium/Low ranking in the
Security tab reads `security-severity` — and, confirmed against
GitHub's own docs, reads it **only** from the rule itself, never from
an individual result. A MobileGate severity maps to GitHub's documented
bands (critical >9.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9) at the
middle of each band:

| MobileGate severity | security-severity | GitHub band |
|---|---|---|
| critical | 9.5 | Critical |
| high | 7.5 | High |
| medium | 5.5 | Medium |
| low | 2.5 | Low |

Because this is rule-level, not result-level, a rule that can produce
findings at more than one severity (MG-004: "high" by default, but
"critical" for an unguarded exported `<provider>` — direct data
exposure, not just an invokable component) reports the **worst
severity actually observed in that run**, not its nominal default — so
a critical provider finding doesn't get silently under-ranked as
merely "high" just because most MG-004 findings aren't providers. The
finding's true, specific severity is still in `properties.severity` on
the result itself.

**Suppressed and baselined findings are not uploaded to SARIF at all.**
This is a deliberate deviation worth calling out explicitly: SARIF has
a native `results[].suppressions` mechanism, and the obvious design
would be to use it so suppressed findings stay visible in the Security
tab without alerting. Confirmed against GitHub's documentation and a
May 2025 GitHub-staff reply on a public community discussion:
**`results[].suppressions` is not currently honored by GitHub's SARIF
ingestion.** A suppressed result uploaded there would not show as
suppressed — it would show as a normal, active, alerting result, which
is the opposite of what suppression means. Rather than ship something
that looks like it works but silently doesn't, MobileGate omits
baselined and `ignore_rules`-suppressed findings from SARIF output
entirely. They remain fully visible, with their reason, in every other
MobileGate output format (terminal, `-json`, `-markdown`) — this only
affects what reaches GitHub's Security tab.

**Re-running doesn't duplicate alerts.** GitHub tracks an alert's
identity across runs via `partialFingerprints.primaryLocationLineHash`
— the only fingerprint key it actually reads. MobileGate puts its own
`finding_hash` there (the same stable identity baseline mode uses),
not a source-line-derived value, since there's frequently no source
line to derive one from.

**What happens if `security-events: write` is missing:** the upload
step (`github/codeql-action/upload-sarif@v3`) fails loudly with
GitHub's own permission error — it is a normal action step with no
`continue-on-error`, so the job fails visibly, the same "fail loudly,
not silently" standard as the PR-comment permission above.

## Development

```sh
make test              # unit + fixture suites (go test ./...)
make fetch-testdata     # pulls the two pinned dev-verification APKs
make oracle             # cross-checks parsers against aapt2/apkanalyzer/dexdump (requires Android SDK cmdline-tools)
goreleaser build --snapshot --clean   # verify cross-compilation locally without tagging a release (requires goreleaser)
```

`.github/workflows/ci.yml` runs the same build/vet/test/goreleaser-build
checks on every push and PR. `.github/workflows/release.yml` runs
`goreleaser release` on a pushed `v*` tag — that's what publishes the
binaries `action.yml` fetches; see `.goreleaser.yml`.

**Pushing changes to `.github/workflows/*.yml` needs a token with the
`workflow` OAuth scope.** A `gh auth login` session (or a PAT) without
it gets rejected with `refusing to allow an OAuth App to create or
update workflow ... without workflow scope` — not obvious the first
time you hit it. Fix: `gh auth refresh -s workflow`. This bit the very
first push of this project's own CI setup, so it'll bite you too if
your token predates adding/editing a workflow file.

See `CLAUDE.md` for the project's hard constraints (Go-only, no
shelling out to JVM tooling, synthetic-fixtures-only, etc.) and
`mobile-security-release-gate-build-prompt-v2.1.md` for the full
original spec.

## License

Apache License 2.0 — see `LICENSE`. Chosen over MIT for the explicit
patent grant: this tool's target adopter (regulated orgs — banking,
healthcare, insurance, fintech) runs legal review on dependencies
before they ship in a CI pipeline, and Apache-2.0's patent clause is
what that review usually asks for. Both direct dependencies
(`github.com/shogo82148/androidbinary`, `github.com/goccy/go-yaml`) are
MIT-licensed and compatible.

MG-001's credential-pattern *shapes* (not code) are adapted from
gitleaks' and trufflehog's public rule sets, cross-checked against each
provider's own published token-format documentation — see
`rules/MG-001-hardcoded-secret.yaml`'s header for full provenance.

## Contributing

See `CONTRIBUTING.md`.
