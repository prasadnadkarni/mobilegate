# MobileGate

[![CI](https://github.com/prasadnadkarni/mobilegate/actions/workflows/ci.yml/badge.svg)](https://github.com/prasadnadkarni/mobilegate/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/prasadnadkarni/mobilegate.svg)](https://pkg.go.dev/github.com/prasadnadkarni/mobilegate)
[![Release](https://img.shields.io/github/v/release/prasadnadkarni/mobilegate)](https://github.com/prasadnadkarni/mobilegate/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21501144.svg)](https://doi.org/10.5281/zenodo.21501144)

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
- uses: prasadnadkarni/mobilegate@v0.4.4
  with:
    apk-path: app/build/outputs/apk/release/app-release-unsigned.apk
```

Full inputs, permissions, and the exit-code/PR-comment behavior are in
[GitHub Action](#github-action) below.

**[DESIGN.md](DESIGN.md)** has the "why" behind everything here — scope
limits, baseline mode's mechanics, the corpus investigation behind
MG-004's warning-tier status, and the SARIF suppressions gap. This
README is the pitch; that's the reasoning.

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
it deliberately does *not* detect as carefully as what it does. See
[DESIGN.md](DESIGN.md#scope-limits--stated-plainly) for exactly what
that costs (no DEX bytecode analysis, no native/NDK parsing, no
content-inference blocking) and why each boundary is deliberate.

## Quickstart

**Install** — four paths, pick based on what you're doing:

| Method | Command | Who it's for |
|---|---|---|
| Homebrew | `brew install prasadnadkarni/tap/mobilegate` | macOS, local/interactive use |
| Docker | `docker run --rm -v "$(pwd)":/work ghcr.io/prasadnadkarni/mobilegate:latest app.apk` | CI that isn't GitHub Actions — GitLab CI, Jenkins, anything where the composite action doesn't apply |
| Release binary | download + checksum-verify from [Releases](https://github.com/prasadnadkarni/mobilegate/releases) | CI pipelines — pinned, checksum-verified (this is what the GitHub Action itself fetches) |
| `go install` | `go install github.com/prasadnadkarni/mobilegate/cmd/mobilegate@latest` | Go developers trying it locally — unversioned, see below |

The Docker image is `scratch`-based (no shell, no libc — matches the
static-binary design) with `WORKDIR /work`, so mount the directory
containing the APK (and `.mobilegate.yml`/baseline file, if any) at
`/work` and pass paths relative to it, as in the command above. Built
`linux/amd64` + `linux/arm64` — the platform is selected automatically
by whatever's pulling the image.

`go install` requires `$(go env GOPATH)/bin` on `PATH`, and the binary
it produces has no version injected — `mobilegate -version` will show
`0.0.0-dev` and say so explicitly, since `go install` doesn't run
goreleaser's `-ldflags` step. That's fine for trying it out, but a
`scanner_version` that doesn't correlate to anything is a real gap when
correlating a bug report's JSON/SARIF output back to a specific build —
for anything beyond a quick local try, prefer one of the other three
paths above, all of which carry a real version.

**Build from source** (for contributors — see `CONTRIBUTING.md`):

```sh
git clone <this-repo>
cd mobilegate
go build -o mobilegate ./cmd/mobilegate
```

Requires Go 1.26.2+ (go.mod's `go` directive is a hard minimum — an
older toolchain will refuse to build or auto-switch, not silently
compile against something else). No other runtime dependency — the
built binary is static and self-contained.

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
scans only block on regressions. Existing findings are grandfathered,
not hidden — see [DESIGN.md](DESIGN.md#baseline-mode-adopt-without-a-wall-of-red)
for the full mechanism and a worked example.

## The rules

Five rules exist today. Each rule requires multiple corroborating
signals before it fires — no rule blocks on a single weak signal.

| Rule | Detects | Blocking tier |
|---|---|---|
| **MG-001** — Hardcoded production secret | AWS access keys, GCP/Firebase API keys, Stripe live secret keys, GitHub PATs (classic + fine-grained), Slack tokens, PEM private-key blocks with an actual key body — in the DEX string pool, `resources.arsc`, `AndroidManifest.xml`, and `assets/**`. Provider-prefix patterns adapted from gitleaks/trufflehog's public rule sets. | Blocking |
| **MG-002** — Cleartext / accept-all transport | `android:usesCleartextTraffic="true"` (explicit, or implicit via `targetSdkVersion < 28`), and `network_security_config.xml` `<base-config>`/`<domain-config>` blocks permitting cleartext — domain-scoped matches only fire against a first-party domain allowlist you configure, never inferred. | Blocking |
| **MG-003** — Plaintext sensitive storage (backup exposure) | `android:allowBackup="true"` (explicit, or implicit via `targetSdkVersion < 31`) with no `fullBackupContent`/`dataExtractionRules` override that actually restricts something, and no custom `backupAgent`. Implicit-and-narrowed-by-`targetSdkVersion≥31` is warning-tier, not blocking — the primary local-extraction path is closed on modern targets, cloud/D2D backup remain a residual risk. | Blocking (one signal is warning-tier) |
| **MG-004** — Exported Android component without permission protection | `android:exported="true"` (explicit) or an unset `android:exported` with an `<intent-filter>` (implicit, pre-API-31 platform default) on an activity/service/receiver/provider, with no covering `android:permission`. Splits first-party vs. library-injected-via-manifest-merger origin (same finding, different remediation). | Warning (see below) |
| **MG-010** — Debug/test build artifact | `android:debuggable="true"` and `android:testOnly="true"` on the release candidate. Not in the original spec's MG-001–MG-009 catalog — split out from MG-003 deliberately: build-artifact hygiene is a different threat model and a different remediation owner than storage exposure. | Blocking |

Each rule's YAML (`rules/*.yaml`) documents its exact signal logic,
what it excludes and why, and the corpus evidence behind blocking-tier
status. That documentation is the actual spec — this table is a
summary of it, not the other way around.

**MG-004** passes its own negative-fixture suite with zero false
positives but ships warning-tier anyway. The reason isn't raw finding
volume — it's that the manifest alone can't distinguish a
protocol-mandated export from an accidental one. Real apps' exported-
component surface is dominated by patterns that are *supposed* to be
exported: media-session playback services, `CustomTabsService`
implementing the Chrome Custom Tabs cross-app contract, widget
receivers, launcher activities. A targeted investigation into the
narrowest defensible blocking tier — first-party service/provider
findings only, leaving the noisier activity/receiver surface at
warning-tier — still shrank from 9 candidates to roughly 3–5 real ones,
concentrated in a single app out of twelve. See
[DESIGN.md](DESIGN.md#mg-004-why-it-isnt-blocking) for the full
investigation and exact numbers.

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
    - com.example.legacy         # MG-004's origin-heuristic override
  source_manifest_path: app/src/main/AndroidManifest.xml   # -sarif output's manifest-finding location — see "SARIF" below

ignore_rules:
  - id: "MG-002"
    reason: "Required — suppression without a reason is a config load error, not a warning."
    paths: ["AndroidManifest.xml"]   # omit to suppress the rule everywhere
```

CLI flags (`-mode`, `-baseline`) override the committed file only when
explicitly passed, so CI can force strict mode for one run without
touching what's checked in. Suppressed findings are never dropped
silently — they show up in every output format as suppressed-with-
reason, the same visibility principle baseline mode applies to
grandfathered debt. `first_party_packages`'s default heuristic and why
exact-package matching was rejected in favor of it are in
[DESIGN.md](DESIGN.md#policy-heuristics-first-party-domains-and-packages).

## GitHub Action

`prasadnadkarni/mobilegate@v0.4.4` is a composite action: it downloads
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

      - uses: prasadnadkarni/mobilegate@v0.4.4
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
      - uses: prasadnadkarni/mobilegate@v0.4.4
        with:
          apk-path: app-release-unsigned.apk
```

### Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `apk-path` | yes | — | Fails the action immediately (before downloading anything) if the file doesn't exist. |
| `config-path` | no | *(unset — MobileGate's own default, `.mobilegate.yml`)* | |
| `baseline-path` | no | *(unset — mode/path come from `.mobilegate.yml`'s `policy.mode`)* | Setting this alone also switches to baseline mode, same shorthand as the CLI's `-baseline` flag. |
| `version` | no | `latest` | Pin an exact tag (`v0.4.0`) for a reproducible pipeline — `latest` can change under you between runs. |
| `comment-on-pr` | no | `true` | No-op (not an error) on any event that isn't a pull request. |
| `comment-marker` | no | `default` | Change only if one workflow scans multiple APKs and needs a separate comment per APK. |
| `fail-on-comment-error` | no | `true` | See "Permissions" below. |
| `github-token` | no | `${{ github.token }}` | |
| `sarif-file` | no | *(unset — no SARIF output, no upload)* | See "SARIF" below. Needs `security-events: write`. |

### Outputs

`gate-decision` (`pass`/`blocked`) and `score`, for a downstream step
that wants to branch on the result beyond the action's own exit code.

### Behavior worth knowing

A `BLOCKED` result must still get its PR comment posted — that's the
whole point, that's when the comment matters most. The action posts/
updates the comment regardless of the result, and only then exits with
the scan's real exit code as its last step. Every comment carries a
hidden marker and is **updated in place** on each run — re-running the
workflow never produces a second comment.

### Permissions

Posting or updating the PR comment needs **`pull-requests: write`** on
the token the workflow gives the action. Many orgs now default
`GITHUB_TOKEN` to read-only, in which case you need the explicit block
shown in the examples above.

**What happens if that permission is missing:** the action does **not**
silently skip the comment and report success. `fail-on-comment-error`
defaults to `true` — a permissions failure posting the comment fails
the action with a message telling you exactly what to add, even if the
scan itself was a clean `PASS`. Set `fail-on-comment-error: false` only
if you'd rather the scan result alone govern the action's outcome.

## SARIF / GitHub Code Scanning

`-sarif <path>` (CLI) / `sarif-file` (action input) writes a SARIF
2.1.0 file and, via the action, uploads it with
`github/codeql-action/upload-sarif@v4` so findings show up in the repo's
**Security → Code scanning** tab alongside CodeQL and any other SARIF
producer:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write   # required for the SARIF upload

steps:
  - uses: prasadnadkarni/mobilegate@v0.4.4
    with:
      apk-path: app/build/outputs/apk/release/app-release-unsigned.apk
      sarif-file: mobilegate.sarif
```

**Read this before relying on where alerts appear to point.** SARIF
assumes a finding lives in a source file GitHub can check out and diff.
MobileGate's findings live inside a compiled binary APK, so locations
are honest rather than precise: manifest-based findings map to
`policy.source_manifest_path` (the file, never a fabricated line
number); everything else — DEX strings, `resources.arsc`, assets,
`network_security_config.xml` — has no source-repo equivalent at all
and maps to the APK's own name, with the real in-artifact location in
the alert's message text. `security-events: write` is required for the
upload step; without it, the step fails loudly, not silently.

[DESIGN.md](DESIGN.md#sarif-source-location-honesty-severity-mapping-and-the-suppressions-gap)
has the exact source-mapping rules, the severity-band table, the
`results[].suppressions` gap discovered while building this (confirmed
against GitHub's own docs — it's not currently honored, so
suppressed/baselined findings are omitted from SARIF entirely rather
than silently not working as suppressions), and the live verification
of alert deduplication across runs.

## Development

```sh
make test              # unit + fixture suites (go test ./...)
make fetch-testdata     # pulls the two pinned dev-verification APKs
make oracle             # cross-checks parsers against aapt2/apkanalyzer/dexdump (requires Android SDK cmdline-tools) — see DESIGN.md for what each oracle verifies
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
time you hit it. Fix: `gh auth refresh -s workflow`.

See `CLAUDE.md` for the project's hard constraints (Go-only, no
shelling out to JVM tooling, synthetic-fixtures-only, etc.) and
`mobile-security-release-gate-build-prompt-v2.1.md` for the full
original spec.

## License

Apache License 2.0 — see `LICENSE`. Chosen over MIT for the explicit
patent grant: this tool's target adopter (regulated orgs — banking,
healthcare, insurance, fintech) runs legal review on dependencies
before they ship in a CI pipeline, and Apache-2.0's patent clause is
what that review usually asks for. Direct dependencies
(`github.com/shogo82148/androidbinary`, `github.com/goccy/go-yaml`,
`github.com/santhosh-tekuri/jsonschema`) are MIT/Apache-2.0-licensed and
compatible.

MG-001's credential-pattern *shapes* (not code) are adapted from
gitleaks' and trufflehog's public rule sets, cross-checked against each
provider's own published token-format documentation — see
`rules/MG-001-hardcoded-secret.yaml`'s header for full provenance.

## Contributing

See `CONTRIBUTING.md`.
