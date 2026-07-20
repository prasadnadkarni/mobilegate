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
| **MG-010** — Debug/test build artifact | `android:debuggable="true"` and `android:testOnly="true"` on the release candidate. Not in the original spec's MG-001–MG-009 catalog — split out from MG-003 deliberately: build-artifact hygiene is a different threat model and a different remediation owner than storage exposure. | Blocking |

Each rule's YAML (`rules/*.yaml`) documents its exact signal logic,
what it excludes and why, and the corpus evidence behind blocking-tier
status. That documentation is the actual spec — this table is a
summary of it, not the other way around.

**MG-004** (exported components without a permission guard) is written
into the spec as a promotion candidate but not implemented — it needs
its own negative-fixture suite before entering the blocking tier, per
this project's own acceptance gate (see below).

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

ignore_rules:
  - id: "MG-002"
    reason: "Required — suppression without a reason is a config load error, not a warning."
    paths: ["AndroidManifest.xml"]   # omit to suppress the rule everywhere
```

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

**Wire into CI** (GitHub Actions example):

```yaml
- name: MobileGate release gate
  run: |
    ./mobilegate app-release.apk
```

The command's exit code alone fails the step on `BLOCKED`. To also post
a PR comment, capture the Markdown output and feed it to whatever
comment-posting action your CI platform provides:

```yaml
- name: MobileGate release gate
  run: ./mobilegate -markdown app-release.apk > mobilegate-comment.md
  # then hand mobilegate-comment.md to your PR-comment action of choice
```

## Development

```sh
make test              # unit + fixture suites (go test ./...)
make fetch-testdata     # pulls the two pinned dev-verification APKs
make oracle             # cross-checks parsers against aapt2/apkanalyzer/dexdump (requires Android SDK cmdline-tools)
```

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
