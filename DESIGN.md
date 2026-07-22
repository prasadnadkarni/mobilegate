# Design notes

This is where MobileGate's scope decisions live — why the parser stops
where it stops, why baseline mode is the adoption mechanism rather than
a config flag, why MG-004 isn't in the blocking tier despite passing its
own fixture suite, and the specific limitation discovered while building
SARIF output. The README is the one-minute pitch; this is the "why,"
for anyone deciding whether to trust, extend, or fork this tool.

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
- Whether a component's Java class actually extends a "safe" base class
  (e.g. `androidx.core.content.FileProvider`) — MobileGate can read the
  manifest's own protective attributes (`android:grantUriPermissions`,
  `<path-permission>`) but cannot verify class inheritance without
  decompiling. See MG-004's section below for a case where this came up
  in practice.
- WebView misconfiguration: `setJavaScriptEnabled(true)`,
  `addJavascriptInterface(...)`, `setAllowFileAccess(true)` are call
  sites with argument values, the same invisible-without-a-method-body
  shape as the two bullets above. Probably the highest-value rule this
  boundary blocks — see "Rules considered and not built" below (MG-006)
  for why.

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

**No LLM in the detection or gate-decision path.** Every signal is
deterministic regex/structural matching over parsed data. The only
place an LLM is even permitted (not currently used) is generating the
human-readable remediation text for a finding a deterministic rule has
already confirmed — never detection, never the gate decision itself.

If a class of bug needs bytecode analysis to catch reliably, the honest
answer is that MobileGate doesn't catch it yet, not that it's "probably
fine." Revisiting any of these requires a deliberate decision to add
bytecode-analysis capability generally, not a one-off carve-out for a
single rule. This is the concrete expression of the precision-over-
recall tradeoff described in the README's "Why this isn't MobSF": every
one of these boundaries exists because the alternative was a
false-positive-prone guess, and a blocking rule that fires on a clean
app is a worse failure than one that misses a real issue.

## Rules considered and not built (MG-005–MG-009)

The ID gap between MG-004 and MG-010 isn't an oversight — the original
spec (`mobile-security-release-gate-build-prompt-v2.1.md`) names five
rules, MG-005 through MG-009, that were considered and deferred, each
for its own specific, structural reason. This section exists so the gap
reads as a deliberate record, not a mystery — and it is a record, not a
roadmap: none of these has a build-order step, a target version, or an
implicit promise it's "coming soon." Revisiting any of them needs the
same thing revisiting a "Scope limits" boundary above does — a
deliberate decision with a reason, not a default assumption that more
rules are always better.

**MG-005 — certificate pinning.** Only the
`network_security_config.xml` `<pin-set>` block is statically
reachable — MobileGate already parses that file format
(`pkg/parser/nsc`) for MG-002, so detecting a declared pin-set would be
nearly free to add. Code-level pinning (OkHttp's `CertificatePinner`,
TrustKit) is constructed inside a method body, the same
invisible-without-bytecode shape as MG-002's TrustManager signal (see
"Scope limits" above). The reason this isn't just "ship the easy half"
is that the easy half is actively misleading on its own: a rule that
only checks `<pin-set>` and reports "no pinning found" would tell a
developer who correctly implemented `CertificatePinner` in code that
they have no pinning at all — worse than not reporting anything.
Warning-tier at best if ever built, and not before code-level detection
exists too.

**MG-006 — WebView misconfiguration.** `setJavaScriptEnabled(true)`,
`addJavascriptInterface(...)`, and `setAllowFileAccess(true)` are call
sites with argument values — invisible to a string-pool-only DEX
parser for the same reason as every other bytecode-gated signal (see
"Scope limits" above, which now names this one explicitly). Worth
calling out on its own: this is probably the highest-value rule on this
whole list if bytecode analysis is ever added. A JS bridge
(`addJavascriptInterface`) exposed to a WebView that also has JavaScript
and untrusted content loading enabled is a real, well-documented RCE
path on Android, not a hardening nice-to-have — the gap here has more
teeth than the other four.

**MG-007 — excessive permissions.** Reachability was never the
problem — every `<uses-permission>` is already visible in the manifest
MobileGate parses for every other rule. The blocker is judgment:
"excessive" only means something relative to an app-category baseline
(a flashlight app requesting `CAMERA` is expected; requesting
`READ_SMS` is not), and MobileGate has no source for that baseline and
no reliable way to infer an app's category from the APK alone. That's
exactly the subjective, context-dependent call the blocking tier exists
to avoid — see "Why this isn't MobSF" in the README. An informational
permission inventory (list them, no verdict) is the most this could
ever be.

**MG-008 — root/jailbreak detection.** Whether an app *has*
root-detection code (checking for `su`, `Superuser.apk`, known build
tags) is partly visible via string-pool signatures. Whether that
detection is *weak* — trivially bypassable — is a bytecode judgment
this tool can't make. But reachability isn't even the real blocker
here: root detection is a runtime defense protecting an already-running
app on an already-compromised device, not a property of the shippable
release artifact itself. It's the wrong threat model for a release
gate, not just an unbuilt rule.

**MG-009 — third-party SDK inventory.** Detecting *which* SDKs an app
bundles is reachable: attributed DEX class names (already extracted for
MG-001's usage-based filtering — see `pkg/parser/dex`) reveal package
namespaces like `com.google.firebase` or `com.facebook.sdk`. Detecting
*which version* usually isn't — Android's build process doesn't
reliably preserve a library's version string anywhere the
manifest/DEX/resources readers can find it. An inventory without
version numbers ("bundles Firebase, bundles the Facebook SDK") could be
built honestly. A CVE-mapped vulnerability claim ("Firebase 9.2.1 has
CVE-2021-XXXXX") needs a version this tool usually can't verify, and a
wrong CVE claim is worse than no claim at all — the same
false-positive-is-worse-than-a-miss principle the rest of this project
is built around, applied to a rule that was never built rather than one
that was built and then constrained.

## Policy heuristics: first-party domains and packages

`policy.first_party_domains` (MG-002) and `policy.first_party_packages`
(MG-004) both exist because a purely inferred heuristic can't fully
resolve "is this actually ours" — a reviewed config entry is the only
way to close that gap completely.

**`first_party_packages`** overrides MG-004's exported-component origin
classification (first-party vs. library-injected-via-dependency). The
default heuristic compares a component's fully-qualified class name
against your app's manifest package at the reverse-DNS org level (2
segments — e.g. `org.mozilla` covers both `org.mozilla.fenix.*` and an
F-Droid rebuild's `org.mozilla.fennec_fdroid` applicationId).

A full exact-package match was tried first and rejected: verified
against the 12-app real corpus, it misclassified genuinely first-party
code as library-origin in 5 of 12 apps, via two recurring, structural
causes:

- **Android build-flavor `applicationId` suffixes.** Fennec's manifest
  package is `org.mozilla.fennec_fdroid` (an F-Droid rebrand), but its
  code is `org.mozilla.fenix.*` — under exact matching, all 10 of its
  MG-004 findings were wrongly flagged library-origin. Same story for
  KeePassDX (`com.kunzisoft.keepass.libre` vs. code under
  `com.kunzisoft.keepass.*`) — all 4 of its findings were misclassified.
- **Same-org, multi-module package roots.** VLC's Android-TV UI module
  lives under `org.videolan.television.*`, not `org.videolan.vlc.*` — 9
  of VLC's 10 "library" findings under exact matching were this, not a
  real dependency.

The 2-segment match fixes both while still correctly catching every
confirmed genuine third-party case in the corpus (`androidx.*`,
`org.unifiedpush.*`, `com.canhub.*`, `com.adjust.*`,
`mozilla.components.*` — none share even the org segment with any app's
own identity).

**Design principle for anything still ambiguous after the heuristic:
fail toward first-party.** Mislabeling a developer's own code as
"library" tells them to ignore a finding they own — a worse error than
the reverse, where library-origin code carries first-party-style
remediation text and the developer looks and correctly concludes it's a
dependency.

**Known remaining gap, not fixable by any segment-count heuristic:**
Nextcloud's client ships legacy `com.owncloud.android.*` classes
alongside its actual manifest package `com.nextcloud.client` — a
holdover from the codebase's ownCloud-client fork history, a genuinely
different org entirely. 9 of Nextcloud's 10 "library" findings are this,
not a real dependency. Only `policy.first_party_packages` closes this
one — it exists specifically because forks, acquisitions, renames, and
white-label builds all break package-prefix inference in ways no
smarter default heuristic can fully close.

## MG-004: why it isn't blocking

MG-004 (exported Android component without permission protection) is
named in the original spec as a blocking-tier promotion candidate, and
it passes its own negative-fixture suite with zero false positives —
this project's technical acceptance bar. It ships warning-tier anyway
(`rules/MG-004-exported-component.yaml`'s `blocking: false`), and the
reason is not simply "too many findings" — it's that **the manifest
alone cannot distinguish a protocol-mandated export from an accidental
one**, and real apps' exported-component surface is dominated by the
former.

**The original signal.** A 12-app real-corpus run found every single
app firing — 89 findings total. Several of the most common recurring
patterns turned out to be structurally required by common libraries,
not developer oversights: `androidx.media.session.MediaButtonReceiver`
(needs to be exported to receive hardware media-button broadcasts, with
no app-controllable permission available to gate it), UnifiedPush's
service/receiver pair (a distributor app must be able to reach them by
the library's own design), and `androidx.profileinstaller.ProfileInstallReceiver`
(guarded by the platform's own `DUMP` permission, correctly falling out
via the plain permission check with no special-casing needed).

**The origin split.** In response, findings were split into first-party
vs. library-origin (see the policy-heuristics section above) — this
made the "not your code" cases visible with correct, different
remediation text, without suppressing them (a library-injected component
is exploitable exactly like a first-party one; only who has to fix it,
and how, differs). Even after the split, first-party-origin findings
alone still fire broadly across the corpus (68 of the 89, once the
2-segment heuristic replaced exact-package matching) — activities and
receivers dominate, and a large share of *those* turned out to also be
structurally-required patterns the origin split doesn't capture, because
origin (who wrote this code) and structural necessity (does this have to
be exported) are different axes. `CustomTabsService` is the clearest
example: first-party code (an app's own developers wrote the class,
correctly classified first-party), implementing a third-party protocol
(the Chrome Custom Tabs cross-app contract, where being exported *is*
the interface — no permission is possible without breaking it).

**The service+provider investigation.** A blocking tier scoped to just
first-party service+provider findings (leaving the noisier,
boilerplate-heavy activity/receiver surface at warning-tier) was
investigated as a narrower, more defensible candidate — checked against
the corpus rather than assumed. Of 68 first-party findings, only 9 are
service/provider, concentrated in 5 of 12 apps:

- **6 services.** 4 are media-session playback services (Nextcloud's
  `BackgroundPlayerService`, AntennaPod's `PlaybackService`, NewPipe's
  `PlayerService`, VLC's `PlaybackService`) — the same structural
  category as `MediaButtonReceiver`: exported so the platform's
  media-session framework and hardware controls can reach them, with no
  meaningful permission an app could add without breaking that
  integration. 1 is Fennec's `CustomTabsService` — a documented
  cross-app API contract, not a system-bound service, but still
  structurally required to be exported. 1 is VLC's
  `RemoteAccessService`, which fits neither pattern — ordinary
  app-specific functionality (a remote-access/web-server feature), a
  real finding with no evidence otherwise.
- **3 providers, all VLC.** `TVSearchProvider` (has `<path-permission>`,
  already severity-downgraded to `high`, not `critical`),
  `FileProvider` and `ArtworkProvider` (`critical`, no
  `<path-permission>`). Whether VLC's `FileProvider` extends
  `androidx.core.content.FileProvider` is unverifiable without
  decompiling DEX bytecode (out of scope — see "Scope limits" above),
  but the manifest evidence is conclusive on its own: VLC's manifest
  declares `androidx.core.content.FileProvider` as a *separate*,
  correctly-configured entry (`exported=false`,
  `grantUriPermissions=true`) alongside `org.videolan.vlc.FileProvider`
  (`exported=true`, none of the standard pattern's protections). Even
  under the most charitable reading, this specific instance is exported
  with zero mitigations — already a deviation from Google's own
  FileProvider guidance ("you must also set... exported... to false"),
  independent of what class it extends.

**Net result:** after separating out the 1 `CustomTabsService` (a
genuine cross-app contract) and the 1 `RemoteAccessService` (ordinary
app functionality, not obviously platform-required, but a single
finding), the defensible candidate set is roughly 3–5 findings
concentrated almost entirely in **one app** (VLC). A blocking tier
justified by one outlier app's own remote-access feature and file
providers is not a defensible general Android security control — it
would functionally be "block VLC specifically." Not shipped.

**Revisit condition:** this is settled on the current 12-app sample, not
closed permanently. It should be revisited if a wider corpus (more apps,
ideally with different architectural patterns than this batch) shows
service/provider volume that isn't this concentrated — with real field
data, not by relaxing this conclusion on the same sample. The full,
living version of this reasoning — including the exact per-app
component names — is the authoritative source; this section summarizes
it, `rules/MG-004-exported-component.yaml`'s own header comments are
the source of truth and get updated first when anything here changes.

## Baseline mode: adopt without a wall of red

Enterprises have existing debt. A gate that blocks on every pre-existing
finding on day one gets disabled, not fixed. Baseline mode snapshots
current findings and blocks only on *regressions* — new blocking
findings not present in that snapshot — while pre-existing debt passes
silently... except it isn't silent: every grandfathered finding is
still shown in the report, just not counted toward the gate decision.

```sh
# Adopt on a legacy app: snapshot what's already there.
mobilegate baseline -write app-release.apk
# wrote baseline: 2 blocking finding(s) captured to .mobilegate-baseline.yml

# From then on, scan against it.
mobilegate -baseline .mobilegate-baseline.yml app-release.apk
```

**The demo that proves the mechanism, not just describes it:** VLC's
corpus scan (see "Corpus results" below) has two pre-existing findings —
an embedded RSA private key and an explicit cleartext-traffic flag.
After writing a baseline from that state:

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

The baseline file (`.mobilegate-baseline.yml`) is plain, sorted,
diffable YAML meant to be committed and reviewed like any other config
change — not an opaque cache:

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
identical hash. The same identity is reused, unchanged, as the SARIF
output's alert-tracking fingerprint — see the SARIF section below.

**Ratchet, not amnesty:** `baseline -write` always replaces the file
with a full snapshot of what's currently found — it never merges with
what was there before. A finding that gets fixed simply isn't in the
next scan, so it isn't in the next write. It cannot silently stay
grandfathered under a stale entry once it's actually gone.

**Fails closed.** A missing baseline file falls back to strict mode with
an explanatory message (expected on first use). A baseline file that's
corrupt, unreadable, or schema-mismatched *also* falls back to strict —
loudly, on stderr, with every existing finding treated as new — never a
silent pass. Same discipline applies to `.mobilegate.yml` itself: a
missing config is a legitimate default; an invalid one falls back to
safe defaults (strict mode, no suppressions) with a loud warning, not a
crash and not a silent pass.

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
MobileGate reports the configuration fact and stops there — it does not
attempt to guess intent, that's exactly the kind of judgment call that
belongs to the human reviewing the finding.

MG-004 (warning-tier, not part of the gate decision above) fired on
every one of the 12 apps — see the "MG-004: why it isn't blocking"
section above for the full breakdown and why that volume didn't
translate into a defensible blocking tier.

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

## Performance

Tracked in `PERFORMANCE.md` — scan time and peak memory against the
formal acceptance targets (P95 < 90s, peak memory < 1 GB, per APK up to
100 MB), measured against the same 10-app corpus batch every time a
rule is added, so the trend is visible before it becomes a problem
rather than discovered after some future rule pushes a real APK over
the limit. The worst observed case with all current rules active is
well inside both targets.

## SARIF: source-location honesty, severity mapping, and the suppressions gap

The README's SARIF section covers basic usage. This is the full
reasoning behind three design decisions that aren't obvious from the
output alone.

**Why locations are sometimes coarse, on purpose.** SARIF assumes a
finding lives in a source file GitHub can check out and diff.
MobileGate's findings live inside a *compiled binary APK* — there is no
source file for a DEX string pool index or a merged `resources.arsc`
entry, and even the manifest MobileGate actually parses is the
compiled, **merged** `AndroidManifest.xml`, not the source file a
developer edits. Rather than fabricate a plausible-but-wrong location
(worse than an honest one — it actively misleads triage: "I checked
that file, there's nothing there"), MobileGate maps locations honestly:

- **Manifest findings** (MG-002's manifest signal, MG-003, MG-004,
  MG-010) map to `policy.source_manifest_path` in `.mobilegate.yml`
  (default: `app/src/main/AndroidManifest.xml`). This is the one case a
  real repo file is being pointed at. Attribute values match what
  MobileGate actually saw (the manifest merger doesn't rewrite
  `android:exported` or `android:allowBackup`), but **line numbers do
  not correspond** to anything in that file — MobileGate never
  fabricates a line number it can't verify; alerts point at the file,
  not a specific line.
- **Everything else** — MG-001 (DEX strings, `resources.arsc`, asset
  files) and MG-002's `network_security_config.xml`-based signal — has
  **no source-repo equivalent at all** and maps `artifactLocation.uri`
  to the APK file's own name. GitHub lists these alerts but cannot
  render an inline PR diff annotation for them, because there genuinely
  isn't a diffable source location. The real in-artifact location
  (which DEX file, which string pool index, which manifest element) is
  always in the alert's message text and in its `properties`,
  specifically so it's still useful even when the physical location is
  coarse.

**Severity mapping.** GitHub's Critical/High/Medium/Low ranking in the
Security tab reads `security-severity` — confirmed against GitHub's own
docs, read **only** from the rule itself, never from an individual
result. A MobileGate severity maps to GitHub's documented bands
(critical >9.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9) at the middle
of each band:

| MobileGate severity | security-severity | GitHub band |
|---|---|---|
| critical | 9.5 | Critical |
| high | 7.5 | High |
| medium | 5.5 | Medium |
| low | 2.5 | Low |

Because this is rule-level, not result-level, a rule that can produce
findings at more than one severity (MG-004: "high" by default, but
"critical" for an unguarded exported `<provider>` — direct data
exposure, not just an invokable component) reports the **worst severity
actually observed in that run**, not its nominal default — so a
critical provider finding doesn't get silently under-ranked as merely
"high" just because most MG-004 findings aren't providers. The
finding's true, specific severity is still in `properties.severity` on
the result itself.

**The suppressions gap.** SARIF has a native `results[].suppressions`
mechanism, and the obvious design would be to use it so suppressed
findings stay visible in the Security tab without alerting. Confirmed
against GitHub's documentation and a May 2025 GitHub-staff reply on a
public community discussion: **`results[].suppressions` is not
currently honored by GitHub's SARIF ingestion.** A suppressed result
uploaded there would not show as suppressed — it would show as a
normal, active, alerting result, which is the opposite of what
suppression means. Rather than ship something that looks like it works
but silently doesn't, MobileGate omits baselined and
`ignore_rules`-suppressed findings from SARIF output entirely. They
remain fully visible, with their reason, in every other MobileGate
output format (terminal, `-json`, `-markdown`) — this only affects what
reaches GitHub's Security tab.

Verified live, not just reasoned about: suppressing MG-004 via
`ignore_rules` and re-uploading caused GitHub to mark the
previously-open MG-004 alerts **"Fixed"** — not "Suppressed" — since
they simply stopped appearing in the new upload. That's a reasonable
outcome (the alert history is preserved, and "Fixed" is at least
honest about "not currently detected"), but it is a genuinely different
signal than "suppressed with a documented reason": the suppression
*reason* text never reaches GitHub's UI at all with this design.

**Alert tracking across runs.** GitHub tracks an alert's identity
across runs via `partialFingerprints.primaryLocationLineHash` — the
only fingerprint key it actually reads; a value under any other key
name is silently ignored, and if the whole `partialFingerprints` object
is empty, GitHub tries to compute its own from surrounding source
lines, which is meaningless for an artifact location with no verified
line. MobileGate puts its own `finding_hash` under that exact key — the
same stable identity baseline mode uses (see "Baseline mode" above) —
rather than a source-line-derived value. Verified live: re-uploading an
identical scan updated the existing 6 alerts in place (same alert
numbers, `most_recent_instance.commit_sha` bumped) rather than creating
6 new ones.
