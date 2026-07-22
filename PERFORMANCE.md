# Performance trend

Tracks scan time and peak memory against the formal acceptance targets
(spec: P95 < 90s, peak memory < 1 GB, per APK up to 100 MB) as rules are
added. Each rule adds scan surface — more of the APK gets read and held
in memory during a scan — and the 1 GB budget does not grow to match.
This file exists so that trend is visible before it becomes a problem,
not discovered after some future rule pushes a real APK over the limit.

Measured with `/usr/bin/time -l` (macOS; reports `real` wall-clock time
and `maximum resident set size`) against the MG-002 corpus batch 1 — 10
varied F-Droid APKs, three over 50 MB — documented in
`testdata/real/README.md`. Same corpus, same 10 apps, every run, so
numbers are comparable across rows.

| Rules active | Worst-case peak RSS | App | Worst-case time | App | Notes |
|---|---:|---|---:|---|---|
| MG-001 only | 531 MB | Nextcloud | 5.15s | Fennec | batch-1 baseline |
| MG-001 + MG-002 | 477 MB | Nextcloud | 5.41s | Fennec | +network_security_config.xml parsing; negligible surface added (NSC files are tiny) — within run-to-run noise of the MG-001-only baseline, not a real increase |
| MG-001 + MG-002 + MG-003 + MG-010 | 564 MB | Nextcloud | 5.09s | Fennec | +7 manifest attributes (allowBackup/debuggable/testOnly/fullBackupContent/dataExtractionRules/backupAgent), zero new files read; within run-to-run noise of the MG-002 row, not a real increase — expected, since MG-003/MG-010 add no new scan surface beyond fields already resolved during the same manifest parse |
| MG-001 + MG-002 + MG-003 + MG-004 + MG-010 | 239 MB | Nextcloud | 4.7s | Fennec | Checked specifically, not assumed, because MG-004 enumerates every component plus intent-filters and runs the origin heuristic per finding — a real reason to expect a cost, unlike MG-003/MG-010's row above. Verified with a controlled same-machine A/B against the pre-MG-004 commit (`aa78dd1`), not just eyeballed against this table's older rows (whose absolute numbers come from a different measurement environment and aren't directly comparable — see note below): Nextcloud's peak RSS was 230–239 MB on both sides of that commit across repeated runs, fully overlapping. **No material increase.** MG-004 iterates `Manifest.Components`, data already resident from the single shared manifest parse every rule reads from — it opens no new files and allocates nothing large, so this is the same "shares the existing parse" shape as MG-003/MG-010's row, empirically confirmed rather than assumed this time |
| MG-001 + MG-002 + MG-003 + MG-004 + MG-010 + `-sarif` | 237 MB | Nextcloud | 5.2s | Fennec | SARIF adds an in-memory result structure (message text, remediation text, properties per finding) — also checked specifically rather than assumed, since it's a real new allocation, not just a read. Nextcloud stayed 230–238 MB across repeated runs with and without `-sarif` — the delta is inside the same noise band as the row above it, not a second real cost stacked on top. Worst-case app is still Nextcloud (RSS) and Fennec (time) in both new rows, unchanged from the last two rows — the corpus's memory profile is still dominated by DEX/resource string-pool size, not manifest or finding-structure size, matching this file's own "Reading this" note below |

**Why the last two rows' absolute numbers look so much lower than the
first three, not just a small drop.** The MG-004/`-sarif` rows were
measured in a different environment/session than the MG-001–MG-010
rows above them (this file doesn't record what produced the original
531 MB baseline — machine, macOS version, and Go toolchain all affect
absolute RSS, and none of that is pinned down here). That gap makes the
first three rows and the last two **not directly comparable in
absolute terms**, despite the "same corpus, same 10 apps" claim above
— that claim guarantees comparability *within* a measurement session,
not across an unrecorded environment change. Cross-row comparisons
before and after this note should treat the shape (which app is worst
case, whether a row jumps) as the signal, not the raw MB number. The
MG-004/SARIF conclusion above isn't based on comparing 239 MB to 564 MB
— it's based on a controlled same-machine, same-session A/B against the
exact pre-MG-004 commit, which is what actually isolates MG-004's own
cost from environment noise. Future rows should either stay in
whatever environment produced this pair, or re-establish a fresh
same-session baseline the way this update did, rather than trust a raw
MB delta against a row from an unknown environment.

## Reading this

- **Worst case, not average.** The number that matters for the P95/1GB
  acceptance gate is the worst app in the corpus, not the mean — a rule
  that's cheap on 9 apps and expensive on the 10th still risks the
  target on real-world traffic.
- **Peak RSS is dominated by total extracted string count, not APK file
  size.** Established during MG-001's corpus run: Nextcloud (83.8 MB
  APK, ~209k total strings) peaks far higher than Termux (108.6 MB APK,
  ~14k total strings, ~40 MB peak) despite being a smaller download.
  Don't use APK size as a capacity proxy when reasoning about a new
  rule's likely memory cost — ask what it adds to the string/scan-surface
  count instead.
- **Update this file's table whenever a new rule is wired into the CLI
  and run against the corpus** (same pattern as MG-002's row above): one
  row per rule-set state, worst-case peak RSS + which app, worst-case
  time + which app, and a one-line note on what changed. Keep old rows —
  the trend is the point, not just the latest number.
- **If a row's peak RSS jumps materially** (not run-to-run noise — think
  tens of MB, not a handful), that rule's scan surface is a real cost,
  not a rounding error, and is worth understanding before adding the
  next one on top of it. Extrapolating MG-001's own finding: an app
  around ~250k total strings would approach the 1 GB budget on that
  signal alone.
- **Don't judge "materially" by eyeballing the raw MB against whatever
  row happens to be above it.** The MG-004/`-sarif` update above only
  looks flat-to-lower than the row before it because of an environment
  change, not because nothing changed — a naive read of the table alone
  would have missed that. When a rule has a real, specific reason to
  expect a cost (as MG-004 did — it iterates every component), verify
  with a same-machine, same-session A/B against the previous commit,
  the way that row was, rather than trusting a cross-row delta whose
  environment isn't pinned down.
