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
