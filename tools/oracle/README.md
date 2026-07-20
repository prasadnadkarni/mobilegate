# Parser oracles

Development-time correctness checks. Each shells out to independent,
from-scratch Android tooling to get a ground-truth read of a real APK,
then diffs that against what our own parser extracted — catching
"parses without crashing but got the wrong answer" bugs that a plain
`go test` run against synthetic fixtures could miss.

Neither is a runtime dependency and neither ships — see the build-tag
comment at the top of each `*_test.go` file. CLAUDE.md's "no shelling out
to anything JVM-based" constraint governs the shipped detection/gate
path; this is developer tooling that never runs in CI or in the
`mobilegate` binary.

## Run

```sh
make oracle
```

Requires Android SDK cmdline-tools (`apkanalyzer`) and/or build-tools
(`aapt2`, `dexdump`), found via `PATH`, `$ANDROID_HOME`, or
`$ANDROID_SDK_ROOT`. Each test skips independently, with a message
explaining what to install, if its tool isn't found — a missing
`dexdump` doesn't block the manifest check or vice versa.

## Manifest oracle (`manifest_oracle_test.go`)

`apkanalyzer manifest print` reconstructs a real, literal
`AndroidManifest.xml` from the binary manifest — the highest-fidelity
ground truth available without writing our own second parser. We diff:

- package name
- `android:usesCleartextTraffic` on `<application>`
- for every `<activity>`/`<service>`/`<receiver>`/`<provider>`:
  `android:exported` and `android:permission`

Falls back to `aapt2 dump badging` (package name only — its summary
format doesn't surface per-component `exported`/`permission`, and `aapt2
dump xmltree`'s text format has changed shape across SDK versions, so we
don't attempt to parse it structurally) if `apkanalyzer` isn't available.

**Verified it actually catches regressions:** temporarily forced
`tristateFrom` in `pkg/parser/manifest/manifest.go` to always return
`True`, ran `make oracle`, and it failed with a precise per-component
diff (11 components' `exported` wrongly `true`, `usesCleartextTraffic`
wrongly `true`). Reverted before committing anything.

## DEX oracle (`dex_oracle_test.go`)

This is the higher-risk one: `pkg/parser/dex` is our own hand-rolled
parser with no maintained library backing it, unlike the manifest path.
`dexdump -f` (Android SDK build-tools, a from-scratch AOSP implementation
of the DEX format) prints each dex file's header, including
`string_ids_size`. For every `classes*.dex` in the APK, we extract it via
our own `pkg/parser/apk`, write it to a temp file, run `dexdump -f` on
that exact file, and assert our `dex.ParseStrings` count matches
`string_ids_size` exactly.

Runs against both fixtures: the single-dex flashlight APK and the
multi-dex NewPipe APK (`classes.dex` + `classes2.dex`), so multi-dex
attribution gets checked against real input, not only the synthetic
`TestParseStrings_MultiDexAttribution` unit test.

**Verified it actually catches regressions:** temporarily made
`ParseStrings` in `pkg/parser/dex/dex.go` drop the last string
(`return out[:len(out)-1], nil`), ran `make oracle`, and it failed on all
three dex files across both fixtures with an exact off-by-one diff
(e.g. `string count parser=21605 dexdump string_ids_size=21606`).
Reverted before committing anything.

## ARSC string pool oracle (`arsc_oracle_test.go`)

Same situation as DEX: `pkg/parser/arsc` is hand-rolled, because
`androidbinary`'s `TableFile` has no public way to enumerate the
resources.arsc string pool (confirmed via `go doc` before writing any
custom code — see that package's doc comment). `aapt2 dump strings` gives
an independent, from-scratch reading of the same pool.

This one compares as a **multiset**, not index-by-index: during
development, `aapt2 dump strings`' printed `String #N` index turned out
not to correspond to the pool's physical on-disk index (confirmed by
manually decoding the raw bytes per the resources.arsc spec, independent
of both implementations — the manual decode matched our extraction
exactly at the indices where aapt2's dump diverged). So instead we assert
every string our extraction returns exists in aapt2's dump with the same
multiplicity, and vice versa — order-independent, but still catches any
truncation, offset, or UTF-8/UTF-16 decoding bug, since those show up as
missing/extra/corrupted entries in the diff regardless of ordering.
Confirmed on both real fixtures: 47,448 and 60,323 strings, zero
divergence.

**Verified it actually catches regressions:** temporarily made
`parseStringPool` in `pkg/parser/arsc/arsc.go` drop the last string
(`return out[:len(out)-1], nil`), ran `make oracle`, and it failed on
both fixtures with an exact one-string diff naming the specific dropped
string (e.g. `only in aapt2's dump: "Urinishlar soni ko'payib ketdi..."`).
Reverted before committing anything.
