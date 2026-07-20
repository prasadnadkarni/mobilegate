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
