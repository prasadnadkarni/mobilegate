# Real-APK dev fixture

`.apk` files in this directory are **never committed** (see `.gitignore`).
They exist only for local, developer-run verification that the parser
handles a real-world APK, not the hand-authored `/testdata/positive` and
`/testdata/negative` synthetic fixtures used by the rule-engine test suite.

We use a small, actively maintained, open-source F-Droid app rather than
any client or production APK — see `CLAUDE.md`: test fixtures must never
come from a real client engagement, and redistributing someone else's
binary in this repo isn't ours to do even for an open-source app, hence
"fetch on demand, don't commit."

## Fetch

```sh
make fetch-testdata
```

This downloads and SHA-256-verifies:

- App: Simple Flashlight (`com.simplemobiletools.flashlight`), F-Droid
- File: `com.simplemobiletools.flashlight_66.apk` (versionName 5.10.1)
- URL: `https://f-droid.org/repo/com.simplemobiletools.flashlight_66.apk`
- SHA-256: `b4cd07c40a3d5711461670a2f460a1447acf3836c0e90471b7ba5c8b4c2f9bb3`

Picked because it's small (~10 MB), has a non-trivial manifest (a dozen+
activities/services/receivers with a mix of exported/non-exported and a
permission-guarded service), and is single-dex — good enough to eyeball
step-1 parser output against. It is not a substitute for the synthetic
positive/negative fixtures rule development needs later.

It also fetches a second, multi-dex fixture, needed because the app
above has only one `classes.dex` and can't exercise multi-dex
attribution against real input:

- App: NewPipe (`org.schabi.newpipe`), F-Droid
- File: `org.schabi.newpipe_1013.apk` (versionName 0.28.8)
- URL: `https://f-droid.org/repo/org.schabi.newpipe_1013.apk`
- SHA-256: `88a1c99ca48394af431b24379783165860aaab3f7f45cce9ca6b8a7d2139a4d6`
- Contains `classes.dex` (64,901 strings) + `classes2.dex` (3,778 strings)

To point the CLI or the oracle tests at a different APK (any legally
redistributable one works fine — it doesn't need to be either of these
exact apps), just download it here yourself; nothing else assumes these
specific files.

## Use

```sh
go run ./cmd/mobilegate testdata/real/com.simplemobiletools.flashlight_66.apk
go run ./cmd/mobilegate testdata/real/org.schabi.newpipe_1013.apk   # multi-dex
make oracle   # cross-checks manifest + DEX string counts against apkanalyzer/aapt2/dexdump — see tools/oracle/README.md
```
