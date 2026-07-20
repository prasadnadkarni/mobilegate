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

## MG-001 corpus — batch 1

A separate, larger set of real APKs for measuring MG-001's recall/precision
and the 90s/1GB performance targets against real-world scan surface —
not parser-oracle fixtures like the two above. Deliberately varied app
categories and sizes (three over 50 MB) rather than ten similar
utilities:

```sh
sh testdata/real/fetch-corpus.sh
```

| App | Package | File | SHA-256 |
|---|---|---|---|
| Firefox (Fennec) — browser | `org.mozilla.fennec_fdroid` | `org.mozilla.fennec_fdroid_1520620.apk` | `f53af67d4ea0a7b42c456f6c6a4302e17d6ba30684482feaf20c8ef7b63ba210` |
| VLC — media player | `org.videolan.vlc` | `org.videolan.vlc_13070108.apk` | `4a9144fadfd8606cc5c0e9db892fd24846b7b2efeb1630db5377955d1612b119` |
| Conversations — XMPP messenger | `eu.siacs.conversations` | `eu.siacs.conversations_4217804.apk` | `dac24c81ba4ca0bbb73dfa11c42eaa90c34fd8375941a0874b37159e2ac07e4d` |
| Nextcloud — cloud storage client | `com.nextcloud.client` | `com.nextcloud.client_340000190.apk` | `005bc619ca577baee8da6e3c160bb99e6a172c46c6b5f9feddfe123fcfd01b07` |
| AntennaPod — podcast player | `de.danoeh.antennapod` | `de.danoeh.antennapod_3110495.apk` | `8faee459f952e62e5c12be18620911b01c15b5fa0ee67768dcf8ae1e1a68b09c` |
| Termux — terminal emulator | `com.termux` | `com.termux_1002.apk` | `e6265a57eb5ca363808488e3b01955958bed93bc0c8a0d281849b363b11027ec` |
| Dolphin — GameCube/Wii emulator | `org.dolphinemu.dolphinemu` | `org.dolphinemu.dolphinemu_42460.apk` | `5279425e01c552ba6cde1adc7f08f1c1f5b8f9271c2418a4ad849ee4106ee719` |
| KeePassDX — password manager | `com.kunzisoft.keepass.libre` | `com.kunzisoft.keepass.libre_44500.apk` | `23d6917bf11fcde7f4a2b8072faa893df857955d6201244e370357bd7d65c598` |
| Material Files — file manager | `me.zhanghai.android.files` | `me.zhanghai.android.files_39.apk` | `ebc5138b6f713f0f73b5467a1a8a4ac3ccfcb2e82135372665b6811a8947641f` |
| Tusky — Mastodon client | `com.keylesspalace.tusky` | `com.keylesspalace.tusky_142.apk` | `3e8fcc49a80d4c30ab6f6037e51402c77e2694d27ec19ae5b8a93cd08b6caffa` |

Results reported in the batch-1 corpus run (see project history / status
report — not duplicated here since these numbers are a point-in-time
measurement, not a fixed spec, and will drift as F-Droid ships new
versions of these apps).
