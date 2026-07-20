#!/bin/sh
# Fetches the MG-001 recall/precision corpus documented in README.md
# ("MG-001 corpus — batch 1"). Not wired into the Makefile's
# fetch-testdata target deliberately: that target fetches the two small,
# essential parser-oracle fixtures every dev needs; this one pulls
# ~1 GB across 10 apps for a one-off measurement exercise, which
# shouldn't be a default of `make fetch-testdata`. Verifies each
# download's SHA-256 against README.md before keeping it.
#
# Usage: sh testdata/real/fetch-corpus.sh
set -eu
cd "$(dirname "$0")"

fetch() {
	file="$1"
	url="$2"
	sha="$3"
	if [ -f "$file" ]; then
		echo "$file already present"
	else
		curl -sSL -o "$file" "$url"
	fi
	echo "$sha  $file" | shasum -a 256 -c -
}

fetch org.mozilla.fennec_fdroid_1520620.apk    https://f-droid.org/repo/org.mozilla.fennec_fdroid_1520620.apk    f53af67d4ea0a7b42c456f6c6a4302e17d6ba30684482feaf20c8ef7b63ba210
fetch org.videolan.vlc_13070108.apk            https://f-droid.org/repo/org.videolan.vlc_13070108.apk            4a9144fadfd8606cc5c0e9db892fd24846b7b2efeb1630db5377955d1612b119
fetch eu.siacs.conversations_4217804.apk       https://f-droid.org/repo/eu.siacs.conversations_4217804.apk       dac24c81ba4ca0bbb73dfa11c42eaa90c34fd8375941a0874b37159e2ac07e4d
fetch com.nextcloud.client_340000190.apk       https://f-droid.org/repo/com.nextcloud.client_340000190.apk       005bc619ca577baee8da6e3c160bb99e6a172c46c6b5f9feddfe123fcfd01b07
fetch de.danoeh.antennapod_3110495.apk         https://f-droid.org/repo/de.danoeh.antennapod_3110495.apk         8faee459f952e62e5c12be18620911b01c15b5fa0ee67768dcf8ae1e1a68b09c
fetch com.termux_1002.apk                      https://f-droid.org/repo/com.termux_1002.apk                      e6265a57eb5ca363808488e3b01955958bed93bc0c8a0d281849b363b11027ec
fetch org.dolphinemu.dolphinemu_42460.apk      https://f-droid.org/repo/org.dolphinemu.dolphinemu_42460.apk      5279425e01c552ba6cde1adc7f08f1c1f5b8f9271c2418a4ad849ee4106ee719
fetch com.kunzisoft.keepass.libre_44500.apk    https://f-droid.org/repo/com.kunzisoft.keepass.libre_44500.apk    23d6917bf11fcde7f4a2b8072faa893df857955d6201244e370357bd7d65c598
fetch me.zhanghai.android.files_39.apk         https://f-droid.org/repo/me.zhanghai.android.files_39.apk         ebc5138b6f713f0f73b5467a1a8a4ac3ccfcb2e82135372665b6811a8947641f
fetch com.keylesspalace.tusky_142.apk          https://f-droid.org/repo/com.keylesspalace.tusky_142.apk          3e8fcc49a80d4c30ab6f6037e51402c77e2694d27ec19ae5b8a93cd08b6caffa

echo "corpus batch 1 ready"
