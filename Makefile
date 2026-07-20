.PHONY: build test oracle fetch-testdata clean

TEST_APK := testdata/real/com.simplemobiletools.flashlight_66.apk
TEST_APK_URL := https://f-droid.org/repo/com.simplemobiletools.flashlight_66.apk
TEST_APK_SHA256 := b4cd07c40a3d5711461670a2f460a1447acf3836c0e90471b7ba5c8b4c2f9bb3

# Multi-dex fixture: NewPipe ships classes.dex + classes2.dex, unlike the
# single-dex flashlight fixture above, so this is the only fixture that
# exercises multi-dex attribution against real input.
MULTIDEX_APK := testdata/real/org.schabi.newpipe_1013.apk
MULTIDEX_APK_URL := https://f-droid.org/repo/org.schabi.newpipe_1013.apk
MULTIDEX_APK_SHA256 := 88a1c99ca48394af431b24379783165860aaab3f7f45cce9ca6b8a7d2139a4d6

# NSC fixture: Tusky is the only app in the batch-1 corpus with an actual
# <domain-config> block (cleartext permitted for .onion domains) rather
# than base-config-only — needed to oracle-verify pkg/parser/nsc's whole
# reason for existing (domain CDATA text), not just its structure.
NSC_APK := testdata/real/com.keylesspalace.tusky_142.apk
NSC_APK_URL := https://f-droid.org/repo/com.keylesspalace.tusky_142.apk
NSC_APK_SHA256 := 3e8fcc49a80d4c30ab6f6037e51402c77e2694d27ec19ae5b8a93cd08b6caffa

build:
	go build -o mobilegate ./cmd/mobilegate

test:
	go test ./...

# fetch-testdata downloads the pinned dev-verification APK documented in
# testdata/real/README.md. Never committed — see .gitignore.
fetch-testdata:
	@if [ -f $(TEST_APK) ]; then \
		echo "$(TEST_APK) already present"; \
	else \
		curl -sSL -o $(TEST_APK) $(TEST_APK_URL); \
	fi
	@echo "$(TEST_APK_SHA256)  $(TEST_APK)" | shasum -a 256 -c -
	@if [ -f $(MULTIDEX_APK) ]; then \
		echo "$(MULTIDEX_APK) already present"; \
	else \
		curl -sSL -o $(MULTIDEX_APK) $(MULTIDEX_APK_URL); \
	fi
	@echo "$(MULTIDEX_APK_SHA256)  $(MULTIDEX_APK)" | shasum -a 256 -c -
	@if [ -f $(NSC_APK) ]; then \
		echo "$(NSC_APK) already present"; \
	else \
		curl -sSL -o $(NSC_APK) $(NSC_APK_URL); \
	fi
	@echo "$(NSC_APK_SHA256)  $(NSC_APK)" | shasum -a 256 -c -

# oracle cross-checks parsed manifest fields against a real Android-SDK
# tool (apkanalyzer or aapt2) as a correctness check independent of our
# own parsing code. Dev-time only: requires the Android SDK command-line
# tools on PATH, is gated behind the "oracle" build tag so it never
# compiles into the release binary or runs in a normal `make test` /
# `go test ./...`, and never ships. See tools/oracle/README.md.
oracle: fetch-testdata
	MOBILEGATE_ORACLE_APK=$(abspath $(TEST_APK)) \
	MOBILEGATE_ORACLE_MULTIDEX_APK=$(abspath $(MULTIDEX_APK)) \
	MOBILEGATE_ORACLE_NSC_APK=$(abspath $(NSC_APK)) \
	go test -tags oracle ./tools/oracle/... -v

clean:
	rm -f mobilegate
