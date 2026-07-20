# Contributing to MobileGate

Read `CLAUDE.md` first. It's the project's actual constitution — hard
constraints that override anything below if the two ever conflict.

## The precision bar is the whole point

This tool's product promise is "a clean APK produces zero blocking
findings." A blocking rule that fires on a clean app is treated as a
worse failure than one that misses a real issue: the false positive
gets the tool disabled entirely, the miss is caught by the human review
this gate sits alongside. That tradeoff governs every PR review here,
not just new-rule PRs.

**No rule enters the blocking tier until it passes the full
negative-fixture suite with zero false positives.** If a candidate rule
can't hit that, it ships as a warning until it can — that's not a
consolation prize, it's the correct outcome. Passing the negative suite
is the harder, more important requirement; "clean APK → PASS" is the
product.

## Before proposing a new rule or signal

1. Check whether it needs DEX bytecode/method-body analysis or
   `lib/*.so` ELF parsing. If it does, it's out of scope until there's a
   deliberate decision to add that capability generally — see the
   README's "Scope limits" section and the "NOT implemented" comments
   in `rules/MG-002-cleartext-transport.yaml` and
   `rules/MG-003-plaintext-storage.yaml` for the reasoning already
   worked through on this exact question, twice.
2. Write both positive fixtures (a minimal case that should fire) and
   negative fixtures (clean-but-tricky cases that should not) before
   writing the detection logic. The negative fixtures are the actual
   spec.
3. Document what the signal does *not* cover in the rule's own YAML
   header, in the same style as the existing four rules. A rule with no
   documented scope boundary reads as "we didn't think about this,"
   even when the boundary was in fact considered.

## Test fixtures

**Synthetic and self-authored only.** Never use findings, binaries, or
data from any real client engagement, even anonymized — this is a
confidentiality exposure and does not belong anywhere near a public
repo. The real-APK fixtures under `testdata/real/` are small,
actively-maintained, open-source F-Droid apps, fetched on demand and
never committed (see `testdata/real/README.md`) — they exist for
parser-oracle verification and corpus-scale precision measurement, not
as a substitute for hand-authored positive/negative rule fixtures.

## Build and test

```sh
go build -o mobilegate ./cmd/mobilegate
go test ./...                    # unit + fixture suites, no external tools needed
make fetch-testdata               # pulls the two pinned dev-verification APKs
make oracle                       # cross-checks parsers against aapt2/apkanalyzer/dexdump
```

`make oracle` requires Android SDK cmdline-tools/build-tools on `PATH`
or via `$ANDROID_HOME`/`$ANDROID_SDK_ROOT`. It's development-only —
gated behind the `oracle` build tag so it never compiles into the
shipped binary and never runs in CI. If you touch a parser
(`pkg/parser/*`), run it; if you add a new hand-rolled parser, add an
oracle for it and mutation-test it (temporarily break the parser in an
obvious way, confirm the oracle fails with a precise diff, revert) —
see `tools/oracle/README.md` for five worked examples of exactly this.

Before sending a PR:

```sh
gofmt -l -w .
go build ./... && go build -tags oracle ./...
go vet ./... && go vet -tags oracle ./...
go test ./...
```

## Scope discipline

If a change isn't part of what you're actually fixing, don't make it —
ask first. Concretely, resist: adding iOS scaffolding of any kind,
adding a config option not already reflected in `.mobilegate.yml`'s
documented schema, adding a fifth blocking rule without the fixture
work above, or "while I'm in here" refactors bundled into an unrelated
fix. Small, reviewable, single-purpose PRs.

## Commit messages

Explain the *why*, not just the *what* — especially for anything that
narrows or widens a rule's scope. "Tighten `private-key-header` to
require an actual key body" is a good subject line; the body should say
what false positive prompted it. Future readers (including future you)
will be relitigating these scope decisions off the code alone unless
the reasoning is in the history.

## License

By contributing, you agree your contribution is licensed under this
project's Apache License 2.0 (see `LICENSE`) — no separate CLA.
