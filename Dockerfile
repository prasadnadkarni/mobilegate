# Built by goreleaser (.goreleaser.yml's dockers_v2: block), not
# directly — goreleaser cross-compiles the binary per platform and
# stages the build context as <platform>/mobilegate (e.g.
# linux/amd64/mobilegate), which $TARGETPLATFORM below selects; this
# file only packages the already-built binary. scratch, not distroless:
# MobileGate is a single static Go binary with no runtime dependencies
# (no libc, no shell, no shelling out — CLAUDE.md's own hard
# constraints) and makes no network calls during a scan, so there's
# nothing distroless would provide (a shell, CA certs, /etc/passwd)
# that this image needs.
FROM scratch
ARG TARGETPLATFORM
WORKDIR /work
COPY $TARGETPLATFORM/mobilegate /mobilegate
ENTRYPOINT ["/mobilegate"]
