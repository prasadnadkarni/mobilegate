// Package rules embeds MobileGate's rule definitions (see
// mobile-security-release-gate-build-prompt-v2.1.md: "Rules as data, not
// hardcoded logic in Go"). Embedding keeps the shipped binary a single
// static file with no runtime dependency on finding these files on disk —
// CLAUDE.md's "single static binary" constraint.
package rules

import "embed"

//go:embed *.yaml
var FS embed.FS
