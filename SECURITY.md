# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, **please do not open a public GitHub issue**.

Instead, report it privately using **GitHub's Private Vulnerability Reporting** by clicking **"Report a vulnerability"** in the **Security** tab of this repository.

### What to Include

Please include the following information:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The potential security impact
- A suggested fix (if available)

### Response Timeline

- I will acknowledge your report within **48 hours**.
- I will aim to resolve confirmed vulnerabilities within **7 days**.

## Scope

MobileGate parses untrusted, potentially adversarial binary input. The
following are in scope:

- Memory-safety or resource-exhaustion issues triggered by a crafted APK
  (unbounded allocation, decompression bombs, hangs, panics in the ZIP,
  DEX, ARSC, binary-XML, or MUTF-8 parsers)
- Bypasses that cause a genuinely failing APK to be reported as PASS —
  e.g. hiding a credential where the scanner does not look, or crafting
  a config/baseline file that suppresses a finding it should not
- Path traversal or arbitrary file write via crafted archive entries
- Secrets or local filesystem paths leaking into JSON, SARIF, or
  Markdown output
- Vulnerabilities in the GitHub Action wrapper (command injection via
  inputs, token exposure in logs)

## Out of Scope

- False positives, and known detection gaps documented in DESIGN.md
  (no DEX bytecode analysis, no `lib/*.so` parsing, Android only) —
  these are documented architectural limits, not vulnerabilities
- Vulnerabilities in third-party dependencies already tracked upstream
- Social engineering
- Network-level DoS against GitHub or other infrastructure
