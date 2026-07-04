# Changelog

All notable changes to Heimdall are documented here. This project adheres to
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-04

Initial release.

### Detection

- **Prompt-injection / tool-poisoning** across all three model-facing surfaces — tools,
  resources, and prompts (and their parameters): instruction-override, concealment,
  fake authority tags (`<IMPORTANT>`), hidden/zero-width characters, base64 blobs,
  tool-shadowing.
- **Capability scope** — filesystem, network egress, shell/exec, dynamic `eval`, and
  specific credential detectors (SSH, AWS, cloud/registry, keychain, `.env`), plus
  hardcoded-credential detection (redacted).
- **Taint / data-flow** (via `acorn`, per-function scoped) — proves a credential-file →
  network or fetch → `eval` path as a precise `file:line → file:line` gate; mere
  co-presence of capabilities is a review surface, not an auto-fail.
- **Provenance** — install-time lifecycle scripts, missing repository/license/author.
- **Transitive dependencies** — latent capabilities inferred from declared deps
  (informational and policy-gateable, never auto-fail).
- **Multi-server composition** — audits an MCP client config as a set: cross-server
  injection→exfiltration chains and tool-name collisions.
- **Drift / rug-pull** — per-item surface fingerprints; `--baseline` diff flags a silently
  changed tool definition as a hard gate.

### Model & policy

- Capability (how powerful) is separated from suspicion (how anomalous); verdict is driven
  only by gates and anomalies, decided by a **policy** you control (`default`, `strict`, or
  a JSON file). Per-finding **severity + confidence**. Audited **waivers** with expiry.

### Surfaces

- CLI, library (`mcp-heimdall-scan`), a Claude Code skill, and a local web UI.
- Live **`--handshake`** mode (runs the server for the real tool list; see `SECURITY.md`).
- **SARIF 2.1.0** output for CI / code scanning.
- Calibration harness (`npm run eval`) over a labeled corpus.

### Validated

- 14 tests; a labeled corpus at 100% precision/recall; and a **1000-server field run**
  (`benchmarks/`) which drove two real false-positive fixes (generic file→network, and
  name-based taint conflating bundled code).
