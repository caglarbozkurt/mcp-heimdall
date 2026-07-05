# Changelog

All notable changes to Heimdall are documented here. This project adheres to
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-07-05

### Added

- **Python coverage.** Capability, provenance, dependency, and CVE analysis now cover Python
  MCP servers, not just JS/TS. A Python dialect of the capability rules (regex over `.py`:
  `subprocess`/`os.system` → exec, `requests`/`httpx`/`aiohttp` → net, `os.environ` → env,
  `eval`/`exec`/`compile` → dynamic-eval, credential paths → secret-access), provenance from
  `pyproject.toml` / `requirements.txt` / `setup.py` (dangerous `setup.py` gates like an npm
  install script), and CVE lookups via OSV's **PyPI** ecosystem. Resolve a published server
  with `heimdall pypi:<name>`. Injection was already language-agnostic. (Proven taint stays
  JS/TS-only — Python falls back to capability co-presence, a conservative gate.)
- **Behavioral validation (`heimdall validate`)** — the missing third leg after the
  distribution run and the labeled corpus. It runs the server with a capability recorder
  preloaded (hooks `fs`/`net`/`http(s)`/`dns`/`child_process`/`vm`/`fetch`/`process.env`),
  drives each tool with synthesized arguments, and diffs the *observed* runtime capabilities
  against the static `report.capabilities`: **confirmed** (flagged and observed), **not
  exercised** (flagged, not triggered — a lower bound, not proof of a false positive), and
  **missed** (observed but not flagged — a real static gap to review). Reads own-package
  file access and npx bootstrap as noise and filters them. Single-server and `--list` batch
  (recall metric). Diagnostic, not a CI gate.
- **Sandboxed execution for `validate`** — each server runs in a throwaway `HOME` + working
  directory (filesystem side effects can't touch the real home) with no inherited secrets,
  reusing the real npm cache for speed. Still runs untrusted code with network/exec side
  effects — VM/container only for anything beyond a curated list.

### Changed

- **Wider capability detection** (driven by the behavioral run's misses): expanded the
  dependency→capability map with service SDKs and HTTP clients (`googleapis`,
  `google-auth-library`, `isomorphic-fetch`, `@mendable/firecrawl-js`, …), added family/scoped
  matching (`@aws-sdk/*`, `@google-cloud/*`, `@octokit/*`, and the scoped `@github/keytar` fork
  the exact-name map was missing), and added `vm` (`runInContext` / `compileFunction` / `new
  vm.Script`) to dynamic-eval detection.

### Validated

- **Behavioral field run over 200 real MCP packages** (`benchmarks/validate-run.md`): 55 booted,
  34 exercised an observable capability. Of capabilities servers actually exercised at runtime,
  static analysis flagged **80.9%** (55/68) — up from 75.8% in the first run after the recall
  fixes above (network misses roughly halved). The misses that remain are structural — a
  capability exercised inside a dependency's internals or a subprocess, which static analysis
  can't see (the reason `validate` exists as a backstop).

## [0.2.0] — 2026-07-04

### Added

- **Known-CVE check (`--online`)** — declared dependencies are checked against the
  [OSV.dev](https://osv.dev) advisory database. Opt-in because it is the only analyzer that
  reaches the network; it sends dependency names + versions (never source). Findings are
  severity-ranked with real CVE/GHSA IDs, itemized worst-first per dependency with a rollup,
  and flow through the policy engine like any other finding (WARN by default, FAIL under
  `strict` or any `failOnSeverity: high` policy — never a hard gate, since a manifest range
  is not a lockfile). Works in the CLI and the browser build (OSV.dev is CORS-enabled). New
  policy fact `no_known_vulnerabilities`. Network failures degrade to an informational notice.
- **CVE toggle in both web UIs** — "Also check dependencies for known CVEs" (off by default).

### Changed

- **Field run expanded to 2,500 real MCP packages** (`benchmarks/`): 1,726 scanned, 0.7%
  flagged. Ecosystem snapshot: ~45% of servers can run shell, 9% can `eval`, 34% can do both
  exec + network. README and `benchmarks/field-run.md` updated.

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
