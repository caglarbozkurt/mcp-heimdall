<div align="center">

<img src="assets/logo.svg" width="84" alt="Heimdall" />

# Heimdall

**The watchman at your agent's gate.**

A security scanner for **Model Context Protocol (MCP) servers** — vet a server,
or a whole agent config, before your agent trusts it.

[![npm](https://img.shields.io/npm/v/mcp-heimdall-scan)](https://www.npmjs.com/package/mcp-heimdall-scan)
[![CI](https://github.com/caglarbozkurt/mcp-heimdall/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/caglarbozkurt/mcp-heimdall/actions/workflows/ci.yml)
[![downloads](https://img.shields.io/npm/dm/mcp-heimdall-scan)](https://www.npmjs.com/package/mcp-heimdall-scan)
[![license](https://img.shields.io/github/license/caglarbozkurt/mcp-heimdall)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A518.17-3fb950)](package.json)
[![try in your browser](https://img.shields.io/badge/try-in%20your%20browser-e3b341)](https://caglarbozkurt.github.io/mcp-heimdall)

</div>

---

MCP servers are unvetted code with a natural-language attack surface: their tool
descriptions go straight to your model, and the server runs with your machine's access.
Heimdall scores **what a server can actually do** — not what it claims — and cites the
exact evidence.

## Quickstart

```bash
npx mcp-heimdall-scan firecrawl-mcp                   # scan a published server
npx mcp-heimdall-scan ./claude_desktop_config.json    # audit your whole agent config
npx mcp-heimdall-scan firecrawl-mcp --online          # + check its deps for known CVEs (OSV.dev)
npx mcp-heimdall-scan ./my-server --policy strict     # gate it in CI
```

No install, runs locally, nothing leaves your machine.

**Or try it in your browser:** [caglarbozkurt.github.io/mcp-heimdall](https://caglarbozkurt.github.io/mcp-heimdall)
— the full scanner runs **100% client-side** (npm packages are fetched via jsDelivr; or paste a
`tools.json` / MCP config). No backend, nothing uploaded. Local paths and `--handshake` need the CLI.

## What it checks

| Check | What it catches |
|---|---|
| 🧬 **Injection** | tool-poisoning across tools, resources & prompts — override, concealment, hidden chars, fake `<IMPORTANT>` tags |
| 🔓 **Capability** | filesystem, network, shell, `eval`, and specific credential access (SSH / AWS / keychain / `.env`) |
| 🎯 **Proven exfil paths** | data-flow that *proves* `secret → network` or `fetch → eval`, `file:line → file:line` |
| 📦 **Provenance & deps** | install-time scripts, missing repo/license, capabilities inherited from dependencies |
| 🛡️ **Known CVEs** *(opt-in)* | declared dependencies checked against the OSV.dev advisory DB — real CVE IDs, severity-ranked (`--online`) |
| 🕸️ **Composition** | audits a whole config: cross-server exfiltration chains & tool-name collisions |
| 🔁 **Drift** | fingerprints the surface — a silently changed tool description (rug-pull) is a hard fail |

Every finding cites `file:line` or `tool:name`. **Capability ≠ risk:** raw power is shown as
an informational profile and never fails the scan — only hard **gates** and real **anomalies** do.

## What makes it different

- **Sees the whole gate.** It reasons across the *set* of servers you've configured — the
  cross-server exfil path neither server shows alone. Most scanners look at one at a time.
- **Proves the path.** Taint/data-flow turns "reads files AND has network = fail" into a
  concrete, located flow — so it doesn't cry wolf on a config read plus an unrelated API call.
- **A gate you control.** Detectors emit facts; a **policy** you define turns them into
  pass / warn / fail. Deny capabilities, require provenance, add audited waivers, gate CI.

## Usage

```bash
heimdall <target> [options]
```

| Target | Example |
|---|---|
| local directory | `heimdall ./servers/my-mcp` |
| npm package | `heimdall some-mcp-package` |
| PyPI package | `heimdall pypi:some-mcp-server` |
| git repository | `heimdall https://github.com/user/repo` |
| tools/list dump | `heimdall tools.json` |
| MCP client config | `heimdall ./claude_desktop_config.json` |

<details>
<summary><b>Options</b></summary>

```
--tools <file>     supplement analysis with a tools/list (or {tools,resources,prompts}) dump
--policy <p>       "default", "strict", or a JSON policy file
--baseline <file>  diff against a prior --json report (drift / rug-pull detection)
--handshake        RUN the server(s) for the live tool list (untrusted code — VM/container only)
--online           check declared deps against OSV.dev for known CVEs (sends dep names, not source)
--json             machine-readable report
--sarif            SARIF 2.1.0 (GitHub code-scanning / CI)
--no-fail          always exit 0

Exit codes: 0 pass/warn · 1 fail · 2 error
```
</details>

## Policies

Detectors emit facts; a **policy** turns them into the verdict. Ship the default, pick
`strict`, or write your own procurement/security criteria:

<details>
<summary><b>Example policy</b> (<code>policy.example.json</code>)</summary>

```json
{
  "name": "acme-procurement",
  "denyCapabilities": ["exec", "dynamic-eval", "secret-access"],
  "require": ["has_repository", "has_license"],
  "failOnSeverity": "high",
  "warnOnSeverity": "low",
  "allow": [{ "id": "capability/scope-mismatch", "reason": "reviewed", "expires": "2026-12-31" }]
}
```
Waivers carry a reason and optional expiry — an expired waiver lapses and re-flags.
</details>

## Library

```ts
import { scan } from "mcp-heimdall-scan";

const report = await scan("some-mcp-server", { policy: "strict" });
if (report.verdict === "fail") throw new Error(report.reasons.join("; "));
```

Also ships as a **Claude Code skill** (`skill/`) — vet a server in-conversation before installing.

## Validate (behavioral cross-check)

Static analysis says what a server *can* do. `heimdall validate` checks that against what it
*actually does* — it runs the server with a capability recorder preloaded (hooking
`fs` / `net` / `http(s)` / `child_process` / `vm` / `fetch` / `process.env`), drives each tool,
and diffs observed runtime behavior against the static flags:

```bash
heimdall validate ./my-server            # one server: confirmed / missed / not-exercised
heimdall validate --list servers.txt     # batch: a recall number over observed behavior
```

- **confirmed** — flagged *and* observed (the static claim held up).
- **not exercised** — flagged but not triggered by naive args (a *lower bound*, **not** proof the flag is wrong).
- **missed** — observed but **not** flagged → a real static gap to review (or an incidental library side effect).

So it's trustworthy for finding false **negatives** (static misses); it does not disprove a flag.
Each server runs in a throwaway `HOME` + working directory with no inherited secrets, but it
still **runs the server and calls its tools** (network/exec side effects) — use a disposable VM/container.

**Behavioral run over 200 real packages** ([`benchmarks/validate-run.md`](benchmarks/validate-run.md)):
55 booted, 34 exercised an observable capability. Of the capabilities servers *actually
exercised at runtime*, the static scan flagged **80.9%** (55/68) — up from 75.8% after the
first run's misses became a fix-list (we widened dependency-based network detection, which
roughly halved the network misses). The misses that remain are **structural**: a capability
exercised *inside a dependency's internals or a subprocess*, which static analysis fundamentally
can't see — which is exactly why `validate` exists as the backstop. Honest recall, openly
reported, improving run over run.

## Tested at scale

Run against **2,500 real MCP packages** from the npm registry (`benchmarks/`): **1,726 scanned**
in ~5 minutes, **0.7% flagged** — robust on messy real-world code. Separately, **100%
precision / recall** on a small labeled corpus (`npm run eval`), including the Damn Vulnerable
MCP project. Full log: [`benchmarks/field-run.md`](benchmarks/field-run.md).

What that scan says about the ecosystem your agent trusts:

| Of 1,726 real MCP servers… | share |
|---|---|
| can **run shell commands** | 45% |
| make **network calls** | 67% |
| can **`eval` code at runtime** | 9% |
| can do **both exec + network** | 34% |
| touch **credential files** | 5% |

The 0.7% flagged were driven by install-time code execution and prompt-injection — including
real servers with **hidden zero-width characters embedded in their tool descriptions**, the
kind of stealth tool-poisoning a keyword scanner sails past.

> A robustness + distribution run is *not* an accuracy benchmark — the 2,500 servers are
> unlabeled. A flag means **review this**, not proven malicious.

## Security & limitations

Heimdall is a **heuristic pre-flight check, not a guarantee** — a PASS isn't proof of safety.
Capability, provenance, and CVE analysis cover **JS/TS and Python**; injection is
language-agnostic. Proven **taint/data-flow is JS/TS only** — Python falls back to
capability co-presence (a conservative gate, not a proven flow).
Everything runs offline by default; `--online` is the one network call (it sends dependency
names + versions to OSV.dev, never your source), and the CVE match is against the declared
range, not a lockfile. `--handshake` **runs untrusted code** and is not a real sandbox. See
[`SECURITY.md`](SECURITY.md) for the full threat model and how to report a vulnerability.

## Contributing

New detection rules are the highest-value contribution — see
[`CONTRIBUTING.md`](CONTRIBUTING.md). By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) · built by [Çağlar Bozkurt](https://github.com/caglarbozkurt)
