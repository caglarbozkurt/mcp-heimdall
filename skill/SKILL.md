---
name: heimdall
description: Vet a Model Context Protocol (MCP) server for safety before installing or connecting it. Use when the user wants to check, audit, scan, or review an MCP server for prompt-injection, data-exfiltration, or malicious capabilities — given a directory, npm package, GitHub repo, or a tools/list JSON dump.
---

# Heimdall

Run a security scan on an MCP server and report the risk.

## When to use

The user is about to install/connect an MCP server and wants to know if it's safe,
or asks to "audit / scan / vet / check" an MCP, or pasted a `tools/list` output and
asked whether the tool descriptions look poisoned.

## How to run

From the Heimdall project directory:

```bash
# local server directory
npx tsx src/cli.ts <path-to-server>

# npm package name, GitHub URL, or a tools/list JSON dump
npx tsx src/cli.ts <npm-package | github-url | tools.json>

# machine-readable
npx tsx src/cli.ts <target> --json

# also check the server's dependencies for known CVEs (queries OSV.dev over the network)
npx tsx src/cli.ts <target> --online
```

If installed globally / as a dependency, use `heimdall <target>` instead.

Add `--online` when the user wants supply-chain coverage: it checks declared dependencies
against the OSV.dev advisory database and reports real CVE IDs. It sends only dependency
names + versions (never source); leave it off to stay fully offline.

For a behavioral cross-check, `heimdall validate <target>` runs the server and calls its
tools to observe what it *actually* does, then compares that to the static flags (confirmed
/ missed / not-exercised). It executes untrusted code with side effects — only suggest it in
a disposable VM/container, never on the user's real machine.

To analyze injection with full fidelity when tool descriptions can't be read from
source, capture the server's `tools/list` output to a file and pass `--tools <file>`.

## Interpreting the result

- **verdict**: `pass` / `warn` / `fail`. Any hard **[GATE]** finding forces `fail`.
- **risk score**: 0 (clean) – 100 (worst).
- **fingerprint**: stable hash of the tool surface. Save it; if it changes on a later
  scan, the MCP silently altered its tools (possible rug-pull).

Summarize the gates and highest-severity findings for the user, cite the evidence
(file:line or `tool:name`), and give a clear install / don't-install recommendation.
Never recommend installing a server with an unresolved GATE finding.
