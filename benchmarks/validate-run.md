# Heimdall behavioral validation run — 2026-07-05

Ran `heimdall validate` over **200** real MCP packages from the npm registry.
Unlike the static field run, this **executes** each server (sandboxed HOME/cwd, no secrets),
drives up to 4 tools, and records *actual* capability use — then diffs it against the static flags.

## Coverage
- Attempted: **200**
- Resolved & driven: **56** (28.0%)
- Booted (handshake + ≥1 tool call): **55** (27.5%)
- Exercised ≥1 observable capability: **34** (17.0%)
- Could not run (404/needs config/no start/timeout): **144**

> Most public MCP servers need API keys or arguments and won't boot under a reduced env — a
> low boot rate is expected. The validation signal comes from the servers that *did* exercise
> capabilities.

## Static vs. observed (per capability, across servers that ran)
| Capability | confirmed | missed | not-exercised |
|---|---|---|---|
| fs-read | 16 | 2 | 23 |
| fs-write | 8 | 2 | 21 |
| net-egress | 20 | 2 | 22 |
| exec | 8 | 1 | 21 |
| dynamic-eval | 0 | 3 | 7 |
| secret-access | 0 | 2 | 4 |
| dotenv-access | 0 | 0 | 12 |
| env-access | 3 | 1 | 44 |

## Headline
- **Recall = 80.9%** (55/68) — of capabilities servers
  actually exercised at runtime, this share was flagged by the static scan.
- **13 missed** — observed but not statically flagged (review: genuine gaps vs. incidental
  library / child-process side effects).

## Caveats
- `not-exercised` is a **lower bound**, not a false positive: naive tool arguments often don't
  trigger a real capability, so precision cannot be measured this way — only recall.
- Behavioral coverage depends on being able to boot the server and trigger its tools; this is a
  **curated behavioral sample**, not the full ecosystem.
- Full per-server results: `benchmarks/validate-run.jsonl`.
