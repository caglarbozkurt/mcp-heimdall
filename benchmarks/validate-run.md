# Heimdall behavioral validation run — 2026-07-04

Ran `heimdall validate` over **200** real MCP packages from the npm registry.
Unlike the static field run, this **executes** each server (sandboxed HOME/cwd, no secrets),
drives up to 4 tools, and records *actual* capability use — then diffs it against the static flags.

## Coverage
- Attempted: **200**
- Resolved & driven: **46** (23.0%)
- Booted (handshake + ≥1 tool call): **45** (22.5%)
- Exercised ≥1 observable capability: **27** (13.5%)
- Could not run (404/needs config/no start/timeout): **154**

> Most public MCP servers need API keys or arguments and won't boot under a reduced env — a
> low boot rate is expected. The validation signal comes from the servers that *did* exercise
> capabilities.

## Static vs. observed (per capability, across servers that ran)
| Capability | confirmed | missed | not-exercised |
|---|---|---|---|
| fs-read | 13 | 2 | 17 |
| fs-write | 8 | 3 | 13 |
| net-egress | 15 | 4 | 15 |
| exec | 7 | 1 | 16 |
| dynamic-eval | 0 | 2 | 6 |
| secret-access | 0 | 2 | 2 |
| dotenv-access | 0 | 0 | 9 |
| env-access | 4 | 1 | 33 |

## Headline
- **Recall = 75.8%** (47/62) — of capabilities servers
  actually exercised at runtime, this share was flagged by the static scan.
- **15 missed** — observed but not statically flagged (review: genuine gaps vs. incidental
  library / child-process side effects).

## Caveats
- `not-exercised` is a **lower bound**, not a false positive: naive tool arguments often don't
  trigger a real capability, so precision cannot be measured this way — only recall.
- Behavioral coverage depends on being able to boot the server and trigger its tools; this is a
  **curated behavioral sample**, not the full ecosystem.
- Full per-server results: `benchmarks/validate-run.jsonl`.
