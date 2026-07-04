# Heimdall field run — 2026-07-04

Scanned **1000** real MCP packages harvested from the npm registry.
This is a **robustness + verdict-distribution** run, not an accuracy benchmark — these
packages are unlabeled (we don't have ground truth for which are malicious). It measures
whether Heimdall runs cleanly at scale and how often it flags real-world servers.

## Coverage
- Packages attempted: **1000**
- Scanned successfully: **742**
- Could not fetch/scan (404, private, timeout, non-package): **258**
- Wall-clock: **2.2 min** (12-way concurrency)

## Verdict distribution (of 742 scanned)
| Verdict | Count | Share |
|---|---|---|
| PASS | 416 | 56.1% |
| WARN | 320 | 43.1% |
| FAIL | 6 | 0.8% |

## Most common hard gates (drivers of FAIL)
- `provenance/install-script-exec` — 4
- `injection/instruction-override` — 1
- `gate/exfil-capability` — 1

## Most common capabilities observed
- env-access — 543
- net-egress — 481
- fs-read — 428
- exec — 347
- fs-write — 330
- dotenv-access — 152
- dynamic-eval — 60
- secret-access — 51

## Servers that FAILed (6)
- `excalidraw-mcp` — provenance/install-script-exec
- `@wonderwhy-er/desktop-commander` — provenance/install-script-exec
- `@kernlang/review-mcp` — injection/instruction-override
- `@tpsdev-ai/flair-mcp` — provenance/install-script-exec
- `marketing-mcp` — provenance/install-script-exec
- `@pi-unipi/mcp` — gate/exfil-capability

## Caveats
- **No labels** → this is not precision/recall. For accuracy see `fixtures/corpus.json` + `npm run eval`.
- A FAIL here is a *signal to review*, not a proof of malice (esp. heuristic gates).
- Some "MCP" packages are libraries/adapters, not servers → they scan as low/no surface.
- Full per-package results: `benchmarks/field-run.jsonl`.
