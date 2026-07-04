# Heimdall field run — 2026-07-04

Scanned **2500** real MCP packages harvested from the npm registry.
This is a **robustness + verdict-distribution** run, not an accuracy benchmark — these
packages are unlabeled (we don't have ground truth for which are malicious). It measures
whether Heimdall runs cleanly at scale and how often it flags real-world servers.

## Coverage
- Packages attempted: **2500**
- Scanned successfully: **1726**
- Could not fetch/scan (404, private, timeout, non-package): **774**
- Wall-clock: **4.7 min** (12-way concurrency)

## Verdict distribution (of 1726 scanned)
| Verdict | Count | Share |
|---|---|---|
| PASS | 974 | 56.4% |
| WARN | 740 | 42.9% |
| FAIL | 12 | 0.7% |

## Most common hard gates (drivers of FAIL)
- `injection/hidden-zero-width` — 36
- `provenance/install-script-exec` — 8
- `injection/conceal-from-user` — 2
- `injection/instruction-override` — 1

## Most common capabilities observed
- env-access — 1323
- net-egress — 1153
- fs-read — 1011
- fs-write — 796
- exec — 785
- dotenv-access — 339
- dynamic-eval — 157
- secret-access — 90

## Servers that FAILed (12)
- `excalidraw-mcp` — provenance/install-script-exec
- `@wonderwhy-er/desktop-commander` — provenance/install-script-exec
- `@kernlang/review-mcp` — injection/instruction-override
- `@ceraph/react-native-mcp` — provenance/install-script-exec
- `@tpsdev-ai/flair-mcp` — provenance/install-script-exec
- `marketing-mcp` — provenance/install-script-exec
- `mcp-sqlite` — provenance/install-script-exec
- `hamravesh-mcp` — injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width
- `@roamzy/mcp-server` — injection/conceal-from-user, injection/conceal-from-user
- `kaax-mcp` — injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width, injection/hidden-zero-width
- `inkstone-mcp` — provenance/install-script-exec
- `forgecraft-mcp` — provenance/install-script-exec

## Caveats
- **No labels** → this is not precision/recall. For accuracy see `fixtures/corpus.json` + `npm run eval`.
- A FAIL here is a *signal to review*, not a proof of malice (esp. heuristic gates).
- Some "MCP" packages are libraries/adapters, not servers → they scan as low/no surface.
- Full per-package results: `benchmarks/field-run.jsonl`.
