# Contributing to Heimdall

Thanks for helping vet the MCP ecosystem. The highest-value contribution is usually a
**new or improved detection rule** — here's how.

## Setup

```bash
npm install
npm run build     # tsc → dist/
npm test          # the test suite (node:test)
```

Heimdall keeps its runtime dependencies minimal on purpose (a security scanner shouldn't
ship a large supply chain). The only runtime dep is `acorn` (for taint analysis). Please
don't add runtime dependencies without discussion.

## Project layout

```
src/
  analyzers/       the detection rules — where most contributions go
    injection.ts     prompt-injection / tool-poisoning (tools, resources, prompts)
    capability.ts    fs / net / exec / eval / credential detectors
    provenance.ts    install scripts, repo/license/author
    dependencies.ts  latent capabilities from declared deps
    gates.ts         cross-capability + taint-aware hard gates
  taint.ts         intra-file, per-function data-flow (acorn)
  policy.ts        turns findings into pass/warn/fail (the single decision point)
  composition.ts   multi-server / config analysis
  scan.ts          orchestrator
fixtures/          test targets (benign + malicious)
benchmarks/        the 1000-server field-run harness
test/              tests
```

## Adding a detection rule

1. **Pick the analyzer** that fits (injection / capability / provenance / gates).
2. **Add the rule** with a stable `id` (e.g. `injection/my-rule`), a `severity`, and a
   `confidence` (`high` for structural facts, `low` for heuristics that may false-positive).
3. **Classify it honestly:**
   - A `gate: true` finding is a **hard red flag** that forces FAIL (e.g. a proven credential
     leak). Reserve gates for things that are rarely legitimate.
   - Capability *facts* that are informational (what a server *can* do) should be `profile: true`
     so they never drive the verdict — only anomalies and gates do.
   - Prefer a **WARN + review** over a false FAIL. Over-firing is how a scanner gets muted.
4. **Add a fixture** under `fixtures/` (a minimal server that triggers — or must *not* trigger —
   the rule) and a **test** in `test/scan.test.ts`.
5. `npm test`.

## Calibrate against real servers before shipping

Unit fixtures prove a rule *fires*; they don't prove it doesn't over-fire in the wild. Run the
field harness before submitting a rule that changes the gate/anomaly logic:

```bash
node benchmarks/harvest.mjs 1000     # refresh the target list from the npm registry
node benchmarks/run.mjs 1000 <date>  # scan them; writes benchmarks/field-run.{jsonl,md}
```

Check the FAIL rate and the top gate drivers. A rule that suddenly fails a large fraction of
real servers is almost certainly over-firing (this is exactly how the file→network and
bundled-taint false positives were caught).

## The accuracy corpus

`fixtures/corpus.json` is the labeled set used for precision/recall:

```bash
npm run eval                         # scores the corpus (precision / recall / accuracy)
```

Grow it: add known-good and known-vulnerable servers with a `label`, and keep precision and
recall at 100% (or explain the regression). Ground-truth labels are the scarce resource here —
new labeled cases are very welcome.

## Style

Match the surrounding code — small, explicit, well-commented rules. Every finding must cite
concrete evidence (`file:line` or `tool:name`); no vibes-based findings.
