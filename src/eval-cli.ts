#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { evaluateCorpus } from "./corpus.js";

async function main() {
  const path = process.argv[2] ?? "fixtures/corpus.json";
  const { cases } = JSON.parse(readFileSync(path, "utf8"));
  const { results, metrics } = await evaluateCorpus(cases);

  for (const r of results) {
    const mark = r.correct ? "✓" : "✗";
    process.stdout.write(`  ${mark} ${r.label.padEnd(9)} ${r.verdict.toUpperCase().padEnd(4)}  ${r.target}\n`);
  }
  const pct = (n: number) => (n * 100).toFixed(1) + "%";
  process.stdout.write(
    `\n  ${metrics.total} cases · precision ${pct(metrics.precision)} · recall ${pct(metrics.recall)} · accuracy ${pct(metrics.accuracy)}\n` +
      `  TP ${metrics.tp}  FP ${metrics.fp}  TN ${metrics.tn}  FN ${metrics.fn}\n`,
  );
  process.exit(metrics.fp + metrics.fn > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`eval: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
