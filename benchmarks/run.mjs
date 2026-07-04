// Field run: scan a large list of real MCP packages and log the results.
// This is a ROBUSTNESS + verdict-distribution run (no ground-truth labels), NOT an
// accuracy benchmark. Usage: node benchmarks/run.mjs [count] [date]
import { appendFileSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const here = new URL(".", import.meta.url);
const targets = readFileSync(new URL("targets.txt", here), "utf8").split("\n").map((s) => s.trim()).filter(Boolean);
const N = Number(process.argv[2] ?? targets.length);
const DATE = process.argv[3] ?? "unknown-date";
const list = targets.slice(0, N);
const CONCURRENCY = 12;
const TIMEOUT_MS = 60_000;

const jsonlPath = new URL("field-run.jsonl", here);
writeFileSync(jsonlPath, "");

function scanOne(pkg) {
  return new Promise((resolve) => {
    const child = spawn("node", ["dist/cli.js", pkg, "--json", "--no-fail"], { cwd: process.cwd() });
    let out = "", err = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); resolve({ target: pkg, error: "timeout" }); }, TIMEOUT_MS);
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => { clearTimeout(timer); resolve({ target: pkg, error: String(e).slice(0, 140) }); });
    child.on("close", () => {
      clearTimeout(timer);
      try {
        const r = JSON.parse(out);
        resolve({
          target: pkg, verdict: r.verdict, score: r.score, toolCount: r.toolCount,
          capabilities: r.capabilities, gates: r.findings.filter((f) => f.gate).map((f) => f.id),
        });
      } catch {
        resolve({ target: pkg, error: (err.split("\n").find(Boolean) || "scan failed").slice(0, 140) });
      }
    });
  });
}

function cleanTemp() {
  try {
    for (const d of readdirSync(tmpdir())) {
      if (/^mcp-audit-(npm|gh)-/.test(d)) rmSync(join(tmpdir(), d), { recursive: true, force: true });
    }
  } catch { /* best effort */ }
}

const results = [];
let idx = 0, done = 0;
const t0 = Date.now();
async function worker() {
  while (idx < list.length) {
    const pkg = list[idx++];
    const r = await scanOne(pkg);
    results.push(r);
    appendFileSync(jsonlPath, JSON.stringify(r) + "\n");
    if (++done % 25 === 0) { process.stdout.write(`  ${done}/${list.length}\n`); cleanTemp(); }
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));
cleanTemp();

// --- summary ---
const durationMin = ((Date.now() - t0) / 60000).toFixed(1);
const ok = results.filter((r) => !r.error);
const errored = results.filter((r) => r.error);
const by = (v) => ok.filter((r) => r.verdict === v).length;
const count = (arr) => {
  const m = new Map();
  for (const x of arr) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
};
const gateCounts = count(ok.flatMap((r) => r.gates ?? []));
const capCounts = count(ok.flatMap((r) => r.capabilities ?? []));
const fails = ok.filter((r) => r.verdict === "fail");
const pct = (n) => ((n / (ok.length || 1)) * 100).toFixed(1) + "%";

const md = `# Heimdall field run — ${DATE}

Scanned **${results.length}** real MCP packages harvested from the npm registry.
This is a **robustness + verdict-distribution** run, not an accuracy benchmark — these
packages are unlabeled (we don't have ground truth for which are malicious). It measures
whether Heimdall runs cleanly at scale and how often it flags real-world servers.

## Coverage
- Packages attempted: **${results.length}**
- Scanned successfully: **${ok.length}**
- Could not fetch/scan (404, private, timeout, non-package): **${errored.length}**
- Wall-clock: **${durationMin} min** (${CONCURRENCY}-way concurrency)

## Verdict distribution (of ${ok.length} scanned)
| Verdict | Count | Share |
|---|---|---|
| PASS | ${by("pass")} | ${pct(by("pass"))} |
| WARN | ${by("warn")} | ${pct(by("warn"))} |
| FAIL | ${by("fail")} | ${pct(by("fail"))} |

## Most common hard gates (drivers of FAIL)
${gateCounts.slice(0, 12).map(([id, n]) => `- \`${id}\` — ${n}`).join("\n") || "- none"}

## Most common capabilities observed
${capCounts.slice(0, 12).map(([c, n]) => `- ${c} — ${n}`).join("\n") || "- none"}

## Servers that FAILed (${fails.length})
${fails.slice(0, 60).map((r) => `- \`${r.target}\` — ${(r.gates ?? []).join(", ") || "policy"}`).join("\n") || "- none"}

## Caveats
- **No labels** → this is not precision/recall. For accuracy see \`fixtures/corpus.json\` + \`npm run eval\`.
- A FAIL here is a *signal to review*, not a proof of malice (esp. heuristic gates).
- Some "MCP" packages are libraries/adapters, not servers → they scan as low/no surface.
- Full per-package results: \`benchmarks/field-run.jsonl\`.
`;

writeFileSync(new URL("field-run.md", here), md);
process.stdout.write(`\nDONE: ${ok.length} scanned, ${errored.length} errored, ${fails.length} FAIL, in ${durationMin} min\n`);
