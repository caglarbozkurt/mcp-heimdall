// Behavioral validation field run. Takes N real MCP packages from targets.txt, runs each
// under `heimdall validate` (spawns the server in a sandboxed HOME/cwd, drives its tools,
// records real capability use), and aggregates how well static flags match runtime behavior.
//
// SAFETY: this EXECUTES untrusted server code and CALLS its tools. Each server runs with a
// throwaway HOME + cwd and no inherited secrets, but network egress and exec still happen.
// Run it in a disposable VM/container for anything beyond a curated, reputable list.
//
// Usage: node benchmarks/validate-run.mjs [count=150] [concurrency=4] [date=YYYY-MM-DD]
import { readFileSync, writeFileSync } from "node:fs";
import { validateServer } from "../dist/index.js";

const N = Number(process.argv[2] ?? 150);
const CONC = Number(process.argv[3] ?? 4);
const DATE = process.argv[4] ?? "unknown-date";

const targets = readFileSync(new URL("./targets.txt", import.meta.url), "utf8")
  .split("\n")
  .map((s) => s.trim())
  .filter(Boolean)
  .slice(0, N);

const CAPS = ["fs-read", "fs-write", "net-egress", "exec", "dynamic-eval", "secret-access", "dotenv-access", "env-access"];
const results = [];
let cursor = 0;

async function worker() {
  while (cursor < targets.length) {
    const t = targets[cursor++];
    try {
      const r = await validateServer(t, { maxTools: 4, timeoutMs: 45_000 });
      results.push(r);
    } catch (e) {
      results.push({ target: t, error: String(e), comparison: [], staticCaps: [], observedCaps: [], toolsCalled: 0 });
    }
    process.stderr.write(`\r${results.length}/${targets.length} scanned`);
  }
}

await Promise.all(Array.from({ length: CONC }, () => worker()));
process.stderr.write("\n");

// ---- aggregate ----
const errored = results.filter((r) => r.error);
const ran = results.filter((r) => !r.error); // resolved + scanned + drove (may still have 0 tools)
const booted = ran.filter((r) => r.toolsCalled > 0);
const exercised = ran.filter((r) => (r.observedCaps ?? []).length > 0);

const perCap = {};
for (const c of CAPS) perCap[c] = { confirmed: 0, missed: 0, notExercised: 0 };
for (const r of ran) {
  for (const c of r.comparison ?? []) {
    if (c.status === "confirmed") perCap[c.cap].confirmed++;
    else if (c.status === "missed") perCap[c.cap].missed++;
    else if (c.status === "not-exercised") perCap[c.cap].notExercised++;
  }
}
const totalConfirmed = Object.values(perCap).reduce((n, v) => n + v.confirmed, 0);
const totalMissed = Object.values(perCap).reduce((n, v) => n + v.missed, 0);
const recall = totalConfirmed + totalMissed ? totalConfirmed / (totalConfirmed + totalMissed) : 1;

writeFileSync(new URL("./validate-run.jsonl", import.meta.url), results.map((r) => JSON.stringify(r)).join("\n") + "\n");

const pct = (n, d) => (d ? ((n / d) * 100).toFixed(1) + "%" : "—");
const md = `# Heimdall behavioral validation run — ${DATE}

Ran \`heimdall validate\` over **${targets.length}** real MCP packages from the npm registry.
Unlike the static field run, this **executes** each server (sandboxed HOME/cwd, no secrets),
drives up to 4 tools, and records *actual* capability use — then diffs it against the static flags.

## Coverage
- Attempted: **${targets.length}**
- Resolved & driven: **${ran.length}** (${pct(ran.length, targets.length)})
- Booted (handshake + ≥1 tool call): **${booted.length}** (${pct(booted.length, targets.length)})
- Exercised ≥1 observable capability: **${exercised.length}** (${pct(exercised.length, targets.length)})
- Could not run (404/needs config/no start/timeout): **${errored.length}**

> Most public MCP servers need API keys or arguments and won't boot under a reduced env — a
> low boot rate is expected. The validation signal comes from the servers that *did* exercise
> capabilities.

## Static vs. observed (per capability, across servers that ran)
| Capability | confirmed | missed | not-exercised |
|---|---|---|---|
${CAPS.map((c) => `| ${c} | ${perCap[c].confirmed} | ${perCap[c].missed} | ${perCap[c].notExercised} |`).join("\n")}

## Headline
- **Recall = ${(recall * 100).toFixed(1)}%** (${totalConfirmed}/${totalConfirmed + totalMissed}) — of capabilities servers
  actually exercised at runtime, this share was flagged by the static scan.
- **${totalMissed} missed** — observed but not statically flagged (review: genuine gaps vs. incidental
  library / child-process side effects).

## Caveats
- \`not-exercised\` is a **lower bound**, not a false positive: naive tool arguments often don't
  trigger a real capability, so precision cannot be measured this way — only recall.
- Behavioral coverage depends on being able to boot the server and trigger its tools; this is a
  **curated behavioral sample**, not the full ecosystem.
- Full per-server results: \`benchmarks/validate-run.jsonl\`.
`;
writeFileSync(new URL("./validate-run.md", import.meta.url), md);

console.log(`\nDONE: ${ran.length}/${targets.length} ran, ${booted.length} booted, ${exercised.length} exercised a capability`);
console.log(`recall ${(recall * 100).toFixed(1)}% (${totalConfirmed}/${totalConfirmed + totalMissed}), ${totalMissed} missed`);
console.log("wrote benchmarks/validate-run.{jsonl,md}");
