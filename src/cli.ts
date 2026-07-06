#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { looksLikeConfig, scanConfig } from "./composition.js";
import { handshake } from "./handshake.js";
import {
  formatBatchReport,
  formatCompositionReport,
  formatReport,
  formatValidateReport,
} from "./report.js";
import { toSarif } from "./sarif.js";
import { scan } from "./scan.js";
import { validateBatch, validateServer } from "./validate.js";

/** True if the input is a JSON MCP *client config* (a set of servers) rather than one server. */
function isConfig(input: string): boolean {
  if (!input.endsWith(".json") || !existsSync(input)) return false;
  try {
    return looksLikeConfig(JSON.parse(readFileSync(input, "utf8")));
  } catch {
    return false;
  }
}

const HELP = `
heimdall — a security scanner for MCP servers

Usage:
  heimdall <target> [options]
  heimdall validate <target> [--list <file>] [--max-tools N]   behavioral cross-check

Target can be:
  ./path/to/server      a local directory containing an MCP server
  some-mcp-package       an npm package name (downloaded via 'npm pack')
  https://github.com/... a git repository URL (shallow-cloned)
  tools.json             a tools/list JSON dump (array or { tools: [...] })

Options:
  --tools <file>     supplement analysis with a tools/list (or {tools,resources,prompts}) dump
  --policy <p>       policy to evaluate against: "default", "strict", or a JSON file path
  --baseline <file>  a prior --json report to diff against (detects drift / rug-pulls)
  --handshake        RUN the server(s) and use the live tools/list (highest fidelity).
                     Executes untrusted code — use only in a disposable VM/container.
  --online           check declared dependencies against the OSV.dev CVE database.
                     Sends only dependency names + versions (never your source).
  --json             output the report as JSON (also useful as a future baseline)
  --sarif            output SARIF 2.1.0 (for GitHub code-scanning / CI)
  --no-fail          always exit 0 (do not exit non-zero on a FAIL verdict)
  -h, --help         show this help

Exit codes: 0 pass/warn, 1 fail (unless --no-fail), 2 error.

'heimdall validate' RUNS the server and CALLS its tools to observe real behavior,
then compares it to the static flags. It executes untrusted code with side effects —
run it ONLY inside a disposable VM or container.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      tools: { type: "string" },
      policy: { type: "string" },
      baseline: { type: "string" },
      handshake: { type: "boolean", default: false },
      online: { type: "boolean", default: false },
      list: { type: "string" },
      "max-tools": { type: "string" },
      json: { type: "boolean", default: false },
      sarif: { type: "boolean", default: false },
      "no-fail": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.handshake) {
    process.stderr.write(
      "⚠ --handshake runs the server(s) as untrusted code. Use only in an isolated environment.\n",
    );
  }
  if (values.online) {
    process.stderr.write(
      "ℹ --online queries OSV.dev with your dependency names + versions (no source is sent).\n",
    );
  }

  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP);
    process.exit(values.help ? 0 : 2);
  }

  // `heimdall validate <target>` — behavioral cross-check (runs the server + calls its tools).
  if (positionals[0] === "validate") {
    process.stderr.write(
      "⚠ validate RUNS the server AND calls its tools (side effects possible). Use a disposable VM/container only.\n",
    );
    const maxTools = values["max-tools"] ? Number(values["max-tools"]) : undefined;
    if (values.list) {
      const inputs = readFileSync(values.list, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"));
      const batch = await validateBatch(inputs, { maxTools });
      process.stdout.write(
        values.json ? JSON.stringify(batch, null, 2) + "\n" : formatBatchReport(batch),
      );
      process.exit(0);
    }
    const target = positionals[1];
    if (!target) {
      process.stderr.write("heimdall validate: provide a <target> or --list <file>.\n");
      process.exit(2);
    }
    const vr = await validateServer(target, { maxTools });
    process.stdout.write(
      values.json ? JSON.stringify(vr, null, 2) + "\n" : formatValidateReport(vr),
    );
    // Diagnostic, not a gate: only a run error is non-zero (MISSED can be incidental noise).
    process.exit(vr.error ? 2 : 0);
  }

  // A client config → audit the whole configured set together (composition analysis).
  if (isConfig(positionals[0])) {
    const cr = await scanConfig(positionals[0], {
      policy: values.policy,
      handshake: values.handshake,
      online: values.online,
    });
    process.stdout.write(
      values.json ? JSON.stringify(cr, null, 2) + "\n" : formatCompositionReport(cr),
    );
    process.exit(cr.verdict === "fail" && !values["no-fail"] ? 1 : 0);
  }

  // Single-server live handshake: spawn `npx -y <pkg>` (or a dir's start) to pull the live surface.
  let surface;
  if (values.handshake) {
    const live = await handshake("npx", ["-y", positionals[0]]);
    if (live.error)
      process.stderr.write(`handshake failed (${live.error}); falling back to static.\n`);
    else surface = { tools: live.tools, resources: live.resources, prompts: live.prompts };
  }

  const report = await scan(positionals[0], {
    toolsFile: values.tools,
    policy: values.policy,
    baseline: values.baseline,
    surface,
    online: values.online,
  });

  if (values.sarif) {
    process.stdout.write(JSON.stringify(toSarif(report), null, 2) + "\n");
  } else if (values.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    process.stdout.write(formatReport(report));
  }

  process.exit(report.verdict === "fail" && !values["no-fail"] ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`heimdall: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
