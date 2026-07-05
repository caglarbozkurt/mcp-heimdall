#!/usr/bin/env node
import { createInterface } from "node:readline";
import { existsSync, readFileSync } from "node:fs";
import { looksLikeConfig, scanConfig } from "./composition.js";
import { scan } from "./scan.js";
import { VERSION } from "./version.js";
import type { CompositionReport, Report } from "./types.js";

/**
 * Heimdall as an MCP server. Exposes a single tool, `scan_mcp_server`, so an agent can vet
 * an MCP server (or a whole client config) *before* trusting it — right inside the loop.
 *
 * Hand-rolled stdio JSON-RPC (no SDK dependency — a security scanner shouldn't ship a supply
 * chain). SAFETY: the tool runs **static analysis only** — it downloads the package but never
 * executes it. The code-execution paths (`--handshake`, `validate`) are deliberately NOT
 * exposed here; an agent must not be able to trigger untrusted-code execution.
 */

const TOOL = {
  name: "scan_mcp_server",
  description:
    "Statically vet an MCP server (or a whole MCP client config) BEFORE trusting or installing it. " +
    "Checks prompt-injection / tool-poisoning, risky capabilities (fs/network/shell/eval/credentials), " +
    "proven data-exfiltration paths, dependency CVEs, provenance, and multi-server composition. " +
    "Returns a pass/warn/fail verdict with cited evidence. Static analysis only — downloads the " +
    "package but does NOT execute it. Use it when the user is about to add/connect an MCP server.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description:
          "What to scan: an npm package name, 'pypi:<name>', a local directory path, a GitHub URL, " +
          "a tools.json dump, or a path to an MCP client config file (audits every server in it).",
      },
      policy: {
        type: "string",
        enum: ["default", "strict"],
        description: "Policy to gate against. 'strict' also fails on high-severity CVEs and denies exec/eval/secret caps.",
      },
      online: {
        type: "boolean",
        description: "Also check dependencies for known CVEs via OSV.dev (makes a network call).",
      },
    },
    required: ["target"],
  },
};

const send = (msg: unknown) => process.stdout.write(JSON.stringify(msg) + "\n");

/** Compact, agent-readable summary of a single-server report. */
function formatReport(r: Report): string {
  const lines = [
    `VERDICT: ${r.verdict.toUpperCase()}  (risk score ${r.score}/100, policy: ${r.policy})`,
    `target: ${r.target} (${r.kind}) — ${r.toolCount} tools`,
    `capabilities: ${r.capabilities.length ? r.capabilities.join(", ") : "none detected"}`,
  ];
  if (r.reasons.length) lines.push(`why: ${r.reasons.join("; ")}`);
  const risk = r.findings.filter((f) => !f.profile);
  if (risk.length) {
    lines.push("", "Risk findings:");
    for (const f of risk.slice(0, 20)) {
      lines.push(`- [${f.severity.toUpperCase()}]${f.gate ? "[GATE]" : ""} ${f.title} (${f.id})${f.location ? ` at ${f.location}` : ""}`);
    }
  } else {
    lines.push("", "No risk findings.");
  }
  lines.push("", "Static heuristic check — a PASS is not proof of safety. It downloaded but did not run the server.");
  return lines.join("\n");
}

/** Compact summary of a multi-server (config) composition report. */
function formatComposition(cr: CompositionReport): string {
  const lines = [`VERDICT: ${cr.verdict.toUpperCase()}  (${cr.serverCount} servers)`, ""];
  for (const s of cr.servers) {
    lines.push(`- ${s.error ? "ERROR" : s.verdict.toUpperCase()}  ${s.name} (${s.target})${s.error ? ` — ${s.error}` : ` — ${s.capabilities.join(",") || "no caps"}`}`);
  }
  if (cr.findings.length) {
    lines.push("", "Cross-server findings:");
    for (const f of cr.findings) lines.push(`- [${f.severity.toUpperCase()}] ${f.title} (${f.id})`);
  } else {
    lines.push("", "No cross-server findings.");
  }
  return lines.join("\n");
}

async function runScan(target: string, policy?: string, online?: boolean): Promise<string> {
  const pol = policy === "strict" ? "strict" : "default";
  // A JSON MCP client config → audit the whole set together.
  if (target.endsWith(".json") && existsSync(target)) {
    try {
      if (looksLikeConfig(JSON.parse(readFileSync(target, "utf8")))) {
        return formatComposition(await scanConfig(target, { policy: pol, online }));
      }
    } catch {
      /* not a config → fall through to single-server scan */
    }
  }
  return formatReport(await scan(target, { policy: pol, online }));
}

const rl = createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const s = line.trim();
  if (!s) return;
  let msg: any;
  try {
    msg = JSON.parse(s);
  } catch {
    return; // ignore non-JSON noise
  }
  const { id, method, params } = msg;

  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "heimdall", version: VERSION },
      },
    });
  } else if (method === "notifications/initialized") {
    // notification — no response
  } else if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: [TOOL] } });
  } else if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments ?? {};
    if (name !== TOOL.name) {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: `unknown tool: ${name}` } });
      return;
    }
    if (!args.target || typeof args.target !== "string") {
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "Provide a 'target' to scan." }], isError: true } });
      return;
    }
    try {
      const text = await runScan(args.target.trim(), args.policy, args.online === true);
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Scan failed: ${message}` }], isError: true } });
    }
  } else if (id != null) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
  }
});
