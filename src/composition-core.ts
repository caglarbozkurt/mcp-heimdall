// Pure composition logic — no Node dependencies, so it works in the browser bundle too.
import type { Finding, Report, Verdict } from "./types.js";

export interface ServerEntry {
  name: string;
  target: string;
  /** Command/args to spawn for a live handshake (present only in the mcpServers form). */
  command?: string;
  args?: string[];
}

export const RANK: Record<Verdict, number> = { pass: 0, warn: 1, fail: 2 };

/** Does this JSON look like an MCP *client* config (a set of servers) rather than one server? */
export function looksLikeConfig(json: unknown): boolean {
  const j = json as any;
  return !!j && typeof j === "object" && (!!j.mcpServers || Array.isArray(j.servers));
}

const dirname = (p: string) => p.replace(/\/[^/]*$/, "") || ".";

/** Derive a scannable target from an `mcpServers` command/args entry (best-effort). */
export function deriveTarget(cfg: any): string | null {
  if (typeof cfg?.target === "string") return cfg.target; // explicit
  const command: string = cfg?.command ?? "";
  const args: string[] = Array.isArray(cfg?.args) ? cfg.args : [];
  if (/\b(npx|npm|pnpm|yarn|bunx)\b/.test(command)) {
    const pkg = args.find((a) => !a.startsWith("-") && a !== "y");
    return pkg ?? null;
  }
  if (/\b(node|bun|tsx|ts-node|deno)\b/.test(command)) {
    const script = args.find((a) => !a.startsWith("-"));
    return script ? dirname(script) : null;
  }
  return command || null;
}

/** Parse either the client form ({ mcpServers: {...} }) or the explicit form ({ servers: [...] }). */
export function parseConfig(json: any): ServerEntry[] {
  if (Array.isArray(json?.servers)) {
    return json.servers
      .filter((s: any) => s && typeof s.name === "string" && typeof s.target === "string")
      .map((s: any) => ({ name: s.name, target: s.target }));
  }
  const out: ServerEntry[] = [];
  for (const [name, cfg] of Object.entries<any>(json?.mcpServers ?? {})) {
    const target = deriveTarget(cfg);
    if (target) out.push({ name, target, command: cfg?.command, args: cfg?.args });
  }
  return out;
}

// Tool-name hints that a server ingests external / attacker-influenceable content.
const EXTERNAL_INGEST =
  /web|search|fetch|browse|scrape|crawl|url|http|email|inbox|mail|ticket|issue|rss|feed|slack|comment|review/i;

function ingestsUntrusted(r: Report): boolean {
  if (r.capabilities.includes("net-egress") || r.capabilities.includes("fs-read")) return true;
  return r.surface.some((s) => EXTERNAL_INGEST.test(s.name));
}
const hasEgress = (r: Report) => r.capabilities.includes("net-egress");

/**
 * Cross-server reasoning: risks that emerge from *composing* servers, invisible to any
 * single-server scan. This is the core differentiator.
 */
export function analyzeComposition(entries: { name: string; report: Report }[]): Finding[] {
  const findings: Finding[] = [];

  const sources = entries.filter((e) => ingestsUntrusted(e.report)).map((e) => e.name);
  const sinks = entries.filter((e) => hasEgress(e.report)).map((e) => e.name);
  const crossPair = sources.some((s) => sinks.some((k) => s !== k));
  if (crossPair) {
    findings.push({
      id: "composition/exfil-chain",
      category: "composition",
      severity: "high",
      confidence: "medium",
      title: "Cross-server exfiltration surface",
      detail:
        `Servers that can ingest external/untrusted content [${sources.join(", ")}] are configured ` +
        `alongside servers that can send data out [${sinks.join(", ")}]. An agent composing them can be ` +
        `steered by injected content to exfiltrate — a path none of these servers exhibits alone.`,
    });
  }

  const byTool = new Map<string, Set<string>>();
  for (const e of entries) {
    for (const item of e.report.surface) {
      if (item.kind !== "tool") continue;
      (byTool.get(item.name) ?? byTool.set(item.name, new Set()).get(item.name)!).add(e.name);
    }
  }
  for (const [tool, servers] of byTool) {
    if (servers.size > 1) {
      findings.push({
        id: "composition/tool-collision",
        category: "composition",
        severity: "medium",
        confidence: "high",
        title: `Tool name collision: "${tool}"`,
        detail: `The tool "${tool}" is defined by multiple servers [${[...servers].join(", ")}]. The agent may invoke the wrong one; a malicious server can shadow a trusted tool.`,
        location: `tool:${tool}`,
      });
    }
  }

  return findings;
}
