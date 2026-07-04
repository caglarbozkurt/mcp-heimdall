import { readFileSync } from "node:fs";
import { analyzeComposition, parseConfig, RANK } from "./composition-core.js";
import { handshake } from "./handshake.js";
import { scan } from "./scan.js";
import type { CompositionReport, Report, ScanOptions, ServerSummary, Verdict } from "./types.js";

// Re-export the pure pieces so existing imports (CLI, tests) keep working.
export { looksLikeConfig, parseConfig, analyzeComposition } from "./composition-core.js";

type Scanned =
  | { name: string; target: string; report: Report }
  | { name: string; target: string; error: string };

/** Audit a configured set of MCP servers together. */
export async function scanConfig(input: string, opts: ScanOptions = {}): Promise<CompositionReport> {
  const json = JSON.parse(readFileSync(input, "utf8"));
  const entries = parseConfig(json);

  const scanned: Scanned[] = await Promise.all(
    entries.map(async (e): Promise<Scanned> => {
      try {
        // --handshake: run the server to pull its live surface (highest fidelity).
        let surface: ScanOptions["surface"];
        if (opts.handshake && e.command) {
          const live = await handshake(e.command, e.args ?? []);
          if (!live.error) surface = { tools: live.tools, resources: live.resources, prompts: live.prompts };
        }
        return { name: e.name, target: e.target, report: await scan(e.target, { policy: opts.policy, surface }) };
      } catch (err) {
        return { name: e.name, target: e.target, error: err instanceof Error ? err.message : String(err) };
      }
    }),
  );

  const ok = scanned.filter((s): s is Extract<Scanned, { report: Report }> => "report" in s);
  const findings = analyzeComposition(ok);

  const servers: ServerSummary[] = scanned.map((s) =>
    "report" in s
      ? {
          name: s.name,
          target: s.target,
          verdict: s.report.verdict,
          score: s.report.score,
          capabilities: s.report.capabilities,
          toolCount: s.report.toolCount,
        }
      : { name: s.name, target: s.target, verdict: "fail", score: 0, capabilities: [], toolCount: 0, error: s.error },
  );

  // Aggregate verdict: worst per-server verdict, raised to at least WARN by composition findings.
  let verdict: Verdict = "pass";
  for (const s of servers) if (RANK[s.verdict] > RANK[verdict]) verdict = s.verdict;
  if (findings.length && verdict === "pass") verdict = "warn";

  return {
    target: input,
    scannedAt: new Date().toISOString(),
    serverCount: servers.length,
    servers,
    findings,
    verdict,
  };
}
