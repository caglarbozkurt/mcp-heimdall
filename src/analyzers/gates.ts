import type { TaintFlow } from "../taint.js";
import type { AnalysisContext } from "../types.js";

/**
 * Cross-capability gates, now taint-aware.
 *
 * When taint analysis parsed the source, a *proven* source→sink flow is a precise
 * critical gate (with file:line locations), while mere co-presence of capabilities is
 * downgraded to a review surface — this kills the "reads a config file AND calls an
 * unrelated API → FAIL" false positive. When taint could NOT parse the source (e.g. raw
 * TS), we fall back to the conservative co-presence gate so recall isn't lost.
 */
export function analyzeGates(
  ctx: AnalysisContext,
  taint: { flows: TaintFlow[]; analyzed: boolean } = { flows: [], analyzed: false },
): void {
  const { caps } = ctx;
  const egress = caps.has("net-egress");
  const secretFiles = caps.has("secret-access");
  const fsRead = caps.has("fs-read");
  const evalCode = caps.has("dynamic-eval");
  const exec = caps.has("exec");

  const exfilFlows = taint.flows.filter((f) => f.kind === "exfil");
  const rceFlows = taint.flows.filter((f) => f.kind === "rce");

  // Proven paths. Only CREDENTIAL-file → network is a hard gate: generic file → network
  // is the ubiquitous "read a document/config and send it to an API" pattern (field-tested
  // against 1000 real servers — treating it as a gate over-fired badly), so it's a review
  // surface, not an auto-FAIL.
  for (const f of exfilFlows) {
    if (f.sourceKind === "secret") {
      ctx.findings.push({
        id: "gate/exfil-flow",
        category: "gate",
        severity: "critical",
        confidence: "high",
        gate: true,
        title: "Proven credential-exfiltration path",
        detail: `Data from a credential file (line ${f.sourceLine}) flows into the outbound call ${f.sink}() — a concrete exfiltration path.`,
        location: `${f.file}:${f.sinkLine}`,
      });
    } else {
      ctx.findings.push({
        id: "capability/read-send-flow",
        category: "capability",
        severity: "high",
        confidence: "medium",
        title: "File data flows to the network",
        detail: `Data read from the filesystem (line ${f.sourceLine}) flows into the outbound call ${f.sink}(). Legitimate for many servers (read-and-send), but review what leaves the machine.`,
        location: `${f.file}:${f.sinkLine}`,
      });
    }
  }
  for (const f of rceFlows) {
    ctx.findings.push({
      id: "gate/rce-flow",
      category: "gate",
      severity: "critical",
      confidence: "high",
      gate: true,
      title: "Proven remote code execution path",
      detail: `Fetched content (line ${f.sourceLine}) flows into ${f.sink}() — attacker-controlled input can reach code execution.`,
      location: `${f.file}:${f.sinkLine}`,
    });
  }

  // --- Exfiltration co-presence ---
  if (secretFiles && egress && exfilFlows.length === 0) {
    if (!taint.analyzed) {
      // Couldn't verify with data-flow → stay conservative: hard gate.
      ctx.findings.push({
        id: "gate/exfil-capability",
        category: "gate",
        severity: "critical",
        confidence: "medium",
        gate: true,
        title: "Credential exfiltration capability",
        detail:
          "Reads credential files AND has network egress. Source could not be data-flow analyzed, so this is treated conservatively as a gate.",
      });
    } else {
      // Taint ran and found no flow → review surface, not an auto-fail.
      ctx.findings.push({
        id: "capability/exfil-surface",
        category: "capability",
        severity: "high",
        confidence: "medium",
        title: "Read-and-send surface (credentials)",
        detail:
          "Reads credential material AND has network egress, but no direct data-flow from the secret to a network call was found (intra-file analysis). Review — cross-file/indirect exfiltration is still possible.",
      });
    }
  } else if (fsRead && egress && exfilFlows.length === 0) {
    ctx.findings.push({
      id: "capability/exfil-surface",
      category: "capability",
      severity: "info",
      profile: true,
      title: "Read-and-send surface",
      detail:
        "Reads local files AND makes outbound network requests. Informational blast-radius note.",
    });
  }

  // --- Code-execution co-presence ---
  if (evalCode && egress && rceFlows.length === 0) {
    if (!taint.analyzed) {
      ctx.findings.push({
        id: "gate/remote-exec-capability",
        category: "gate",
        severity: "critical",
        confidence: "medium",
        gate: true,
        title: "Remote code execution capability",
        detail:
          "Fetches remote content AND evaluates code. Source could not be data-flow analyzed, so this is treated conservatively as a gate.",
      });
    } else {
      ctx.findings.push({
        id: "capability/exec-surface",
        category: "capability",
        severity: "high",
        confidence: "medium",
        title: "Fetch-and-eval surface",
        detail:
          "Fetches remotely AND evaluates code, but no direct flow from fetched content to eval was found. Review.",
      });
    }
  } else if (exec && egress && rceFlows.length === 0) {
    ctx.findings.push({
      id: "capability/exec-surface",
      category: "capability",
      severity: "info",
      profile: true,
      title: "Fetch-and-exec surface",
      detail: "Makes outbound requests AND executes commands. Informational blast-radius note.",
    });
  }
}
