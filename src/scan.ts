import { readFileSync } from "node:fs";
import { analyzeCapability } from "./analyzers/capability.js";
import { analyzeDependencies } from "./analyzers/dependencies.js";
import { analyzeGates } from "./analyzers/gates.js";
import { analyzeInjection } from "./analyzers/injection.js";
import { analyzeProvenance } from "./analyzers/provenance.js";
import { analyzePythonCapability, analyzePythonProvenance } from "./analyzers/python.js";
import { analyzeVulnerabilities } from "./analyzers/vulnerabilities.js";
import { diffSurface } from "./drift.js";
import { extractPrompts, extractResources, extractTools } from "./extract.js";
import { fingerprintTools, surfaceItems } from "./fingerprint.js";
import { evaluate, resolvePolicy } from "./policy.js";
import { resolveTarget } from "./resolve.js";
import { sortFindings } from "./score.js";
import { analyzeTaint } from "./taint.js";
import type { AnalysisContext, Report, ScanOptions } from "./types.js";

/**
 * Scan an MCP server and produce a risk report.
 * @param input a local directory, npm package name, GitHub URL, or a tools/list JSON dump.
 */
export async function scan(input: string, opts: ScanOptions = {}): Promise<Report> {
  const target = await resolveTarget(input, opts);
  if (opts.surface) {
    // Live handshake surface takes precedence over static extraction (highest fidelity).
    target.tools = opts.surface.tools;
    target.resources = opts.surface.resources;
    target.prompts = opts.surface.prompts;
  } else {
    if (target.tools.length === 0) target.tools = extractTools(target);
    if (target.resources.length === 0) target.resources = extractResources(target);
    if (target.prompts.length === 0) target.prompts = extractPrompts(target);
  }

  const ctx: AnalysisContext = { target, caps: new Set(), depCaps: new Set(), findings: [] };
  analyzeInjection(ctx); // language-agnostic (reads description text)
  if (target.language === "python") {
    // Python dialect: regex capability + manifest provenance (no AST taint — co-presence gates).
    analyzePythonCapability(ctx);
    analyzePythonProvenance(ctx);
  } else {
    analyzeCapability(ctx);
    analyzeDependencies(ctx);
    analyzeProvenance(ctx);
  }
  analyzeGates(ctx, analyzeTaint(target.sourceFiles)); // taint-aware for JS; Python → co-presence
  if (opts.online) await analyzeVulnerabilities(ctx); // opt-in OSV.dev CVE lookup (network)

  // Reported capabilities = proven (source) ∪ latent (dependencies). Gates used ctx.caps
  // only, so latent dep capabilities inform the profile and policy without hard-failing.
  const capabilities = [...new Set([...ctx.caps, ...ctx.depCaps])].sort();
  const surface = surfaceItems(target.tools, target.resources, target.prompts);

  // Drift / rug-pull detection against a prior report. Runs before the verdict so a
  // silently-changed tool description can hard-fail.
  if (opts.baseline) {
    const baseline: Report =
      typeof opts.baseline === "string"
        ? JSON.parse(readFileSync(opts.baseline, "utf8"))
        : opts.baseline;
    ctx.findings.push(...diffSurface(baseline, { surface, capabilities }));
  }

  const now = new Date().toISOString();
  const policy = resolvePolicy(opts.policy);
  const { verdict, score, reasons, notices } = evaluate(
    ctx.findings,
    capabilities,
    target.tools.length,
    policy,
    now,
  );
  ctx.findings.push(...notices);

  return {
    target: input,
    kind: target.kind,
    scannedAt: now,
    fingerprint: fingerprintTools(target.tools),
    verdict,
    policy: policy.name,
    reasons,
    score,
    toolCount: target.tools.length,
    resourceCount: target.resources.length,
    promptCount: target.prompts.length,
    capabilities,
    surface,
    findings: sortFindings(ctx.findings),
  };
}
