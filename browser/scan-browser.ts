// Browser build of Heimdall. Runs the exact same analyzers as the CLI, but resolves
// package files over jsDelivr (CORS-enabled) instead of npm/fs — so a full scan happens
// entirely in the visitor's browser, with no backend. Deployable to GitHub Pages.
import { analyzeCapability } from "../src/analyzers/capability.js";
import { analyzeDependencies } from "../src/analyzers/dependencies.js";
import { analyzeGates } from "../src/analyzers/gates.js";
import { analyzeInjection } from "../src/analyzers/injection.js";
import { analyzeProvenance } from "../src/analyzers/provenance.js";
import { analyzeComposition, looksLikeConfig, parseConfig, RANK } from "../src/composition-core.js";
import { extractPrompts, extractResources, extractTools, parseSurfaceDump } from "../src/extract.js";
import { fingerprintTools, surfaceItems } from "../src/fingerprint.js";
import { evaluate, resolvePolicy } from "../src/policy.js";
import { sortFindings } from "../src/score.js";
import { analyzeTaint } from "../src/taint.js";
import type {
  AnalysisContext,
  CompositionReport,
  Report,
  ScanOptions,
  ServerSummary,
  Target,
} from "../src/types.js";

const SOURCE_EXT = /\.(js|mjs|cjs|ts|mts|cts)$/;
const SKIP_DIR = /(^|\/)(node_modules|test|tests|__tests__|examples?|coverage)\//;
const MAX_FILES = 40;
const MAX_BYTES = 2_000_000;

const getJSON = (url: string) => fetch(url).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`${r.status}`))));
const getText = (url: string) => fetch(url).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`${r.status}`))));

/** Resolve an npm package's source over jsDelivr into a scannable Target. */
async function resolveNpm(pkg: string): Promise<Target> {
  let meta: any;
  try {
    meta = await getJSON(`https://data.jsdelivr.com/v1/packages/npm/${pkg}`);
  } catch {
    throw new Error(`package "${pkg}" not found on npm`);
  }
  const version = meta.tags?.latest ?? meta.versions?.[0]?.version;
  if (!version) throw new Error(`no published version for "${pkg}"`);

  const flat = await getJSON(`https://data.jsdelivr.com/v1/packages/npm/${pkg}@${version}?structure=flat`);
  const paths: string[] = (flat.files ?? []).map((f: any) => f.name);

  let packageJson: Record<string, any> | undefined;
  try {
    packageJson = await getJSON(`https://cdn.jsdelivr.net/npm/${pkg}@${version}/package.json`);
  } catch {
    /* some packages omit it from the CDN root — fine */
  }

  const srcPaths = paths.filter((p) => SOURCE_EXT.test(p) && !SKIP_DIR.test(p)).slice(0, MAX_FILES);
  const sourceFiles = (
    await Promise.all(
      srcPaths.map(async (p) => {
        try {
          const content = await getText(`https://cdn.jsdelivr.net/npm/${pkg}@${version}${p}`);
          return content.length <= MAX_BYTES ? { path: p.replace(/^\//, ""), content } : null;
        } catch {
          return null;
        }
      }),
    )
  ).filter((f): f is { path: string; content: string } => f !== null);

  return { kind: "npm", ref: `${pkg}@${version}`, packageJson, sourceFiles, tools: [], resources: [], prompts: [] };
}

function isGithub(input: string): boolean {
  return /^https?:\/\/github\.com\//.test(input) || /^gh:/.test(input);
}

/** Run the standard analyzer pipeline over a resolved Target (mirrors the CLI's scan()). */
function runPipeline(target: Target, refLabel: string, opts: ScanOptions): Report {
  if (opts.surface) {
    target.tools = opts.surface.tools;
    target.resources = opts.surface.resources;
    target.prompts = opts.surface.prompts;
  } else {
    if (target.tools.length === 0) target.tools = extractTools(target);
    if (target.resources.length === 0) target.resources = extractResources(target);
    if (target.prompts.length === 0) target.prompts = extractPrompts(target);
  }

  const ctx: AnalysisContext = { target, caps: new Set(), depCaps: new Set(), findings: [] };
  analyzeInjection(ctx);
  analyzeCapability(ctx);
  analyzeDependencies(ctx);
  analyzeProvenance(ctx);
  analyzeGates(ctx, analyzeTaint(target.sourceFiles));

  const capabilities = [...new Set([...ctx.caps, ...ctx.depCaps])].sort();
  const surface = surfaceItems(target.tools, target.resources, target.prompts);
  const now = new Date().toISOString();
  const policy = resolvePolicy(opts.policy);
  const { verdict, score, reasons, notices } = evaluate(ctx.findings, capabilities, target.tools.length, policy, now);
  ctx.findings.push(...notices);

  return {
    target: refLabel,
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

async function scanConfigBrowser(json: any, opts: ScanOptions): Promise<CompositionReport> {
  const entries = parseConfig(json);
  const scanned = await Promise.all(
    entries.map(async (e) => {
      try {
        if (isGithub(e.target) || e.target.startsWith(".") || e.target.startsWith("/")) {
          throw new Error("only npm servers can be scanned in the browser");
        }
        const target = await resolveNpm(e.target);
        return { name: e.name, target: e.target, report: runPipeline(target, e.target, { policy: opts.policy }) };
      } catch (err) {
        return { name: e.name, target: e.target, error: err instanceof Error ? err.message : String(err) };
      }
    }),
  );

  const ok = scanned.filter((s): s is { name: string; target: string; report: Report } => "report" in s);
  const findings = analyzeComposition(ok);
  const servers: ServerSummary[] = scanned.map((s) =>
    "report" in s
      ? { name: s.name, target: s.target, verdict: s.report.verdict, score: s.report.score, capabilities: s.report.capabilities, toolCount: s.report.toolCount }
      : { name: s.name, target: s.target, verdict: "fail", score: 0, capabilities: [], toolCount: 0, error: (s as any).error },
  );
  let verdict: Report["verdict"] = "pass";
  for (const s of servers) if (RANK[s.verdict] > RANK[verdict]) verdict = s.verdict;
  if (findings.length && verdict === "pass") verdict = "warn";

  return { target: "config", scannedAt: new Date().toISOString(), serverCount: servers.length, servers, findings, verdict };
}

export type BrowserResult = (Report & { composition?: false }) | (CompositionReport & { composition: true });

/**
 * Scan a target entirely in the browser. Accepts an npm package name, or pasted JSON
 * (a tools/list dump or an MCP client config). Local paths, GitHub URLs, and --handshake
 * are not available client-side.
 */
export async function scanBrowser(input: string, opts: ScanOptions = {}): Promise<BrowserResult> {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("enter a target");

  if (/^[[{]/.test(trimmed)) {
    let json: any;
    try {
      json = JSON.parse(trimmed);
    } catch {
      throw new Error("that looks like JSON but didn't parse");
    }
    if (looksLikeConfig(json)) return { ...(await scanConfigBrowser(json, opts)), composition: true };
    const surface = parseSurfaceDump(json);
    const target: Target = { kind: "tools", ref: "pasted", sourceFiles: [], ...surface };
    return { ...runPipeline(target, "pasted JSON", opts), composition: false };
  }

  if (isGithub(trimmed)) {
    throw new Error("GitHub scanning isn't available in the browser yet — use the npm package name, or run the CLI");
  }
  if (trimmed.startsWith(".") || trimmed.startsWith("/")) {
    throw new Error("local paths can't be scanned in the browser — run the CLI, or scan the npm package name");
  }

  const target = await resolveNpm(trimmed);
  return { ...runPipeline(target, trimmed, opts), composition: false };
}
