import type { AnalysisContext, Finding } from "../types.js";
import { snippet } from "../util.js";

/** Shell/code-exec patterns that make an npm lifecycle script dangerous. */
const DANGEROUS_SCRIPT =
  /\b(curl|wget|bash|sh\s+-c|node\s+-e|node\s+--eval|eval|base64\s+-d|powershell|iwr|invoke-webrequest)\b/i;

const LIFECYCLE_HOOKS = ["preinstall", "install", "postinstall", "prepare"];

export function analyzeProvenance(ctx: AnalysisContext): void {
  const pkg = ctx.target.packageJson;
  if (!pkg) {
    // With no package AND no source (a raw tools/list dump), provenance simply isn't
    // assessable — that's informational, not a risk. With source but no manifest, it's an anomaly.
    const noContext = ctx.target.sourceFiles.length === 0;
    ctx.findings.push({
      id: "provenance/no-manifest",
      category: "provenance",
      severity: noContext ? "info" : "medium",
      confidence: "high",
      profile: noContext,
      title: "No package manifest found",
      detail: noContext
        ? "No package context (a raw tools/list dump); publisher, license, and dependency provenance were not assessed."
        : "No package.json was found, so publisher, license, and dependency provenance cannot be established.",
    });
    return;
  }

  const scripts: Record<string, string> = pkg.scripts ?? {};

  for (const hook of LIFECYCLE_HOOKS) {
    const body = scripts[hook];
    if (!body) continue;
    const dangerous = DANGEROUS_SCRIPT.test(body);
    // "prepare" is a standard build hook (runs on publish / git-dep install); benign by
    // convention. The install-time hooks are the ones worth a human glance.
    const buildHook = hook === "prepare";
    if (dangerous) {
      ctx.findings.push({
        id: "provenance/install-script-exec",
        category: "provenance",
        severity: "critical",
        gate: true,
        title: `Code execution in "${hook}" lifecycle script`,
        detail: `The "${hook}" script runs automatically on install and executes code / fetches remote content.`,
        evidence: snippet(body),
        location: "package.json:scripts",
      });
    } else {
      ctx.findings.push({
        id: buildHook ? "provenance/build-hook" : "provenance/install-script",
        category: "provenance",
        severity: buildHook ? "info" : "medium",
        profile: buildHook, // normal build hook = informational; install hooks = anomaly
        title: buildHook ? `"${hook}" build hook present` : `"${hook}" install script present`,
        detail: buildHook
          ? `The "${hook}" script is a standard build hook.`
          : `The "${hook}" script runs automatically on install. Review it before installing.`,
        evidence: snippet(body),
        location: "package.json:scripts",
      });
    }
  }

  // Provenance hygiene signals — informational trust context, not risk drivers on their own.
  if (!pkg.repository) {
    ctx.findings.push({
      id: "provenance/no-repository",
      category: "provenance",
      severity: "info",
      profile: true,
      title: "No source repository declared",
      detail:
        "Package does not declare a repository, so the source cannot be independently reviewed.",
      location: "package.json",
    });
  }
  if (!pkg.license) {
    ctx.findings.push({
      id: "provenance/no-license",
      category: "provenance",
      severity: "info",
      profile: true,
      title: "No license declared",
      detail: "Package declares no license.",
      location: "package.json",
    });
  }
  if (!pkg.author && !pkg.maintainers) {
    ctx.findings.push({
      id: "provenance/anonymous-publisher",
      category: "provenance",
      severity: "info",
      profile: true,
      title: "No author or maintainer declared",
      detail: "Package declares no author or maintainer.",
      location: "package.json",
    });
  }
}
