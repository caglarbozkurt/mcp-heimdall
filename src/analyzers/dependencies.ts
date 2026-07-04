import type { AnalysisContext } from "../types.js";

/**
 * Map a declared dependency name to the capability it grants. A clean server source can
 * still exfiltrate/exec through a dependency, so we surface the *latent* capability from
 * the manifest — no install needed. These are informational (dep presence ≠ malicious use)
 * and never trip the hard gates (see scan.ts), but a policy can still deny them.
 */
const DEP_CAPABILITY: Record<string, string> = {
  // outbound network
  axios: "net-egress",
  "node-fetch": "net-egress",
  got: "net-egress",
  undici: "net-egress",
  superagent: "net-egress",
  request: "net-egress",
  ky: "net-egress",
  needle: "net-egress",
  phin: "net-egress",
  puppeteer: "net-egress",
  "puppeteer-core": "net-egress",
  playwright: "net-egress",
  "playwright-core": "net-egress",
  // command execution
  execa: "exec",
  shelljs: "exec",
  "node-pty": "exec",
  "cross-spawn": "exec",
  zx: "exec",
  // dynamic evaluation
  vm2: "dynamic-eval",
  "safe-eval": "dynamic-eval",
  notevil: "dynamic-eval",
  // secrets / config
  keytar: "secret-access",
  dotenv: "dotenv-access",
};

export function analyzeDependencies(ctx: AnalysisContext): void {
  const pkg = ctx.target.packageJson;
  if (!pkg) return;

  const deps = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
  } as Record<string, string>;
  const names = Object.keys(deps);
  if (names.length === 0) return;

  for (const name of names) {
    const cap = DEP_CAPABILITY[name];
    if (!cap) continue;
    ctx.depCaps.add(cap);
    ctx.findings.push({
      id: "provenance/dependency-capability",
      category: "provenance",
      severity: "info",
      confidence: "medium",
      profile: true, // latent capability via supply chain — informational, not a proven risk
      title: `Dependency provides capability: ${cap}`,
      detail: `Declared dependency "${name}" can perform "${cap}". Latent (not necessarily used by the server), but it is part of the trusted-code surface.`,
      evidence: `${name}@${deps[name]}`,
      location: "package.json:dependencies",
    });
  }
}
