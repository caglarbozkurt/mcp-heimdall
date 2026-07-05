import type { AnalysisContext } from "../types.js";

/**
 * Map a declared dependency name to the capability it grants. A clean server source can
 * still exfiltrate/exec through a dependency, so we surface the *latent* capability from
 * the manifest — no install needed. These are informational (dep presence ≠ malicious use)
 * and never trip the hard gates (see scan.ts), but a policy can still deny them.
 *
 * Expanded after a behavioral validation run showed static missing network egress that
 * happened through SDK/client dependencies (googleapis, firecrawl-js, isomorphic-fetch, …)
 * and credential access through scoped variants (@github/keytar) the exact-name map skipped.
 */
const DEP_CAPABILITY: Record<string, string> = {
  // --- outbound network: fetch/http clients ---
  axios: "net-egress",
  "node-fetch": "net-egress",
  "node-fetch-native": "net-egress",
  "isomorphic-fetch": "net-egress",
  "cross-fetch": "net-egress",
  got: "net-egress",
  undici: "net-egress",
  superagent: "net-egress",
  request: "net-egress",
  ky: "net-egress",
  needle: "net-egress",
  phin: "net-egress",
  gaxios: "net-egress",
  "graphql-request": "net-egress",
  ws: "net-egress",
  eventsource: "net-egress",
  nodemailer: "net-egress",
  "@grpc/grpc-js": "net-egress",
  // browsers / scrapers
  puppeteer: "net-egress",
  "puppeteer-core": "net-egress",
  playwright: "net-egress",
  "playwright-core": "net-egress",
  "@playwright/test": "net-egress",
  // service SDKs that talk to their API over the network
  googleapis: "net-egress",
  "google-auth-library": "net-egress",
  openai: "net-egress",
  "@anthropic-ai/sdk": "net-egress",
  "@mendable/firecrawl-js": "net-egress",
  "duck-duck-scrape": "net-egress",
  cheerio: "net-egress", // usually paired with a fetch, but frequently the scrape surface
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

/**
 * Scoped/family dependencies: a package under one of these scopes (or matching a suffix)
 * grants the capability. This catches the long tail of SDK families and scoped forks that
 * an exact-name map misses — e.g. every `@aws-sdk/*` client, or `@github/keytar`.
 */
const DEP_CAPABILITY_PREFIX: [string, string][] = [
  ["@aws-sdk/", "net-egress"],
  ["@google-cloud/", "net-egress"],
  ["@azure/", "net-egress"],
  ["@octokit/", "net-egress"],
  ["@slack/", "net-egress"],
  ["@sendgrid/", "net-egress"],
  ["@notionhq/", "net-egress"],
];

/** Suffix matches for scoped forks, e.g. `@github/keytar` → `keytar`. */
const DEP_CAPABILITY_SUFFIX: [string, string][] = [["/keytar", "secret-access"]];

/** Resolve a dependency name to a latent capability, honoring exact, prefix, and suffix rules. */
export function capForDep(name: string): string | undefined {
  if (DEP_CAPABILITY[name]) return DEP_CAPABILITY[name];
  for (const [prefix, cap] of DEP_CAPABILITY_PREFIX) if (name.startsWith(prefix)) return cap;
  for (const [suffix, cap] of DEP_CAPABILITY_SUFFIX) if (name.endsWith(suffix)) return cap;
  return undefined;
}

export function analyzeDependencies(ctx: AnalysisContext): void {
  const pkg = ctx.target.packageJson;
  if (!pkg) return;

  const deps = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
  } as Record<string, string>;
  const names = Object.keys(deps);
  if (names.length === 0) return;

  const seen = new Set<string>();
  for (const name of names) {
    const cap = capForDep(name);
    if (!cap) continue;
    ctx.depCaps.add(cap);
    if (seen.has(name)) continue;
    seen.add(name);
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
