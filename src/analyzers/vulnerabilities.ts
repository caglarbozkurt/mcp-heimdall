import { SEVERITY_RANK } from "../score.js";
import type { AnalysisContext, Finding, Severity } from "../types.js";
import { parsePyDeps } from "./python.js";

/**
 * Known-CVE check for declared dependencies, via the OSV.dev advisory database.
 *
 * This is the one analyzer that reaches the network, so it is **opt-in** (`--online` /
 * `opts.online`) — the rest of Heimdall runs fully offline. It sends only dependency
 * *names and versions* to OSV.dev (never your source), and it emits normal findings that
 * the policy engine decides on: a known vuln WARNs by default and FAILs under `strict`
 * (or any policy with `failOnSeverity: high`). No hard gate — a manifest range is not a
 * lockfile, so the match is a strong review signal, not a proof of an exploitable install.
 */

const OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";
const MAX_DETAILS = 60; // bound the detail fan-out on pathological dep trees
const PER_DEP_CAP = 6; // most-severe advisories to itemize per dependency (rest rolled up)
const TIMEOUT_MS = 12_000;

export interface DepVersion {
  name: string;
  range: string;
  /** The concrete version queried against OSV (coerced from the range). */
  version: string;
}

/**
 * Coerce a package.json version spec to a concrete version to query OSV with, or null if
 * it can't be mapped to a registry release (tags, git/file/workspace specs, bare `*`).
 * A manifest gives ranges, not resolved versions — we query the declared floor and say so.
 */
export function coerceVersion(range: string): string | null {
  if (typeof range !== "string") return null;
  const r = range.trim();
  if (!r || /^(latest|next|\*|x)$/i.test(r)) return null;
  // npm:alias@1.2.3 → pull the aliased version
  const alias = r.match(/^npm:[^@]+@(.+)$/i);
  const spec = alias ? alias[1] : r;
  // Non-registry specs can't be range-matched by OSV.
  if (!alias && /^(git|https?|file|link|workspace|github|[\w.-]+\/[\w.-]+)/i.test(spec))
    return null;
  const m = spec.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  const [, major, minor = "0", patch = "0"] = m;
  return `${major}.${minor}.${patch}`;
}

const SEVERITY_WORD: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
};

/** Map an OSV vuln record to a Heimdall severity (GHSA label first, then a CVSS score). */
export function mapSeverity(vuln: any): Severity {
  const word = vuln?.database_specific?.severity;
  if (typeof word === "string" && SEVERITY_WORD[word.toUpperCase()]) {
    return SEVERITY_WORD[word.toUpperCase()];
  }
  for (const s of Array.isArray(vuln?.severity) ? vuln.severity : []) {
    const score = Number(s?.score);
    if (!Number.isNaN(score)) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "medium";
      return "low";
    }
  }
  return "medium"; // unknown severity → reviewable, but not an auto-fail under the default policy
}

/** Build the finding for a single (dependency, advisory) pair. */
export function vulnerabilityFinding(dep: DepVersion, id: string, detail: any): Finding {
  const cve = (detail?.aliases ?? []).find((a: string) => /^CVE-/i.test(a));
  const summary =
    detail?.summary ||
    (typeof detail?.details === "string" ? detail.details.slice(0, 120) : "") ||
    "known security advisory";
  return {
    id: "provenance/known-vulnerability",
    category: "provenance",
    severity: detail ? mapSeverity(detail) : "medium",
    confidence: "medium", // version came from the range, not a lockfile
    title: `Known vulnerability in ${dep.name}: ${summary}`,
    detail:
      `Declared dependency "${dep.name}@${dep.range}" (checked as ${dep.version}) is affected by ${id}` +
      `${cve ? ` (${cve})` : ""}. The version was resolved from the manifest range, not a lockfile — ` +
      `confirm the installed version. Advisory: https://osv.dev/${id}`,
    evidence: `${dep.name}@${dep.version} → ${id}${cve ? ` (${cve})` : ""}`,
    location: "package.json:dependencies",
  };
}

async function fetchJSON(url: string, init?: RequestInit): Promise<any> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/** Resolve declared deps to concrete versions we can query. */
export function resolveDeps(pkg: Record<string, any> | undefined): DepVersion[] {
  if (!pkg) return [];
  const declared = { ...(pkg.dependencies ?? {}), ...(pkg.optionalDependencies ?? {}) } as Record<
    string,
    string
  >;
  const out: DepVersion[] = [];
  for (const [name, range] of Object.entries(declared)) {
    const version = coerceVersion(range);
    if (version) out.push({ name, range, version });
  }
  return out;
}

/** Resolve declared Python deps to concrete versions we can query. */
function resolvePyDeps(target: AnalysisContext["target"]): DepVersion[] {
  const out: DepVersion[] = [];
  for (const dep of parsePyDeps(target)) {
    const version = coerceVersion(dep.spec);
    if (version) out.push({ name: dep.name, range: dep.spec, version });
  }
  return out;
}

/**
 * Query OSV.dev for known vulnerabilities in the target's declared dependencies and push
 * a finding per (dependency, advisory). Network failures degrade to an informational
 * profile finding — they never break the scan or change the verdict. Ecosystem follows the
 * target language: npm for JS/TS, PyPI for Python (OSV covers both with the same API).
 */
export async function analyzeVulnerabilities(ctx: AnalysisContext): Promise<void> {
  const python = ctx.target.language === "python";
  const ecosystem = python ? "PyPI" : "npm";
  const deps = python ? resolvePyDeps(ctx.target) : resolveDeps(ctx.target.packageJson);
  if (deps.length === 0) return;

  let batch: any;
  try {
    batch = await fetchJSON(OSV_QUERYBATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: deps.map((d) => ({ package: { ecosystem, name: d.name }, version: d.version })),
      }),
    });
  } catch (err) {
    ctx.findings.push({
      id: "provenance/vuln-scan-unavailable",
      category: "provenance",
      severity: "info",
      confidence: "high",
      profile: true, // informational — never affects the verdict
      title: "Dependency vulnerability check unavailable",
      detail: `Could not reach the OSV.dev advisory database (${
        err instanceof Error ? err.message : String(err)
      }); dependencies were not checked for known CVEs.`,
    });
    return;
  }

  const hits: { dep: DepVersion; ids: string[] }[] = [];
  const idSet = new Set<string>();
  (batch?.results ?? []).forEach((res: any, i: number) => {
    const ids: string[] = (res?.vulns ?? []).map((v: any) => v.id).filter(Boolean);
    if (ids.length && deps[i]) {
      hits.push({ dep: deps[i], ids });
      ids.forEach((id) => idSet.add(id));
    }
  });
  if (hits.length === 0) return;

  // Hydrate advisory details (severity + summary) for the flagged ids, bounded.
  const wanted = [...idSet].slice(0, MAX_DETAILS);
  const details = new Map<string, any>();
  await Promise.all(
    wanted.map(async (id) => {
      try {
        details.set(id, await fetchJSON(OSV_VULN + encodeURIComponent(id)));
      } catch {
        /* leave undetailed → severity defaults to medium */
      }
    }),
  );

  for (const hit of hits) {
    // Surface the most severe advisories first; itemize up to PER_DEP_CAP, roll up the rest.
    const ranked = [...hit.ids].sort(
      (a, b) =>
        SEVERITY_RANK[mapSeverity(details.get(a))] - SEVERITY_RANK[mapSeverity(details.get(b))],
    );
    for (const id of ranked.slice(0, PER_DEP_CAP)) {
      ctx.findings.push(vulnerabilityFinding(hit.dep, id, details.get(id)));
    }
    const extra = ranked.length - PER_DEP_CAP;
    if (extra > 0) {
      ctx.findings.push({
        id: "provenance/known-vulnerability",
        category: "provenance",
        severity: "info",
        confidence: "medium",
        title: `${extra} more known ${extra === 1 ? "advisory" : "advisories"} in ${hit.dep.name}`,
        detail: `${hit.dep.name}@${hit.dep.version} has ${ranked.length} total advisories in OSV.dev; the ${PER_DEP_CAP} most severe are itemized above. Full list: https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(hit.dep.name)}`,
        location: "package.json:dependencies",
      });
    }
  }
}
