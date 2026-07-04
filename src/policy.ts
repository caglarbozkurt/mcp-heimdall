import { readFileSync } from "node:fs";
import { computeScore, SEVERITY_RANK } from "./score.js";
import type { Finding, Policy, Verdict, Waiver } from "./types.js";

/** Default policy — reproduces the built-in behavior: only gates fail; medium+ anomalies warn. */
export const DEFAULT_POLICY: Policy = {
  name: "default",
  gate: [],
  denyCapabilities: [],
  require: [],
  failOnSeverity: "none",
  warnOnSeverity: "medium",
  allow: [],
};

/** A stricter example policy for procurement/security gating. */
export const STRICT_POLICY: Policy = {
  name: "strict",
  gate: [],
  denyCapabilities: ["exec", "dynamic-eval", "secret-access"],
  require: ["has_repository", "has_license"],
  failOnSeverity: "high",
  warnOnSeverity: "low",
  allow: [],
};

export const BUILTIN_POLICIES: Record<string, Policy> = {
  default: DEFAULT_POLICY,
  strict: STRICT_POLICY,
};

/** Resolve a policy from a built-in name, a JSON file path, or a Policy object. */
export function resolvePolicy(policy?: string | Policy): Policy {
  if (!policy) return DEFAULT_POLICY;
  if (typeof policy === "object") return { ...DEFAULT_POLICY, ...policy };
  if (BUILTIN_POLICIES[policy]) return BUILTIN_POLICIES[policy];
  // treat as a file path; user policies extend the default
  const parsed = JSON.parse(readFileSync(policy, "utf8"));
  return { ...DEFAULT_POLICY, ...parsed, name: parsed.name ?? policy };
}

/** Whether a named fact holds, given the findings and tool count. */
function factSatisfied(req: string, findings: Finding[], toolCount: number): boolean {
  const absent = (id: string) => !findings.some((f) => f.id === id);
  const noManifest = findings.some((f) => f.id === "provenance/no-manifest");
  switch (req) {
    case "has_repository":
      return !noManifest && absent("provenance/no-repository");
    case "has_license":
      return !noManifest && absent("provenance/no-license");
    case "has_author":
      return !noManifest && absent("provenance/anonymous-publisher");
    case "no_install_scripts":
      return absent("provenance/install-script") && absent("provenance/install-script-exec");
    case "no_known_vulnerabilities":
      return absent("provenance/known-vulnerability");
    case "tools_extracted":
      return toolCount > 0;
    default:
      return true; // unknown requirement — ignored
  }
}

export interface Evaluation {
  verdict: Verdict;
  score: number;
  reasons: string[];
  /** Any expired-waiver notices to surface as findings. */
  notices: Finding[];
}

const asWaiver = (w: string | Waiver): Waiver => (typeof w === "string" ? { id: w } : w);

/** Turn facts into a verdict under a policy. This is the single decision point. */
export function evaluate(
  findings: Finding[],
  capabilities: string[],
  toolCount: number,
  policy: Policy,
  now: string = new Date().toISOString(),
): Evaluation {
  const reasons: string[] = [];
  const notices: Finding[] = [];

  // Resolve waivers: a waiver suppresses its finding only while unexpired. An expired
  // waiver stops suppressing AND raises an audit notice.
  const activeWaived = new Set<string>();
  const expiredIds = new Set<string>();
  for (const w of policy.allow.map(asWaiver)) {
    if (w.expires && w.expires <= now) expiredIds.add(w.id);
    else activeWaived.add(w.id);
  }
  for (const id of expiredIds) {
    if (!activeWaived.has(id) && findings.some((f) => f.id === id)) {
      notices.push({
        id: "waiver/expired",
        category: "provenance",
        severity: "low",
        confidence: "high",
        title: `Waiver expired for ${id}`,
        detail: `A policy waiver for "${id}" has expired; the finding is being counted again.`,
      });
    }
  }

  const active = findings.filter((f) => !activeWaived.has(f.id));
  const risk = active.filter((f) => !f.profile);

  // Denied capabilities
  const deniedCaps = capabilities.filter((c) => policy.denyCapabilities.includes(c));
  for (const c of deniedCaps) reasons.push(`denied capability: ${c}`);

  // Unmet requirements
  const unmet = policy.require.filter((r) => !factSatisfied(r, active, toolCount));
  for (const r of unmet) reasons.push(`unmet requirement: ${r}`);

  // Gates
  const gates = risk.filter((f) => f.gate || policy.gate.includes(f.id));
  for (const g of gates) reasons.push(`gate: ${g.id}`);

  // Anomalies (non-gate, non-profile risk findings)
  const anomalies = risk.filter((f) => !(f.gate || policy.gate.includes(f.id)));
  let worst: number | null = null;
  for (const a of anomalies) {
    const r = SEVERITY_RANK[a.severity];
    if (worst === null || r < worst) worst = r;
  }

  const failRank =
    policy.failOnSeverity !== "none" ? SEVERITY_RANK[policy.failOnSeverity] : null;
  const warnRank = SEVERITY_RANK[policy.warnOnSeverity];

  const hardFail = deniedCaps.length > 0 || unmet.length > 0 || gates.length > 0;

  let verdict: Verdict;
  if (hardFail) {
    verdict = "fail";
  } else if (failRank !== null && worst !== null && worst <= failRank) {
    verdict = "fail";
  } else if (worst !== null && worst <= warnRank) {
    verdict = "warn";
  } else {
    verdict = "pass";
  }

  // Record the anomalies that met the warn bar, so a WARN/FAIL is always explainable.
  if (verdict !== "pass") {
    const seen = new Set<string>();
    for (const a of anomalies) {
      if (SEVERITY_RANK[a.severity] <= warnRank && !seen.has(a.id)) {
        seen.add(a.id);
        reasons.push(`anomaly: ${a.id}`);
      }
    }
  }

  return { verdict, score: computeScore(risk, verdict === "fail"), reasons, notices };
}
