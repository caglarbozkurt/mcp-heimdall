import type { Finding, Severity } from "./types.js";

const WEIGHT: Record<Severity, number> = {
  critical: 45,
  high: 22,
  medium: 9,
  low: 3,
  info: 0,
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    // gates first, then risk findings, then profile items; within each, by severity
    if (a.gate !== b.gate) return a.gate ? -1 : 1;
    if (!!a.profile !== !!b.profile) return a.profile ? 1 : -1;
    return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  });
}

/**
 * Numeric risk score (0–100), derived only from non-profile findings and deduped by
 * rule id so a pattern repeated across many tools doesn't compound. The verdict is
 * decided by the policy, not here; `failed` just floors a failing scan at 80.
 */
export function computeScore(findings: Finding[], failed: boolean): number {
  const counted = new Map<string, Severity>();
  for (const f of findings) if (!f.profile && !counted.has(f.id)) counted.set(f.id, f.severity);
  const raw = [...counted.values()].reduce((sum, sev) => sum + WEIGHT[sev], 0);
  return Math.min(100, failed ? Math.max(80, raw) : raw);
}
