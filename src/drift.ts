import type { Finding, Report, SurfaceItem } from "./types.js";

const key = (i: SurfaceItem) => `${i.kind}:${i.name}`;

/**
 * Diff a baseline report's surface against the current one and emit drift findings.
 * A description/parameter change on an already-approved tool is the classic "rug-pull":
 * benign at approval, malicious after. Capability additions are the other half.
 */
type Surface = Pick<Report, "surface" | "capabilities">;

export function diffSurface(baseline: Surface, current: Surface): Finding[] {
  const findings: Finding[] = [];
  const baseMap = new Map(baseline.surface.map((i) => [key(i), i]));
  const curMap = new Map(current.surface.map((i) => [key(i), i]));

  for (const [k, cur] of curMap) {
    const prev = baseMap.get(k);
    if (!prev) {
      findings.push({
        id: "drift/surface-added",
        category: "drift",
        severity: "medium",
        confidence: "high",
        title: `New ${cur.kind} added since baseline`,
        detail: `${cur.kind} "${cur.name}" was not present in the baseline. Review it before re-approving.`,
        location: k,
      });
    } else if (prev.hash !== cur.hash) {
      findings.push({
        // The rug-pull signal: an approved item's model-facing text changed.
        id: "drift/description-changed",
        category: "drift",
        severity: "high",
        confidence: "high",
        gate: true,
        title: `${cur.kind} definition changed since baseline`,
        detail: `${cur.kind} "${cur.name}" changed its description/parameters after the baseline was recorded. This is how a rug-pull hides injection after approval — re-review before trusting.`,
        location: k,
      });
    }
  }

  for (const [k, prev] of baseMap) {
    if (!curMap.has(k)) {
      findings.push({
        id: "drift/surface-removed",
        category: "drift",
        severity: "low",
        confidence: "high",
        title: `${prev.kind} removed since baseline`,
        detail: `${prev.kind} "${prev.name}" was present in the baseline but is gone now.`,
        location: k,
      });
    }
  }

  // Capability additions across versions (e.g. a tool server that grew network egress).
  const gained = current.capabilities.filter((c) => !baseline.capabilities.includes(c));
  for (const cap of gained) {
    findings.push({
      id: "drift/capability-added",
      category: "drift",
      severity: "high",
      confidence: "high",
      title: `New capability since baseline: ${cap}`,
      detail: `The server gained the "${cap}" capability since the baseline. Capability escalation after approval warrants re-review.`,
    });
  }

  return findings;
}
