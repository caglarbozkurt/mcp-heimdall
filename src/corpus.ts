import { scan } from "./scan.js";
import type { Policy } from "./types.js";

export interface CorpusCase {
  target: string;
  label: "benign" | "malicious";
  policy?: string | Policy;
  baseline?: string;
}

export interface CaseResult {
  target: string;
  label: CorpusCase["label"];
  verdict: string;
  flagged: boolean; // FAIL = flagged as malicious
  correct: boolean;
}

export interface CorpusMetrics {
  total: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  accuracy: number;
}

/**
 * Run the scanner over a labeled corpus and score it. This is the calibration harness:
 * grow the corpus, run it, and tune thresholds/rules against precision & recall instead
 * of guessing. `flagged` = a FAIL verdict; `malicious` is the ground truth.
 */
export async function evaluateCorpus(
  cases: CorpusCase[],
): Promise<{ results: CaseResult[]; metrics: CorpusMetrics }> {
  const results: CaseResult[] = [];
  for (const c of cases) {
    const report = await scan(c.target, { policy: c.policy, baseline: c.baseline });
    const flagged = report.verdict === "fail";
    const malicious = c.label === "malicious";
    results.push({
      target: c.target,
      label: c.label,
      verdict: report.verdict,
      flagged,
      correct: flagged === malicious,
    });
  }

  const tp = results.filter((r) => r.flagged && r.label === "malicious").length;
  const fp = results.filter((r) => r.flagged && r.label === "benign").length;
  const tn = results.filter((r) => !r.flagged && r.label === "benign").length;
  const fn = results.filter((r) => !r.flagged && r.label === "malicious").length;
  const safe = (n: number, d: number) => (d === 0 ? 1 : n / d);

  return {
    results,
    metrics: {
      total: results.length,
      tp,
      fp,
      tn,
      fn,
      precision: safe(tp, tp + fp),
      recall: safe(tp, tp + fn),
      accuracy: safe(tp + tn, results.length),
    },
  };
}
