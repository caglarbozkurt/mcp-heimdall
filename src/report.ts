import type { BatchReport, ValidateReport } from "./validate.js";
import type { CompositionReport, Finding, Report, Severity, Verdict } from "./types.js";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: (s) => c("1;31", s),
  high: (s) => c("31", s),
  medium: (s) => c("33", s),
  low: (s) => c("34", s),
  info: (s) => c("2", s),
};

const VERDICT_STYLE: Record<Verdict, (s: string) => string> = {
  pass: (s) => c("1;32", s),
  warn: (s) => c("1;33", s),
  fail: (s) => c("1;31", s),
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
  info: "INFO",
};

export function formatReport(report: Report): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  ${c("1", "heimdall")}  ${report.target}  ${c("2", `(${report.kind})`)}`);
  const surface = [
    `${report.toolCount} tools`,
    report.resourceCount ? `${report.resourceCount} resources` : "",
    report.promptCount ? `${report.promptCount} prompts` : "",
  ]
    .filter(Boolean)
    .join(", ");
  lines.push(
    `  verdict: ${VERDICT_STYLE[report.verdict](report.verdict.toUpperCase())}` +
      `   risk score: ${report.score}/100   ${surface}   policy: ${report.policy}`,
  );
  if (report.reasons.length) {
    lines.push(`  ${c("2", "why: " + report.reasons.join("; "))}`);
  }
  lines.push(`  fingerprint: ${c("2", report.fingerprint)}`);
  lines.push(
    `  capabilities: ${
      report.capabilities.length ? report.capabilities.join(", ") : c("2", "none detected")
    }`,
  );
  lines.push("");

  const risk = report.findings.filter((f) => !f.profile);
  const profile = report.findings.filter((f) => f.profile);

  if (risk.length === 0) {
    lines.push(`  ${c("1;32", "No risk findings.")}`);
  } else {
    lines.push(`  ${c("1", "Risk findings")}`);
    for (const f of risk) lines.push(formatFinding(f));
  }

  if (profile.length) {
    lines.push("");
    lines.push(`  ${c("2", "Profile (informational — does not affect verdict)")}`);
    for (const f of profile) lines.push(formatFinding(f));
  }

  lines.push("");
  return lines.join("\n");
}

export function formatCompositionReport(report: CompositionReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  ${c("1", "heimdall")}  ${report.target}  ${c("2", "(composition)")}`);
  lines.push(
    `  verdict: ${VERDICT_STYLE[report.verdict](report.verdict.toUpperCase())}` +
      `   servers: ${report.serverCount}`,
  );
  lines.push("");
  lines.push(`  ${c("1", "Servers")}`);
  for (const s of report.servers) {
    const v = s.error ? c("1;31", "ERROR") : VERDICT_STYLE[s.verdict](s.verdict.toUpperCase());
    const caps = s.capabilities.length ? c("2", s.capabilities.join(",")) : c("2", "—");
    lines.push(`  ${v}  ${s.name}  ${c("2", s.target)}`);
    lines.push(`        ${s.error ? c("2", s.error) : `${s.toolCount} tools · ${caps}`}`);
  }
  lines.push("");
  if (report.findings.length === 0) {
    lines.push(`  ${c("1;32", "No cross-server findings.")}`);
  } else {
    lines.push(`  ${c("1", "Cross-server findings")}`);
    for (const f of report.findings) lines.push(formatFinding(f));
  }
  lines.push("");
  return lines.join("\n");
}

const STATUS_STYLE: Record<string, (s: string) => string> = {
  confirmed: (s) => c("1;32", s),
  "not-exercised": (s) => c("2", s),
  missed: (s) => c("1;31", s),
  clean: (s) => c("2", s),
};
const STATUS_LABEL: Record<string, string> = {
  confirmed: "✓ CONFIRMED   ",
  "not-exercised": "· not exercised",
  missed: "✗ MISSED      ",
  clean: "—             ",
};

/** Render a single behavioral-validation report. */
export function formatValidateReport(r: ValidateReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  ${c("1", "heimdall validate")}  ${r.target}  ${c("2", `(${r.kind})`)}`);
  if (r.error) {
    lines.push(`  ${c("1;31", "could not run:")} ${r.error}`);
    lines.push("");
    return lines.join("\n");
  }
  lines.push(
    `  ${c("2", `drove ${r.toolsCalled} tool call(s); compared static flags vs. observed runtime behavior`)}`,
  );
  lines.push("");
  lines.push(
    `  ${c("1", "capability")}        ${c("1", "static")}   ${c("1", "observed")}   ${c("1", "result")}`,
  );
  for (const cap of r.comparison) {
    if (cap.status === "clean") continue;
    const s = cap.static ? c("32", "yes") : c("2", "no ");
    const o = cap.observed ? c("32", "yes") : c("2", "no ");
    lines.push(
      `  ${cap.cap.padEnd(16)}  ${s}      ${o}       ${STATUS_STYLE[cap.status](STATUS_LABEL[cap.status])}`,
    );
  }
  const anyShown = r.comparison.some((c) => c.status !== "clean");
  if (!anyShown) lines.push(`  ${c("2", "no capabilities flagged or observed")}`);
  lines.push("");
  lines.push(
    `  ${c("1", "summary")}: ${c("1;32", r.confirmed + " confirmed")}, ` +
      `${r.missed ? c("1;31", r.missed + " missed") : "0 missed"}, ` +
      `${c("2", r.notExercised + " flagged-but-not-exercised")}`,
  );
  if (r.missed) {
    lines.push(
      `  ${c("1;31", "⚠ MISSED = observed at runtime but not statically flagged — review it.")}`,
    );
    lines.push(
      `  ${c("2", "  (a genuine static gap, or an incidental library / child-process side effect)")}`,
    );
  }
  lines.push(
    `  ${c("2", "'not exercised' ≠ wrong: naive tool inputs may not trigger a real capability.")}`,
  );
  lines.push("");
  return lines.join("\n");
}

/** Render an aggregate validation report over many servers. */
export function formatBatchReport(b: BatchReport): string {
  const lines: string[] = [];
  const ran = b.servers.filter((s) => !s.error);
  lines.push("");
  lines.push(`  ${c("1", "heimdall validate")}  ${b.servers.length} server(s) (${ran.length} ran)`);
  lines.push("");
  lines.push(
    `  ${c("1", "capability")}        ${c("1", "confirmed")}   ${c("1", "missed")}   ${c("1", "not-exercised")}`,
  );
  for (const cap of Object.keys(b.perCap)) {
    const v = b.perCap[cap];
    if (!v.confirmed && !v.missed && !v.notExercised) continue;
    const miss = v.missed ? c("1;31", String(v.missed).padStart(6)) : String(v.missed).padStart(6);
    lines.push(
      `  ${cap.padEnd(16)}  ${String(v.confirmed).padStart(9)}   ${miss}   ${String(v.notExercised).padStart(13)}`,
    );
  }
  lines.push("");
  lines.push(
    `  ${c("1", "recall")} (observed behavior that static flagged): ` +
      `${c("1;36", (b.recall * 100).toFixed(1) + "%")}  ${c("2", `(${b.totalConfirmed}/${b.totalConfirmed + b.totalMissed})`)}`,
  );
  lines.push(
    `  ${c("2", "recall is the trustworthy metric here; precision is a lower bound (non-triggering ≠ absence).")}`,
  );
  lines.push("");
  return lines.join("\n");
}

function formatFinding(f: Finding): string {
  const tag = SEVERITY_STYLE[f.severity](SEVERITY_LABEL[f.severity]);
  const gate = f.gate ? c("1;31", " [GATE]") : "";
  const conf =
    f.confidence && f.confidence !== "high" ? c("2", ` (${f.confidence} confidence)`) : "";
  const head = `  ${tag}${gate}  ${f.title}${conf}  ${c("2", f.id)}`;
  const parts = [head, `        ${f.detail}`];
  if (f.location) parts.push(`        ${c("2", "at " + f.location)}`);
  if (f.evidence) parts.push(`        ${c("2", "› " + f.evidence)}`);
  return parts.join("\n");
}
