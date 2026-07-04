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

function formatFinding(f: Finding): string {
  const tag = SEVERITY_STYLE[f.severity](SEVERITY_LABEL[f.severity]);
  const gate = f.gate ? c("1;31", " [GATE]") : "";
  const conf = f.confidence && f.confidence !== "high" ? c("2", ` (${f.confidence} confidence)`) : "";
  const head = `  ${tag}${gate}  ${f.title}${conf}  ${c("2", f.id)}`;
  const parts = [head, `        ${f.detail}`];
  if (f.location) parts.push(`        ${c("2", "at " + f.location)}`);
  if (f.evidence) parts.push(`        ${c("2", "› " + f.evidence)}`);
  return parts.join("\n");
}
