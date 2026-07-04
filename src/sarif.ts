import type { Report, Severity } from "./types.js";

const LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

/**
 * Emit a SARIF 2.1.0 log so findings drop into GitHub code-scanning, CI dashboards, etc.
 * Logical locations are used (tool:/resource:/file:) since not everything maps to a file.
 */
export function toSarif(report: Report): Record<string, unknown> {
  const rules = new Map<string, Record<string, unknown>>();
  const results = report.findings.map((f) => {
    if (!rules.has(f.id)) {
      rules.set(f.id, { id: f.id, name: f.title, shortDescription: { text: f.title } });
    }
    const [file, line] = (f.location ?? "").split(":");
    const isFile = f.location && /\.[a-z]+$/i.test(file);
    return {
      ruleId: f.id,
      level: LEVEL[f.severity],
      message: { text: f.evidence ? `${f.detail} [${f.evidence}]` : f.detail },
      properties: { severity: f.severity, confidence: f.confidence ?? "high", category: f.category },
      locations: f.location
        ? [
            isFile
              ? {
                  physicalLocation: {
                    artifactLocation: { uri: file },
                    ...(line ? { region: { startLine: Number(line) || 1 } } : {}),
                  },
                }
              : { logicalLocations: [{ fullyQualifiedName: f.location }] },
          ]
        : [],
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "heimdall",
            informationUri: "https://github.com/caglarbozkurt/mcp-heimdall",
            rules: [...rules.values()],
          },
        },
        results,
        properties: {
          verdict: report.verdict,
          policy: report.policy,
          score: report.score,
          fingerprint: report.fingerprint,
        },
      },
    ],
  };
}
