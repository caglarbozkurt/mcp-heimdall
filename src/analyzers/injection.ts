import type { AnalysisContext, Confidence, Finding, Severity, ToolDef } from "../types.js";
import { snippet } from "../util.js";

interface Rule {
  id: string;
  severity: Severity;
  confidence: Confidence;
  gate?: boolean;
  title: string;
  test: RegExp;
}

// Invisible/zero-width code points built programmatically to avoid literal
// invisible characters in source: ZWSP, ZWNJ, ZWJ, word-joiner, BOM/ZWNBSP.
const ZERO_WIDTH_RE = new RegExp(
  "[" + [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff].map((c) => String.fromCodePoint(c)).join("") + "]",
);

/**
 * Prompt-injection / tool-poisoning rules. These run against every tool description
 * and every parameter description — the text the model actually ingests.
 */
const RULES: Rule[] = [
  {
    // Rarely legitimate: telling the model to disregard its instructions.
    id: "injection/instruction-override",
    severity: "critical",
    confidence: "high",
    gate: true,
    title: "Instruction-override phrasing",
    test: /\b(ignore|disregard|forget|override)\b[^.]{0,40}\b(previous|prior|above|earlier|instruction|instructions|context|system prompt)\b/i,
  },
  {
    // Rarely legitimate: telling the model to hide its actions from the user.
    id: "injection/conceal-from-user",
    severity: "critical",
    confidence: "high",
    gate: true,
    title: "Instruction to conceal actions from the user",
    test: /\b(without (telling|informing|notifying) (the )?user|do not (tell|inform|mention|reveal|disclose)|don'?t (tell|let) the user)\b/i,
  },
  {
    // Suspicious: directing data to an external destination.
    id: "injection/exfil-directive",
    severity: "high",
    confidence: "medium",
    title: "Data-exfiltration directive in text",
    test: /\b(send|forward|post|upload|transmit|exfiltrate)\b[^.]{0,60}(https?:\/\/|\b\S+@\S+\.|webhook)/i,
  },
  {
    // Common in legitimate tool descriptions ("you should always use this tool for…"),
    // so this is informational, not a gate. Weight rises only with corroborating gates.
    id: "injection/imperative-guidance",
    severity: "low",
    confidence: "low",
    title: "Imperative guidance aimed at the model",
    test: /\b(you must|you should always|always make sure to|before (responding|answering)|as your (first|very first) (action|step))\b/i,
  },
  {
    id: "injection/hidden-tag-chars",
    severity: "critical",
    confidence: "high",
    gate: true,
    title: "Hidden Unicode tag characters",
    test: /[\u{E0000}-\u{E007F}]/u,
  },
  {
    // Fake authority tags used to smuggle instructions the model will treat as
    // privileged. A hallmark of tool poisoning; rarely legitimate in a description.
    id: "injection/pseudo-instruction-tag",
    severity: "high",
    confidence: "medium",
    gate: true,
    title: "Fake authority tag in description (tool poisoning)",
    test: /<\/?\s*(important|system|secret|admin|instructions?|confidential|hidden|internal|do[ _-]?not[ _-]?share)\b[^>]*>/i,
  },
  {
    id: "injection/hidden-zero-width",
    severity: "high",
    confidence: "high",
    gate: true,
    title: "Hidden zero-width characters",
    test: ZERO_WIDTH_RE,
  },
  {
    id: "injection/html-comment",
    severity: "medium",
    confidence: "medium",
    title: "Hidden HTML comment in description",
    test: /<!--[\s\S]*?-->/,
  },
  {
    id: "injection/base64-blob",
    severity: "medium",
    confidence: "low",
    title: "Embedded base64 blob in description",
    test: /[A-Za-z0-9+/]{60,}={0,2}/,
  },
  {
    id: "injection/tool-shadowing",
    severity: "medium",
    confidence: "low",
    title: "Possible tool-shadowing language",
    test: /\b(instead of|rather than|override the|other tools?|all other tools|when (using|calling) (any|other))\b/i,
  },
];

function checkText(text: string, location: string, findings: Finding[]): void {
  for (const rule of RULES) {
    const m = rule.test.exec(text);
    if (m) {
      findings.push({
        id: rule.id,
        category: "injection",
        severity: rule.severity,
        confidence: rule.confidence,
        gate: rule.gate,
        title: rule.title,
        detail: `Detected in text ingested by the model at ${location}.`,
        evidence: snippet(m[0]),
        location,
      });
    }
  }
}

/** Run every injection rule over one surface (tool / resource / prompt) and its params. */
function checkSurface(items: ToolDef[], kind: string, findings: Finding[]): void {
  for (const item of items) {
    if (item.description) checkText(item.description, `${kind}:${item.name}`, findings);
    for (const param of item.parameters ?? []) {
      if (param.description) {
        checkText(param.description, `${kind}:${item.name}/param:${param.name}`, findings);
      }
    }
  }
}

export function analyzeInjection(ctx: AnalysisContext): void {
  const { tools, resources, prompts } = ctx.target;
  if (tools.length + resources.length + prompts.length === 0) {
    ctx.findings.push({
      id: "injection/no-surface",
      category: "injection",
      severity: "info",
      confidence: "high",
      title: "No tool/resource/prompt definitions available",
      detail:
        "Could not extract any model-facing surface from source. Supply a tools/list dump with --tools for full injection analysis.",
    });
    return;
  }

  checkSurface(tools, "tool", ctx.findings);
  checkSurface(resources, "resource", ctx.findings);
  checkSurface(prompts, "prompt", ctx.findings);
}
