export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How sure we are the finding is real (vs. a heuristic that may false-positive). */
export type Confidence = "high" | "medium" | "low";

export type Category = "injection" | "capability" | "provenance" | "gate" | "drift" | "composition";

/** A single reproducible finding. Every finding must point at concrete evidence. */
export interface Finding {
  /** Stable rule id, e.g. "injection/instruction-override". */
  id: string;
  category: Category;
  severity: Severity;
  /** Confidence the finding is real. Defaults to "high" when omitted. */
  confidence?: Confidence;
  title: string;
  detail: string;
  /** Short snippet of the offending text/code. */
  evidence?: string;
  /** Where it was found: "file.js:12" or "tool:save_note" or "tool:save_note/param:body". */
  location?: string;
  /** Hard gate: any true gate forces a FAIL verdict regardless of score. */
  gate?: boolean;
  /**
   * Informational capability/hygiene item describing what the server *can* do or its
   * packaging. Profile findings never drive the verdict — only gates and anomalies do.
   */
  profile?: boolean;
}

export interface ToolParam {
  name: string;
  description?: string;
}

export interface ToolDef {
  name: string;
  description?: string;
  parameters?: ToolParam[];
}

/** A model-facing surface exposed by the server. All three feed text to the model. */
export type SurfaceKind = "tool" | "resource" | "prompt";

export interface SourceFile {
  /** Path relative to the target root. */
  path: string;
  content: string;
}

export type TargetKind = "dir" | "npm" | "pypi" | "github" | "tools";

/** Which language's deep analyzers (capability, provenance, deps, CVE) to run. */
export type Language = "js" | "python" | "unknown";

export interface Target {
  kind: TargetKind;
  /** The original user-supplied reference. */
  ref: string;
  /** Resolved local directory, when applicable. */
  rootDir?: string;
  packageJson?: Record<string, any>;
  /** Detected implementation language — selects the capability/provenance/CVE dialect. */
  language?: Language;
  sourceFiles: SourceFile[];
  tools: ToolDef[];
  /** Resources exposed by the server (their contents get fed to the model). */
  resources: ToolDef[];
  /** Prompt templates exposed by the server (also fed to the model). */
  prompts: ToolDef[];
}

/** Mutable state threaded through the analyzers. */
export interface AnalysisContext {
  target: Target;
  /** Capabilities PROVEN in the server's own source. These drive the hard gates. */
  caps: Set<string>;
  /**
   * Capabilities LATENT via declared dependencies (the dep can do it, but use isn't proven).
   * Informational + policy-gateable, but deliberately kept out of the hard exfil/RCE gates.
   */
  depCaps: Set<string>;
  findings: Finding[];
}

export type Verdict = "pass" | "warn" | "fail";

/**
 * A policy turns facts (findings + capabilities) into a verdict. The default policy
 * reproduces the built-in behavior; orgs can supply their own procurement/security
 * criteria. Detectors never decide the verdict — the policy does.
 */
export interface Policy {
  name: string;
  /** Extra finding ids to treat as hard-fail gates (on top of findings already flagged gate). */
  gate: string[];
  /** Capabilities that force FAIL if present, e.g. ["exec", "secret-access"]. */
  denyCapabilities: string[];
  /** Facts that must hold or the verdict FAILs, e.g. ["has_repository", "has_license"]. */
  require: string[];
  /** Any non-profile anomaly at this severity or worse FAILs. "none" = only gates fail. */
  failOnSeverity: Severity | "none";
  /** Any non-profile anomaly at this severity or worse WARNs. */
  warnOnSeverity: Severity;
  /**
   * Findings to suppress. A bare string suppresses that id forever; a Waiver adds an
   * audit trail (reason) and optional expiry after which the suppression lapses.
   */
  allow: (string | Waiver)[];
}

/** An audit-friendly, optionally time-boxed suppression of a finding. */
export interface Waiver {
  /** Finding id to suppress. */
  id: string;
  /** Why it was accepted (recorded for audit). */
  reason?: string;
  /** ISO date after which the waiver lapses and the finding counts again. */
  expires?: string;
}

/** One diffable item of the server's model-facing surface, with a content hash. */
export interface SurfaceItem {
  kind: SurfaceKind;
  name: string;
  hash: string;
}

export interface Report {
  target: string;
  kind: TargetKind;
  scannedAt: string;
  /** Stable hash of the tool surface — diff this across versions to catch rug-pulls. */
  fingerprint: string;
  verdict: Verdict;
  /** Name of the policy the verdict was evaluated against. */
  policy: string;
  /** Human-readable reasons the verdict was reached (gates, denied caps, unmet reqs, anomalies). */
  reasons: string[];
  /** Risk score 0 (clean) – 100 (worst). Derived from gates + anomalies only. */
  score: number;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  /** What the server can touch, e.g. ["fs-read", "net-egress"]. Informational. */
  capabilities: string[];
  /** The diffable surface (per-item content hashes) — baseline this to detect rug-pulls. */
  surface: SurfaceItem[];
  findings: Finding[];
}

/** Per-server summary within a multi-server (composition) scan. */
export interface ServerSummary {
  name: string;
  target: string;
  verdict: Verdict;
  score: number;
  capabilities: string[];
  toolCount: number;
  /** Present if this server could not be scanned. */
  error?: string;
}

/** Result of auditing a configured *set* of MCP servers together. */
export interface CompositionReport {
  target: string;
  scannedAt: string;
  serverCount: number;
  servers: ServerSummary[];
  /** Cross-server findings (exfil chains, tool-name collisions) — risks no single server shows. */
  findings: Finding[];
  verdict: Verdict;
}

export interface ScanOptions {
  /** Path to a JSON file with a tools/list dump (array or { tools/resources/prompts: [...] }). */
  toolsFile?: string;
  /** Force the target kind instead of auto-detecting. */
  kind?: TargetKind;
  /** A built-in policy name, a path to a policy JSON file, or a Policy object. */
  policy?: string | Policy;
  /** A prior Report (or path to one) to diff against, to detect drift / rug-pulls. */
  baseline?: string | Report;
  /** Live surface (from a handshake) to use instead of static extraction. */
  surface?: { tools: ToolDef[]; resources: ToolDef[]; prompts: ToolDef[] };
  /** For scanConfig: spawn each server and use its live handshake surface. Runs untrusted code. */
  handshake?: boolean;
  /**
   * Check declared dependencies against the OSV.dev advisory database for known CVEs.
   * Opt-in because it reaches the network (sends only dep names + versions, never source).
   */
  online?: boolean;
}
