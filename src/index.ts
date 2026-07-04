export { scan } from "./scan.js";
export { computeScore, sortFindings } from "./score.js";
export {
  evaluate,
  resolvePolicy,
  DEFAULT_POLICY,
  STRICT_POLICY,
  BUILTIN_POLICIES,
} from "./policy.js";
export { fingerprintTools, surfaceItems } from "./fingerprint.js";
export { diffSurface } from "./drift.js";
export { toSarif } from "./sarif.js";
export { scanConfig, analyzeComposition, parseConfig, looksLikeConfig } from "./composition.js";
export { analyzeTaint, analyzeFileTaint } from "./taint.js";
export {
  analyzeVulnerabilities,
  coerceVersion,
  mapSeverity,
  resolveDeps,
  vulnerabilityFinding,
} from "./analyzers/vulnerabilities.js";
export { handshake } from "./handshake.js";
export { evaluateCorpus } from "./corpus.js";
export {
  parseToolsDump,
  parseSurfaceDump,
  extractTools,
  extractResources,
  extractPrompts,
  normalizeTool,
} from "./extract.js";
export * from "./types.js";
