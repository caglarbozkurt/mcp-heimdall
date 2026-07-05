import type { AnalysisContext, Confidence, Severity } from "../types.js";
import { lineAt, snippet, stripComments } from "../util.js";

interface CapRule {
  cap: string;
  id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  detail: string;
  test: RegExp;
}

/**
 * Capability rules. We score what the code *can do* (objective) rather than intent
 * (unknowable). Each match records a capability flag on the context so gates.ts can
 * reason about dangerous combinations (e.g. local-read + network-egress = exfil).
 */
const CAP_RULES: CapRule[] = [
  {
    cap: "fs-read",
    id: "capability/fs-read",
    severity: "low",
    confidence: "high",
    title: "Filesystem read access",
    detail: "Reads from the filesystem.",
    test: /\b(readFileSync|readFile|createReadStream|readdirSync|readdir|fs\.promises\.readFile)\b/,
  },
  {
    cap: "fs-write",
    id: "capability/fs-write",
    severity: "medium",
    confidence: "high",
    title: "Filesystem write access",
    detail: "Writes to the filesystem.",
    test: /\b(writeFileSync|writeFile|createWriteStream|appendFileSync|appendFile|unlinkSync|rmSync|rm)\b/,
  },
  {
    cap: "net-egress",
    id: "capability/net-egress",
    severity: "low",
    confidence: "high",
    title: "Outbound network access",
    detail: "Makes outbound network requests.",
    test: /\bfetch\s*\(|\baxios\b|\bnode-fetch\b|new\s+XMLHttpRequest|require\(['"](node:)?(https?|net|dgram)['"]\)|from\s+['"](node:)?(https?|net|dgram)['"]/,
  },
  {
    cap: "exec",
    id: "capability/exec",
    severity: "high",
    confidence: "high",
    title: "Shell / command execution",
    detail: "Executes shell commands or spawns child processes.",
    test: /\bchild_process\b|require\(['"](node:)?child_process['"]\)|\b(execSync|execFileSync?|exec|spawnSync?)\s*\(/,
  },
  {
    cap: "dynamic-eval",
    id: "capability/dynamic-eval",
    severity: "high",
    confidence: "high",
    title: "Dynamic code evaluation",
    detail: "Evaluates code at runtime (eval / new Function / vm).",
    test: /\beval\s*\(|new\s+Function\s*\(|\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\b/,
  },
  // --- credential/secret access, split into concrete detectors (all flag "secret-access") ---
  {
    cap: "secret-access",
    id: "capability/secret-ssh",
    severity: "high",
    confidence: "high",
    title: "Access to SSH keys",
    detail: "References SSH private keys or authorized_keys.",
    test: /\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\bauthorized_keys\b/i,
  },
  {
    cap: "secret-access",
    id: "capability/secret-aws",
    severity: "high",
    confidence: "high",
    title: "Access to AWS credentials",
    detail: "References AWS credential files or secret keys.",
    test: /\.aws\/credentials|\bAWS_SECRET_ACCESS_KEY\b/,
  },
  {
    cap: "secret-access",
    id: "capability/secret-cloud",
    severity: "high",
    confidence: "high",
    title: "Access to cloud/registry credentials",
    detail: "References GCP, Docker, npm, or .netrc credential stores.",
    test: /\.config\/gcloud|GOOGLE_APPLICATION_CREDENTIALS|\.docker\/config\.json|\.npmrc\b|\.netrc\b/i,
  },
  {
    cap: "secret-access",
    id: "capability/secret-keychain",
    severity: "high",
    confidence: "medium",
    title: "Access to OS keychain / secret store",
    detail: "Uses the OS keychain or a secret-store library.",
    test: /\bkeytar\b|\bkeychain\b|security\s+find-generic-password|\blibsecret\b/i,
  },
  {
    // Deliberately a SEPARATE cap ("dotenv-access"), not "secret-access": loading a
    // .env for config is ubiquitous and benign, so it must NOT trip the exfil gate.
    cap: "dotenv-access",
    id: "capability/secret-dotenv",
    severity: "low",
    confidence: "medium",
    title: "Reads .env config file",
    detail: "Loads configuration/secrets from a .env file (dotenv or direct read).",
    test: /\bdotenv\b|readFileSync\([^)]*\.env['"]|['"][^'"]*\.env['"]/,
  },
  {
    cap: "env-access",
    id: "capability/env-access",
    severity: "info",
    confidence: "high",
    title: "Reads environment variables",
    detail: "Reads process environment variables (commonly for configuration).",
    test: /\bprocess\.env\b/,
  },
];

// Hardcoded credentials embedded in source — a leak, not a capability. Reported as a
// non-profile anomaly (real defect), separate from the capability profile.
const HARDCODED_KEY =
  /\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{35})\b/;

/** Words in the package name/description that legitimately imply broad reach. */
const NETWORK_PURPOSE = /(http|api|web|fetch|download|url|proxy|search|weather|cloud|remote|sync|scrape|browser)/i;

export function analyzeCapability(ctx: AnalysisContext): void {
  const seen = new Set<string>();

  for (const file of ctx.target.sourceFiles) {
    const code = stripComments(file.content); // don't match capability words in comments
    for (const rule of CAP_RULES) {
      const m = rule.test.exec(code);
      if (!m) continue;
      ctx.caps.add(rule.cap);
      if (seen.has(rule.cap)) continue; // one finding per capability
      seen.add(rule.cap);
      ctx.findings.push({
        id: rule.id,
        category: "capability",
        severity: rule.severity,
        confidence: rule.confidence,
        profile: true, // raw capability = what it CAN do; informational, not a risk signal
        title: rule.title,
        detail: rule.detail,
        evidence: snippet(m[0]),
        location: `${file.path}:${lineAt(code, m.index)}`,
      });
    }
  }

  // Hardcoded credentials embedded in source (a leak, not a capability).
  const secretsSeen = new Set<string>();
  for (const file of ctx.target.sourceFiles) {
    const m = HARDCODED_KEY.exec(stripComments(file.content));
    if (!m || secretsSeen.has(file.path)) continue;
    secretsSeen.add(file.path);
    ctx.findings.push({
      id: "capability/hardcoded-credential",
      category: "capability",
      severity: "high",
      confidence: "medium",
      title: "Hardcoded credential in source",
      detail: "A string matching a known API-key/token format is embedded in the source.",
      evidence: snippet(m[0].slice(0, 6) + "…"), // redact — never echo the full secret
      location: `${file.path}:${lineAt(file.content, m.index)}`,
    });
  }

  // Scope-vs-purpose: a server whose stated purpose has nothing to do with the
  // network but which nonetheless reads locally AND reaches out is suspicious.
  const purposeText = [ctx.target.packageJson?.name, ctx.target.packageJson?.description]
    .filter(Boolean)
    .join(" ");
  const purposeImpliesNetwork = NETWORK_PURPOSE.test(purposeText);
  if (ctx.caps.has("fs-read") && ctx.caps.has("net-egress") && purposeText && !purposeImpliesNetwork) {
    ctx.findings.push({
      // NOT a profile item: capability contradicting stated purpose is a real anomaly.
      id: "capability/scope-mismatch",
      category: "capability",
      severity: "high",
      confidence: "low", // keyword heuristic on stated purpose — worth review, not certainty
      title: "Capability exceeds stated purpose",
      detail: `Reads local files and makes network calls, but the stated purpose ("${snippet(
        purposeText,
        60,
      )}") does not imply networking.`,
      location: "package.json",
    });
  }
}
