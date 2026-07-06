import type { AnalysisContext, Confidence, Finding, Severity, Target } from "../types.js";
import { lineAt, snippet } from "../util.js";

/**
 * Python dialect of the capability + provenance analyzers. MCP has a large Python server
 * ecosystem that the JS/TS analyzers can't see. This mirrors the JS capability model with
 * Python patterns (regex, not AST) and parses pyproject.toml / requirements.txt / setup.py.
 *
 * Honest fidelity: this is regex-based (no Python AST), so there is no real taint/data-flow
 * for Python — gates fall back to capability co-presence, same as unparseable JS. Injection
 * analysis is already language-agnostic and covers Python for free.
 */

interface PyCapRule {
  cap: string;
  id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  detail: string;
  test: RegExp;
}

const PY_CAP_RULES: PyCapRule[] = [
  {
    cap: "exec",
    id: "capability/py-exec",
    severity: "high",
    confidence: "high",
    title: "Shell / command execution",
    detail: "Runs shell commands or spawns processes (subprocess / os.system).",
    test: /\bsubprocess\.(run|call|check_output|check_call|Popen|getoutput)\b|\bos\.(system|popen|posix_spawn\w*)\b|\bpty\.spawn\b/,
  },
  {
    cap: "net-egress",
    id: "capability/py-net",
    severity: "low",
    confidence: "high",
    title: "Outbound network access",
    detail: "Makes outbound network requests.",
    test: /\b(requests\.(get|post|put|delete|patch|head|request|Session)|httpx\.|aiohttp\.|urllib\.request|urllib3\.|http\.client\.|socket\.socket|smtplib\.|ftplib\.|websockets\.|boto3\.)|import\s+(requests|httpx|aiohttp|urllib3|websockets)/,
  },
  {
    cap: "fs-write",
    id: "capability/py-fs-write",
    severity: "medium",
    confidence: "high",
    title: "Filesystem write access",
    detail: "Writes or deletes files.",
    test: /\bopen\s*\([^)]*['"][wax]\b|\.write_text\s*\(|\.write_bytes\s*\(|\bos\.(remove|unlink|rmdir|mkdir|makedirs)\b|\bshutil\.(rmtree|move|copy\w*)\b/,
  },
  {
    cap: "fs-read",
    id: "capability/py-fs-read",
    severity: "low",
    confidence: "high",
    title: "Filesystem read access",
    detail: "Reads from the filesystem.",
    test: /\bopen\s*\(|\.read_text\s*\(|\.read_bytes\s*\(|\bos\.(listdir|walk|scandir)\b|\bpathlib\b|\bglob\.(glob|iglob)\b/,
  },
  {
    cap: "dynamic-eval",
    id: "capability/py-eval",
    severity: "high",
    confidence: "high",
    title: "Dynamic code evaluation",
    detail: "Evaluates code at runtime (eval / exec / compile / __import__).",
    test: /\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\b__import__\s*\(/,
  },
  {
    cap: "secret-access",
    id: "capability/py-secret",
    severity: "high",
    confidence: "high",
    title: "Access to credentials / secret store",
    detail: "References SSH/AWS/cloud credential files or a secret store.",
    test: /\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\bboto3\b|\bkeyring\b|GOOGLE_APPLICATION_CREDENTIALS|\.netrc\b/i,
  },
  {
    cap: "dotenv-access",
    id: "capability/py-dotenv",
    severity: "low",
    confidence: "medium",
    title: "Reads .env config file",
    detail: "Loads configuration from a .env file (python-dotenv or direct read).",
    test: /\bdotenv\b|\bload_dotenv\s*\(|['"][^'"]*\.env['"]/,
  },
  {
    cap: "env-access",
    id: "capability/py-env",
    severity: "info",
    confidence: "high",
    title: "Reads environment variables",
    detail: "Reads process environment variables (commonly for configuration).",
    test: /\bos\.environ\b|\bos\.getenv\s*\(/,
  },
];

/** Blank out `#` comments (offset-preserving) so capability words in comments don't match. */
export function stripPyComments(src: string): string {
  return src.replace(/#[^\n]*/g, (m) => " ".repeat(m.length));
}

const isPy = (path: string) => /\.py$/i.test(path);

export function analyzePythonCapability(ctx: AnalysisContext): void {
  const seen = new Set<string>();
  for (const file of ctx.target.sourceFiles) {
    if (!isPy(file.path)) continue;
    const code = stripPyComments(file.content);
    for (const rule of PY_CAP_RULES) {
      const m = rule.test.exec(code);
      if (!m) continue;
      ctx.caps.add(rule.cap);
      if (seen.has(rule.cap)) continue;
      seen.add(rule.cap);
      ctx.findings.push({
        id: rule.id,
        category: "capability",
        severity: rule.severity,
        confidence: rule.confidence,
        profile: true,
        title: rule.title,
        detail: rule.detail,
        evidence: snippet(m[0]),
        location: `${file.path}:${lineAt(code, m.index)}`,
      });
    }
  }
}

// --- dependency + provenance parsing -----------------------------------------

export interface PyDep {
  name: string;
  spec: string;
}

const readFile = (target: Target, name: string): string | undefined =>
  target.sourceFiles.find((f) => f.path === name || f.path.endsWith("/" + name))?.content;

/** Split a PEP 508 requirement ("httpx[cli]>=0.24,<1 ; python_version>'3.8'") into name + spec. */
function parseRequirement(line: string): PyDep | undefined {
  const s = line.split("#")[0].split(";")[0].trim();
  if (!s || s.startsWith("-") || /^(https?:\/\/|git\+|file:)/i.test(s)) return undefined; // skip URLs (not "httpx"!)
  const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
  if (!m) return undefined;
  const name = m[1];
  const spec = s
    .slice(name.length)
    .replace(/\[[^\]]*\]/, "")
    .trim();
  return { name, spec };
}

/** Extract the string items of a `key = [ ... ]` array, tolerating brackets inside quotes. */
function extractArrayStrings(text: string, key: string): string[] {
  const open = text.search(new RegExp(key + "\\s*=\\s*\\["));
  if (open < 0) return [];
  const out: string[] = [];
  let inStr = false;
  let quote = "";
  let cur = "";
  for (let i = text.indexOf("[", open) + 1; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (c === quote) {
        out.push(cur);
        cur = "";
        inStr = false;
      } else cur += c;
    } else if (c === '"' || c === "'") {
      inStr = true;
      quote = c;
    } else if (c === "]") break; // array close (brackets inside strings are handled above)
  }
  return out;
}

/** Extract declared dependencies from pyproject.toml, requirements.txt, or setup.py. */
export function parsePyDeps(target: Target): PyDep[] {
  const out: PyDep[] = [];
  const seen = new Set<string>();
  const add = (d?: PyDep) => {
    if (d && !seen.has(d.name.toLowerCase())) {
      seen.add(d.name.toLowerCase());
      out.push(d);
    }
  };

  const pyproject = readFile(target, "pyproject.toml");
  if (pyproject) {
    // PEP 621: dependencies = ["requests>=2", "httpx", "requests[socks]>=2.0"]
    for (const q of extractArrayStrings(pyproject, "dependencies")) add(parseRequirement(q));
    // Poetry: [tool.poetry.dependencies] name = "^1.2"
    const poetry = pyproject.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(\n\[|$)/);
    if (poetry)
      for (const line of poetry[1].split("\n")) {
        const lm = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["']?([^"'\n]*)/);
        if (lm && lm[1].toLowerCase() !== "python") add({ name: lm[1], spec: lm[2].trim() });
      }
  }

  const reqs = readFile(target, "requirements.txt");
  if (reqs) for (const line of reqs.split("\n")) add(parseRequirement(line));

  const setup = readFile(target, "setup.py");
  if (setup)
    for (const q of extractArrayStrings(setup, "install_requires")) add(parseRequirement(q));
  return out;
}

/** Shell/code-exec patterns that make a setup.py dangerous (pip runs it on sdist install). */
const DANGEROUS_SETUP =
  /\b(subprocess|os\.system|os\.popen|urllib|requests\.|socket|eval\s*\(|exec\s*\(|base64\.b64decode|__import__)\b/;

export function analyzePythonProvenance(ctx: AnalysisContext): void {
  const t = ctx.target;
  const pyproject = readFile(t, "pyproject.toml");
  const setup = readFile(t, "setup.py");

  if (setup && DANGEROUS_SETUP.test(stripPyComments(setup))) {
    const m = DANGEROUS_SETUP.exec(stripPyComments(setup))!;
    ctx.findings.push({
      id: "provenance/install-script-exec",
      category: "provenance",
      severity: "critical",
      gate: true,
      title: "Code execution in setup.py",
      detail:
        "setup.py runs on install (from an sdist) and executes code / fetches remote content.",
      evidence: snippet(m[0]),
      location: "setup.py",
    });
  } else if (setup) {
    ctx.findings.push({
      id: "provenance/install-script",
      category: "provenance",
      severity: "medium",
      title: "setup.py present (runs on install)",
      detail: "Installing from an sdist executes setup.py. Review it before installing.",
      location: "setup.py",
    });
  }

  // Hygiene: no manifest at all, or missing license — informational trust context.
  if (!pyproject && !setup && !readFile(t, "requirements.txt")) {
    ctx.findings.push({
      id: "provenance/no-manifest",
      category: "provenance",
      severity: "info",
      confidence: "high",
      profile: true,
      title: "No Python package manifest found",
      detail: "No pyproject.toml / setup.py / requirements.txt, so provenance can't be assessed.",
    });
    return;
  }
  const hasLicense = /license/i.test(pyproject ?? "") || /license/i.test(setup ?? "");
  if (!hasLicense) {
    ctx.findings.push({
      id: "provenance/no-license",
      category: "provenance",
      severity: "info",
      profile: true,
      title: "No license declared",
      detail: "The Python manifest declares no license.",
      location: pyproject ? "pyproject.toml" : "setup.py",
    });
  }

  // Latent capabilities via declared Python deps (informational, like the JS side).
  for (const dep of parsePyDeps(t)) {
    const cap = pyCapForDep(dep.name);
    if (!cap) continue;
    ctx.depCaps.add(cap);
    ctx.findings.push({
      id: "provenance/dependency-capability",
      category: "provenance",
      severity: "info",
      confidence: "medium",
      profile: true,
      title: `Dependency provides capability: ${cap}`,
      detail: `Declared dependency "${dep.name}" can perform "${cap}". Latent, but part of the trusted-code surface.`,
      evidence: `${dep.name}${dep.spec}`,
      location: "pyproject.toml/requirements.txt",
    } as Finding);
  }
}

/** Map a Python dependency to a latent capability. */
export function pyCapForDep(name: string): string | undefined {
  const n = name.toLowerCase();
  if (
    /^(requests|httpx|aiohttp|urllib3|websockets|boto3|botocore|google-api|google-cloud|openai|anthropic|firecrawl)/.test(
      n,
    )
  )
    return "net-egress";
  if (/^(keyring)/.test(n)) return "secret-access";
  if (/^(python-dotenv|dotenv)$/.test(n)) return "dotenv-access";
  return undefined;
}
