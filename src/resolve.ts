import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { parseSurfaceDump } from "./extract.js";
import type { Language, ScanOptions, SourceFile, Target, TargetKind, ToolDef } from "./types.js";

interface Surface {
  tools: ToolDef[];
  resources: ToolDef[];
  prompts: ToolDef[];
}
const EMPTY_SURFACE: Surface = { tools: [], resources: [], prompts: [] };

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py"]);
// Manifest files we always collect (even though they aren't "source") so the Python
// provenance/dep analyzers can read them out of target.sourceFiles.
const MANIFEST_FILES = new Set(["pyproject.toml", "requirements.txt", "setup.cfg"]);
// Note: we do NOT skip dist/build — published npm packages ship their compiled
// code there, and analyzing what actually runs is the whole point.
const SKIP_DIRS = new Set(["node_modules", ".git", "coverage", ".next", ".turbo", "__pycache__", ".venv", "venv"]);
const MAX_FILES = 1000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function detectKind(input: string): TargetKind {
  if (input.startsWith("pypi:")) return "pypi";
  if (/^https?:\/\/|^git@|github\.com/.test(input)) return "github";
  if (input.endsWith(".json") && existsSync(input)) return "tools";
  if (existsSync(input) && statSync(input).isDirectory()) return "dir";
  return "npm";
}

/** Decide which language's deep analyzers to run, from manifests then file mix. */
function detectLanguage(root: string, packageJson: Record<string, any> | undefined, files: SourceFile[]): Language {
  if (["pyproject.toml", "setup.py", "requirements.txt", "setup.cfg"].some((f) => existsSync(join(root, f)))) return "python";
  if (packageJson) return "js";
  const py = files.filter((f) => /\.py$/i.test(f.path)).length;
  const js = files.filter((f) => /\.(js|mjs|cjs|ts|mts|cts)$/i.test(f.path)).length;
  if (py > js && py > 0) return "python";
  if (js > 0) return "js";
  return "unknown";
}

function walkSource(root: string): SourceFile[] {
  const files: SourceFile[] = [];
  const stack = [root];
  while (stack.length && files.length < MAX_FILES) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(entry)) stack.push(full);
        continue;
      }
      const dot = entry.lastIndexOf(".");
      const ext = dot >= 0 ? entry.slice(dot) : "";
      if ((!SOURCE_EXT.has(ext) && !MANIFEST_FILES.has(entry)) || st.size > MAX_FILE_BYTES) continue;
      try {
        files.push({ path: relative(root, full), content: readFileSync(full, "utf8") });
      } catch {
        /* unreadable — skip */
      }
      if (files.length >= MAX_FILES) break;
    }
  }
  return files;
}

function readPackageJson(root: string): Record<string, any> | undefined {
  const p = join(root, "package.json");
  if (!existsSync(p)) return undefined;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return undefined;
  }
}

function buildDirTarget(kind: TargetKind, ref: string, root: string, surface: Surface): Target {
  const packageJson = readPackageJson(root);
  const sourceFiles = walkSource(root);
  return {
    kind,
    ref,
    rootDir: root,
    packageJson,
    language: detectLanguage(root, packageJson, sourceFiles),
    sourceFiles,
    tools: surface.tools,
    resources: surface.resources,
    prompts: surface.prompts,
  };
}

function fetchNpm(pkg: string): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-audit-npm-"));
  execFileSync("npm", ["pack", pkg, "--pack-destination", dir], { stdio: "pipe" });
  const tgz = readdirSync(dir).find((f) => f.endsWith(".tgz"));
  if (!tgz) throw new Error(`npm pack produced no tarball for "${pkg}"`);
  execFileSync("tar", ["-xzf", join(dir, tgz), "-C", dir], { stdio: "pipe" });
  return join(dir, "package"); // npm tarballs extract to ./package
}

async function fetchPyPI(pkg: string): Promise<string> {
  let meta: any;
  try {
    meta = await (await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`)).json();
  } catch {
    throw new Error(`package "${pkg}" not found on PyPI`);
  }
  const files: any[] = meta?.urls ?? [];
  const sdist = files.find((f) => f.packagetype === "sdist") ?? files[0];
  if (!sdist?.url) throw new Error(`no downloadable release for "${pkg}"`);
  const buf = Buffer.from(await (await fetch(sdist.url)).arrayBuffer());
  const dir = mkdtempSync(join(tmpdir(), "mcp-audit-pypi-"));
  const archive = join(dir, sdist.filename ?? "pkg.tar.gz");
  writeFileSync(archive, buf);
  try {
    execFileSync("tar", ["-xzf", archive, "-C", dir], { stdio: "pipe" });
  } catch {
    execFileSync("unzip", ["-o", archive, "-d", dir], { stdio: "pipe" }); // wheels/zip sdists
  }
  const sub = readdirSync(dir).find((d) => {
    try {
      return statSync(join(dir, d)).isDirectory();
    } catch {
      return false;
    }
  });
  return sub ? join(dir, sub) : dir;
}

function cloneGithub(url: string): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-audit-gh-"));
  execFileSync("git", ["clone", "--depth", "1", url, dir], { stdio: "pipe" });
  return dir;
}

export async function resolveTarget(input: string, opts: ScanOptions = {}): Promise<Target> {
  const dump = opts.toolsFile ? parseSurfaceDump(JSON.parse(readFileSync(opts.toolsFile, "utf8"))) : EMPTY_SURFACE;
  const kind = opts.kind ?? detectKind(input);

  switch (kind) {
    case "tools": {
      const surface = dump.tools.length || dump.resources.length || dump.prompts.length
        ? dump
        : parseSurfaceDump(JSON.parse(readFileSync(input, "utf8")));
      return { kind, ref: input, sourceFiles: [], ...surface };
    }
    case "npm":
      return buildDirTarget(kind, input, fetchNpm(input), dump);
    case "pypi":
      return buildDirTarget("pypi", input, await fetchPyPI(input.replace(/^pypi:/, "")), dump);
    case "github":
      return buildDirTarget(kind, input, cloneGithub(input), dump);
    case "dir":
    default:
      return buildDirTarget("dir", input, input, dump);
  }
}
