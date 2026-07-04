import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { parseSurfaceDump } from "./extract.js";
import type { ScanOptions, SourceFile, Target, TargetKind, ToolDef } from "./types.js";

interface Surface {
  tools: ToolDef[];
  resources: ToolDef[];
  prompts: ToolDef[];
}
const EMPTY_SURFACE: Surface = { tools: [], resources: [], prompts: [] };

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]);
// Note: we do NOT skip dist/build — published npm packages ship their compiled
// code there, and analyzing what actually runs is the whole point.
const SKIP_DIRS = new Set(["node_modules", ".git", "coverage", ".next", ".turbo"]);
const MAX_FILES = 1000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function detectKind(input: string): TargetKind {
  if (/^https?:\/\/|^git@|github\.com/.test(input)) return "github";
  if (input.endsWith(".json") && existsSync(input)) return "tools";
  if (existsSync(input) && statSync(input).isDirectory()) return "dir";
  return "npm";
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
      if (!SOURCE_EXT.has(ext) || st.size > MAX_FILE_BYTES) continue;
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
  return {
    kind,
    ref,
    rootDir: root,
    packageJson: readPackageJson(root),
    sourceFiles: walkSource(root),
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
    case "github":
      return buildDirTarget(kind, input, cloneGithub(input), dump);
    case "dir":
    default:
      return buildDirTarget("dir", input, input, dump);
  }
}
