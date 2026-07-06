import type { Target, ToolDef, ToolParam } from "./types.js";

/**
 * Normalize a raw tools/list entry (as returned by an MCP server) into a ToolDef.
 * Accepts the MCP shape: { name, description, inputSchema: { properties: {...} } }.
 */
export function normalizeTool(raw: any): ToolDef | null {
  if (!raw || typeof raw.name !== "string") return null;
  const params: ToolParam[] = [];
  const props =
    raw.inputSchema?.properties ?? raw.parameters?.properties ?? raw.input_schema?.properties;
  if (props && typeof props === "object") {
    for (const [name, schema] of Object.entries<any>(props)) {
      params.push({
        name,
        description: typeof schema?.description === "string" ? schema.description : undefined,
      });
    }
  }
  return {
    name: raw.name,
    description: typeof raw.description === "string" ? raw.description : undefined,
    parameters: params.length ? params : undefined,
  };
}

/** Normalize a resource or prompt entry. Resources use uri if unnamed; prompts carry arguments. */
export function normalizeItem(raw: any): ToolDef | null {
  if (!raw || typeof raw !== "object") return null;
  const name =
    typeof raw.name === "string" ? raw.name : typeof raw.uri === "string" ? raw.uri : null;
  if (!name) return null;
  const params: ToolParam[] = Array.isArray(raw.arguments)
    ? raw.arguments
        .filter((a: any) => a && typeof a.name === "string")
        .map((a: any) => ({
          name: a.name,
          description: typeof a.description === "string" ? a.description : undefined,
        }))
    : [];
  return {
    name,
    description: typeof raw.description === "string" ? raw.description : undefined,
    parameters: params.length ? params : undefined,
  };
}

/** Parse a tools/list dump: an array, or { tools: [...] }, or { result: { tools: [...] } }. */
export function parseToolsDump(json: unknown): ToolDef[] {
  const arr = Array.isArray(json)
    ? json
    : ((json as any)?.tools ?? (json as any)?.result?.tools ?? []);
  if (!Array.isArray(arr)) return [];
  return arr.map(normalizeTool).filter((t): t is ToolDef => t !== null);
}

/** Parse a combined dump: { tools, resources, prompts } (any subset). */
export function parseSurfaceDump(json: unknown): {
  tools: ToolDef[];
  resources: ToolDef[];
  prompts: ToolDef[];
} {
  const j = json as any;
  const resArr = j?.resources ?? j?.result?.resources ?? [];
  const promptArr = j?.prompts ?? j?.result?.prompts ?? [];
  return {
    tools: parseToolsDump(json),
    resources: (Array.isArray(resArr) ? resArr : [])
      .map(normalizeItem)
      .filter((t): t is ToolDef => !!t),
    prompts: (Array.isArray(promptArr) ? promptArr : [])
      .map(normalizeItem)
      .filter((t): t is ToolDef => !!t),
  };
}

// Best-effort extraction of registrations directly from source. Supply --tools for full
// fidelity (descriptions built by concatenation are captured only partially).

// Find the nearest description literal within a window of an object.
const DESC_NEAR = /description\s*:\s*(['"`])((?:\\.|[^\\])*?)\1/;
// Tools/resources/prompts array form: { name: "...", description: "...", ... }
const GENERIC_OBJECT =
  /name\s*:\s*(['"`])(.+?)\1[\s\S]{0,400}?description\s*:\s*(['"`])([\s\S]+?)\3/g;

function unescape(s: string): string {
  return s
    .replace(/\\n/g, " ")
    .replace(/\\t/g, " ")
    .replace(/\\(["'`\\])/g, "$1");
}

/** Extract registrations for a surface given its registration verbs (e.g. tool|registerTool). */
function extractSurface(target: Target, verbs: string, includeGeneric: boolean): ToolDef[] {
  const stringForm = new RegExp(
    `\\b(?:${verbs})\\(\\s*(['"\`])(.+?)\\1\\s*,\\s*(['"\`])([\\s\\S]*?)\\3`,
    "g",
  );
  const objectForm = new RegExp(`\\b(?:${verbs})\\(\\s*(['"\`])(.+?)\\1\\s*,\\s*\\{`, "g");

  const byName = new Map<string, ToolDef>();
  const add = (name?: string, description?: string) => {
    if (!name || byName.has(name)) return;
    byName.set(name, { name, description: description ? unescape(description) : undefined });
  };

  for (const file of target.sourceFiles) {
    const src = file.content;
    let m: RegExpExecArray | null;

    objectForm.lastIndex = 0;
    while ((m = objectForm.exec(src)) !== null) {
      const d = DESC_NEAR.exec(src.slice(m.index, m.index + 1200));
      add(m[2], d?.[2]);
    }
    stringForm.lastIndex = 0;
    while ((m = stringForm.exec(src)) !== null) add(m[2], m[4]);

    // Only tools get the loose generic-object pass (it's noisy; reserve for the primary surface).
    if (includeGeneric) {
      GENERIC_OBJECT.lastIndex = 0;
      while ((m = GENERIC_OBJECT.exec(src)) !== null) add(m[2], m[4]);
    }
  }
  return [...byName.values()];
}

export function extractTools(target: Target): ToolDef[] {
  return extractSurface(target, "tool|registerTool|addTool", true);
}

export function extractResources(target: Target): ToolDef[] {
  return extractSurface(target, "resource|registerResource|addResource", false);
}

export function extractPrompts(target: Target): ToolDef[] {
  return extractSurface(target, "prompt|registerPrompt|addPrompt", false);
}
