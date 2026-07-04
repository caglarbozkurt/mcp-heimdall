import { createHash } from "node:crypto";
import type { SurfaceItem, SurfaceKind, ToolDef } from "./types.js";

function sha(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/** Canonical string for one tool/resource/prompt (name + description + param names/descs). */
function canonical(t: ToolDef): string {
  const params = [...(t.parameters ?? [])]
    .map((p) => `${p.name}:${(p.description ?? "").trim()}`)
    .sort()
    .join("|");
  return `${t.name}\n${(t.description ?? "").trim()}\n${params}`;
}

/**
 * Deterministic hash of the whole tool surface. Stable across runs so it can be diffed
 * version-over-version to detect silent changes ("rug-pulls").
 */
export function fingerprintTools(tools: ToolDef[]): string {
  const normalized = [...tools].map(canonical).sort();
  return sha(JSON.stringify(normalized)).slice(0, 16);
}

/** Per-item content hashes across all model-facing surfaces, for drift detection. */
export function surfaceItems(
  tools: ToolDef[],
  resources: ToolDef[],
  prompts: ToolDef[],
): SurfaceItem[] {
  const items: SurfaceItem[] = [];
  const add = (kind: SurfaceKind, list: ToolDef[]) => {
    for (const t of list) items.push({ kind, name: t.name, hash: sha(canonical(t)).slice(0, 16) });
  };
  add("tool", tools);
  add("resource", resources);
  add("prompt", prompts);
  return items.sort((a, b) => (a.kind + a.name).localeCompare(b.kind + b.name));
}
