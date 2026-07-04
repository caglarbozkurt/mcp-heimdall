/** 1-indexed line number for a character offset within text. */
export function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/** Collapse whitespace and truncate for use as short evidence in a finding. */
export function snippet(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max - 1) + "…" : flat;
}

/**
 * Blank out // and /* *\/ comments so capability detection matches real code, not words
 * in prose. Replaces comment bodies with spaces (same length, newlines kept) so byte
 * offsets — and therefore line numbers — are preserved. The `[^:]` guard avoids eating
 * the `//` in `https://`.
 */
export function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:])(\/\/[^\n]*)/g, (_all, p1: string, cmt: string) => p1 + cmt.replace(/./g, " "));
}
