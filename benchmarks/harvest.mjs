// Harvest a large list of real MCP-server package names from the npm registry search API.
// Output: benchmarks/targets.txt (one package name per line).
import { writeFileSync } from "node:fs";

const QUERIES = ["mcp", "mcp server", "model context protocol", "mcp-server", "mcp tools", "mcp client"];
const LIMIT = Number(process.argv[2] ?? 1000);
const names = new Set();

const looksLikeMcp = (p) =>
  /\bmcp\b|model[-\s]?context[-\s]?protocol/i.test(`${p.name} ${(p.keywords || []).join(" ")} ${p.description || ""}`);

for (const q of QUERIES) {
  for (let from = 0; from < 1000 && names.size < LIMIT; from += 250) {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=250&from=${from}`;
    let objects;
    try {
      objects = (await (await fetch(url)).json()).objects ?? [];
    } catch {
      break;
    }
    if (!objects.length) break;
    for (const o of objects) if (looksLikeMcp(o.package)) names.add(o.package.name);
    if (objects.length < 250) break;
  }
  if (names.size >= LIMIT) break;
}

const list = [...names].slice(0, LIMIT);
writeFileSync(new URL("./targets.txt", import.meta.url), list.join("\n") + "\n");
console.log(`harvested ${list.length} MCP package names`);
