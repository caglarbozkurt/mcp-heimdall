// Bundle the browser scanner into a single self-contained script for GitHub Pages.
import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

await build({
  entryPoints: [join(here, "scan-browser.ts")],
  bundle: true,
  format: "iife",
  globalName: "Heimdall",
  platform: "browser",
  target: "es2020",
  minify: true,
  outfile: join(root, "pages", "heimdall.js"),
  alias: {
    "node:crypto": join(here, "shims", "node-crypto.ts"),
    "node:fs": join(here, "shims", "node-fs.ts"),
  },
  logLevel: "info",
});
