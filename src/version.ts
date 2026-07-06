import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The package version, read from package.json at runtime so it never goes stale. Node-only. */
export const VERSION: string = (() => {
  try {
    return JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
    ).version;
  } catch {
    return "0.0.0";
  }
})();
