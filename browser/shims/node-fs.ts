// Browser shim for node:fs. policy.ts imports readFileSync (for file-path policies),
// but the browser only ever passes built-in policy names or inline policy objects, so
// this path is never actually called — it just needs to exist for the bundle to link.
export function readFileSync(): string {
  throw new Error("filesystem access is not available in the browser build");
}
