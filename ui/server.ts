import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const INDEX = join(here, "index.html");
const PORT = Number(process.env.PORT ?? 4319);

function send(res: import("node:http").ServerResponse, status: number, body: string, type: string) {
  // no-store so the dev UI never serves a stale cached page/CSS
  res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  res.end(body);
}

const SEVERITIES = new Set(["none", "critical", "high", "medium", "low", "info"]);
const strArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];

/** Whitelist a policy object coming from the web to known fields and safe values. */
function sanitizePolicy(p: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: typeof p.name === "string" ? p.name.slice(0, 60) : "custom",
    gate: strArray(p.gate),
    denyCapabilities: strArray(p.denyCapabilities),
    require: strArray(p.require),
    allow: strArray(p.allow),
  };
  if (typeof p.failOnSeverity === "string" && SEVERITIES.has(p.failOnSeverity))
    out.failOnSeverity = p.failOnSeverity;
  if (typeof p.warnOnSeverity === "string" && SEVERITIES.has(p.warnOnSeverity))
    out.warnOnSeverity = p.warnOnSeverity;
  return out;
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
      return send(res, 200, readFileSync(INDEX, "utf8"), "text/html; charset=utf-8");
    }

    if (req.method === "POST" && req.url === "/api/scan") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const { target, policy } = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      if (!target || typeof target !== "string") {
        return send(res, 400, JSON.stringify({ error: "Provide a 'target' string." }), "application/json");
      }
      // Accept only built-in policy names or an inline policy object — never a string
      // file path from a web request (that would let a caller read arbitrary files).
      let policyArg: string | Record<string, unknown> | undefined;
      if (policy === "default" || policy === "strict") policyArg = policy;
      else if (policy && typeof policy === "object") policyArg = sanitizePolicy(policy);
      try {
        const report = await scan(target.trim(), { policy: policyArg as never });
        return send(res, 200, JSON.stringify(report), "application/json");
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return send(res, 200, JSON.stringify({ error: message }), "application/json");
      }
    }

    send(res, 404, "Not found", "text/plain");
  } catch (err) {
    send(res, 500, JSON.stringify({ error: String(err) }), "application/json");
  }
});

server.listen(PORT, () => {
  process.stdout.write(`Heimdall UI running at http://localhost:${PORT}\n`);
});
