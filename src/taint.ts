import { parse } from "acorn";
import type { SourceFile } from "./types.js";

export interface TaintFlow {
  kind: "exfil" | "rce";
  sourceKind: "secret" | "fs" | "env" | "net";
  sink: string;
  file: string;
  sourceLine: number;
  sinkLine: number;
}

const READ_FNS = new Set(["readFileSync", "readFile", "readdir", "readdirSync", "createReadStream"]);
// A named HTTP client whose call sends data out. Kept tight to avoid matching e.g. Map.get.
const NET_CALLEE = /^(fetch$|axios(\.|$)|got(\.|$)|ky(\.|$)|superagent(\.|$)|needle(\.|$)|phin(\.|$)|undici(\.|$))|(^|\.)(http|https)\.(request|get|post)$/;
// Assigns a variable that IS an http request object (so req.end/.write/.send is a real sink).
const REQUEST_MAKER = /(^|\.)(http|https)\.(request|get)$/;
const REQ_BODY = new Set(["end", "write", "send"]);
const SECRET_PATH = /\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.netrc|\.npmrc|\.docker\/config/i;

type Node = any;
type Origin = { kind: TaintFlow["sourceKind"]; line: number };

function line(node: Node): number {
  return node?.loc?.start?.line ?? 0;
}

/** Dotted name of a call/member callee, e.g. "fs.readFileSync" or "fetch". */
function calleeStr(node: Node): string {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && !node.computed) {
    return `${calleeStr(node.object)}.${node.property.name}`;
  }
  return node.type === "MemberExpression" ? calleeStr(node.object) : "";
}

function isProcessEnv(node: Node): boolean {
  return (
    node?.type === "MemberExpression" &&
    node.object?.type === "Identifier" &&
    node.object.name === "process" &&
    node.property?.name === "env"
  );
}

/** If this node is itself a taint source, return its origin. */
function sourceOf(node: Node): Origin | null {
  if (isProcessEnv(node)) return { kind: "env", line: line(node) };
  if (node?.type === "CallExpression" || node?.type === "NewExpression") {
    const base = calleeStr(node.callee).split(".").pop() ?? "";
    if (READ_FNS.has(base)) {
      // secret if any string literal anywhere in the args matches a credential path
      let secret = false;
      for (const a of node.arguments ?? [])
        walk(a, (x: Node) => {
          if (x.type === "Literal" && typeof x.value === "string" && SECRET_PATH.test(x.value)) secret = true;
        });
      return { kind: secret ? "secret" : "fs", line: line(node) };
    }
    if (NET_CALLEE.test(calleeStr(node.callee))) return { kind: "net", line: line(node) };
  }
  return null;
}

function walk(node: Node, cb: (n: Node) => void): void {
  if (!node || typeof node.type !== "string") return;
  cb(node);
  for (const key of Object.keys(node)) {
    if (key === "type" || key === "loc" || key === "start" || key === "end" || key === "range") continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach((c) => walk(c, cb));
    else if (child && typeof child.type === "string") walk(child, cb);
  }
}

/** Walk within one scope: visits `root` and descendants but NOT nested function bodies. */
function scopedWalk(node: Node, cb: (n: Node) => void, root: Node): void {
  if (!node || typeof node.type !== "string") return;
  if (/Function/.test(node.type) && node !== root) return; // nested function = its own scope
  cb(node);
  for (const key of Object.keys(node)) {
    if (key === "type" || key === "loc" || key === "start" || key === "end" || key === "range") continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach((c) => scopedWalk(c, cb, root));
    else if (child && typeof child.type === "string") scopedWalk(child, cb, root);
  }
}

/** Returns null if the file could not be parsed (e.g. TS syntax), else its taint flows. */
export function analyzeFileTaint(file: SourceFile): TaintFlow[] | null {
  let ast: Node;
  const opts = { ecmaVersion: "latest" as const, locations: true, allowReturnOutsideFunction: true };
  try {
    ast = parse(file.content, { ...opts, sourceType: "module" });
  } catch {
    try {
      ast = parse(file.content, { ...opts, sourceType: "script" });
    } catch {
      return null; // unparseable (e.g. TS syntax) — caller keeps conservative gates
    }
  }

  const flows: TaintFlow[] = [];

  // Analyze each scope (module top-level + every function body) independently, so a
  // variable name in one function can't taint a sink in an unrelated function — the FP
  // that made bundled dist/index.js files fail (a fetch and an eval thousands of lines apart).
  const scopes: Node[] = [ast];
  walk(ast, (n) => { if (/Function/.test(n.type)) scopes.push(n); });

  const isNetSink = (n: Node, requestObjects: Set<string>): boolean => {
    if (NET_CALLEE.test(calleeStr(n.callee))) return true;
    const c = n.callee;
    return (
      c?.type === "MemberExpression" &&
      !c.computed &&
      REQ_BODY.has(c.property?.name) &&
      c.object?.type === "Identifier" &&
      requestObjects.has(c.object.name)
    );
  };
  // RCE sinks kept narrow (eval / new Function) — matching child_process/.exec by name
  // produces too many false positives (e.g. regex.exec).
  const isExecSink = (n: Node): boolean =>
    calleeStr(n.callee) === "eval" || (n.type === "NewExpression" && calleeStr(n.callee) === "Function");

  for (const scope of scopes) {
    const tainted = new Map<string, Origin>();
    const requestObjects = new Set<string>();

    const originIn = (node: Node): Origin | null => {
      let found: Origin | null = null;
      walk(node, (n) => {
        if (found) return;
        const s = sourceOf(n);
        if (s) found = s;
        else if (n.type === "Identifier" && tainted.has(n.name)) found = tainted.get(n.name)!;
      });
      return found;
    };

    // Propagate taint through assignments in this scope; two passes catch forward refs.
    for (let pass = 0; pass < 2; pass++) {
      scopedWalk(scope, (n) => {
        if (n.type === "VariableDeclarator" && n.id?.type === "Identifier") {
          if (n.init) {
            const o = originIn(n.init);
            if (o) tainted.set(n.id.name, o);
            if (
              (n.init.type === "CallExpression" || n.init.type === "NewExpression") &&
              REQUEST_MAKER.test(calleeStr(n.init.callee))
            ) {
              requestObjects.add(n.id.name);
            }
          }
        } else if (n.type === "AssignmentExpression" && n.left?.type === "Identifier" && n.right) {
          const o = originIn(n.right);
          if (o) tainted.set(n.left.name, o);
        }
      }, scope);
    }

    scopedWalk(scope, (n) => {
      if (n.type !== "CallExpression" && n.type !== "NewExpression") return;
      const net = isNetSink(n, requestObjects);
      const exec = isExecSink(n);
      if (!net && !exec) return;
      for (const arg of n.arguments ?? []) {
        const o = originIn(arg);
        if (!o) continue;
        if (net && (o.kind === "fs" || o.kind === "secret")) {
          flows.push({ kind: "exfil", sourceKind: o.kind, sink: calleeStr(n.callee) || "request", file: file.path, sourceLine: o.line, sinkLine: line(n) });
          break;
        }
        if (exec && o.kind === "net") {
          flows.push({ kind: "rce", sourceKind: o.kind, sink: calleeStr(n.callee) || "eval", file: file.path, sourceLine: o.line, sinkLine: line(n) });
          break;
        }
      }
    }, scope);
  }

  return flows;
}

/**
 * Intra-file taint analysis across all source files.
 * `analyzed` is false only if NO file could be parsed (so callers keep conservative gates).
 */
export function analyzeTaint(files: SourceFile[]): { flows: TaintFlow[]; analyzed: boolean } {
  const flows: TaintFlow[] = [];
  let analyzed = false;
  for (const f of files) {
    const r = analyzeFileTaint(f);
    if (r === null) continue;
    analyzed = true;
    flows.push(...r);
  }
  return { flows, analyzed };
}
