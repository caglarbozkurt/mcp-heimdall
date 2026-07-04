import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scan } from "./scan.js";
import type { Report, Target, ToolDef } from "./types.js";
import { resolveTarget } from "./resolve.js";

/**
 * Behavioral validation: run the server for real, observe what it *actually does*, and
 * check it against what Heimdall flagged statically.
 *
 * This is the missing third leg (distribution run → labeled corpus → behavioral truth).
 * A capability recorder is preloaded into the server process; it records every real
 * filesystem / network / exec / eval / env access. We then drive the server's tools and
 * compare the observed capabilities to the static `report.capabilities`.
 *
 * Read the results asymmetrically:
 *  - observed AND flagged        → CONFIRMED (static claim validated by behavior)
 *  - flagged but NOT observed    → NOT EXERCISED (we couldn't trigger it with naive args;
 *                                   NOT proof the flag is wrong — the code may still do it)
 *  - observed but NOT flagged    → MISSED (a real static gap — the strongest signal here)
 *
 * So this harness is trustworthy for finding false NEGATIVES (static misses); it is a
 * lower bound, not a verdict, on false positives.
 *
 * DANGER: `validate` not only RUNS untrusted server code (like `--handshake`), it also
 * CALLS every tool with synthetic arguments — which can have side effects (delete files,
 * send requests). Run it ONLY inside a disposable VM or container.
 */

/** Capabilities the recorder can observe at runtime (must match the static vocabulary). */
export const OBSERVABLE_CAPS = [
  "fs-read",
  "fs-write",
  "net-egress",
  "exec",
  "dynamic-eval",
  "secret-access",
  "dotenv-access",
  "env-access",
] as const;

export type ObservableCap = (typeof OBSERVABLE_CAPS)[number];
export type CapStatus = "confirmed" | "not-exercised" | "missed" | "clean";

export interface CapComparison {
  cap: ObservableCap;
  static: boolean;
  observed: boolean;
  status: CapStatus;
}

export interface ValidateReport {
  target: string;
  kind: Target["kind"];
  toolsCalled: number;
  staticCaps: string[];
  observedCaps: string[];
  comparison: CapComparison[];
  /** Counts for quick reading / aggregation. */
  confirmed: number;
  missed: number;
  notExercised: number;
  error?: string;
}

/** One recorded runtime event from the preloaded capability recorder. */
interface RecordEvent {
  t: number;
  cap: string;
  via?: string;
  arg?: string;
}

// ---------------------------------------------------------------------------
// The recorder — emitted to a temp CJS file and preloaded via NODE_OPTIONS.
// Intentionally free of backslashes and backticks so it survives templating.
// It captures fs.appendFileSync BEFORE patching (no recursion / self-flagging),
// wraps built-ins best-effort, and appends JSON lines to HEIMDALL_RECORD.
// ---------------------------------------------------------------------------
const RECORDER_JS = `
(function () {
  try {
    var REC = process.env.HEIMDALL_RECORD;
    if (!REC) return;
    var fs = require('fs');
    var realAppend = fs.appendFileSync.bind(fs);
    var NL = String.fromCharCode(10);
    var BS = String.fromCharCode(92);
    // Re-entrancy guard: writing our own record file trips the patched fs methods, which
    // would otherwise log the recorder's writes as server activity. While a log() call is
    // in flight, any nested capability event (from the write itself) is ignored.
    var inLog = false;
    function log(cap, via, arg) {
      if (inLog) return;
      inLog = true;
      try { realAppend(REC, JSON.stringify({ t: Date.now(), cap: cap, via: via, arg: String(arg == null ? '' : arg).slice(0, 120) }) + NL); } catch (e) {}
      inLog = false;
    }
    function norm(p) { try { return String(p).split(BS).join('/').toLowerCase(); } catch (e) { return ''; } }
    var RECN = norm(REC);
    // The server's own package root: reading/writing your own bundled files is not an
    // interesting capability (that's just your code loading itself). A real capability is
    // reaching OUTSIDE the package — user data, /etc, $HOME, the network, a shell.
    var ROOTN = norm(process.env.HEIMDALL_ROOT || '');
    function isSecret(p) { p = norm(p); return p.indexOf('.ssh/') >= 0 || p.indexOf('id_rsa') >= 0 || p.indexOf('id_ed25519') >= 0 || p.indexOf('authorized_keys') >= 0 || p.indexOf('.aws/credentials') >= 0 || p.indexOf('.config/gcloud') >= 0 || p.indexOf('.docker/config.json') >= 0 || p.indexOf('.npmrc') >= 0 || p.indexOf('.netrc') >= 0 || p.indexOf('google_application_credentials') >= 0; }
    function isDotenv(p) { p = norm(p).split('/').pop() || ''; return p.indexOf('.env') === 0; }
    function fileCap(p, kind) {
      var np = norm(p);
      if (RECN && np && np.indexOf(RECN) >= 0) return; // never log our own record file
      if (ROOTN && np && np.indexOf(ROOTN) === 0) return; // reading own package files ≠ a capability
      log(kind, kind, p);
      if (kind === 'fs-read' && p != null) { if (isSecret(p)) log('secret-access', 'fs', p); if (isDotenv(p)) log('dotenv-access', 'fs', p); }
    }
    function wrap(obj, name, fn) { try { var orig = obj[name]; if (typeof orig !== 'function') return; obj[name] = function () { try { fn.apply(null, arguments); } catch (e) {} return orig.apply(this, arguments); }; } catch (e) {} }
    function host(o) { if (!o) return ''; if (typeof o === 'string') return o; return o.host || o.hostname || ''; }

    ['readFile','readFileSync','createReadStream','readdir','readdirSync','open','openSync'].forEach(function (m) { wrap(fs, m, function (p) { fileCap(p, 'fs-read'); }); });
    ['writeFile','writeFileSync','appendFile','appendFileSync','createWriteStream','unlink','unlinkSync','rm','rmSync','mkdir','mkdirSync'].forEach(function (m) { wrap(fs, m, function (p) { fileCap(p, 'fs-write'); }); });
    try { var fsp = fs.promises; ['readFile','readdir','open'].forEach(function (m) { wrap(fsp, m, function (p) { fileCap(p, 'fs-read'); }); }); ['writeFile','appendFile','unlink','rm','mkdir'].forEach(function (m) { wrap(fsp, m, function (p) { fileCap(p, 'fs-write'); }); }); } catch (e) {}

    try { var net = require('net'); wrap(net, 'connect', function () { log('net-egress', 'net.connect', host(arguments[0])); }); wrap(net, 'createConnection', function () { log('net-egress', 'net.createConnection', host(arguments[0])); }); wrap(net.Socket.prototype, 'connect', function () { log('net-egress', 'socket.connect', host(arguments[0])); }); } catch (e) {}
    try { var http = require('http'); wrap(http, 'request', function (o) { log('net-egress', 'http.request', host(o)); }); wrap(http, 'get', function (o) { log('net-egress', 'http.get', host(o)); }); } catch (e) {}
    try { var https = require('https'); wrap(https, 'request', function (o) { log('net-egress', 'https.request', host(o)); }); wrap(https, 'get', function (o) { log('net-egress', 'https.get', host(o)); }); } catch (e) {}
    try { var dns = require('dns'); wrap(dns, 'lookup', function (h) { log('net-egress', 'dns.lookup', h); }); } catch (e) {}
    try { var dgram = require('dgram'); wrap(dgram, 'createSocket', function () { log('net-egress', 'dgram', ''); }); } catch (e) {}
    try { if (typeof globalThis.fetch === 'function') { var of = globalThis.fetch; globalThis.fetch = function (u) { try { log('net-egress', 'fetch', typeof u === 'string' ? u : (u && u.url)); } catch (e) {} return of.apply(this, arguments); }; } } catch (e) {}

    try { var cp = require('child_process'); ['exec','execSync','execFile','execFileSync','spawn','spawnSync','fork'].forEach(function (m) { wrap(cp, m, function (c) { log('exec', 'cp.' + m, c); }); }); } catch (e) {}

    try { var vm = require('vm'); ['runInThisContext','runInNewContext','runInContext','compileFunction'].forEach(function (m) { wrap(vm, m, function () { log('dynamic-eval', 'vm.' + m, ''); }); }); } catch (e) {}

    try {
      var realEnv = process.env; var envLogged = false;
      process.env = new Proxy(realEnv, {
        get: function (t, k) { if (!envLogged && typeof k === 'string' && k !== 'HEIMDALL_RECORD') { envLogged = true; log('env-access', 'process.env', k); } return t[k]; },
        set: function (t, k, v) { t[k] = v; return true; },
        has: function (t, k) { return k in t; },
        deleteProperty: function (t, k) { delete t[k]; return true; }
      });
    } catch (e) {}
  } catch (e) {}
})();
`;

// ---------------------------------------------------------------------------
// Pure helpers (unit-testable, no process spawning)
// ---------------------------------------------------------------------------

/** Synthesize a plausible value for a JSON-schema property, to exercise a tool. */
export function sampleValue(prop: any): unknown {
  if (!prop || typeof prop !== "object") return "test";
  if (prop.default !== undefined) return prop.default;
  if (Array.isArray(prop.enum) && prop.enum.length) return prop.enum[0];
  if (prop.example !== undefined) return prop.example;
  switch (prop.type) {
    case "number":
    case "integer":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "test";
  }
}

/** Build an arguments object for a tool from its inputSchema (fills required props). */
export function synthArgs(inputSchema: any): Record<string, unknown> {
  const props = (inputSchema && inputSchema.properties) || {};
  const required: string[] =
    Array.isArray(inputSchema?.required) && inputSchema.required.length
      ? inputSchema.required
      : Object.keys(props);
  const out: Record<string, unknown> = {};
  for (const key of required) out[key] = sampleValue(props[key]);
  return out;
}

/** Reduce recorded events (optionally after a cutoff) to the set of observed capabilities. */
export function observedCaps(events: RecordEvent[], since = 0): Set<string> {
  const caps = new Set<string>();
  for (const e of events) {
    if (e && typeof e.t === "number" && e.t >= since && typeof e.cap === "string") caps.add(e.cap);
  }
  return caps;
}

/** Diff static vs observed capabilities into a per-capability comparison. */
export function compareCaps(staticCaps: Set<string>, observed: Set<string>): CapComparison[] {
  return OBSERVABLE_CAPS.map((cap) => {
    const s = staticCaps.has(cap);
    const o = observed.has(cap);
    const status: CapStatus = s && o ? "confirmed" : s ? "not-exercised" : o ? "missed" : "clean";
    return { cap, static: s, observed: o, status };
  });
}

// ---------------------------------------------------------------------------
// Driver: spawn the server with the recorder, handshake, invoke tools
// ---------------------------------------------------------------------------

function spawnPlan(target: Target): { command: string; args: string[]; filterBootstrap: boolean } {
  if (target.kind === "npm") {
    // npx installs deps and runs the bin; its bootstrap fs/net is filtered out by time.
    return { command: "npx", args: ["-y", target.ref], filterBootstrap: true };
  }
  // dir / github: spawn the entry directly (assumes deps are installed). No bootstrap noise.
  const pkg = target.packageJson ?? {};
  let entry = "index.js";
  if (typeof pkg.bin === "string") entry = pkg.bin;
  else if (pkg.bin && typeof pkg.bin === "object") entry = String(Object.values(pkg.bin)[0]);
  else if (typeof pkg.main === "string") entry = pkg.main;
  return { command: "node", args: [join(target.rootDir ?? ".", entry)], filterBootstrap: false };
}

interface DriveResult {
  initAt: number;
  toolsCalled: number;
  error?: string;
}

interface DriveOptions {
  maxTools?: number;
  timeoutMs?: number;
}

/** Spawn the server (recorder preloaded), handshake, and call each tool once. */
function driveServer(
  plan: { command: string; args: string[] },
  recorderPath: string,
  recordPath: string,
  rootAbs: string,
  opts: DriveOptions,
): Promise<DriveResult> {
  const maxTools = opts.maxTools ?? 25;
  const timeoutMs = opts.timeoutMs ?? 30_000;

  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(plan.command, plan.args, {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          SystemRoot: process.env.SystemRoot,
          // Preload the recorder into the server (and any node children it spawns).
          NODE_OPTIONS: `--require ${recorderPath}`,
          HEIMDALL_RECORD: recordPath,
          HEIMDALL_ROOT: rootAbs,
        },
      });
    } catch (err) {
      return resolve({ initAt: 0, toolsCalled: 0, error: err instanceof Error ? err.message : String(err) });
    }

    const pending = new Map<number, (msg: any) => void>();
    let nextId = 1;
    let buf = "";
    let done = false;

    const finish = (res: DriveResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
      resolve(res);
    };
    const timer = setTimeout(() => finish({ initAt: 0, toolsCalled: 0, error: "validate timed out" }), timeoutMs);

    child.on("error", (e: Error) => finish({ initAt: 0, toolsCalled: 0, error: e.message }));
    child.stdout!.on("data", (d: Buffer) => {
      buf += d.toString();
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg: any;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg && msg.id != null && pending.has(msg.id)) {
          pending.get(msg.id)!(msg);
          pending.delete(msg.id);
        }
      }
    });

    const request = (method: string, params: unknown, waitMs = 8000): Promise<any> =>
      new Promise((res) => {
        const id = nextId++;
        pending.set(id, res);
        setTimeout(() => {
          if (pending.has(id)) {
            pending.delete(id);
            res(null);
          }
        }, waitMs);
        try {
          child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        } catch {
          res(null);
        }
      });
    const notify = (method: string) => {
      try {
        child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
      } catch {
        /* pipe closed */
      }
    };
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

    (async () => {
      const init = await request("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "heimdall-validate", version: "0.2.0" },
      });
      if (!init) return finish({ initAt: 0, toolsCalled: 0, error: "no initialize response" });
      const initAt = Date.now(); // events at/after this exclude npx bootstrap
      notify("notifications/initialized");

      const list = await request("tools/list", {});
      const tools: ToolDef[] = (list?.result?.tools ?? []) as any[];

      let called = 0;
      for (const tool of tools.slice(0, maxTools)) {
        const name = (tool as any)?.name;
        if (!name) continue;
        await request(
          "tools/call",
          { name, arguments: synthArgs((tool as any).inputSchema) },
          4000,
        );
        called++;
      }

      // Give late/async capability side effects a moment to fire before we kill.
      await sleep(600);
      finish({ initAt, toolsCalled: called });
    })();
  });
}

function readEvents(recordPath: string): RecordEvent[] {
  let raw: string;
  try {
    raw = readFileSync(recordPath, "utf8");
  } catch {
    return [];
  }
  const out: RecordEvent[] = [];
  for (const line of raw.split("\n")) {
    const s = line.trim();
    if (!s) continue;
    try {
      out.push(JSON.parse(s));
    } catch {
      /* ignore partial line */
    }
  }
  return out;
}

export interface ValidateOptions {
  maxTools?: number;
  timeoutMs?: number;
  /** Provide a pre-computed static report to avoid a second resolve/scan. */
  report?: Report;
}

/** Validate one server: run it, observe behavior, and diff against the static scan. */
export async function validateServer(input: string, opts: ValidateOptions = {}): Promise<ValidateReport> {
  let target: Target;
  let report: Report;
  try {
    target = await resolveTarget(input);
    report = opts.report ?? (await scan(input));
  } catch (err) {
    return {
      target: input,
      kind: "npm",
      toolsCalled: 0,
      staticCaps: [],
      observedCaps: [],
      comparison: [],
      confirmed: 0,
      missed: 0,
      notExercised: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  const workdir = mkdtempSync(join(tmpdir(), "mcp-audit-validate-"));
  const recorderPath = join(workdir, "recorder.cjs");
  const recordPath = join(workdir, "events.jsonl");
  writeFileSync(recorderPath, RECORDER_JS);
  writeFileSync(recordPath, "");

  const plan = spawnPlan(target);
  // Own-package root: for a spawned dir we filter reads under it; for npx (npm) the server
  // runs from an install cache elsewhere, so this won't match — the time cutoff handles that.
  const rootAbs = target.rootDir ? resolve(target.rootDir) : "";
  const drive = await driveServer(plan, recorderPath, recordPath, rootAbs, opts);

  const events = readEvents(recordPath);
  try {
    rmSync(workdir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }

  const observed = observedCaps(events, plan.filterBootstrap ? drive.initAt : 0);
  const staticSet = new Set(report.capabilities.filter((c) => (OBSERVABLE_CAPS as readonly string[]).includes(c)));
  const comparison = compareCaps(staticSet, observed);

  return {
    target: input,
    kind: target.kind,
    toolsCalled: drive.toolsCalled,
    staticCaps: [...staticSet].sort(),
    observedCaps: [...observed].filter((c) => (OBSERVABLE_CAPS as readonly string[]).includes(c)).sort(),
    comparison,
    confirmed: comparison.filter((c) => c.status === "confirmed").length,
    missed: comparison.filter((c) => c.status === "missed").length,
    notExercised: comparison.filter((c) => c.status === "not-exercised").length,
    error: drive.error,
  };
}

export interface BatchReport {
  servers: ValidateReport[];
  /** Per-capability tallies across all servers. */
  perCap: Record<string, { confirmed: number; missed: number; notExercised: number }>;
  /** Recall = confirmed / (confirmed + missed): of observed capabilities, how many were flagged. */
  recall: number;
  totalConfirmed: number;
  totalMissed: number;
}

/** Validate a list of servers and aggregate a recall number over observed behavior. */
export async function validateBatch(inputs: string[], opts: ValidateOptions = {}): Promise<BatchReport> {
  const servers: ValidateReport[] = [];
  for (const input of inputs) servers.push(await validateServer(input, opts));

  const perCap: BatchReport["perCap"] = {};
  for (const cap of OBSERVABLE_CAPS) perCap[cap] = { confirmed: 0, missed: 0, notExercised: 0 };
  for (const s of servers) {
    for (const c of s.comparison) {
      if (c.status === "confirmed") perCap[c.cap].confirmed++;
      else if (c.status === "missed") perCap[c.cap].missed++;
      else if (c.status === "not-exercised") perCap[c.cap].notExercised++;
    }
  }
  const totalConfirmed = Object.values(perCap).reduce((n, v) => n + v.confirmed, 0);
  const totalMissed = Object.values(perCap).reduce((n, v) => n + v.missed, 0);
  const denom = totalConfirmed + totalMissed;
  return { servers, perCap, recall: denom ? totalConfirmed / denom : 1, totalConfirmed, totalMissed };
}
