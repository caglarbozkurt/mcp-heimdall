import { spawn } from "node:child_process";
import { normalizeItem, normalizeTool } from "./extract.js";
import type { ToolDef } from "./types.js";

export interface HandshakeResult {
  tools: ToolDef[];
  resources: ToolDef[];
  prompts: ToolDef[];
  error?: string;
}

export interface HandshakeOptions {
  cwd?: string;
  timeoutMs?: number;
}

/**
 * Complete the MCP stdio handshake against a server process and pull its live
 * tools/resources/prompts. This is the highest-fidelity input — it captures
 * dynamically-generated descriptions that static extraction cannot see.
 *
 * SECURITY: this SPAWNS AND RUNS the server (untrusted code). It runs with a reduced
 * environment (no inherited secrets beyond PATH/HOME) and a hard timeout+kill, but that
 * is NOT a real sandbox. Run `--handshake` only inside a disposable VM/container.
 */
export function handshake(
  command: string,
  args: string[] = [],
  opts: HandshakeOptions = {},
): Promise<HandshakeResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const empty: HandshakeResult = { tools: [], resources: [], prompts: [] };

  return new Promise((resolve) => {
    let child: any;
    try {
      child = spawn(command, args, {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: opts.cwd ?? process.cwd(),
        // Reduced env: don't hand the user's API keys/secrets to untrusted code.
        env: { PATH: process.env.PATH, HOME: process.env.HOME, SystemRoot: process.env.SystemRoot },
      });
    } catch (err) {
      return resolve({ ...empty, error: err instanceof Error ? err.message : String(err) });
    }

    const pending = new Map<number, (msg: any) => void>();
    let nextId = 1;
    let buf = "";

    const finish = (res: HandshakeResult) => {
      clearTimeout(timer);
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
      resolve(res);
    };
    const timer = setTimeout(() => finish({ ...empty, error: "handshake timed out" }), timeoutMs);

    child.on("error", (e: Error) => finish({ ...empty, error: e.message }));
    child.stdout.on("data", (d: Buffer) => {
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
          continue; // server logged non-JSON to stdout — ignore
        }
        if (msg && msg.id != null && pending.has(msg.id)) {
          pending.get(msg.id)!(msg);
          pending.delete(msg.id);
        }
      }
    });

    const request = (method: string, params: unknown): Promise<any> =>
      new Promise((res) => {
        const id = nextId++;
        pending.set(id, res);
        setTimeout(() => {
          if (pending.has(id)) {
            pending.delete(id);
            res(null);
          }
        }, timeoutMs);
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });
    const notify = (method: string) =>
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");

    (async () => {
      const init = await request("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "heimdall", version: "0.1.0" },
      });
      if (!init) return finish({ ...empty, error: "no initialize response" });
      notify("notifications/initialized");

      const [t, r, p] = await Promise.all([
        request("tools/list", {}),
        request("resources/list", {}),
        request("prompts/list", {}),
      ]);

      finish({
        tools: (t?.result?.tools ?? []).map(normalizeTool).filter(Boolean) as ToolDef[],
        resources: (r?.result?.resources ?? []).map(normalizeItem).filter(Boolean) as ToolDef[],
        prompts: (p?.result?.prompts ?? []).map(normalizeItem).filter(Boolean) as ToolDef[],
      });
    })();
  });
}
