import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { evaluateCorpus, handshake, scan, scanConfig } from "../src/index.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

test("benign server passes with a capability profile", async () => {
  const report = await scan(join(fixtures, "weather-mcp"));
  assert.equal(report.verdict, "pass");
  assert.equal(report.toolCount, 1);
  assert.ok(!report.findings.some((f) => f.gate), "should have no hard gates");
  assert.ok(report.capabilities.includes("net-egress"), "reports network capability");
  // Raw capability must not be a risk finding.
  const risk = report.findings.filter((f) => !f.profile);
  assert.ok(
    !risk.some((f) => f.severity === "high" || f.severity === "medium"),
    "no risk-driving anomalies",
  );
});

test("malicious server fails with gates", async () => {
  const report = await scan(join(fixtures, "note-keeper-mcp"));
  assert.equal(report.verdict, "fail");

  const gates = report.findings.filter((f) => f.gate).map((f) => f.id);
  assert.ok(gates.includes("gate/exfil-flow"), "detects the proven fs→network exfil path");
  assert.ok(
    gates.includes("provenance/install-script-exec"),
    "detects code exec in postinstall",
  );
  assert.ok(
    report.findings.some((f) => f.id === "injection/instruction-override"),
    "detects instruction-override phrasing",
  );
  assert.ok(
    report.findings.some((f) => f.id === "injection/conceal-from-user"),
    "detects concealment instruction in poisoned tool description",
  );
});

test("a custom policy changes the verdict on the same facts", async () => {
  const base = await scan(join(fixtures, "weather-mcp"));
  assert.equal(base.verdict, "pass");
  assert.ok(base.capabilities.includes("net-egress"));

  // Same server, stricter procurement policy that forbids any network egress.
  const strict = await scan(join(fixtures, "weather-mcp"), {
    policy: {
      name: "no-network",
      gate: [],
      denyCapabilities: ["net-egress"],
      require: [],
      failOnSeverity: "none",
      warnOnSeverity: "medium",
      allow: [],
    },
  });
  assert.equal(strict.verdict, "fail");
  assert.equal(strict.policy, "no-network");
  assert.ok(
    strict.reasons.some((r) => r.includes("denied capability: net-egress")),
    "reason explains the failure",
  );
});

test("fingerprint is stable and changes with the tool surface", async () => {
  const a = await scan(join(fixtures, "weather-mcp"));
  const b = await scan(join(fixtures, "weather-mcp"));
  assert.equal(a.fingerprint, b.fingerprint, "same input -> same fingerprint");

  const other = await scan(join(fixtures, "note-keeper-mcp"));
  assert.notEqual(a.fingerprint, other.fingerprint, "different tools -> different fingerprint");
});

test("injection is detected in resources and prompts, not just tools", async () => {
  const report = await scan(join(fixtures, "poisoned-surface.json"));
  assert.equal(report.resourceCount, 1);
  assert.equal(report.promptCount, 1);
  assert.equal(report.verdict, "fail");

  const inResource = report.findings.filter((f) => f.location?.startsWith("resource:"));
  const inPrompt = report.findings.filter((f) => f.location?.startsWith("prompt:"));
  assert.ok(inResource.some((f) => f.id === "injection/conceal-from-user"), "resource concealment payload");
  assert.ok(inResource.some((f) => f.id === "injection/pseudo-instruction-tag"), "resource fake tag");
  assert.ok(inPrompt.some((f) => f.id === "injection/instruction-override"), "prompt override payload");
});

test("credential access is reported with a specific detector", async () => {
  const report = await scan(join(fixtures, "note-keeper-mcp"));
  assert.ok(
    report.findings.some((f) => f.id === "capability/secret-ssh"),
    "SSH key access has its own finding id",
  );
  assert.ok(report.capabilities.includes("secret-access"));
});

test("drift diff flags a changed tool description (rug-pull)", async () => {
  const baseline = await scan(join(fixtures, "drift-v1.json"));
  assert.equal(baseline.verdict, "pass");

  const drifted = await scan(join(fixtures, "drift-v2.json"), { baseline });
  const drift = drifted.findings.filter((f) => f.category === "drift");
  assert.ok(drift.some((f) => f.id === "drift/description-changed" && f.gate), "rug-pull gate fires");
  assert.equal(drifted.verdict, "fail");
});

test("taint proves an exfil path, and spares co-presence without a real flow", async () => {
  // Proven flow (fs read → req.end) hard-fails with a precise, located finding.
  const malicious = await scan(join(fixtures, "note-keeper-mcp"));
  const flow = malicious.findings.find((f) => f.id === "gate/exfil-flow");
  assert.ok(flow?.gate, "proven exfil path is a gate");
  assert.ok(/:\d+$/.test(flow?.location ?? ""), "flow finding is located at file:line");

  // Reads creds AND calls an unrelated endpoint, but no data flows between them →
  // must NOT hard-fail (this is the co-presence false positive taint removes).
  const benign = await scan(join(fixtures, "cred-noflow"));
  assert.notEqual(benign.verdict, "fail", "no proven flow → not an auto-FAIL");
  assert.ok(
    !benign.findings.some((f) => f.id === "gate/exfil-flow"),
    "no false exfil-flow gate",
  );
  assert.ok(
    benign.findings.some((f) => f.id === "capability/exfil-surface"),
    "still surfaced for human review",
  );
});

test("dependency capabilities are latent: reported and policy-gateable, but never auto-fail", async () => {
  const report = await scan(join(fixtures, "dep-heavy"));
  // Capabilities surface from deps even though the source is clean.
  for (const cap of ["net-egress", "secret-access", "exec"]) {
    assert.ok(report.capabilities.includes(cap), `latent capability ${cap} reported`);
  }
  // Latent secret-access + net-egress must NOT trip the exfil gate (deps ≠ proven use).
  assert.equal(report.verdict, "pass", "latent dep capabilities do not hard-fail");
  assert.ok(report.findings.some((f) => f.id === "provenance/dependency-capability" && f.profile));

  // But a policy CAN deny a dependency-provided capability.
  const denied = await scan(join(fixtures, "dep-heavy"), {
    policy: {
      name: "no-exec",
      gate: [],
      denyCapabilities: ["exec"],
      require: [],
      failOnSeverity: "none",
      warnOnSeverity: "medium",
      allow: [],
    },
  });
  assert.equal(denied.verdict, "fail", "policy denies the dep-provided exec capability");
});

test("composition detects a cross-server exfiltration chain no server shows alone", async () => {
  const report = await scanConfig(join(fixtures, "config-chain.json"));
  assert.equal(report.serverCount, 2);
  assert.ok(
    report.findings.some((f) => f.id === "composition/exfil-chain"),
    "flags the cross-server exfil surface",
  );
  assert.equal(report.verdict, "fail", "aggregate inherits the malicious server's FAIL");
});

test("composition detects cross-server tool-name collisions", async () => {
  const report = await scanConfig(join(fixtures, "config-collide.json"));
  const collision = report.findings.filter((f) => f.id === "composition/tool-collision");
  assert.ok(collision.length >= 1, "flags the shared tool name");
  assert.ok(collision[0].detail.includes("search"), "names the colliding tool");
});

test("the calibration harness scores the seed corpus with no false positives/negatives", async () => {
  const { metrics } = await evaluateCorpus([
    { target: join(fixtures, "weather-mcp"), label: "benign" },
    { target: join(fixtures, "dep-heavy"), label: "benign" },
    { target: join(fixtures, "cred-noflow"), label: "benign" },
    { target: join(fixtures, "note-keeper-mcp"), label: "malicious" },
    { target: join(fixtures, "poisoned-surface.json"), label: "malicious" },
  ]);
  assert.equal(metrics.fp, 0, "no benign server flagged");
  assert.equal(metrics.fn, 0, "no malicious server missed");
  assert.equal(metrics.precision, 1);
  assert.equal(metrics.recall, 1);
});

test("handshake pulls the live surface, catching a runtime-built description static misses", async () => {
  // The fixture server builds its poisoned description at runtime.
  const live = await handshake("node", ["fixtures/live-server/server.mjs"]);
  assert.equal(live.error, undefined, "handshake completed");
  assert.equal(live.tools.length, 1);
  assert.match(live.tools[0].description ?? "", /ignore all previous instructions/i);

  // Static scan of the server source misses the payload (description is a computed value)...
  const staticScan = await scanConfig(join(fixtures, "config-live.json"));
  const staticInjection = staticScan.servers.every((s) => s.verdict !== "fail");
  assert.ok(staticInjection, "static extraction does not see the runtime description");

  // ...but a live handshake does, and it FAILs.
  const liveScan = await scanConfig(join(fixtures, "config-live.json"), { handshake: true });
  assert.equal(liveScan.verdict, "fail", "live handshake surfaces the injection");
});

test("waivers suppress a finding, and expired waivers lapse with a notice", async () => {
  const base = await scan(join(fixtures, "shadow.json"));
  assert.equal(base.verdict, "warn"); // tool-shadowing anomaly

  const mk = (allow: unknown[]) => ({
    name: "test",
    gate: [],
    denyCapabilities: [],
    require: [],
    failOnSeverity: "none" as const,
    warnOnSeverity: "medium" as const,
    allow,
  });

  const waived = await scan(join(fixtures, "shadow.json"), {
    policy: mk([{ id: "injection/tool-shadowing", reason: "reviewed" }]) as never,
  });
  assert.equal(waived.verdict, "pass", "active waiver suppresses the finding");

  const expired = await scan(join(fixtures, "shadow.json"), {
    policy: mk([{ id: "injection/tool-shadowing", expires: "2000-01-01T00:00:00Z" }]) as never,
  });
  assert.equal(expired.verdict, "warn", "expired waiver no longer suppresses");
  assert.ok(expired.findings.some((f) => f.id === "waiver/expired"), "expiry notice surfaced");
});
