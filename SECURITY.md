# Security policy

Heimdall is a security tool, so its own security and its limits both matter. Please read
the threat model below — it is as important as the reporting process.

## Reporting a vulnerability in Heimdall

If you find a vulnerability **in Heimdall itself** (for example: a crafted MCP server or
input that makes Heimdall execute code, read files outside its target, hang, or crash):

- **Preferred:** open a private report via GitHub's **"Report a vulnerability"** (Security
  Advisories) on this repository. This keeps the details private until a fix ships.
- **Alternative:** email the maintainer at tokiyashi@gmail.com.
- **Please do not** open a public issue for a suspected vulnerability.

This is a young, best-effort open-source project — expect an acknowledgement within a few
days, not an SLA. Credit is given to reporters unless you prefer to stay anonymous.

## Threat model and limitations — read this

**Heimdall is a heuristic scanner, not a guarantee.**

- A **PASS is not proof that a server is safe.** It means Heimdall found nothing it flags.
- A **FAIL / WARN means "review this," not "proven malicious."** Rules are heuristic and can
  false-positive; a determined attacker can evade static analysis.
- Verdicts are calibrated against a small labeled corpus plus a 1000-server field run, not a
  large validated benchmark. Treat the output as **one input to a human decision**, alongside
  reading the code, checking provenance, and sandboxing at runtime.

### Coverage limits

- **Static analysis** only, except for `--handshake` (below). Taint/data-flow is intra-file
  and best-effort; it can miss cross-file or obfuscated flows.
- **Language:** capability, provenance, and taint analysis understand **JavaScript/TypeScript**.
  Injection analysis is language-agnostic (it reads description text), but a Python/Go/etc.
  server gets only injection coverage.
- **Regex-based rules** run over untrusted input (tool descriptions, source). We try to keep
  patterns linear, but treat pathological ReDoS on hostile input as a known consideration —
  reports welcome.

### ⚠️ `--handshake` runs untrusted code

By default Heimdall does **not** execute the servers it scans — it reads their code and
metadata statically. The **one exception** is `--handshake`, which **spawns the server
process** to read its live tool list.

- `--handshake` runs the target with a **reduced environment** (no inherited secrets beyond
  `PATH`/`HOME`) and a **hard timeout + kill**. This is a mitigation, **not a real sandbox.**
- **Only use `--handshake` inside a disposable VM or container**, never on a machine with
  credentials or data you care about.
- Downloading a package (`npm pack`) or cloning a repo for a *static* scan does not run the
  server's code; install scripts are **detected, not executed**. `--handshake` is the only
  code-execution path.

### `--online` is the only network call

By default Heimdall runs **fully offline** and sends nothing off your machine. `--online`
enables the OSV.dev CVE lookup, which **transmits the target's dependency names and versions**
(from its `package.json`) to `api.osv.dev`. It never sends your source. The match is against
the **declared version range**, not an installed lockfile, so a hit is a strong review signal,
not proof the installed tree is exploitable — hence it WARNs rather than hard-gating.

### What Heimdall is not

It is a **pre-flight check**, not runtime protection. It does not replace sandboxing,
runtime monitoring, dependency-vulnerability scanning, or human code review.
