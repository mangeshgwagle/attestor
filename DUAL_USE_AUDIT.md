# Attestor — Dual-Use Audit & Distribution Split

Evidence-based inventory of what ships in the repo, so you know exactly what a
public release would distribute. Capability flags come from grepping each module
for live-network and code-execution primitives (not from names).

## The two lanes

### Defensive core (the `attestor` CLI)
Everything reachable from `attestor <command>` is analysis + remediation. It reads
code, never attacks anything, and makes no outbound connections on the default
paths. Modules: `dataflow`, `taint_tracker`, `confirm` (non-detonating — records
the sink, never executes it), `secret_scanner`, `iac_scanner`, `js_scanner`,
`sca_scanner`, `exploit_detector` (detects malware, doesn't make it), `triage`,
`vendored`, `autofix`, `compliance`, `sarif_output`, `git_history`, `cicd_scanner`,
`supply_chain`, `binary_analyzer`, `semantic_similarity`, `evaluate`,
`bench_compare`, `flywheel`, `check`. **This is what you install and share.**

### Red-team lane (NOT wired into the CLI — run each script deliberately)
| Module | Live network? | Executes code? | What it actually does |
|---|---|---|---|
| `active_scan42` | **YES** (1 call) | no | Live web probing of an **explicit authorized target**; bounded, canary-marker checks; reports candidates with request/response evidence. Its own header calls this "the deliberate network-active exception." |
| `msf_lite42` | **YES** (1 call) | no | Sends HTTP requests (urllib) to a target for check-style probes. |
| `recon_net42` | socket refs | no | Network recon / listener scaffolding; no live send detected at module top level. |
| `crashforge42` | no | **YES** (1) | Local fuzzer — `exec`s the target source under test. Execution is of code *you point it at*, locally. |
| `offensive_lab42` | 1 ref | **YES** (3) | Offensive lab/harness that executes candidate code locally. |
| `poc_generator` | no | in templates | Emits PoC payload **strings** (marked educational); nothing runs. |
| `poc_gen42` | 9 refs | in templates | Large PoC generator: webshells, deserialization gadgets, SSTI, socket-probe snippets. Payloads use **benign canaries** (`echo CANARY`). Generation only. |
| `poc_writer42` | in emitted script | no | Writes runnable attack scripts; **"nothing is executed at generation time"** — each script has a `TARGET` constant the operator must set and run. |
| `payload_decoder` | no | no | Decodes obfuscated payloads (analysis). |
| `password_audit` | **no (offline)** | no | **NEW** — JtR-lite offline hash auditor. Audits hashes you supply; gated behind `--yes-authorized`; no online/login attack surface. |
| `pwnbridge42`, `offensive_fuzz42`, `mayhem`, `escape_lab414`, `purple_team42` | no | no | Red-team-named; no live-network/exec primitives detected. Scaffolding/labs/analysis — review individually before any release. |

## Findings
1. **Nothing auto-deploys.** No module reaches out and attacks on its own. The two
   network-live scanners (`active_scan42`, `msf_lite42`) require an explicit target
   and are bounded/canary-based. Payload generators never execute what they write.
2. **The offensive lane is not in the CLI.** The installed `attestor` command cannot
   launch any of it; the red-team modules are standalone scripts (`python
   detector/<module>.py`), invoked deliberately.
3. **`password_audit` is offline by design** — it's a hash-strength audit, not an
   online credential attack.

## Recommended distribution split
Keep two packages so what you share by default is defense-only:

- **`attestor`** (public-safe): the defensive core above + the `attestor` CLI.
- **`attestor-redteam`** (private / deliberate release): the red-team lane table
  above, each with its authorization header.

Mechanics (no file moves needed now, which avoids conflicts with the in-flight
`corpus-benchmark` work): declare the split via packaging `extras` and a module
allowlist, then physically separate later. Until then, the practical guarantee
already holds: **`attestor` (the CLI) ships defense only; the offensive scripts
require deliberate, direct invocation.**

## Bottom line for a Kali box
Running these against systems you're authorized to test is their intended use.
Just remember: a public repo/PyPI release distributes the red-team lane too — that
should be a deliberate decision, and this split is how you make it one.
