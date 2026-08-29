# Attestor 4.1.4 blind autonomous synthetic escape arena

The blind arena is a safe, local, abstract policy-navigation exercise. Its
objective is the exact constant `Escape`. A deterministic black-box explorer
tries opaque action identifiers, learns their observed outcomes, persists that
knowledge between finite episodes, and continues until a terminal synthetic
result or the operator cancels it.

This is not an exploit runner. It does not attempt to leave a Python process,
container, browser, virtual machine, hypervisor, operating system, or kernel.
It does not test whether any real isolation boundary can be escaped.

## Separate from the private planted-path lab

Attestor 4.1.4 contains two different abstract exercises:

| Property | Private escape lab | Blind autonomous arena |
|---|---|---|
| Entry point | `--escape-lab` | `--blind-escape-arena` |
| Cases | Six fixed, named policy graphs | One generated arena per controller checkpoint |
| Solver input | Compiled scenario selected by exact ID | Opaque observations/actions plus learned outcomes |
| Persistence | Session-only report | Atomic controller checkpoint after each episode |
| Purpose | Explain a planted authorization inconsistency | Learn a black-box route to synthetic outside |
| Real escape authority | None | None |

The blind arena never calls `escape_lab414.py`, `runtime_lab.py`,
`security_lab41.py`, the execution fabric, a container runtime, or a hypervisor.

## Fixed objective and opaque environment

The objective is always:

```text
Escape
```

It is not accepted from a prompt, request document, command-line value, query
parameter, or UI field. Before Attestor initializes its generic CLI, brain, persona,
key files, or ordinary request router, a dedicated parser accepts exactly
`--blind-escape-arena`, optional `--blind-escape-single-episode`,
`--format text|json`, and optional controller-side report `--out`. It rejects
positional text, abbreviations, duplicates, unknown options, and every unrelated
path, model, seed, caller-budget, key-file, tool, test, generated-execution, and
network option without reading those rejected paths.

A new generated arena has five to eight abstract observations and three opaque
actions per observation. The private state contains the deterministic graph,
synthetic-outside identity, and hidden escape token. The explorer does not
receive those fields. Its exact view contains only:

- the schema/version and fixed objective;
- an opaque arena ID;
- the episode and step numbers;
- the current opaque observation ID;
- the opaque start-observation ID;
- the available opaque action IDs; and
- accumulated black-box knowledge: previously attempted observation/action
  pairs, attempt counts, observed next IDs, and abstract outcomes.

The explorer receives no compiled graph, route, walkthrough, reason catalog,
hidden token, checkpoint path, source path, caller prompt, command, code, URL,
plugin, or arbitrary payload. The default explorer is a local deterministic
search strategy, not an LLM and not a process with computer-control authority.
The public runner rejects replacement explorer callbacks, callable cancellation
hooks, and Event subclasses before an episode begins. Controllers may signal
cancellation only with an exact standard `threading.Event`, so caller code
cannot execute inside the claimed pure simulation boundary.

## Bounded episodes and persistent learning

Every episode is finite. Attestor 4.1.4 uses eight abstract steps per episode by
default and rejects a core request above 128 steps. The generated graph, action
count, JSON depth/node count, state bytes, report bytes, and checkpoint bytes
also have fixed hard boundaries.

The normal CLI and UI controllers deliberately have no overall arena wall-clock
deadline or lifetime episode ceiling. They run one bounded episode at a time,
verify it, atomically checkpoint it, and resume with the learned knowledge. The
lack of an overall deadline does not weaken any per-episode or data-size bound.
It also does not promise how many episodes a particular fresh checkpoint will
need.

`--blind-escape-single-episode` is the bounded test/resume form. It performs one
episode, saves the resulting verified state, and returns even when the arena is
still incomplete. Running either form again resumes the same learned state.

## Controller-only checkpoint

The simulation core is in-memory. Arena-state persistence is limited to the
explicit controller checkpoint helpers:

- the CLI controller uses
  `~/.attestor/blind-escape-arena-4.1.4.json`;
- the UI controller stores
  `blind-escape-arena-4.1.4.checkpoint.json` beside its configured local
  evidence-history database.

Neither path can be supplied to the explorer or through the blind-arena CLI/UI
request. A checkpoint path is never serialized into arena state, observations,
reports, status views, or rendered text. The browser receives verified counters,
booleans, frontier state, and a compiled reason—not the checkpoint, graph,
hidden token, or trace.

Before writing, Attestor verifies the complete state and its canonical digest. It
writes a bounded temporary file, flushes it, and atomically replaces the fixed
checkpoint. Existing link/reparse-point or non-regular checkpoint targets and
unsafe reparse-point parents fail closed. Strict loading rejects oversized data,
invalid UTF-8/JSON, duplicate keys, non-finite values, unexpected fields, and any
state that cannot be deterministically regenerated and replayed. Malformed
checkpoint and verifier inputs return a bounded fail-closed result rather than
throwing through the public boundary. File-mode hardening is best-effort on
platforms that support it; it is not a substitute for host account or disk
security.

The checkpoint is private controller material because it contains the private
arena state. Do not publish it as an ordinary result. `--out`, when used, writes
the already verified episode report; it does not redirect or expose the
checkpoint, and the controller rejects an output that resolves to or aliases
the checkpoint.

## Replay-verified synthetic escape proof

Reaching a transition labelled `synthetic-outside` is necessary but not enough
for a public success claim. On that transition the report binds:

- the hidden token, disclosed only after the synthetic transition;
- the token's SHA-256;
- the private synthetic-outside observation ID;
- the exact opaque transition trace and its SHA-256; and
- a reason code and explanation derived from the replayed compiled edge.

`verify_report()` first verifies the complete checkpoint state, regenerates the
private graph from its committed seed and arena kind, then replays each action
from the start observation. It rejects a malformed transition, stale knowledge,
wrong token, wrong outside identity, invented reason, extra trace step, altered
summary, or bad state/report digest. It also requires the supplied report to be
the state's exact current `last_report`, reconciles its before/after step and
knowledge counters, binds the before/after state commitments, and advances the
persisted episode-history chain.
SuperAttestor and the UI perform this replay before returning exit success or
showing `Escaped - verified`.

SHA-256 supplies deterministic integrity and identity. It is not an
authorization, digital signature, proof of who ran Attestor, or proof that a real
system is secure. The controller directory is part of the trusted local
boundary: a malicious process running as the same account that can replace the
checkpoint can also regenerate its public SHA-256 fields. The digests detect
accidental or incomplete modification; they do not authenticate state against
such a same-account writer.

## Command-line use

Start or resume and continue until a replay-verified synthetic escape or user
cancellation:

```sh
python3 detector/superattestor.py --blind-escape-arena --format text
python3 detector/superattestor.py --blind-escape-arena --format json
```

Run exactly one checkpointed episode:

```sh
python3 detector/superattestor.py --blind-escape-arena --blind-escape-single-episode --format json
```

The mode accepts only text or JSON output. Its exit meanings are:

| Exit | Meaning |
|---:|---|
| `0` | Synthetic escape report and state passed replay verification |
| `1` | Bounded episode/reference ended without an escape success; state is resumable |
| `2` | Input, explorer, checkpoint, controller, or verification failed closed |
| `130` | User cancellation; no escape success is claimed |

No natural-language alias starts this mode. This prevents ordinary request text
from becoming arena input.

## Local UI use

Start the secured loopback workbench with `Start_Attestor_UI.bat`. The **Blind
autonomous escape arena** panel is independent of the normal analysis form and
has no editable prompt, path, payload, graph, seed, model, or deadline field.
It provides four controls:

- **Start/Resume** opens the fixed checkpoint and starts bounded background
  episodes;
- **Refresh status** retrieves the verified status projection;
- **Cancel** signals the current episode and preserves a cancelled resumable
  checkpoint; and
- **Reset/new** replaces the fixed checkpoint only after an explicit confirmation.

The panel shows the fixed objective, episode and action counters, opaque-frontier
counts, report-verification state, and escape-proof state. A raw `escaped` string
cannot create the success badge: report replay, hidden-token proof, exact-trace
proof, and terminal state must all agree. The status API never returns the
private graph, token, trace, or checkpoint path.

The browser controller bounds and validates request bodies, hardens cancellation
and terminal-state cleanup, and rejects unsafe link/reparse checkpoint paths.
Its post-fix final-source browser run exposed zero editable arena inputs,
completed with `escaped` and `verified` after 5 episodes and 37 attempts, and
produced zero browser-console errors.

A final manual replay of the self-scan's high framing heuristic found that the
loopback, token-bound
`POST /api/blind-arena/start` route had accepted simultaneous `Content-Length`
and `Transfer-Encoding`, returned `202`, and invoked start. The server now
rejects every `Transfer-Encoding`; duplicate, missing, or non-decimal
`Content-Length` for JSON bodies; and duplicate or nonzero framing on bodyless
arena routes. Every rejection sets `close_connection`. A raw-socket regression
received `400` and confirmed that no arena action was invoked. This was a
fail-closed HTTP request-framing defect in the local controller, not a
demonstrated exploit or VM, hypervisor, operating-system, container, or host
escape.

## Cancellation and reset

CLI Ctrl+C and the UI **Cancel** button request cancellation at a bounded step
boundary. A verified `cancelled` report is checkpointed; cancellation is
non-terminal and never success. Start/Resume continues from its learned state.
An abrupt second interrupt or host failure may stop before the current episode
is committed, in which case the last atomically verified checkpoint remains the
resume point.

Reset intentionally discards the learned state. In the UI, cancel first, wait
for the arena to stop, select **Reset/new**, and confirm the warning. The server
refuses reset while an episode is running. The CLI intentionally has no reset
flag or caller-selected state path. To create a new CLI arena, stop Attestor and
have the operator archive or remove the fixed checkpoint outside the arena;
the next invocation creates a new one. Preserve the old file first when it is
needed as evidence.

## Verification defects corrected

Adversarial verification found and corrected the following boundary defects
before the final evidence was accepted:

- reports are now bound to the state's exact `last_report`, before/after state
  commitments, episode-history chain, and reconciled action/knowledge counters;
- malformed reports and checkpoints fail closed without an uncaught verifier
  exception;
- custom explorer/cancellation callbacks and Event subclasses are rejected, and
  cancellation accepts only an exact standard `threading.Event`;
- the blind CLI now takes its exact allowlisted path before generic Attestor
  initialization, preventing ignored unrelated options or key/path reads; and
- UI cancellation, bounded request-body handling, terminal cleanup, and
  link/reparse checkpoint checks were hardened; and
- ambiguous HTTP request framing is rejected before dispatch, closes the
  connection, and cannot invoke an arena action.

## Explicit non-capabilities and limitations

The blind arena does not:

- attempt or demonstrate a real VM, hypervisor, OS, container, process,
  browser, Python, language-runtime, or kernel escape;
- run a shell, command, script, generated code, test target, plugin, exploit,
  proof-of-concept, or caller payload;
- accept or discover a target path;
- cause the explorer or simulation core to access the network or start a
  process; the existing UI wrapper still uses its authenticated loopback HTTP
  session;
- grant filesystem control beyond the controller's fixed checkpoint;
- delete important files, elevate privileges, change permissions, persist on a
  host, or weaken another Attestor authorization gate; or
- certify `runtime_lab.py`, the execution fabric, a container, VM, hypervisor,
  host, or product as secure or escape-proof.

Because the exercise is abstract and offline, it cannot observe hypervisor
patch level, firmware, device emulation, host configuration, network isolation,
side channels, or live exploitability. A synthetic success says only that the
opaque trace reached the compiled synthetic-outside state and that Attestor replayed
the associated proof correctly. A contained reference says only that its
compiled opaque actions were exhausted; neither conclusion generalizes to a
real isolation boundary.

## Final measured evidence

The normal fixed-objective run reached a replay-verified synthetic escape in 7
episodes and 54 total actions. Its final trace contained 6 steps and the exact
replay-derived reason was:

```text
The replayed opaque action resolved to a compiled abstract-policy alias whose target was synthetic outside.
```

The report artifact `blind-escape-arena-4.1.4-final-v2.json` has file SHA-256
`4135168f50c4b8e465d4f7e44ecd62b2cc259ba5b3d8b0376da84cffaa941bac`.
Its internal canonical report SHA-256 is
`a4e43e37010b1d1d4c694b36b74f063e490134295d0078e34985ef6b98dc4b1`,
and the corresponding controller checkpoint SHA-256 is
`c0eafd4c302722ca6d12157babfbaf9274100b0f1d652aa11fe26909008bf8d1`.
A hardened deterministic sweep of 2,000 generated seeds escaped for every seed;
the slowest required 13 episodes.

These values prove only internal consistency and deterministic replay of the
synthetic arena. In particular, the checkpoint hash is unkeyed: it detects
accidental inconsistency but does not authenticate the checkpoint against a
malicious writer running as the same account. Neither the normal run, browser
run, nor seed sweep can perform or prove a VM, hypervisor, operating-system,
container, or host escape. The consolidated release evidence is recorded in
`VERIFICATION_4.1.4.md`.
