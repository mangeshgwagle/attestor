# Attestor 4.1.4 release notes

Attestor 4.1.4 adds three sealed operating profiles, secondary evidence
adjudication, stronger worker/resource enforcement, profile-safe history, a
safe blind autonomous synthetic escape arena, and a current UI/CLI route. It
reuses the replay-verified 4.1.3 engines instead of
silently relabelling them; their identities remain visible inside the 4.1.4
envelope.

## Three variants

| Variant | Stable slug | Intended use | Coding snapshot files | Coding max/file | Coding snapshot total | Coding graph nodes | Public findings | Worker time | Worker memory | Concurrency |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Cockroach Janta Party | `cockroach-janta-party` | maximum analysis | 10,000 | 32 MiB | 256 MiB | 250,000 | 20,000 | 180 s | 1,536 MiB | 8 |
| South Park | `south-park` | balanced default | 6,000 | 3 MiB | 96 MiB | 180,000 | 8,000 | 120 s | 768 MiB | 4 |
| Gruppe Sechs | `gruppe-sechs` | lightweight/constrained | 3,000 | 2 MiB | 64 MiB | 120,000 | 4,000 | 60 s | 384 MiB | 2 |

### Cockroach Janta Party response language

Cockroach Janta Party alone uses `C3`, Attestor's custom evidence-dense advanced
technical response register. This is explicitly **not** an official CEFR level,
language-proficiency certification, or permission tier. It cannot increase the
strength of evidence or authorize an operation. South Park and Gruppe Sechs keep
the existing 4.1.3 response behavior.

The exact language policy is serialized inside the canonical variant profile,
so it changes and is protected by that profile's SHA-256 identity. Attestor also
replays it against `response_414`, the analyzer identity, structured Q&A, SARIF,
rendered text, and the workbench's verified result descriptor. There is no
request field that can promote another profile to C3; even a re-digested and
re-guarded mismatch fails semantic report verification.

### Cockroach Janta Party local artifact control

Cockroach Janta Party alone now exposes a default-deny local-control route for
an exact set of caller-supplied files. It supports content-free file inspection,
schema-only SQLite understanding, bounded lexical SQL classification, and
complete replacement previews. The authorization is short-lived, one-use,
in-memory, and bound to the canonical profile identity, local root, exact
relative paths and SHA-256 values, action, organization, issuer assertion,
purpose, and operation identity.

The intended TCS workflow starts with local file copies supplied by an
authorized TCS/Tata Consultancy Services custodian. That custodian may be the
user's uncle, but family relationship alone is not permission. Attestor records the
assertion and explicitly does not claim to verify the issuer's identity,
employment, ownership, legal authority, or confidentiality obligations.

Database understanding is deliberately non-operational:

- SQLite must be a checkpointed single-file snapshot without WAL, SHM, or
  journal sidecars. Attestor copies the exact authorized bytes to a private
  immutable read-only snapshot, hardens the connection, and reports schema
  objects, columns, indexes, and relationships without querying application row
  values.
- SQL text is never executed. Attestor performs bounded generic lexical
  classification of statement types, write/destructive intent, transaction
  ordering, and selected privileged-risk markers. This is not dialect parsing,
  database validation, or a connection to a database server.

File editing requires two independent CLI invocations. The preview-only run
returns `preview.preview_evidence_sha256`; the apply run must repeat the exact
request, permission confirmation, and separate apply confirmation while passing
that digest through `--cjp-preview-evidence-sha256`. Attestor re-hashes all evidence
and recomputes the preview before it issues the one-use apply authorization.
The digest binds target/backup root identities, the complete candidate, and
every before/after file hash independently of bounded display diffs. Eligible
writes use a fresh exclusive transaction backup directory, staged bytes,
root/stale-source guards, atomic replacement, final target verification, and
bounded rollback attempts whose failures remain visible.

Every apply transaction reports `cleanup_complete` and a bounded
`cleanup_errors` list. Backup, staging, rollback-stage, descriptor, and
cooperative-lock cleanup failures survive into both JSON and terminal-safe text.
If replacement already committed, the transaction remains truthfully `applied`
while the CLI returns a warning exit; cleanup trouble is never used to pretend
that the edit did not occur.

This route grants no TCS account, network, live-database, credential,
administrator/elevation, arbitrary shell/process, registry/service, persistence,
or drive-wide authority. It never executes supplied SQL, migrations, or target
code, and it refuses editing SQLite and artifacts with Attestor's blocked
executable/system suffixes. Exact schemas and commands are in
[`CJP_LOCAL_CONTROL_4.1.4.md`](CJP_LOCAL_CONTROL_4.1.4.md).

### Private sandbox escape-lab simulation

Cockroach Janta Party now has a sealed, session-only defensive escape exercise.
`escape_lab414.py` contains six fixed in-memory policy graphs: five contain one
planted authorization defect, and one is a contained reference. Attestor performs a
bounded deterministic breadth-first traversal, returns the exact abstract path
to `simulated-outside`, explains the compiled policy defect used by that path,
and provides a mitigation. Complete replay verification catches semantic report
tampering even when a caller recomputes the outer SHA-256.

This mode is not connected to `runtime_lab.py`, `security_lab41.py`, the
execution fabric, or an operating-system sandbox. Its simulation core accepts no
command, source, path, URL, payload, plugin, or arbitrary scenario. The core
starts no process, reads or writes no host file, uses no network, executes no
target code, and never attempts a real host, process, VM, container,
language-runtime, or kernel escape. The CLI/UI wrapper may start Attestor and
serialize requested output; those ordinary wrapper effects do not grant the
simulation any host authority. Selecting `--escape-lab` confirms only the
data-only simulation.

The satirical CJP deletion line has been removed, together with the
`cjp_satire` report block. Automatic deletion authority and probability are 0%
and are now stated through the lab's safety controls; no permission,
local-control, or deletion behavior changes. See
[`PRIVATE_ESCAPE_LAB_4.1.4.md`](PRIVATE_ESCAPE_LAB_4.1.4.md) for the scenarios,
controls, replay contract, and commands.

### Blind autonomous synthetic escape arena

`blind_escape_arena414.py` adds a second, deliberately separate abstract
exercise. Its objective is the exact constant `Escape`. The default local
explorer is not given the private graph, route, walkthrough, hidden token,
reason catalog, or any caller text. It receives only opaque observation/action
identifiers and the black-box knowledge learned from earlier attempts. The CLI
and UI accept no prompt, path, scenario, payload, model, arbitrary explorer,
seed, tool, target-execution, or network option for this mode.

The CLI mode is parsed before the generic Attestor parser initializes a brain,
persona, key files, or request routing. Its exact surface is
`--blind-escape-arena`, optional `--blind-escape-single-episode`,
`--format text|json`, and optional controller-side report `--out`. Positional
input, abbreviations, duplicates, unknown options, and unrelated project/key
paths fail without being read or silently ignored.

The public core rejects replacement explorer callbacks and callable
cancellation hooks before running them. Only the compiled deterministic
explorer and an exact standard cancellation Event are accepted, preserving the
in-memory no-command/no-network/no-file-effect simulation boundary.

Each episode is finite: the released default is eight abstract steps and the
core refuses more than 128. The controller atomically checkpoints the verified
state after every completed episode. The normal CLI and UI controllers impose
no overall arena deadline or lifetime episode ceiling; they resume bounded
episodes until a terminal synthetic result or cancellation. This absence of an
overall deadline does not remove the per-episode, state-size, report-size, graph,
action, or JSON-structure bounds.

The checkpoint is controller-only. Its path is not supplied to the explorer and
does not enter state, observations, episode reports, status responses, or
rendered text. The simulation core remains in-memory; the arena-state
controller's only mode-specific persistent file is its atomic checkpoint. A
cancelled episode is checkpointed as cancelled and is never promoted to
success. Starting again
resumes learned black-box knowledge; creating a new arena requires an explicit
reset of that fixed checkpoint.

Checkpoint/report loading and public verification are no-throw, bounded, and
fail-closed for malformed JSON values. Controller output cannot resolve to or
alias the private checkpoint, and checkpoint targets and parents are rejected
when link/reparse or non-regular metadata makes the local boundary unsafe.

An `escaped` status is public only after `verify_report()` replays every opaque
transition against the deterministically regenerated private graph and verifies
the hidden token, token digest, synthetic outside identity, trace digest, and
compiled reason. The verifier also binds the report to the state's exact current
last episode, binds its before/after state, reconciles action and knowledge
counters, and checks the episode-history commitment. The token is hidden from
the explorer and disclosed only in an escape proof. These SHA-256 commitments are unkeyed
consistency checks, not authentication against a malicious same-account writer.
This proves a synthetic policy transition, not a real exploit or containment
boundary. The arena cannot perform or prove a VM, hypervisor, operating-system,
process, container, host, browser, language-runtime, or kernel escape; it
provides no shell, command, code, arbitrary payload/path, network,
target-execution, deletion, elevation, persistence, or permission capability.
See [`BLIND_ESCAPE_ARENA_4.1.4.md`](BLIND_ESCAPE_ARENA_4.1.4.md) for the complete
state, proof, CLI/UI, cancellation, reset, and limitation contract.

“Coding snapshot” means the immutable snapshot consumed by the
`coding-static` worker; “Coding graph nodes” means that worker's semantic-graph
ceiling. Those four columns are not global inherited-analyzer limits.
Inherited 4.1.3 analyzers retain separately reported internal caps, and limit
hits or omitted coverage remain explicit gaps. The other resource fields are
also stage-specific as identified in the effective policy and worker
attestation.

The names are presentation labels. The security contract is identical for all
three:

- execution and repair require separate authorization;
- authorization is scope-bound and is never retained;
- network and target execution remain disabled by default;
- source/evidence SHA-256 binding and Truth Guard are mandatory;
- failures and tighter engine limits become explicit coverage gaps;
- no profile can enable automatic apply or weaken fail-closed behavior.

`variant414.py` stores each complete profile as an immutable release singleton,
computes a deterministic profile identity, and rejects mutated, cloned, forged,
case-changed, whitespace-changed, or unknown API/UI slugs. Interactive CLI
aliases are resolved before crossing the API boundary.

## Lower-hallucination finding adjudication

`adjudication414.py` adds a bounded, deterministic secondary layer:

- every supplied finding is preserved;
- classifications are `supported`, `contested`, or `insufficient`;
- natural-language similarity is not used to invent contradictions;
- mixed structured evidence and exact structured claims expose contradictions;
- ambiguous and unlinked evidence cannot affect classification;
- uncovered and unfamiliar high-risk areas stay visible;
- a cited source line is not automatically treated as proof of the diagnostic.

The strongest profile adjudicates the largest bounded subset. Any retained
finding outside that secondary boundary is reported as a gap, never silently
treated as confirmed or resolved.

## Inherited security and error-detection hardening

The final 4.1.4 audit also corrected defects in inherited engines that remain
reachable through the compatibility stack:

- Truth Guard 3.5 and 4.0 reject an unsigned `algorithm=none` ledger when a
  verification key is supplied, closing an authentication downgrade.
- Attestor 4.0 and Security Fabric apply their public limits only after global
  deterministic severity ranking, so late critical findings cannot be hidden
  behind earlier lower-severity rows.
- Redacted object keys use collision-safe identities, and excessively deep
  inputs return typed bounded errors instead of leaking `RecursionError`.
- Exact-file remediation no longer reads sibling files or widens to the parent
  project. Repository copy/hash/scan and test claims are refused until project
  scope is explicitly selected; unsupported exact files report partial
  coverage rather than clean.
- Omitted components and unavailable evidence remain explicit `not-run` or gap
  states rather than being counted as completed analysis.
- Truth Guard 3.5 validates the complete compatibility document under a local
  500,000-node boundary before sending a deterministic, digest-bound exact-field
  projection to the older 100,000-node independent validator. Full-source hash,
  exact source/view node counts, retained/omitted collection counts, and
  projection identity are replay-checked; the global legacy boundary was not
  raised.
- Attestor 3.0 applies the same fail-closed pattern to high-cardinality semantic
  evidence. Its projection preserves every finding identity, numeric derivation,
  coverage collection, and complete improvement proof required for filtering,
  while the full report remains bounded and digest-bound. Its JSON and classic
  renderers use the same local hard boundary.
- Attestor 4.1 converts a typed inherited Truth Guard compatibility failure into an
  explicit unavailable compatibility proof and visible gap instead of aborting
  the current analyzer. It does not relabel missing compatibility evidence as
  complete.
- Expected Attestor 4.1.4 CLI failures no longer disclose raw Python tracebacks.
  Text uses a bounded stderr message; JSON and SARIF return parseable
  failed-closed envelopes with no findings or claimed result.
- The 4.1.3 posture scanner rejects duplicate JSON object keys instead of
  accepting last-key-wins parsing, ignores detector regex-rule declarations as
  executable behavior, and requires a literal or numeric value before emitting
  the static nonce/IV indicator. The inherited Security Max compatibility scan
  also excludes regex-rule declaration lines from behavior findings.

The generated VS Code server bundle was restaged after these inherited changes,
and its manifest now binds the exact hardened detector bytes.

## Improved results and validation opportunities

The inherited Repair Director now defaults to including its selected complete
bounded candidate in the 4.1.4 review report when one is available. The new
`improvement_delivery_414` view distinguishes:

- a proposed review candidate;
- a statically qualified candidate;
- a scanner/build/test-verified dry run;
- a separately authorized applied result.

Static qualification is not called verification. Automatic apply remains off.

For contested and insufficient findings, Attestor creates a bounded
`validation_opportunities_414` plan. The plan may recommend compiler/sanitizer,
concurrency, dependency/security, regression, property, or fuzz-oriented
evidence collection. It contains no executable commands, starts no process,
uses no network, writes no target file, and consumes no authorization.

## Harder worker and report boundaries

- Worker request objects now have per-action field allowlists.
- Timeout, output, and memory limits are selected from the canonical profile
  and repeated in the worker attestation.
- The coding-static worker enforces the selected snapshot file/byte and
  semantic-graph node limits; those values do not replace the caps inside
  inherited analyzers.
- Inherited analyzers report their own internal caps, and a limit hit remains a
  coverage gap.
- Only configured worker actions are scheduled; omitted actions create explicit
  not-run coverage evidence.
- Public finding and UI-output ceilings are profile-specific.
- Windows' standard library still cannot provide the POSIX `RLIMIT_AS` hard
  memory boundary. That limitation is reported rather than hidden.
- Network denial in these Python workers is contractual, not a kernel network
  namespace. The report continues to state that gap.

## Profile-safe evidence history

Evidence records persist the exact variant slug and profile SHA-256. A comparison
is non-comparable when the identities differ or when only one side has a 4.1.4
identity. Such a comparison returns no added, persistent, or resolved lifecycle
deltas, preventing a light scan from claiming a stronger scan's findings
disappeared.

Historical profile identities may still be stored even if a later binary no
longer compiles that exact SHA. This preserves audit history while ensuring a
different SHA remains non-comparable.

## CLI, UI, and output

- `superattestor.py --attestor414 --variant <slug> TARGET` selects 4.1.4.
- `superattestor.py --escape-lab [--escape-scenario <compiled-id>]` runs the
  private, data-only CJP policy simulation. Text and JSON are supported; a
  simulated planted escape returns the ordinary finding/action exit `1`.
- `superattestor.py --blind-escape-arena` starts or resumes the fixed-objective
  blind arena. Text and JSON are supported. The default continues bounded
  episodes without an overall arena deadline; `--blind-escape-single-episode`
  runs one checkpointed episode for a resumable test. A dedicated early parser
  accepts only those mode flags, `--format text|json`, and optional report
  `--out`; it rejects all other arguments before generic initialization.
- Current natural maximum requests and `--improve` route to 4.1.4.
- `--attestor413` and `--attestor41` remain explicit 4.1.3 compatibility modes.
- `south-park` is the default when no variant is supplied.
- Variant selection is invalid for unrelated research, pathless computer,
  private escape-lab, blind-arena, and historical compatibility modes.
- Conflicting top-level modes fail instead of relying on parser precedence.
- JSON and SARIF bind the verified profile slug, display name, SHA-256, and
  adjudication identity. They also expose the profile-bound response-language
  tier and explicitly record that C3 is not an official CEFR claim.
- The local workbench validates exact slugs server-side and displays the variant
  from verified output rather than echoing the request. Its stdout ceiling and
  per-worker timeout come from the canonical profile. A distinct deterministic
  outer-process timeout leaves time for inherited analysis and final replay
  verification; browser-supplied timeout fields cannot override either limit.
- Escape-lab UI results are session-only and are not added to shared scan
  history. Its prompt/path input is disabled, and the visible boundary notice
  states that the simulation has no real-host authority.
- The separate blind-arena panel exposes **Start/Resume**, **Refresh status**,
  **Cancel**, and explicitly confirmed **Reset/new** controls. It has no prompt,
  path, payload, graph, walkthrough, or deadline field. The UI displays `Escaped - verified`
  only when the report, hidden token, exact trace, and terminal state agree; a
  raw status string cannot produce the success label.

Convenience launchers are included for each variant:

- `Run_Cockroach_Janta_Party.bat` / `.sh`
- `Run_South_Park.bat` / `.sh`
- `Run_Gruppe_Sechs.bat` / `.sh`

## Final verification evidence

The clean post-fix regression run completed as follows:

```text
Ran 1662 tests in 288.316s
OK (skipped=28)
```

The planted corpus contained 19 files and produced 48 total observations. All
42 expected planted bugs were detected (42/42). Skips are recorded as skips,
not passes.

The final strongest-profile bounded self-scan used 22 byte-for-byte
hash-identical release files, including the blind-arena core. Its
9,894,742-byte report replay-verified with zero skipped files, workspace errors,
or component errors. It retained 232 observations (1 high, 212 medium, and 19
low), classified every row as `insufficient`, and reported no critical,
supported, or contested finding. The report file SHA-256 is
`a25787b4d65b470d6a922ca89d276bdca5d52dfef51865e9f1ce39eb5c26b1c6`.
The one high row is the inferred framing-header co-occurrence heuristic at the
new rejection helper; manual and raw-socket checks prove the helper returns 400,
closes the connection, and invokes no arena action for those requests.

The final private escape-lab artifact is 11,343 bytes with file SHA-256
`4041fd37ed1c91cabad51546c4d20bcc640465c07970b1ecf982d14311d540a4`
and replay-verified report SHA-256
`8031234f1feb1af1cd4738028921645212e4f49bed6626e7100651d5d06feaa0`.
It contains six compiled scenarios: five planted simulated escapes and one
contained reference. Each simulated escape includes its exact abstract path,
compiled reason, and mitigation. All real-effect controls are false, including
`files_deleted`; deletion authority and probability are 0%.

The final normal blind-arena run escaped and replay-verified in 7 episodes and
54 total actions, with 6 steps in its final trace. Its exact compiled reason was:

```text
The replayed opaque action resolved to a compiled abstract-policy alias whose target was synthetic outside.
```

The artifact
`blind-escape-arena-4.1.4-final-v2.json` has file SHA-256
`4135168f50c4b8e465d4f7e44ecd62b2cc259ba5b3d8b0376da84cffaa941bac`,
internal report SHA-256
`a4e43e37010b1d1d4c694b36b74f063e490134295d0078e34985ef6b98dc4b1`,
and corresponding checkpoint SHA-256
`c0eafd4c302722ca6d12157babfbaf9274100b0f1d652aa11fe26909008bf8d1`.
Every arena in a hardened 2,000-seed sweep escaped; the maximum was 13
episodes.

The post-fix final-source authenticated loopback-browser run exposed zero
editable arena inputs, escaped and verified in 5 episodes and 37 attempts, and
logged zero browser console errors. These are synthetic replay results only;
they cannot perform or prove a VM, hypervisor, OS, container, or host escape. The checkpoint digest is
an unkeyed consistency value, not authentication against a malicious writer
with the same account access.

Blind-arena verification also found and fixed incomplete report-to-state,
episode-history, and counter binding; verifier/checkpoint exceptions on malformed
values; acceptance of custom explorer/cancellation callbacks or Event
subclasses; late generic CLI parsing that could initialize unrelated services or
ignore options; and UI cancellation, request-body, terminal-cleanup, and
link/reparse weaknesses. The final full-suite result above includes those
changes and their focused regressions.

A final manual raw-request replay of the self-scan's high framing heuristic
found that the loopback, token-bound
`POST /api/blind-arena/start` endpoint accepted simultaneous `Content-Length`
and `Transfer-Encoding`, returned `202`, and invoked start. This was a
fail-closed HTTP framing defect, not a demonstrated exploit or host/VM/container
escape. The server now rejects any `Transfer-Encoding`; duplicate, missing, or
non-decimal `Content-Length` for JSON bodies; and duplicate or nonzero framing
on bodyless arena routes; every rejection sets `close_connection`. A raw-socket
regression received `400` and confirmed that no arena action was invoked. The
full-suite and strongest-profile self-scan were rerun after this correction.

The actual running-state UI capture is
`.attestor414_verification/attestor-4.1.4-live-selfscan.png`. It is a real screenshot,
not a generated illustration. The 55,543-byte PNG has SHA-256
`2931ca649beb5b2ae0c667489b36b07adcbbf081011877d8e79e07bc20561ba0`.
The pictured job was cancelled after capture, so the image proves only the live
running UI state; completion evidence comes from the separately replay-verified
JSON report.

## Known limits

The profile resource fields are stage-specific, not an operating-system sandbox
for the whole inherited orchestrator. In particular, the standard-library
Windows build cannot apply the POSIX address-space limit, and parent-process
memory is not profile-limited. Cockroach Janta Party can therefore be slow and
memory-intensive on a very large source tree. The UI retains a separate bounded
outer-process timeout and rejects partial machine reports.

During release verification, a full strongest-profile scan of Attestor's entire
detector tree was stopped without accepting a report after the parent reached
about 4.1 GiB. A final hash-identical 22-file production scope did complete and
replay-verify. It retained 232 observations, classified all 232 as insufficient,
and reported no critical, supported, or contested finding. Its one high inferred
row points to the explicit framing-rejection helper and was not confirmed as a
defect; raw-socket verification proves the relevant requests fail closed.
Earlier false positives on detector rule declarations and dynamic nonce fields
were corrected and are absent from the accepted report. See
[`VERIFICATION_4.1.4.md`](VERIFICATION_4.1.4.md) for the exact evidence and
limitations.

## Compatibility and limitations

- Attestor remains a bounded analyzer, not a proof that code is correct, secure, or
  exploitable.
- Parser-derived and lexical observations retain their actual evidence labels.
- Static attack paths are hypotheses, not runtime exploit demonstrations.
- Dynamic testing, online research, and applying a repair remain separate
  permissioned operations.
- The blind arena is an abstract black-box state-machine exercise. It does not
  test the security of `runtime_lab.py`, the execution fabric, a container, a
  virtual machine, a hypervisor, or the host operating system, and it cannot
  establish that any of them is escape-proof.
- The 15,000-entry precision catalog is inherited; 4.1.4 does not advertise an
  inflated rule count as intelligence.
- SHA-256 provides deterministic integrity and identity. Optional HMAC provides
  shared-key authentication, not public-key non-repudiation.

Exact test and self-scan evidence is recorded in
`VERIFICATION_4.1.4.md`. The adjacent release manifest and `.sha256` file bind
the final package.
