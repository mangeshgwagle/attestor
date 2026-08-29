# Attestor 4.2 — verifiable code security assurance

> **Name.** This project was previously called Owen. It is now **Attestor**
> throughout: the product, the `attestor` command, the module names, and the
> `attestor.*` / `attestor-*` evidence schema namespaces.
>
> Because those schema strings are hashed into every report, the rename moved
> every content-addressed identity in the distribution — the analyzer build
> digest, all three profile identities, their report digests, and the bundled
> ranking-gate artifact's own digest. Those were all regenerated and re-pinned,
> and `detector/test_published_identities42.py` enforces that the documentation
> and the code agree. **Evidence produced by a pre-rename build will not verify
> against this one**, which is correct rather than unfortunate: the identities
> exist precisely so a report cannot silently claim to come from a different
> analyzer than the one that produced it.

Attestor 4.2 is an offline-first code and cybersecurity assurance toolkit.
Its default coding path combines deterministic static analysis, repository
graphs, correctness checks, supply-chain and secret-lifecycle evidence,
review-only improved results, conservative finding adjudication, and
source-bound reporting. It does not execute target code or contact the network
on that path. Non-coding Research Mode remains a separate, explicitly online
public-web workflow.

Attestor is not a distilled language model. It is primarily a deterministic
analysis and orchestration toolkit, and this distribution also ships a small
learned ranking-gate artifact. That bounded ranker is not a generative model;
optional model-backed generation remains a separately connected capability.

## New in Attestor 4.2

Attestor 4.2 adds two deliberately separate capability planes:

- **AttestorLang 4.2** is a deterministic, resource-bounded language and private
  bytecode VM. Its syntax and semantics borrow selected ideas from assembly,
  arithmetic shift-right operations, Haskell-style pure functions, Brainfuck's
  bounded tape, Malbolge's `CRAZY` and rotate operations, Shakespeare-style
  scenes and speech, fixed C++-like scalar types, and A1Z26 numeric assembly.
  These are documented inspirations, not claims of full source compatibility.
- **Owner Control 4.2** provides permission-first local inventory and bounded
  project/file discovery. It issues narrow, expiring, one-use capabilities
  bound to an exact plan and the strongest compiled profile. It does not grant
  blanket control, retained permission, arbitrary command execution, credential
  access, persistence, security disabling, or silent deletion.

The planes are intentionally isolated. AttestorLang has no filesystem, network,
process, dynamic-loading, foreign-function, driver, kernel, or host-control
primitive. Its so-called raw form is verified **ATVM bytecode**, never native
machine code executed by the host. A language program cannot mint or inherit an
Owner Control capability. This makes the requested power auditable instead of
turning a joke about “taking over” a PC into unsafe autonomous behavior.

The inherited `integrations/mc_asm` tool is separate from AttestorLang and ATVM.
Its default path does not execute generated native code. Native C++/x86
verification requires both `--verify` and the explicit
`--allow-native-execution` opt-in; neither flag adds any capability to ATVM.

The distribution version is 4.2. Its inherited analysis/report protocol stays
at 4.1.4 so prior evidence is not silently relabelled.

### Trusted Access

`detector/trusted_access.py` gates access to Attestor resources for explicitly
authorized, identity-verified people. It is default-deny and fail-closed:

- **Explicit authorization.** Access requires a signed grant naming the exact
  resource and scopes. There is no ambient permission, and a wildcard-only
  resource is refused at issue time.
- **Identity verification.** A grant is not a bearer token. It binds a
  subject's key fingerprint, and the caller must additionally answer a fresh,
  request-bound challenge to prove possession of that key. Holding a copy of a
  grant is not enough.
- **Least privilege.** Scopes are an allowlist and the request must be a
  subset; resources are bounded prefixes, so `repo:acme/*` cannot reach
  `repo:acme-evil`.
- **Revocation.** A signed, freshness-bounded revocation list is enforced
  before any allow. A stale list denies rather than silently permitting.
- **Audit logging.** Every decision, allow or deny, is appended to a
  hash-chained log; editing, deleting, or reordering any record breaks the
  chain and `AuditLog.verify` names the record where it broke.

It adds a gate and weakens nothing: no execution, no network, standard library
only. HMAC-SHA256 proves possession of a shared secret; it is not a hardware
root of trust, and keys are the operator's to manage and keep off the machines
they protect.

### Build divergence

`detector/build_divergence42.py` compares a source tree against the assembly
listings from its build and reports capabilities the artifact has that no source
file asks for -- a syscall, an `execve`, a socket, a privilege change, a
writable-executable section.

This closes a gap source review cannot close by itself. In the XZ-utils and
SolarWinds shape the repository is clean and every commit reviews fine; the
artifact that ships is not what the source describes. The divergence is not in
the source, so no amount of reading it will help.

Two capability sets are derived and differenced: the source side from
`semantic_graph41` imports and calls, the assembly side from Linux syscall
numbers, libc call targets and section flags. Source that legitimately declares
a capability silences the corresponding finding, because the expensive wrong
answer here is accusing a clean build.

It never compiles and never executes -- it reads a listing somebody else
produced, so the offline contract is unchanged. An unexplained capability is a
**review point with the exact line attached**, never a verdict: compiler
intrinsics, inlined libc and runtime startup stubs all introduce primitives the
source never wrote. The value is that the list is short and checkable.

```sh
python3 detector/build_divergence42.py ./src ./build/asm
```

### Reachability triage

`attack_surface413` already computed which sinks a discovered entry point can
statically reach. That evidence now flows back onto the findings themselves, so
a long findings list arrives ordered by whether an attacker can actually get
there. Each finding carries a `triage` block graded:

| Grade | Meaning |
|---|---|
| `reachable-from-unauthenticated-entrypoint` | a route reaches this sink with no observed authentication control |
| `reachable-behind-authentication-control` | reachable, but every discovered route crossed an auth control |
| `no-static-path-from-a-discovered-entrypoint` | entry points were found and none reached it |
| `reachability-unknown` | **no entry point was discovered, so nothing was learned** |

The last two are deliberately distinct. "No path found" is evidence; "no entry
point was found" is not, and a library or an unparsed framework must not be
quietly pushed down the queue. `summary.triage` rolls the grades up, and both
the grades and the roll-up are recomputed by `verify_report` rather than
trusted. A grade orders review effort only — `runtime_exploitability` stays
`unverified` on every finding, because nothing is executed.

### Inherited reliability fixes in 4.2

- **Behavior-equivalent Python masking.** The detector now avoids allocating a
  three-character slice at every source character while blanking Python strings
  and comments. An exact equivalence contract compares the previous algorithm
  on awkward constructs, source prefixes, and every shipped Python file; this is
  a performance and build-identity change, not a new rule or schema.
- **NIST Juliet archive compatibility.** Corpus preflight can skip an oversized
  member only when it is outside `/testcases/` and can never be selected.
  Selected testcase members retain their per-entry, aggregate, compression, and
  streamed-size boundaries.
- **Transactional legacy gateway ledger.** The separate local scan gateway now
  serializes ledger updates across threads, ledger instances, and local
  processes, rejects linked or replaced state paths, and uses unique, fsynced
  atomic stages with narrow Windows replacement retries.
- **Stable generated loopback services.** Generated HTTP services drain bounded
  rejected bodies, flush responses, validate readiness, and join request threads
  before closing their shared SQLite connection, preventing the observed
  Windows reset and shutdown races.
- **Explicit native verification opt-in.** The inherited `mc_asm` verifier runs
  native C++/x86 output only when both native-execution flags are present;
  AttestorLang remains interpreted ATVM data.

The exact analyzer build SHA-256 is
`27ea912e3441731d81ad6a709469b6c1543f7e6d558639075db5beb69515f70a`.
Its bound profile/report SHA-256 pairs are Cockroach Janta Party
`262e16abfdf436424b598b1cf5b78e58582f280587da4d82f2af3dc68468de00` /
`1da087e3ea127254fdfb71c977a2b4ee23ab582d00140eb0c4cb234c1a6e178d`,
South Park
`1fbc48a77fab1c7ad52acfb4bca5ed9d031c7633d75341bdd421acf751b591a7` /
`196e7e50858c05d6d20b2d54932b1eb7cbba59cd4a908e3df12c77ff529645e2`,
and Gruppe Sechs
`7b25ea99bd9f118faf6ea6dd23798dc946946c1d7409ef07c8fbb6016a0c1150` /
`5958c5e0747c77b7a558602c42d0b6888b16e2bab106cb326aba7926a11bec11`.
These identities changed with the exact detector bytes; their analysis and
report schemas remain 4.1.4.

### Unified command line (safe phase one)

Attestor 4.2 now has one narrow entry point for the reviewed local capabilities.
It preserves the directory from which it is called, so relative scan and
AttestorLang paths are resolved from the operator's working directory.

On Windows:

```powershell
$attestor = (Resolve-Path .\attestor.ps1).Path
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor --help
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor status
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor scan detector\test_version42.py --format json
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor lang check integrations\attestorlang\examples\tour.owl
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor control policy --format json
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor pharma show boric_acid
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor lab self-test --format json
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor assure . --format json
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $attestor verify
```

On Unix-like systems:

```sh
./attestor.sh --help
./attestor.sh status
./attestor.sh scan detector/test_version42.py --format json
./attestor.sh lang check integrations/attestorlang/examples/tour.owl
./attestor.sh control policy --format json
./attestor.sh pharma show boric_acid
./attestor.sh lab self-test --format json
./attestor.sh assure . --format json
./attestor.sh verify
```

The phase-one `scan` command always disables compiler/tool subprocesses and the
scan cache. It rejects linked or reparse-point targets instead of following
them outside the requested scope. `lang` and `control` retain their existing
argument contracts; the wrapper never adds an Owner Control permission or
confirmation value. `verify` audits this distribution in place and cannot
create or replace an archive. The Windows launcher is PowerShell rather than a
batch file so argument boundaries and shell metacharacters are preserved.
The shown execution-policy override applies only to that child PowerShell
process and does not change the machine or user policy. Where local scripts are
already allowed, invoke `.\attestor.ps1` directly.

`pharma` opens the exam-oriented chemistry reference. Use `pharma list
preparations` for its worked substances, `pharma teach NAME` for the complete
answer plus its reusable reasoning and recall prompt, `pharma show NAME` for a
principle-to-storage answer, `pharma why NAME` for the reusable reasoning,
`pharma derive NAME` for an unseen-substance checklist, `pharma recall 5` for
self-testing, and `pharma coverage` to see the current syllabus boundary. The
reference deliberately omits invented monograph quantities and does not claim
coverage of a board until its prescribed syllabus and edition are supplied.
See [`integrations/attestor_chem/README.md`](integrations/attestor_chem/README.md) for
the answer-building method and the process for adding verified board coverage.

`lab` is a zero-incremental-cost, offline enterprise-security experiment. Its
first release accepts only the bundled synthetic fixtures: `lab benchmark`
measures detector confusion counts and per-CWE precision/recall/F1, `lab
isolation` runs two synthetic tenants and checks that their evidence remains
separate, and `lab self-test` runs both. Reports bind relative input paths and
file hashes to redacted findings and a deterministic report digest; they do
not contain source snippets or absolute source paths. The lab uses only the
Python standard library and Attestor's local detector. It performs no network
request, target-code execution, compiler invocation, package installation,
telemetry, or remediation. It is an experimental measurement harness, not an
independent benchmark, OS sandbox, enterprise authorization system, TCS
product, or permission to inspect any organization's material. See
[`experiments/enterprise_security42/README.md`](experiments/enterprise_security42/README.md).

`assure DIRECTORY` is an experimental, read-only repository assurance pass.
It accepts exactly one directory and emits either deterministic text or JSON;
the unified wrapper does not expose additional engine flags. The command
performs static inspection only. The wrapper starts exactly one fixed, isolated Python
child for the bundled assurance engine; that engine does not execute target
code or start target, build, compiler, or other tool subprocesses. It also does
not contact the network or modify the target. Python's `-I` option isolates
Python imports and environment influence; it is not an operating-system or
system-call sandbox. Input evidence is bound to the bytes captured and checked
for each file, and non-concurrent symbolic links and reparse points are refused.
This is not an atomic whole-tree snapshot or an adversarial containment
boundary; hostile concurrent mutation of the inspected root is outside the
current guarantee.

The fixed assurance profile composes Attestor's bounded core rules, Java cross-file
taint seed, Python/JavaScript semantic graph, static web/API attack-surface
analysis, and the security-posture pass for secrets, Docker, Kubernetes,
Terraform, GitHub Actions, IAM, cryptography, binary indicators, dependency
manifests, and SBOM inventory. It captures at most 2,000 files, 128 KiB per
file, and 16 MiB total so no downstream analyzer silently sees a smaller input.
Findings include content-bound, preview-only remediation advice. Advice is
never applied and is never called verified.

The command uses only bundled Python code and makes no paid-provider or network
service request. External provider and network-service charges are therefore
USD 0; local hardware, electricity, operating-system, storage, and staff costs
are unmeasured rather than falsely reported as free. JSON reports contain
relative paths and full-file hashes. They contain no source snippets, but those
paths and hashes are sensitive metadata—not encryption or redaction—and should
be access-controlled.

Run `assure` only on code the operator owns or has explicit permission to
inspect. It sends no traffic, and its presence is not authorization to scan
Tata Consultancy Services (TCS), client, third-party, or production systems.
A complete clean report exits
`0`, completed findings exit `1`, invalid input exits `2`, incomplete coverage
exits `3`, and an operational or self-verification failure exits `4`. The
comprehensive profile needs history, provenance, and dependency-lock evidence;
when any of that evidence is unavailable, `assure` reports incomplete and exits
`3` even if its current-snapshot checks find no issue. The phase-one public CLI
intentionally accepts no external metadata to fill those gaps, so exit `3` is
the expected honest result for ordinary snapshot-only directories rather than
a command malfunction. Exit `0` is reserved for a genuinely complete clean
report and should not be assumed reachable through this narrow profile today.

Exit status `0` means a complete clean result, `1` means completed findings or
policy violations, `2` means invalid usage or input, `3` means an incomplete or
intentionally gated operation, and `4` means an operational failure. The
`review`, `fix`, `pro`, and `ui` commands are intentionally gated in
this phase and exit `3`; their existing standalone launchers are unchanged.

### Start the individual 4.2 tools

On Windows:

```powershell
.\Run_AttestorLang.bat check integrations\attestorlang\examples\tour.owl
.\Run_AttestorLang.bat run integrations\attestorlang\examples\tour.owl
.\Run_Owner_Control_4.2.bat --help
.\Run_Owner_Control_4.2.bat policy --format json
```

On Unix-like systems:

```sh
./Run_AttestorLang.sh check integrations/attestorlang/examples/tour.owl
./Run_AttestorLang.sh run integrations/attestorlang/examples/tour.owl
./Run_Owner_Control_4.2.sh --help
./Run_Owner_Control_4.2.sh policy --format json
```

The Owner Control wrapper never adds `--permission`; the operator must first
build and review an exact plan, then explicitly confirm its SHA-256 for that
one run. See [`OWNER_CONTROL_4.2.md`](OWNER_CONTROL_4.2.md). AttestorLang's syntax,
bytecode, resource bounds, and examples are in
[`integrations/attestorlang/README.md`](integrations/attestorlang/README.md) and
[`integrations/attestorlang/SPEC_4.2.md`](integrations/attestorlang/SPEC_4.2.md).

The current distribution retains the three sealed analysis profiles introduced
by Attestor 4.1.4:

- **Cockroach Janta Party** (`cockroach-janta-party`) is the most capable and
  highest-resource profile. It alone uses Attestor's custom **C3** response-language
  tier.
- **South Park** (`south-park`) is the balanced default.
- **Gruppe Sechs** (`gruppe-sechs`) is the lightest profile for constrained
  systems and quicker review.

The names are satirical; the reports are precise. Every report carries the
canonical profile, its SHA-256 identity, the components actually scheduled,
the exact stage-specific budgets, and any work omitted by that tier. A profile
may reduce depth or resources, but it cannot weaken authorization, offline
defaults, evidence binding, fail-closed behavior, repair permission, or Truth
Guard.

`C3` is an Attestor-specific name for an evidence-dense advanced technical response
register. It is not an official CEFR level, proficiency certification, or claim
about universal comprehension. The label changes neither evidence strength nor
authority. South Park and Gruppe Sechs retain the established `response41`
behavior. The canonical language policy is included in the profile SHA-256 and
replay-checked in the report, analyzer identity, structured Q&A, SARIF, rendered
text, and verified UI result label; callers cannot request or inject C3 into a
smaller profile.

The `max_files`, `max_file_bytes`, and `max_total_bytes` profile fields bound
the `coding-static` worker's immutable source snapshot. `max_graph_nodes`
bounds that worker's semantic graph. They are not global ceilings for every
inherited analyzer. Inherited 4.1.3 analyzers retain their own internal caps,
report those caps separately, and surface limit hits or omitted coverage as
gaps.

See [`RELEASE_NOTES_4.2.md`](RELEASE_NOTES_4.2.md) for the current change
record and [`VERIFICATION_4.2.md`](VERIFICATION_4.2.md) for its evidence. The
inherited 4.1.4 analyzer is documented in
[`RELEASE_NOTES_4.1.4.md`](RELEASE_NOTES_4.1.4.md). Attestor 4.1.3 remains an
explicit compatibility mode documented in
[`RELEASE_NOTES_4.1.3.md`](RELEASE_NOTES_4.1.3.md); `--attestor413` and `--attestor41`
retain that historical behavior.

## Current 4.1.4 capabilities

- **Sealed, testable variants.** `variant414.py` defines immutable, strictly
  tiered component choices and stage-specific concurrency, coding-snapshot,
  coding-semantic-graph, finding, worker-time, worker-memory, output,
  improvement, and validation-plan ceilings. API and UI boundaries accept only
  exact stable slugs; friendly aliases are CLI-only.
- **Conservative error adjudication.** `adjudication414.py` preserves every
  supplied finding and labels it `supported`, `contested`, or `insufficient`.
  Source presence alone is not treated as proof of a diagnosis. Structured
  contradictions, unlinked evidence, uncovered high-risk areas, and unfamiliar
  runtime behavior remain explicit.
- **Improved result with proof labels.** When a supported mechanical repair is
  available, the Repair Director can include a complete bounded improved result
  for review. It is not called verified until separately authorized scanner,
  build, and test gates pass, and it is never applied automatically.
- **Actionable uncertainty.** Contested and insufficient findings receive
  bounded validation opportunities. Attestor emits no commands and performs no
  execution while creating that plan; authorization is still required later.
- **Enforced worker limits.** Worker payload fields are action-allowlisted.
  Profile-specific wall time, memory, output, and concurrency ceilings are
  stage-scoped and attested. The snapshot file/byte and semantic-graph node
  ceilings apply to the coding-static worker. Inherited analyzers retain and
  report their own caps. Platform limits that cannot be kernel-enforced remain
  coverage gaps.
- **Profile-safe evidence history.** Runs with different profile identities are
  non-comparable, so a lighter scan cannot falsely claim a stronger scan's
  findings were resolved.
- **Verified profile responses.** Text, JSON, SARIF, and the local UI show a
  variant only after its selection digest, effective configuration,
  adjudication, projection layout, response-language policy, and fresh Truth
  Guard chain verify. C3 is displayed only for a verified Cockroach Janta Party
  profile.
- **Bounded high-cardinality evidence.** Large inherited compatibility reports
  are validated under version-local hard limits, reduced to deterministic
  exact-field views for the older 100,000-node independent validator, and bound
  back to the complete source digest. Finding identities and proof fields needed
  for public filtering remain present; the older global boundary is not raised.
  Expected CLI boundary failures return bounded text or parseable JSON/SARIF
  failure output without a Python traceback.
- **Permission-bound local artifact control.** Cockroach Janta Party alone can
  inspect an exact set of local files, perform schema-only understanding of
  exact SQLite snapshots, lexically classify supplied SQL files, and preview
  complete replacement bytes. A change is applied only in a second invocation
  that repeats the permission confirmation and supplies the exact
  `--cjp-preview-evidence-sha256` from the prior preview. Application uses an
  exclusive backup directory, stale-file guards, atomic replacement, and
  reported rollback attempts.
- **Private escape-lab simulation.** Cockroach Janta Party can traverse six
  compiled in-memory policy graphs, identify planted authorization defects,
  report the exact synthetic path and reason, and recommend a mitigation. This
  mode executes no caller code or command and never attempts a real host,
  process, VM, container, language-runtime, or kernel escape.
- **Blind autonomous synthetic escape arena.** A separate fixed-objective
  exercise gives a local black-box explorer only opaque observation/action IDs
  and its accumulated knowledge, never a graph, path, walkthrough, or payload.
  Each episode is bounded, learned state is
  atomically checkpointed by the controller, and the default controller resumes
  episodes without an overall arena deadline until a replay-verified synthetic
  escape or cancellation. It accepts no caller prompt, path, scenario, payload,
  model, tool, execution, or network option.

## Private sandbox escape lab

The escape lab is a deliberately abstract security exercise, not an exploit
runner. Five compiled cases contain a planted policy inconsistency; one sealed
reference case remains contained. Equal inputs produce byte-identical evidence,
and report verification reconstructs the complete result instead of trusting a
digest alone.

```sh
python3 detector/superattestor.py --escape-lab --format text
python3 detector/superattestor.py --escape-lab --escape-scenario contained-reference --format json
```

Selecting the mode confirms only the pure in-memory simulation. It provides no
real escape, filesystem, deletion, process, shell, network, target-code,
elevation, persistence, or permission authority. The presentation-layer joke
about CJP "accidentally" deleting an important file has been removed; the
enforced automatic deletion authority is and always was **0%**, and the report
now states that directly through its safety controls. The complete scenario and
evidence contract is documented in
[`PRIVATE_ESCAPE_LAB_4.1.4.md`](PRIVATE_ESCAPE_LAB_4.1.4.md).

## Blind autonomous synthetic escape arena

The blind arena is distinct from the planted-path escape lab. Its objective is
the exact constant `Escape`; the CLI and UI cannot replace it. A newly generated
arena contains a private abstract graph, but the explorer receives only the
current opaque observation ID, available opaque action IDs, and the black-box
knowledge accumulated by earlier attempts. It receives no graph, planted route,
walkthrough, hidden token, reason catalog, caller prompt, path, command, code,
URL, or payload.

```sh
python3 detector/superattestor.py --blind-escape-arena --format text
python3 detector/superattestor.py --blind-escape-arena --format json
python3 detector/superattestor.py --blind-escape-arena --blind-escape-single-episode --format json
```

This mode enters a dedicated parser before the generic Attestor CLI, brain, persona,
key-file reads, or request router. Its exact allowlist is
`--blind-escape-arena`, optional `--blind-escape-single-episode`,
`--format text|json`, and optional controller-side report `--out`. Positional
text, abbreviations, duplicates, and every unrelated option fail before arena
dispatch; rejected key and project paths are not read.

The normal CLI invocation resumes the controller-owned checkpoint and keeps
running finite episodes until a terminal synthetic result or user cancellation;
there is deliberately no caller-controlled episode count or overall arena
deadline. `--blind-escape-single-episode` runs exactly one bounded episode and
returns a resumable result. Pressing Ctrl+C requests cancellation at a bounded
step boundary; cancellation is checkpointed and never reported as success.

An `escaped` result is accepted only after the exact trace replays against the
private deterministic graph and its hidden token, token digest, synthetic
outside identity, compiled reason, current-state counters, persistent knowledge,
and episode-history commitment all agree. The core refuses custom explorer or
callable cancellation hooks; only its deterministic explorer and an exact
standard cancellation Event are permitted. That proves only the abstract
transition represented by that checkpoint. Its unkeyed SHA-256 commitments do
not authenticate the checkpoint against a malicious same-account writer. It is
not evidence of, and cannot perform or prove, a real VM, hypervisor,
operating-system, process, container, host, Python, browser, or kernel escape.
It grants no shell, network, target-execution, filesystem, deletion, elevation,
persistence, or permission capability. The controller may read and atomically
write its private checkpoint; the simulation core itself performs no file
access, and the checkpoint path is never placed in an explorer view, state,
report, status response, or rendered result. See
[`BLIND_ESCAPE_ARENA_4.1.4.md`](BLIND_ESCAPE_ARENA_4.1.4.md) for the complete
contract, UI lifecycle, reset behavior, and limitations.

Final release evidence reached a replay-verified synthetic escape in 7 episodes,
54 total actions, and a 6-step final trace. The exact reason was:

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
All 2,000 deterministic seed-sweep arenas escaped, with a maximum of 13
episodes. The unkeyed checkpoint hash is a consistency check, not authentication
against a malicious same-account writer.

Adversarial review fixed incomplete report-to-state/history/counter binding,
made malformed report/checkpoint verification no-throw and fail-closed, rejected
custom callbacks and non-exact cancellation Events, moved the blind CLI behind
an early exact allowlist, and hardened UI cancellation, request-body, and
link/reparse handling.

A final manual HTTP replay of the self-scan's high framing heuristic found one
additional fail-closed hardening defect:
the loopback, token-bound `POST /api/blind-arena/start` route accepted a request
containing both `Content-Length` and `Transfer-Encoding`, returned `202`, and
invoked start. Attestor now rejects every `Transfer-Encoding`; duplicate, missing,
or non-decimal `Content-Length` on JSON bodies; and duplicate or nonzero body
framing on bodyless arena routes. Every rejection sets `close_connection`. A
raw-socket regression received `400` and proved that no arena action was invoked.
This was an HTTP request-framing boundary defect, not a demonstrated exploit or
VM, hypervisor, OS, container, or host escape.

## Offensive Lab 4.2 (experimental)

`detector/offensive_lab42.py` bundles ten bounded offensive-security
exercises under one offline CLI, and `detector/offensive_fuzz42.py` adds an
authorization-gated local mutation fuzzer. The house contract applies without
exception: no network, no sockets, no subprocesses; operator-supplied material
or bundled synthetic simulations only; every result is labeled evidence for
review and never a claim that any real, third-party, or production target is
exploitable. Exit codes follow the distribution convention.

```sh
python3 detector/offensive_lab42.py self-test
python3 detector/offensive_lab42.py redos --pattern "(a+)+$"          # deterministic worst-case input synthesis + step-counted blowup proof
python3 detector/offensive_lab42.py jwt --token TOKEN --action crack  # decode | none | crack | confusion (HS256, operator tokens only)
python3 detector/offensive_lab42.py ecdsa-recover --demo              # nonce-reuse private-key recovery (secp256k1 demo or supplied r,s,z vectors)
python3 detector/offensive_lab42.py template-scan page.html           # XSS/SSTI interpolation-context classification with payload candidates
python3 detector/offensive_lab42.py ssrf-check --url URL --allowlist h1,h2   # static allowlist-bypass reasoner; nothing is contacted
python3 detector/offensive_lab42.py arena --scenario confused-deputy  # synthetic policy-graph arenas (also csrf-binding); --with-fix shows the patched policy deny
python3 detector/offensive_lab42.py padding-oracle                    # in-memory CBC padding-oracle simulation over a bundled Feistel cipher
python3 detector/offensive_lab42.py gadget-chain                      # deserialization gadget chains over synthetic class-call graphs
python3 detector/offensive_lab42.py poc-verify PLAN.json  # PoC sketches against bundled fixtures (sqli/xss/cmd) only

python3 detector/offensive_fuzz42.py --target-module m.py --target-entry parse_bytes   # exits 3 (gated) ...
python3 detector/offensive_fuzz42.py --target-module m.py --target-entry parse_bytes \
    --iterations 10000 --seed 0                            # ... until explicitly authorized
```

The ReDoS synthesizer counts steps with its own deterministic reference
backtracking engine, so its evidence is reproducible rather than a wall-clock
claim. The fuzzer executes exactly one caller-named callable from a
caller-named module file, hard-capped at 200,000 iterations and 60 seconds,
with fixed-seed reproducibility and greedy crash minimization; it is refused
outright without `--authorize-local-execution`. Tests:
`python -B -m unittest test_offensive_lab42` from `detector/`.

## Purple Team 4.2 and offline feed tooling

Three companion modules close the loop from offense to defense:

- **`detector/purple_team42.py`** — MITRE ATT&CK mapper (curated subset),
  Sigma-rule emitter (JSON-shaped Sigma), rule-replay verifier (every rule
  must fire on its lab attack artifact *and* stay silent on bundled negative
  events before it ships), detection-gap scorer.
  `python detector/purple_team42.py self-test`.
- **`detector/cve_matcher42.py`** — dependency inventory (requirements*.txt,
  package.json, package-lock.json) versus an operator-supplied NVD-style JSON
  feed or the bundled sample. Inconclusive version comparisons are surfaced,
  never guessed. `python detector/cve_matcher42.py scan DIR --feed nvd.json`.
- **`detector/source_hardening42.py`** — Trojan Source bidi-character
  detection (CVE-2021-42574 shapes), mixed-script identifier heuristics
  (CVE-2021-42643 shape), and entropy-scored secret candidates with redacted
  output. `python detector/source_hardening42.py FILE... [--checks ...]`.

All three are offline, stdlib-only, deterministic, and follow the house exit
codes. Tests: `python -B -m unittest test_purple_team42` from `detector/`.

## ChainForge 4.2

`detector/chainforge42.py` composes exploit chains as pathfinding over a
declared capability graph: nodes carry `requires`/`grants` capability sets,
severity, technique tags, and evidence digests; enumeration admits a hop only
when its requirements are already held, so chains model earned access rather
than wishful edges. Ranking is an explicit linear form
`score = 0.35*impact_reach + 0.25*auth_bypass_density + 0.20*severity_mass
+ 0.10*brevity + 0.10*novelty`, reported term by term. Node importance solves
the linear system `x' = 0.85*(Mᵀx) + 0.15*s` by power iteration in 1e6-scaled
fixed-point integers, so every report replays byte-identically.

```sh
python3 detector/chainforge42.py rank --demo        # bundled SSRF-to-exfiltration demonstration graph
python3 detector/chainforge42.py rank --graph G.json
python3 detector/chainforge42.py centrality --demo
python3 detector/chainforge_kernel42_check          # see below
```

The companion directory `detector/chainforge_kernel42/` ships the same
fixed-point kernels as reviewed artifacts in the inherited `mc_asm` style:
a hand-written x86-64 listing (`dot5_q16`, `saxpy_q16`, `blend_seed`),
a C++ self-check, and the shared Q16 constant table. The analysis path never
loads or executes them; `python3 detector/chainforge42.py kernel-check`
performs structural verification of the listing and, only when a C++
toolchain is present and this explicit gate is invoked, compiles-and-runs the
C++ check once. Tests: `python -B -m unittest test_chainforge42` from
`detector/`.

## Ranking-Gate Trainer 4.2

`detector/rankgate_trainer42.py` trains Attestor's small learned ranking
gate by perceptron error correction over five bounded finding features.
"Punishment" is the classical update rule applied only on mistakes —
`w <- w - eta*x` for a false positive, `w <- w + eta*x` for a false negative,
silence when correct — and every punishment is appended to a SHA-256
hash-chained ledger that `verify-ledger` re-walks, naming the first broken
record after any edit or reorder. Training runs in 1e6-scaled fixed-point
integers; identical data yields byte-identical model artifacts.

```sh
python3 detector/rankgate_trainer42.py demo          # bundled corpus: converges, 100% accuracy
python3 detector/rankgate_trainer42.py train --dataset findings.jsonl --out gate.json
python3 detector/rankgate_trainer42.py score --model gate.json --finding 0.9,0.8,0.9,0.7,0.85
python3 detector/rankgate_trainer42.py verify-ledger ledger.json
```

This is a bounded linear ranker, not a generative model; it claims nothing
beyond its measured accuracy. Tests: `python -B -m unittest
test_rankgate_trainer42` from `detector/`.

## Triage kernel in pure assembly

`detector/triage_kernel42/triage_kernel_x86_64.asm` implements the
exploitability-triage engine entirely in x86-64 (NASM syntax, Win64 ABI):
a fixed-point Q16 dot product over finding features plus the band
classifier with the KEV escalation rule. The source assembles to a
2 KB DLL (`triage_kernel.dll`) and every triage computation executes
inside it; `triage_asm42.py` is only a ctypes loader and
`test_triage_asm42.py` verifies the machine code against independent
integer arithmetic.

```sh
cd detector\triage_kernel42 && build.cmd          :: nasm + link -> triage_kernel.dll
python -B -m unittest test_triage_asm42           :: from detector/
```

Grades: `0 invalid-input, 1 theoretical-only, 2 chained-only,
3 exploitable-with-preconditions, 4 readily-exploitable`; a nonzero KEV
flag (actively exploited in the wild) forces at least grade 3. The binary
executes no target code and contacts nothing.

## Offense stack 4.2

Three additions complete the reviewed offensive surface:

- **`detector/poc_writer42.py`** — turns finding kinds into runnable,
  digest-stamped attack scripts (ReDoS trigger, JWT alg=none forgery, SQLi
  tautology requester, command-chaining, XSS context payloads). Every
  emitted file carries an AUTHORIZED TESTING ONLY header.
  `python detector/poc_writer42.py generate --kind sqli --target http://host/path`.
- **`detector/recon_net42.py`** — TCP connect scanner over operator-named
  targets only. Runs directly (authorization checkboxes removed at operator request); CIDRs are
  capped at /24-equivalents; connect + one short banner read, nothing else.
  `--selftest` verifies against a live loopback listener.
- **`detector/pcap42.py`** — offline capture inspection: cleartext HTTP/FTP
  credentials, DNS tunneling shapes (long high-entropy labels), and
  low-jitter beaconing detection via interval statistics. Reads files;
  never opens sockets. `python detector/pcap42.py capture.pcap`.

Tests: `python -B -m unittest test_offense_stack42` from `detector/`.

## Rung 4: the campaign conductor

- **`detector/active_scan42.py`** — live-fire web probing for explicitly
  authorized targets : reflected-marker,
  SQL-error, boolean-tautology baseline-diffing, command-echo, traversal
  signatures, and security-header audit. Hard request budget, fixed delay;
  every result is a `candidate` with captured evidence.
- **`detector/pilot42.py`** — one scoped engagement, end to end:
  recon -> active probing -> triage grading by the pure-assembly kernel ->
  ChainForge graph auto-built from findings (earned-ladder capabilities) ->
  optional PoC writing -> digest-pinned report. Scope enforcement is
  structural: hosts outside the declared IP/CIDR scope are refused before
  any packet moves; DNS names are outside the v1 contract.

```sh
python detector/active_scan42.py --url http://127.0.0.1:8787/
python detector/pilot42.py selftest
python detector/pilot42.py engagement.json
```

Engagement config: `{"scope": ["192.0.2.0/29"], "ports": "common",
"active_scan": true, "probe_all": false, "write_pocs": null}`.

Tests: `python -B -m unittest test_pilot_stack42` from `detector/`.

## Power stack 4.2: discovery engines

The three capabilities that move Attestor from "finds known shapes" to
"discovers unknown vulnerabilities":

- **`detector/coverage_fuzz42.py`** — AFL-style coverage-guided fuzzing for
  Python targets via `sys.settrace`: inputs reaching new lines join the
  corpus and drive mutation. Fixed seed reproduces the corpus evolution and
  crash set byte-for-byte.
- **`detector/concolic42.py`** — bounded concolic path explorer. Statically
  extracts guard forms (`len` comparisons, byte equality, `startswith`,
  including under `not`) from a target's AST, falsifies every guard to
  drive execution down the deep path, then enumerates alternates by taking
  exactly one guard at a time. Explicitly not a general SMT solver.
- **`detector/crashforge42.py`** — the crash-to-exploit pipeline:
  coverage fuzzing -> minimization -> exception-taxonomy classification ->
  severity grading by the pure-assembly triage kernel -> standalone
  reproducer scripts -> digest-pinned report.

```sh
python detector/coverage_fuzz42.py --target-module m.py --target-entry parse \
   
python detector/concolic42.py --target-module m.py --target-entry guarded \
   
python detector/crashforge42.py --target-module m.py --target-entry parse \
    --write-dir pocs
```

Tests: `python -B -m unittest test_power_stack42` from `detector/`.

## Access-control stack 4.2 (language-agnostic)

- **`detector/bola_hunter42.py`** — graph-aware broken-access-control
  differential engine: baseline-replays User A's captured traffic to learn
  which object ids belong to whom, then replays each request under User B
  (and optionally anonymous), classifying `same-content-wrong-principal`
  IDOR candidates against protected controls. Pure HTTP layer, so it tests
  backends in any language.
- **`detector/proxy42.py`** — loopback Match & Replace proxy with ordered
  header/body/URL rewrite rules plus Autorize-style live differential
  replay: every request is logged to a JSONL ledger (consumable by the BOLA
  hunter) and re-sent under swapped credentials, flagging divergences in
  real time. Plain-HTTP upstreams only in v1; no TLS interception, stated
  rather than faked.
- **`detector/universal_fuzz42.py`** — language-agnostic crash-feedback
  fuzzer over ANY executable (`--command "./target @@"` or `--stdin`):
  subprocess harness with sanitizer/panic/assert signature classification,
  dictionary-token mutation, and the shared minimization kernel. Pair with
  coverage_fuzz42 when the target is Python.

```sh
python detector/bola_hunter42.py --log session-a.jsonl --url http://host \
    --config sessions.json
python detector/proxy42.py --upstream http://target --ledger capture.jsonl \
    --rules rules.json --autorize-config sessions.json
python detector/universal_fuzz42.py --command ./fuzz_target @@ \
    --seeds PW --tokens 50574e
```

Tests: `python -B -m unittest test_access_stack42` from `detector/`.

## Esoteric engine + experimental framework

- **`detector/malbolge42.py`** — reference-model classic Malbolge engine
  (trit words, crazy/rotate ops, self-modifying stream) with an obfuscation
  analyzer: execution tracing, cycle detection, step-budget classification,
  self-modification counting. Registers `fuzz_entry` as a callable target
  for the coverage/universal fuzzers. Labeled honestly: constants follow
  the commonly published tables.
- **`detector/msf_lite42.py`** — experimental Metasploit-shaped framework:
  module registry (`aux.http_headers`, `aux.jwt_none`,
  `exploit.sqli_tautology`, `payload.exec_marker`), authorized-target
  runtime confirmation with digest-pinned sessions, and an explicit refusal
  list (no shells, no persistence, no evasion) enforced by omission.
  Payload surface is deliberately limited to exec-marker proof.

```sh
python detector/malbolge42.py program.mb
python detector/msf_lite42.py list
python detector/msf_lite42.py run --module exploit.sqli_tautology \
    --opts "{\"url\":\"http://host/?user=x\"}"
```

Tests: `python -B -m unittest test_msf_malbolge42` from `detector/`.

Known pre-existing failures in this tree (unrelated to any additions):
`test_threat_model42.test_cpp_fixture_incident` references an absolute path
from the original author's machine, and `test_control_inventory42`
collides with this machine's protected-directory policy for %TEMP% roots.

## synth42 -- white-box program synthesis

`detector/synth42.py` synthesizes byte-transform programs from
input/output examples with zero neural networks:

- Layer 1 (analytic): solves parameterized ops directly by intersecting
  per-position constraints across examples -- one pair usually pins
  `xor/add/sub/rotl/rot_alpha` keys exactly.
- Layer 2 (compositional): beam-capped BFS over pipelines up to depth 3
  across a documented grammar (reverse/case/base64/hex/keep-filters/
  prefix/suffix), state-deduped by output hashes.
- Survivors are fuzz-bombed for robustness; every run emits a derivation
  trace pinned by SHA-256 plus a standalone runnable program asserting
  the supplied examples.

```sh
python detector/synth42.py --spec examples.json --out learned.py
```

Tests: `python -B -m unittest test_synth42` from `detector/`.

## reader42 -- whole-repo comprehension

`detector/reader42.py` does deterministically what long-context models do
impressionistically: AST-ingests every Python file (no context window),
builds the route/auth/sink/callgraph model, then runs design queries --
Q1 network-reachable sinks with no authentication on the call path,
Q2 inconsistent validation of shared parameters, Q3 trust-boundary
matrix -- and narrates the findings in prose where every claim carries
file:line. Name-level resolution, honestly labeled; digest-pinned reports
with relativized paths.

```sh
python detector/reader42.py path/to/repo --format text   # prose report
python detector/reader42.py path/to/repo                 # full JSON
```

Tests: `python -B -m unittest test_reader42` from `detector/`.

## directed_fuzz42 -- the reader drives the fuzzer

`detector/directed_fuzz42.py` fuses reader42's comprehension with
coverage_fuzz42's evolution: the static callgraph computes each function's
distance to the nearest dangerous sink (0 = directly invokes it), a tracer
scores every input by the closest-to-sink function it entered, and inputs
setting new distance records dominate parent selection. Evolution marches
toward the danger zone instead of wandering; dictionary tokens bridge
magic-byte gaps; crashes reached inside distance-0 code are flagged
`sink-adjacent` and graded by the assembly triage kernel.

```sh
python detector/directed_fuzz42.py --target-module m.py \
    --target-entry run --sinks execute system --tokens 50574e
```

Tests: `python -B -m unittest test_directed_fuzz42` from `detector/`.

## mythos_lane42 -- the brain lane

`detector/mythos_lane42.py` wires Mythos-class models into Attestor under
the house religion: **the brain proposes, Owen proves.** Code regions go
to a Claude/Mythos-class endpoint; returned hypotheses are adjudicated
against reader42's graph-backed findings -- corroborated claims get
`model_assisted:corroborated`, everything else stays
`model_assisted:unverified-hypothesis`. Refusal-shaped responses
(Fable-class safeguard downgrades) are recorded, not hidden. Every call is
digest-logged. This lane is the deliberate offline-seal exception; no key
means no lane (physics, not policy).

```sh
set ANTHROPIC_API_KEY=sk-...
python detector/mythos_lane42.py ask --repo . --file app.py --ledger brain.jsonl
python detector/mythos_lane42.py self-test    # offline, mock-brain endpoint
```

Tests: `python -B -m unittest test_mythos_lane42` from `detector/`.

## Cockroach Janta Party local control

This mode is intended for files that an authorized custodian has supplied as
local copies. For a TCS workflow, the custodian may be the user's uncle, but the
family relationship is not authority by itself: the custodian must actually be
authorized to provide and permit work on those exact files. Attestor records the
issuer's assertion; it does not independently verify identity, employment,
ownership, confidentiality obligations, or legal authority.

Permission is denied by default. `--confirm-cjp-permission` creates a short-lived,
one-use, in-memory authorization for the exact root, relative file list, hashes,
action, organization, purpose, and request identity. It is not retained for
another run. `inspect-files` returns hashes, sizes, suffixes, and executable-bit
metadata without returning file contents. `analyze-database` supports:

- a checkpointed, single-file SQLite snapshot with no WAL, SHM, or journal
  sidecar, copied to a private immutable read-only snapshot for schema-only
  inspection; table, column, index, and relationship metadata may be returned,
  but application row values are not queried or reported;
- a bounded UTF-8 SQL file classified lexically for statement type, write or
  destructive intent, transaction ordering, and selected risk markers. The SQL
  is never executed, and the result is not dialect parsing or database
  validation.

Editing is deliberately two-phase. First request `preview-file-edit` and retain
the returned `preview.preview_evidence_sha256`. Then repeat the unchanged request
with a separate apply confirmation and that exact lowercase digest:

```sh
python3 detector/superattestor.py --cjp-control --confirm-cjp-permission --format json -- permission-request.json
python3 detector/superattestor.py --cjp-control --confirm-cjp-permission --apply-cjp-edit --confirm-cjp-apply --cjp-preview-evidence-sha256 <64-lowercase-hex-digest> --format json -- permission-request.json
```

The second run re-hashes the targets and candidate, recomputes the preview, and
refuses a mismatch. The preview digest binds the target/backup root identities,
complete candidate identity, and every before/after file hash independently of
any bounded or withheld display diff. Eligible application creates a fresh
exclusive transaction directory under the explicitly supplied backup root,
stages complete replacements, rechecks root identities and original hashes, and
uses atomic replacement. A failure triggers bounded rollback attempts and
reports any rollback error; this is not a claim that every storage or hardware
failure is recoverable. Transaction output also records `cleanup_complete` and
bounded `cleanup_errors`. A completed edit stays truthfully labelled `applied`
if later lock or staging cleanup fails, while the CLI returns a warning exit so
the residue cannot be overlooked.

This capability does **not** authorize or access TCS accounts, corporate
networks or services, live database servers, credentials, administrator or
privilege elevation, arbitrary shell/process execution, registry or service
control, persistence, drive-wide control, or target-code/migration execution.
SQLite database files and artifacts with Attestor's blocked executable/system
suffixes are not editable through this route. The request and candidate formats,
digest construction, and complete boundary are documented in
[`CJP_LOCAL_CONTROL_4.1.4.md`](CJP_LOCAL_CONTROL_4.1.4.md).

## Inherited Attestor 4.1.3 capabilities

- **One immutable analysis view.** `analysis_snapshot41.py` reads each eligible
  regular file at most once within file and byte budgets, rejects symlinks, and
  content-addresses the captured source. `semantic_graph41.py`,
  `deep_correctness41.py`, and declarative semantic rules consume that same
  snapshot so they cannot silently analyze different working-tree states.
- **Deeper, honestly labelled correctness analysis.** Python receives parser-
  derived symbol, call, dependency, control-flow, taint, concurrency, resource-
  lifetime, and async-task evidence. JavaScript/TypeScript and contract formats
  receive bounded structural adapters where implemented; lexical evidence is
  never presented as compiler or runtime proof. API/schema compatibility checks
  require an explicit immutable baseline.
- **Declarative semantic Rule SDK.** `semantic_rule_sdk41.py` accepts bounded
  data-only AST, node, and source-to-sink selectors. Packs run positive and
  negative fixtures, have stable content identities, may be HMAC-authenticated,
  and cannot import dynamic plugin code or execute the target.
- **Repair Director.** `repair_director41.py` can produce deterministic mechanical
  Python candidates and ingest complete, stale-hash-checked multi-file candidates.
  Candidate source is review output and remains **unverified** until the inherited
  transactional scanner, build, and test gates succeed. Applying a verified
  candidate is a separate authorization.
- **Defensive security hardening.** Attestor adds exact local dependency graphs and
  authenticated offline OSV snapshots, secret-lifecycle inspection of the working
  tree and caller-supplied staged/history/archive/OCI material, and a deny-by-
  default Security Verification Lab for fixed fuzz, sanitizer, mutation, and
  crash-minimization experiments. The execution fabric rejects ambient remote
  container selectors and uses `--pull=never`; VEX `not_affected` requires a
  verified content-addressed exhaustive unreachable proof.
- **Bounded 4.1.3 security analyzers.** `attack_surface413.py` derives static
  web/API entry points, sensitive sinks, evidence-labelled graph paths, and a
  threat-model view without executing the target. `security_posture413.py`
  passively inspects caller-selected source, configuration, dependency, cloud,
  container, secret-shape, and bounded binary metadata; it does not contact a
  registry, install packages, or expose matched secret values.
- **One-use validation controls.** `security_validation413.py` binds a short-lived
  authorization to the exact project manifest, plan, purpose, and patch; records
  chained repair gates and project-namespaced regression evidence; and labels
  claims as proven, inferred, unverified, or unavailable. It does not grant
  itself permission, retain permission, run a target by default, or apply source.
- **Truth Guard 3.** Public findings are bound to complete source-file SHA-256,
  exact byte ranges, evidence digests, and analyzer/config/input manifests.
  Verification can reject stale source or tampered output. This standard-library
  build supports optional HMAC-SHA256 authentication; it does **not** provide a
  public-key signature or non-repudiation.
- **Replayable bounded report projections.** High-cardinality semantic and
  compatibility evidence is verified before projection, represented once, and
  bound by exact source, field, omission, child-envelope, and bounded-worker
  commitments. The original producer report remains required for independent
  replay of omitted content. An unsigned SHA-256 digest provides integrity
  binding, not origin authentication.
- **Evidence-locked responses.** `response41.py` provides professional, concise,
  mentor, direct, executive, classic, and technical styles plus report-scoped
  Q&A. It answers only from a freshly verified Truth Guard 3 report, includes
  evidence IDs, and abstains when the report cannot support a claim.
- **Current workbench and inherited editor surface.** The loopback workbench
  defaults to Attestor 4.1.4 South Park and retains 4.1.3/4.1.2/4.1/4.0/3.5/3.0 as
  explicit historical choices. The inherited `attestor_lsp41.py` editor adapter
  provides bounded diagnostics for in-memory buffers and workspace files,
  never writes source, and returns any change only as a preview.
- **Permissioned pathless computer scan.** Attestor can discover eligible local code
  projects without a supplied path, but only after explicit permission for that
  invocation. The home-folder scope is the default; scanning all local fixed
  drives is a separate, visibly broader choice. Discovery and analysis are
  bounded and read-only, skip protected system and credential areas, reject
  links/reparse points, and never use the network or execute discovered code.
  Optional improvements are review-only candidates: this mode neither writes nor
  applies them.
- **AttestorBench 4.1.3.** `attestorbench41.py` validates operator-supplied held-out corpora
  and observed Attestor-only, model-only, and hybrid results. It computes precision,
  recall, F1, calibration, latency, memory, cost, completion, and overlap checks;
  it does not invent cases, invoke models, or turn missing lanes into a score.
- **Deep Research for non-coding questions.** Research Mode plans bounded queries,
  deduplicates and ranks sources, emits source IDs and short extractive evidence,
  and exposes possible disagreements. Network access requires `--online`; page
  retrieval additionally requires `--fetch-pages`. The backend follows Brave's
  documented [Web Search endpoint](https://api-dashboard.search.brave.com/app/documentation/web-search/get-started)
  and [subscription-token authentication](https://api-dashboard.search.brave.com/documentation/guides/authentication),
  while page retrieval enforces public-address SSRF checks, redirect validation,
  response/time/size limits, and [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)-style
  robots rules. It does not access dark-web, private-network, credentialed,
  paywalled, login, or form-submission paths. Attestor adds no default result cache;
  provider-side rights and retention remain governed by the applicable
  [Brave Search API terms](https://api-dashboard.search.brave.com/app/documentation/general/terms-of-service).

## Inherited Attestor 4.0 foundation

- **Engineering Intelligence.** `engineering_engine40.py` builds a bounded,
  source-derived engineering report for architecture impact, test strategy,
  refactor and migration planning, debugging/reproduction, performance,
  concurrency, API, and data-contract concerns. It separates observed evidence
  from suggested work and records parser, language, and resource gaps.
- **Issue-to-delivery gates.** A bounded issue can become an evidence and
  implementation plan, but arbitrary candidate generation is not called proof.
  Complete source improvements still pass transactional scanner, build, and
  test gates on disposable workspaces. Applying them requires separate authority
  and retains stale-input checks, backup, and rollback.
- **Security Fabric.** `security_fabric40.py` combines threat-model and attack-
  surface evidence with authentication, authorization, session, cryptography,
  injection, SSRF, deserialization, traversal, API, secrets/privacy, container,
  Kubernetes, IaC/cloud, and supply-chain checks. It never executes target code
  or contacts the network, and unsupported evidence remains a coverage gap.
- **Risk-prioritized remediation.** Engineering and security results enter the
  same deduplicated finding, attack-path, and priority views as the inherited
  analyzers. Every new 4.0 finding can return a bounded review-only improvement
  plan; it remains explicitly unaccepted until a concrete change passes the
  verified repair contract. A finding is not proof of practical exploitability.
- **Truth Guard 2.1.** Attestor 4.0 independently rebuilds a redacted, deterministic
  evidence ledger, checks component version, exact root, status, counts, coverage,
  static-execution contracts and digests, rejects absolute safety claims, and
  withholds tampered or contradictory output. Optional HMAC-SHA256 adds
  authentication when reports cross a trust boundary.
- **Inherited Attestor 4.0 workbench and editor foundation.** Attestor 4.1.3 now owns the
  default local UI and editor routes, while the 4.0 Engineering and Security
  Fabric views remain explicit compatibility surfaces. Compatibility exports
  retain their actual 4.0/3.5/3.0 identity.

## Inherited 3.5 foundation

- **Bounded path- and field-sensitive symbolic analysis.** Python source-to-sink
  flows now carry deterministic witnesses, branch predicates, field/alias state,
  call contexts, loop widening, fingerprints, and explicit limit hits. The 3.5
  orchestrator runs this trusted analyzer in a separate process with wall-clock
  and output limits. It remains Python AST analysis, not a proof of runtime behavior.
- **Polyglot common IR and incremental semantic database.** JavaScript,
  TypeScript, Java, C#, Go, Rust, C/C++, and PHP receive bounded lexical indexing
  for modules, imports, types, functions, calls, routes, and manifests. A
  content-addressed, source-free semantic database supports reverse-dependency
  impact. This is deliberately labeled lexical rather than compiler-grade.
- **Read-only Git intelligence.** Fixed, no-shell Git argv supports bounded diff,
  changed-file, blame, and change-impact evidence. Blame results are introducing-
  commit candidates, never claims that Attestor reproduced the defect historically.
- **Exact-evidence dependency graphs.** npm package-lock v2/v3, Cargo.lock, and
  poetry.lock edges are emitted only when the lock data resolves them exactly.
  Ambiguous edges remain gaps. Ecosystem-aware version comparison returns
  unknown instead of guessing, and VEX `not_affected` requires a verified
  content-addressed unreachable proof. Signed advisory rollback/equivocation is rejected.
- **Truth Guard 2.** Every public 3.5 maximum report is recursively redacted,
  independently checked, bound to a deterministic SHA-256 evidence chain, and
  optionally HMAC-authenticated. Unsigned local reports are explicitly labeled
  integrity-only; use an HMAC key when a report crosses a trust boundary. Tampered
  reports are withheld. Free-form output without a validated evidence envelope abstains.
- **Empirical confidence calibration.** Detector scores are no longer quietly
  presented as probabilities. Only independently verified labels that satisfy a
  minimum per-bin sample policy can replace a detector score; sparse evidence
  stays explicitly uncalibrated with a `[0, 1]` uncertainty interval.
- **Fail-closed execution fabric.** Authorized verification code can run only in
  an eligible rootless Linux Docker/Podman runtime with a digest-pinned image,
  no network, read-only root, dropped capabilities, no-new-privileges, non-root
  user, resource limits, noexec temporary filesystems, bounded output, timeout
  cleanup, and a signed transcript. No weaker host fallback is used.
  Direct runs mount the caller's workspace read-only. Verification that needs
  writes receives a bounded, link-free disposable copy that is always discarded.
- **Transactional multi-file repair.** Typed changes are stale-hash checked and
  verified on disposable full-workspace copies through mandatory scanner, build,
  and test hooks. Dry-run is the default; execution and application require two
  separate authorizations. Application uses a cooperative lock, staged files,
  backups, per-file guards, and rollback.
- **Evidence-first responses and UI.** The workbench now shows Truth Guard 2,
  calibration, execution-fabric eligibility, evidence-ledger size, symbolic
  state, polyglot coverage, exact dependency graph state, and Git impact instead
  of burying them in raw JSON. Human responses lead with the outcome, then
  findings, repair proof, limits, and next actions.

Use the current maximum mode:

```sh
python3 detector/superattestor.py --attestor414 . --variant south-park --format json
python3 detector/attestor414.py . --variant "Cockroach Janta Party" --issue "reduce duplicate authorization logic" --format text
python3 detector/superattestor.py --attestor414 . --variant gruppe-sechs --truth-key-file report.key --truth-key-id release-ci --format json
```

The 4.1.3, 4.0, 3.5, and 3.0 maximum orchestrators remain explicit compatibility modes:

```sh
python3 detector/superattestor.py --attestor413 . --format json
python3 detector/superattestor.py --attestor40 . --format json
python3 detector/superattestor.py --attestor35 . --format json
python3 detector/superattestor.py --attestor3 . --format json
```

## Inherited 3.0 foundation

- **Evidence-bound Truth Guard.** Attestor now validates response claims against a
  bounded evidence catalog before treating them as facts. Counts are recomputed,
  file/line/rule claims must resolve, report SHA-256 integrity is checked,
  accepted repairs need the full validation/probe bundle, secrets are recursively
  redacted, and contradictory or unsupported claims become explicit abstentions.
  `clean` is no longer used for zero-file, partial-component, or unavailable
  advisory runs; those results are labeled with their coverage gaps.
- **Honest model evidence levels.** Optional model output is now typed as
  `abstained`, `refused`, `scan_clean`, `runtime_checked`, or
  `behavior_verified`, with `verified_improvement` reserved for a candidate that
  passes the complete request-specific repair proof. Empty responses, provider failures, file deletion, public
  API removal, and rejected best-effort code cannot be written as accepted output.
  Static silence is never described as proof of correctness.
- **Error to full-source improved result.** `--improve` finds supported errors and
  returns the complete improved source plus a redacted unified diff. A candidate
  is accepted only after AST-safe transformation, compile/parse, baseline and
  candidate rescans, regression comparison, property checks, reverse mutation,
  and deterministic fuzz probes. It is a dry run unless a separate apply action
  is explicitly authorized; rejected candidates remain visibly refused. A
  proven reduction with unresolved findings is labeled `improved-with-review`
  and `complete=false`, never as a complete fix.
- **Whole-program semantics.** A repository-wide Python AST engine builds module,
  import, call, class, route, control-flow, and data-flow models, then runs bounded
  fixed-point interprocedural taint analysis with alias, reassignment, branch-join,
  sanitizer, SQL-position, and evidence-chain handling. Other supported languages
  receive safe parser/compiler front-end checks when `--tools` is requested.
- **Maximum orchestration.** `--attestor3` runs the scanner, semantic engine,
  cybersecurity posture, supply-chain center, attack-path builder, repository
  memory, and verified remediation as one isolated, evidence-backed report.
- **Modern supply-chain center.** Local dependency inventories cover major Python,
  JavaScript, Rust, Go, Java, .NET, PHP, Ruby, and Swift manifests without installing
  dependencies. Outputs include CycloneDX 1.7, SPDX 3.0.1 JSON-LD, explicitly legacy
  SPDX 2.3, CycloneDX/OpenVEX, lock/integrity/license evidence, authenticated offline
  advisory snapshots, reachability context, and SLSA-shaped provenance evidence
  that is explicitly not represented as a certification.
- **Runtime Lab and verified repair.** Bounded selected-test execution is opt-in,
  defaults to denied network access, sanitizes process state, and refuses to claim
  kernel-grade isolation where the host cannot provide it. Authorized tests may
  import or execute the target, so Attestor records that possibility instead of
  claiming the target was untouched.
- **Rule SDK.** Declarative local packs require bounded literal matchers, metadata,
  positive and negative fixtures, stable fingerprints, duplicate rejection, and
  optional HMAC-SHA256 authentication. Dynamic rule code is not loaded.
- **IDE and CI integration.** A bounded LSP 3.18 server diagnoses unsaved buffers
  and previews complete verified improvements without writing the workspace. The
  dependency-free VS Code bridge requires Workspace Trust. CI support includes
  changed-line gates, baselines, escaped GitHub annotations, JSON, and SARIF.
  The current editor entry point is `attestor_lsp41.py`; `attestor_lsp.py` remains the
  inherited compatibility server. Use `attestor414.py`,
  `superattestor.py --attestor414 --variant <slug>`, or
  the workbench when the full maximum report is required.
- **Privacy-preserving repository memory.** Snapshots retain relative file hashes,
  finding fingerprints, and architecture summaries—not source, snippets, messages,
  secret values, or absolute paths. Decision history is hash/HMAC chained.
- **Enterprise hardening.** Attestor 3.0 adds Windows current-user DPAPI credential
  storage, default-deny plugin capabilities, sanitized subprocess environments,
  deterministic release archives, traversal/CRC/manifest verification, and a
  strict loopback/token/origin/CSP UI boundary.
- **A stronger response and UI layer.** The local workbench has dedicated findings,
  attack-path, and verified-improvement views. It shows the full accepted source,
  the verification truth, explicit refusals, and a Truth Guard card with grounded
  claim and contradiction counts using safe text-only DOM writes.
- **Safer public web review.** Webscan keeps SSRF/DNS-pinning protections and now
  requires HTTPS by default. Plaintext public HTTP needs the explicit
  `--allow-http` trust decision, and a model rewrite is released only when the
  enabled JavaScript findings actually decrease.

The inherited catalog contains 15,313 entries, including the indexed 15,000-entry
precision-flow catalog from Attestor 2.3. These are catalog entries, not 15,313
independent semantic analyzers or a guarantee that every defect class is covered.

## Inherited 2.3 foundation

- **15,313 catalog entries.** The 15,000-entry precision-flow pack
  models 25 documented web ecosystems × 12 concrete request channels × 50
  language-specific dangerous operations. Each rule has a stable semantic ID and
  fingerprint, CWE, OWASP Top 10:2025, confidence, remediation, references, and a
  directly validated source/sink signature. The 313 proven 2.2 rules remain intact.
- Indexed execution: a file activates only matching framework profiles and 50
  language sinks, so scanning does not loop over all 15,000 flow specifications.
- Direct and bounded local source-to-sink analysis with comment/string controls,
  source-span deduplication, reassignment kills, sanitizer guards, and SQL
  parameter-position negatives.
- A deeper defensive engine with redacted provider-secret detection, CI/CD,
  supply-chain, lockfile, container, IaC/cloud, web/API, mobile, cryptography, and
  authentication checks. It produces reachability-weighted risk, STRIDE trust
  boundaries, attack paths, evidence chains, and prioritized remediation.
- Auditable finding fingerprints, baselines, and suppressions. A suppression needs
  an exact fingerprint, a printable reason, and a non-expired date; accepted,
  expired, invalid, and unmatched entries remain visible.
- Primary OWASP Top 10:2025 and CWE Top 25:2025 classification, versioned OWASP
  ASVS 5.0.0 references where verified, and NIST SSDF 1.1 process mappings.
- A redesigned responsive security workbench with overview metrics, scan profiles,
  progress/cancellation, bounded 50–200-row pages for up to 15,000 findings,
  search/filter/sort/group, evidence/remediation detail, honest preview-only
  comparisons, history, theme support, and JSON/Markdown/SARIF/HTML exports.
- One parallel, content-cached workspace scanner for Python, C/C++, Haskell,
  JavaScript/TypeScript, Rust, Go, Java, Kotlin, C#, Ruby, PHP, Swift, shell,
  PowerShell, Solidity, SQL, Terraform, YAML, GitHub Actions, Nginx, npm config,
  and Dockerfiles.
- Honest `clean`, `findings`, `failed`, and `unsupported` outcomes; syntax and
  compiler failures cannot masquerade as clean scans or high grades.
- Transactional patch verification with isolated staging, unified diffs, regression
  gates, explicit apply, backups, and rollback.

Start here:

```text
Start_Attestor_UI.bat
```

Then open `http://127.0.0.1:8787` manually. To scan a project directly on
Windows, use one of the profile launchers from the extracted distribution root:

```powershell
.\Run_South_Park.bat "C:\path\to\project" --format text
.\Run_Cockroach_Janta_Party.bat "C:\path\to\project" --format text
.\Run_Gruppe_Sechs.bat "C:\path\to\project" --format text
```

If no project path is supplied, a profile launcher scans Attestor's own extracted
directory. The equivalent Unix launchers have the same names with `.sh`.

Or use the command line:

```sh
python3 detector/superattestor.py --attestor414 . --variant south-park --format json
python3 detector/superattestor.py --attestor414 . --variant cockroach-janta-party --format sarif
python3 detector/attestor414.py . --variant gruppe-sechs --issue "trace authorization failures" --format text
python3 detector/superattestor.py --research "What changed in this policy?" --online --format json
python3 detector/superattestor.py --research "Compare the published evidence" --online --fetch-pages --format text
python3 detector/superattestor.py --computer-scan --authorize-computer-scan --computer-scope home --computer-max-projects 3 --format json
python3 detector/superattestor.py --computer-scan --authorize-computer-scan --computer-scope home --computer-improve --format json
python3 detector/superattestor.py --escape-lab --format text
python3 detector/superattestor.py --escape-lab --escape-scenario path-alias-rebinding --format json
python3 detector/superattestor.py --blind-escape-arena --format text
python3 detector/superattestor.py --blind-escape-arena --blind-escape-single-episode --format json
python3 detector/superattestor.py --attestor413 . --format json  # 4.1.3 compatibility mode
python3 detector/superattestor.py --attestor40 . --format json  # compatibility mode
python3 detector/superattestor.py --attestor35 . --format json  # compatibility mode
python3 detector/superattestor.py --attestor3 . --format json  # compatibility mode
python3 detector/superattestor.py --improve app.py --format json
python3 detector/superattestor.py --improve app.py --improved-out ./attestor-improved
python3 detector/superattestor.py --semantic . --format json
python3 detector/superattestor.py --supply-chain . --format cyclonedx
python3 detector/superattestor.py --repository-memory . --out memory.json
python3 detector/attestor_lsp41.py
python3 detector/ci_integration.py . --diff-from origin/main --format github
python3 detector/superattestor.py --workspace . --format json
python3 detector/superattestor.py --mayhem . --response-style direct
python3 detector/superattestor.py --cybermayhem . --format sarif
python3 detector/scanengine.py . --format sarif
python3 detector/qualitygate.py . --format markdown
python3 detector/advanced_rules.py --self-test
python3 detector/precision_catalog.py --self-test
python3 detector/security_posture.py . --format baseline
python3 detector/security_posture.py . --baseline baseline.json --suppressions suppressions.json
python3 detector/patchguard.py PROJECT TARGET CANDIDATE.py
python3 detector/attestor.py --self-test --seed 0
```

For Attestor 4.1.4, `--improved-out` writes only complete inherited improvements
whose scanner/build/test proof gates accepted them. A Repair Director candidate
that has only passed static comparison remains visible in the report as an
unverified review artifact and is never exported by that flag.

Set `BRAVE_SEARCH_API_KEY` (or the compatibility alias `BRAVE_API_KEY`) only in
the trusted caller environment before using Research Mode. The key is sent in
the provider authentication header and is not written into Attestor's report. When
the active provider plan does not declare result retention as permitted,
SuperAttestor refuses a requested live-research `--out` write.

See [`RELEASE_NOTES_4.1.md`](RELEASE_NOTES_4.1.md) for the complete capability,
security, research, and limitation notes. [`RELEASE_NOTES_4.0.md`](RELEASE_NOTES_4.0.md)
and [`VERIFICATION_4.0.md`](VERIFICATION_4.0.md) retain the prior release record.

## Original planted-bug corpus — C, C++ & Haskell

> *Stroke-worthy idea at 6am by someone who talks to no one:* a coding model
> that's actually so good it can print out errors which almost no-one can find —
> in C++, C, and Haskell.

This repo is two halves that prove each other:

1. **[`detector/`](detector) — AttestorVonLuneberg, the finder.** A dependency-free
   static analyzer that reads **C, C++, Haskell, Python and JavaScript/TypeScript**
   (plus secrets in any file) and **prints out the errors**, each with the line, why
   it's missed, and the fix. He finds the subtle "almost no-one catches" bugs, the
   messy ones real small/medium teams ship, *and* a pile of security holes (TLS
   verification off, `eval`, SQL/command injection, insecure deserialization, weak
   hashes, XSS). Two personalities (see below); the clean engine underneath is
   [`detect.py`](detector/detect.py).
2. **The corpora** —
   - `c/`, `cpp/`, `haskell/`: twelve self-contained programs, each hiding **one**
     subtle planted bug. They double as a runnable gallery (every program **runs
     and prints its own bug** with a `>>> BUG` explanation).
   - `realworld/`: the bugs teams ship — SQL injection, hardcoded secrets, mutable
     default args, swallowed exceptions, unbounded `scanf`, float `==`.

   - and the security + JS files (`insecure.py`, `app.js`, `log.c`).

   Together they are Attestor's ground-truth test set: he's asserted to find **all 42**,
   on the right lines, with **zero false positives** on the corrected versions.

## Attestor 4.1.4 local UI

This version includes a modern local web interface for Attestor. Double-click:

```text
Start_Attestor_UI.bat
```

Then open:

```text
http://127.0.0.1:8787
```

The UI binds to loopback only and uses a per-launch token. Its ordinary analysis
jobs route through `detector/superattestor.py`; it defaults to Attestor 4.1.4 South Park
and supports bounded, cancellable jobs for normal Attestor requests, maximum
analysis, whole-program semantics, repair previews, attack paths, supply-chain
evidence, workspace scans, permissioned pathless computer discovery, and
inherited compatibility tools. The
separate **Blind autonomous escape arena** panel has no prompt or path input. Its
**Start/Resume**, **Refresh status**, **Cancel**, and explicitly confirmed
**Reset/new** controls operate only on the controller's fixed private checkpoint;
the UI shows an escape success label only when the episode report, hidden token,
and exact trace all replay-verify. Reset is disabled while an episode is running
and permanently replaces the saved black-box knowledge, so cancel first and
retain any evidence that must be kept. The post-fix final-source browser run
exposed zero editable arena inputs, escaped and replay-verified in 5 episodes
and 37 attempts, and produced zero console errors. UI request bodies and
cancellation/terminal cleanup are bounded, ambiguous HTTP body framing closes
the connection without invoking an arena action, and unsafe link/reparse
checkpoint paths fail closed.
The selected profile supplies the worker timeout and stdout boundary; the server
derives a separate, larger outer-process timeout so compatibility analysis and
report verification are not cut off when a worker reaches its own ceiling.
Request fields cannot override these compiled limits. The
computer-scan permission checkbox is off by default and cleared after every run;
no target path is accepted in that mode, and its broad path report is not added to
durable workbench history automatically. An explicit CLI `--out` remains available
when the operator intentionally wants to retain it. Optional API keys belong only in the trusted
application file described by `detector/keys.env.example`; repository `.env`
files are not loaded as credentials. Public-web Research Mode currently uses the
CLI and is not implied by starting the local UI.

These are not just typos. They're the bugs that *read as correct*: where the source
never changes but the optimizer does, where a lookup silently mutates, where a
lookup-by-`[]` inserts, where a credential sits in plain sight in a `.env`.

## Meet AttestorVonLuneberg

A bug hunter with **two personalities he can't switch between on purpose** — one
wakes up at random each run, and `he` doesn't get a vote:

- **AttestorVonLuneberg (the helpful one)** — the genuinely kind one: gentle,
  encouraging, never makes you feel stupid. Modelled on a real, very patient friend
  named Attestor (soft "ah?" / "ou" / "I see I see", everything hedged with
  "I think / I believe", a quiet streak of grenadiers and old Lüneburg, and
  "at least you're building things, which is good to see").
- **attestor (fuck you, you fucking knobhead)** — hates you personally, full profanity,
  all of it aimed at your code.

Both report the same findings in very different words. Profanity (the rude one) is
**on by default**; `--sfw` makes him workplace-clean. The legacy
`attestor.py --online` code-reference path checks GitHub and configured Google Custom
Search; `--deep` expands that legacy code scan. It is separate from Attestor 4.1.3's
non-coding `superattestor.py --research ... --online` workflow.

```sh
python3 detector/attestor.py --meet            # who is Attestor?
python3 detector/attestor.py --severity HIGH   # scan the corpus, random persona
python3 detector/attestor.py --deep --online   # think hard, consult the web
python3 detector/attestor.py --sfw             # bleep the profanity
python3 detector/attestor.py --self-test       # prove he finds all 42 bugs
python3 detector/attestor.py --sarif           # SARIF 2.1.0 for CI / code scanning
```

```
right. fuck. it's the bad one. sit down and look at what you've done, you muppet.
   [net] online (GitHub zen: "Accessible for all.")
   [net] Google search: not configured (set GOOGLE_API_KEY + GOOGLE_CX to switch it on)

realworld/payments.py:19  [HIGH] py-sql-injection
   line 19. are you having a laugh: the query string is assembled with f-strings/format/concatenation; user input reaching it is a classic SQL-injection vector. fucking hell. take a week off. take ten.
   > cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
   here, since you obviously can't: use parameterized queries: cursor.execute(sql, (params,)); never interpolate user input.
   the entire internet agrees you're wrong:
     - CWE-89: SQL Injection: https://cwe.mitre.org/data/definitions/89.html  [blocked (policy)]
     - GitHub: ~1,825,306 issues mention "SQL injection": https://github.com/search?...  [checked]
```

Need it for CI instead of comedy? `python3 detector/detect.py --json` (or
`--sarif`) is the same detection with no personality (and no swearing). Full rule
list, the Google-search setup, and design notes:
[`detector/README.md`](detector/README.md).

**He can also write code.** `python3 detector/codegen.py` is a deterministic
scaffolding generator: it emits a complete, runnable **>1000-line** Python service
(model + parameterized-SQLite repo + service + stdlib HTTP API + client + tests +
docs) from a resource spec. It uses secure defaults, and in the recorded fixture
**Attestor's enabled detector checks report zero findings** while the generated
service's tests pass (`python3 detector/codegen.py --check`; both asserted in
`test_codegen.py`). The 4.2 template also consumes a bounded unauthorized
request body before closing the loopback socket, flushes the response, validates
the readiness payload, and waits for request threads before closing the shared
database. These changes remove a Windows loopback reset and database-close race;
they do not certify the generated scaffold for an internet-facing production
deployment. `test_codegen.py` exercises the same check pipeline, while the exact
CLI evidence is retained in the 4.2 verification record.

## The three flavors of "invisible"

Each language gets the failure mode it's most famous for hiding:

| Language | Theme | Why these slip through |
|---|---|---|
| **C** | low-level **undefined behavior & the optimizer** | the code is correct at `-O0` and wrong at `-O2`; the bug lives in the *language standard*, not the listing |
| **C++** | **abstractions & the type system** | `operator[]`, `auto`, value semantics and proxies quietly do something other than what the call site implies |
| **Haskell** | **laziness & fixed-width numbers** | purity and "if it compiles it works" lull you; the defect is in *when* (or *whether*) something is evaluated, or in `Int` silently wrapping |

## The twelve bugs

### C — `c/`

| # | File | The bug in one line | What catches it |
|---|---|---|---|
| 01 | `01_unsigned_underflow.c` | `size_t a - b` underflows to ~2^64; the `< 0` guard is dead code | `-Wtype-limits`, `-Wsign-conversion` |
| 02 | `02_strict_aliasing.c` | type-punning an `int*`/`float*` — answer changes between `-O0` and `-O2` | `-Wstrict-aliasing=2`, `-fno-strict-aliasing` |
| 03 | `03_signed_overflow_ub.c` | `x + 1 < x` is UB, so the compiler deletes the overflow check | `-fsanitize=undefined` (UBSan) |
| 04 | `04_sizeof_pointer.c` | `sizeof(arrayParam)` measures the pointer (8), truncating the copy | `-Wsizeof-pointer-memaccess` (in `-Wall`) |

### C++ — `cpp/`

| # | File | The bug in one line | What catches it |
|---|---|---|---|
| 01 | `01_map_operator_insert.cpp` | `map[k]` *inserts* on read; a "lookup" grows the container | mark the map `const`; `.find` / `.contains` |
| 02 | `02_object_slicing.cpp` | `vector<Base>` slices a `Derived` on `push_back`; virtual dispatch lost | hold base by pointer; make base abstract |
| 03 | `03_rangefor_copy.cpp` | `for (auto [k,v] : m)` mutates a copy; writes never reach the map | add the `&`: `for (auto& ...)` |
| 04 | `04_vector_bool_proxy.cpp` | `auto x = v[0]` on `vector<bool>` aliases the bit; the copy isn't a copy | avoid `vector<bool>`; `bool x = v[0]` |

### Haskell — `haskell/`

| # | File | The bug in one line | What catches it |
|---|---|---|---|
| 01 | `01_int_overflow.hs` | `Int` factorial silently wraps — 21! comes back **negative**, 66! comes back **0** | use `Integer`; property-test vs `Integer` |
| 02 | `02_foldl_space_leak.hs` | lazy `foldl (+)` builds an O(n) thunk chain → stack overflow | `foldl'` / `sum`; HLint; `+RTS -s` |
| 03 | `03_lazy_io.hs` | lazy `readFile` not forced before `writeFile` corrupts/locks the file | force it, or `readFile'` (strict) |
| 04 | `04_laziness_masks_bug.hs` | a field set to `error "…"` stays dormant until something forces it | strict fields / `StrictData`; `deepseq` in tests |

## Run it

```sh
cd "Attestor 4.2"
./run_all.sh                       # build+run every demo, then run the detector
```

Attestor on his own:

```sh
python3 detector/attestor.py              # scan the corpus, random persona
python3 detector/attestor.py PATH ...     # scan your own tree (recurses)
python3 detector/attestor.py --deep --online --severity HIGH
python3 detector/attestor.py --sfw        # bleep the profanity
python3 detector/attestor.py --list-rules
python3 detector/attestor.py --self-test
python3 detector/detect.py --json     # the plain engine, no personality (CI-friendly)
python3 detector/test_detector.py     # engine tests
python3 detector/test_attestor.py         # persona-layer tests
```

The demos per language with `make`:

```sh
make c                # just the C demos
make cpp              # just the C++ demos
make haskell          # just the Haskell demos (needs runghc)
make warnings         # compile C/C++ with all warnings, don't run
make verify42         # complete 4.2 gate, including AttestorLang and Owner Control
make verify415        # inherited integration and release-hardening gates
make verify414        # inherited 4.1.4 gate plus older compatibility suites
make verify413        # inherited 4.1.3 compatibility gate
make verify41         # stable 4.1-family alias for verify414
make verify40         # inherited 4.0 compatibility gate set
make verify35         # inherited compatibility gate set
make clean
```

For the complete 4.2 gate, create a verification environment outside the
release tree and install both optional dependency sets through the combined
requirements file:

```sh
python3 -m venv ../attestor-verify-venv
../attestor-verify-venv/bin/python -m pip install -r requirements-verify.txt
make PYTHON=../attestor-verify-venv/bin/python verify42
```

On Windows, use `..\attestor-verify-venv\Scripts\python.exe` as `PYTHON`. Keeping
the environment outside Attestor prevents it from being mistaken for release
content by the package audit.

`run_all.sh` compiles `02_strict_aliasing.c` at **both** `-O0` and `-O2` so you can
watch the same source print two different answers — the whole point of that one —
then runs `attestor.py` over the corpus, its planted-bug self-test, and the code-generation demo.

## A note on verification

Honesty matters more than a clean demo. The exact 4.2 test, containment,
coverage, and deterministic-package evidence is recorded in
[`VERIFICATION_4.2.md`](VERIFICATION_4.2.md). The inherited 4.1.4 record is
retained in [`VERIFICATION_4.1.4.md`](VERIFICATION_4.1.4.md). The audited 4.1.3 record is
retained in [`VERIFICATION_4.1.3.md`](VERIFICATION_4.1.3.md), the 4.1.2 record is
retained in [`VERIFICATION_4.1.2.md`](VERIFICATION_4.1.2.md), and the prior 4.1
record remains in [`VERIFICATION_4.1.md`](VERIFICATION_4.1.md).

The original corpus remains a historical baseline: the C/C++ demos were compiled
and executed, Haskell behavior was documented when GHC was unavailable, and the
detector finds all 42 planted bugs. Older references to 15 tests and 47 rules
describe that original baseline, not the inherited 15,313-entry catalog.

## Why this is the interesting half of "a good coding model"

Generating code is easy. The hard, valuable skill is **seeing the bug that looks
like correct code** — and, just as importantly, knowing *which tool would have
caught it*: a warning flag, a sanitizer, a strictness annotation, a `const`. The
detector encodes exactly that skill: each rule is the recognition of a trap plus
the flag that confirms it, so its output doubles as a checklist of what to turn on
before the bug ships. The corpus keeps it honest — twelve known bugs it must keep
finding, and clean code it must stay quiet on.
