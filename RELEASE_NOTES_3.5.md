# Attestor 3.5 release notes

Attestor 3.5 is a separate release. The Attestor 3.0 package is not overwritten, and
`superattestor.py --attestor3` remains available as a compatibility path.

## Maximum orchestration

`detector/attestor35.py` emits the versioned `attestor-maximum/3.5` report and is exposed
through `superattestor.py --attestor35`. It retains the 3.0 scanner, semantic, security,
supply-chain, attack-path, repository-memory, and verified-remediation pipeline,
then adds the following evidence surfaces.

### Bounded symbolic paths

`symbolic_engine35.py` performs Python AST abstract interpretation with immutable
SSA-like states, branch predicates, exact dictionary/field tracking, alias-aware
heap updates, bounded call contexts, conservative unknown-call propagation, loop
widening, context-specific sanitizers, and typed source-to-sink witnesses. Every
report includes coverage gaps, limit hits, metrics, and a payload digest.

The maximum orchestrator runs the analyzer as a trusted isolated worker with a
45-second default wall-clock boundary, a 16 MiB aggregate source-input boundary,
a 16 MiB output boundary, and reduced state/step/context limits. The engine does not execute or import target code. It
is Python-only and does not claim class-method, reflection, generated-code,
lambda/comprehension, macro, or runtime coverage that it did not observe.

### Polyglot IR, semantic cache, and Git

`polyglot_ir35.py` builds a deterministic common lexical IR for JavaScript,
TypeScript, Java, C#, Go, Rust, C/C++, and PHP plus declarative manifests. It
extracts bounded modules, imports, types, functions, calls, routes, and explicit
parse gaps. It never runs compilers, builds, package hooks, or target code.

`git_intelligence35.py` provides a source-free, content-addressed incremental
semantic database with schema/root/analyzer/hash/privacy validation and reverse-
dependency impact. Its Git facade admits only bounded read-only rev-parse, diff,
and blame operations through fixed argv and `shell=False`. Introducing-commit
results are blame attribution candidates; no bisect, historical build, test, or
exploit is run.

### Supply-chain proof upgrades

`supply_chain35.py` extracts exact dependency edges from npm package-lock v2/v3,
Cargo.lock, and poetry.lock. When an edge is ambiguous or a lock format lacks the
required graph evidence, the report records a gap rather than inventing an edge.
Version comparison implements bounded SemVer and a PEP 440 subset and returns
unknown for unsupported forms.

VEX `not_affected` requires a verified SHA-256 reachability proof with an
exhaustive observed-entrypoint marker. A boolean supplied by a caller is not
accepted. Signed advisory snapshots must be cryptographically valid, fresh, and
monotonic; rollback and same-time equivocation are rejected.

### Truth Guard 2 and calibration

`truth_guard35.py` redacts the public document, independently rechecks structured
claims, records contradictions, and builds a deterministic SHA-256 chain over up
to 20,000 evidence leaves. The public report is bound to both the source-document
and evidence-chain digests and can be HMAC-authenticated. The default local report
is labeled integrity-only, not authenticated; `--truth-key-file` and
`--truth-key-id` authenticate reports that cross a trust boundary. A modified
report is withheld by `safe_public_report`.

`calibration35.py` separates detector ranking scores from empirical probability.
Profiles accept only independently labelled observations carrying an explicit
verified-label marker, dataset identity, and label source. Sparse bins do not
replace scores. Profiles and corpora are content-addressed and expose Brier score,
expected calibration error, sample counts, empirical rates, and Wilson intervals.

### Fail-closed execution and transactional repair

`execution_fabric35.py` detects Docker/Podman capability but considers only a
rootless hardened Linux runtime eligible. Commands require a lowercase OCI image
pinned by SHA-256 and explicit execution authorization. The fixed container argv
uses no network, a read-only root, dropped capabilities, no-new-privileges,
numeric non-root identity, CPU/memory/PID limits, and noexec temporary filesystems.
Output is bounded and secret-redacted; timeout cleanup names and removes the
container; every event is HMAC/SHA-256 chained. There is no host or weaker-runtime
fallback. Direct execution mounts the requested workspace read-only. Hooks that
need writes run only against a bounded, link-free temporary copy, which is discarded.

`transactional_repair35.py` accepts typed multi-file add/update/delete plans bound
to target rules or fingerprints. It rejects path escapes, symlinks, case
collisions, stale hashes, excessive erasure/growth, Python parse failure, source
deletion, and conservative public-API loss. Mandatory scanner, build, and test
hooks each receive independent disposable full-project copies through the
execution fabric. Verification requires target reduction and no new findings.
The default is a verified dry run; application needs a second authorization and
uses a cooperative lock, staged replacements, backups, per-file stale guards,
and guarded rollback.

## Workbench and responses

The local UI remains loopback-only with a per-launch token, origin/host checks,
strict CSP, a bounded worker queue, cancellation, secret-filtered diagnostics,
and text-only DOM writes. The 3.5 overview adds live cards for empirical
calibration, fail-closed sandbox eligibility, evidence-ledger size, symbolic
analysis, polyglot coverage, dependency graph proof, and Git impact.

`response35.py` renders only a valid Truth Guard 2 document. Responses lead with
the outcome and separately identify observed findings, verified/refused repairs,
coverage gaps, unknowns, and next actions. No-findings output is never upgraded
to “no bugs” or “completely secure.”

## Honest limitations

- Static and lexical analysis cannot prove the absence of all defects or practical exploitability.
- The symbolic engine is Python AST analysis; its operation bounds are not a mathematical runtime proof, so the 3.5 worker also enforces wall time.
- The symbolic worker enforces a 16 MiB aggregate input boundary; skipped inputs are reported as explicit coverage gaps.
- Polyglot IR is lexical and does not resolve compiler types, overloads, macros, reflection, generated code, or dynamic dispatch.
- Git blame candidates are not historically reproduced introducing commits.
- Real container execution was not available in the recorded Windows verification; runtime behavior was exercised with adversarial mocks and fails closed when capability is absent.
- Windows containers are detected but ineligible because equivalent Linux hardening controls are not proven.
- Multi-file application is rollback-based on ordinary files; a host crash or non-cooperating writer cannot be made mathematically atomic.
- Non-Python public-API preservation is a conservative heuristic.
- Exact dependency graphs currently cover three lockfile families; other inventory remains available through the inherited supply-chain center.
- The catalog size is not a recall, precision, security, or correctness guarantee.
- Unsigned Truth Guard 2 reports prove internal consistency only. Use HMAC authentication when the verifier does not trust the report producer or storage path.

See `VERIFICATION_3.5.md` for the recorded test, static-analysis, browser, and
release-integrity evidence.
