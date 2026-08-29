# Attestor 4.1 release notes

Attestor 4.1 adds an evidence-bound analysis layer to the verified Attestor 4.0
foundation, an explicitly authorized Research Mode for non-coding questions,
and a separately authorized pathless local project-discovery mode. The default
maximum path remains offline static analysis. It does not execute target code,
call a provider, or edit the workspace.

The release version is `4.1.0`; its maximum-report schema is
`attestor-maximum/4.1`.

## Current entry points

```sh
python3 detector/superattestor.py --attestor41 . --format json
python3 detector/attestor41.py . --issue "trace the authorization failure" --format text
python3 detector/superattestor.py --attestor41 . --response-style technical --format text
python3 detector/superattestor.py --computer-scan --authorize-computer-scan --computer-scope home --computer-max-projects 3 --format json
```

`superattestor.py --attestor41` and `attestor41.py` are the current maximum-analysis paths.
The unversioned dispatcher continues to expose the rest of Attestor's specialized
tools; selecting 4.0, 3.5, or 3.0 is always explicit.

## Permissioned pathless computer discovery

`computer_scan41.py` finds eligible local code projects without accepting a
target path. The capability is default-deny: discovery begins only when the same
invocation includes `--authorize-computer-scan`. UI consent starts unchecked and
is cleared after every run. `home` is the narrow default scope;
`fixed-drives` is a separate broader selection for local fixed drives.

The walker is bounded by project, directory, file, and depth limits; selected
analysis is also subject to Attestor's normal file-size and aggregate-byte limits. It
skips protected system, credential, browser-profile, and cache areas; refuses
symlinks/reparse points and cross-filesystem mounts; and does not access the
network, import or execute target code, write source files, or apply repairs.
`--computer-improve` enables only review-only candidate preparation. The report
identifies discovered/selected projects and records exclusions, limits, and
incomplete coverage rather than claiming a complete computer audit. Broad scan
paths are session-only in the workbench; durable retention requires an explicit
CLI `--out` path.

## One immutable analysis view

`analysis_snapshot41.py` captures eligible regular files into one immutable,
content-addressed snapshot. It:

- reads each captured file at most once;
- rejects symlinks and detects files that change during capture;
- applies file-count, per-file, and total-byte budgets;
- records skipped, unsupported, changed, and limit-hit evidence as gaps; and
- performs no imports, process creation, network access, target execution, or
  filesystem writes.

The snapshot exposes deterministic added/removed/changed/unchanged evidence for
two captured views. The semantic graph also exposes an in-memory facts cache keyed
by path, source SHA-256, and adapter identity. This is content invalidation inside
a caller process, not an undisclosed persistent source cache.

## Semantic graph and deep correctness

`semantic_graph41.py` builds a shared repository graph from the snapshot. Python
uses CPython's parser for modules, symbols, imports, calls, control-flow-shaped
edges, data dependencies, and bounded interprocedural source-to-sink witnesses.
JavaScript/TypeScript receives a bounded structural lexical adapter. Unsupported
languages and adapter limits are explicit gaps; lexical evidence is not described
as compiler-grade.

`deep_correctness41.py` adds bounded static candidates for:

- Python concurrency and lock-order concerns;
- resource-lifetime and child-process reaping concerns;
- unobserved asynchronous tasks;
- supported OpenAPI, JSON Schema, Avro, GraphQL, and Protobuf compatibility
  changes; and
- destructive or newly introduced migration shapes.

Compatibility conclusions require an explicitly supplied immutable baseline.
GraphQL, Protobuf, and SQL adapters are labelled lexical. Deadlock, race,
resource, async, and migration results remain static candidates rather than
runtime or production-behavior proof.

## Declarative semantic Rule SDK

`semantic_rule_sdk41.py` adds data-only `ast-call`, `ast-node`, and
`flow-to-sink` selectors. A pack must pass schema checks, stable identity checks,
positive fixtures, and negative fixtures before evaluation. Optional detached
HMAC-SHA256 authentication can protect a shared-key distribution boundary.

The SDK has no executable plugin lane: it does not import rule code, accept a
regular-expression program, execute the target, use the network, or write the
workspace. Semantic SDK findings are additional analysis results; they are not
inflated into the inherited catalog-entry count.

## Bounded analyzer workers

`bounded_worker41.py` exposes only fixed `coding-static` and `security-static`
actions. It starts an isolated Python child with sanitized environment state,
bounded JSON input/output, a wall timeout, and available operating-system CPU,
address-space, descriptor, and file-size limits. The child loads Attestor analyzers,
not target modules.

Windows cannot provide every POSIX resource primitive through this standard-
library worker. That platform difference is returned as boundary evidence rather
than hidden. A timeout, malformed report, oversized output, or unavailable
component fails closed and becomes a coverage gap.

## Repair Director

`repair_director41.py` manages bounded complete-source candidates. It can:

- produce deterministic mechanical Python candidates for supported remediation
  shapes;
- ingest strict JSON candidates from an external producer without contacting
  that producer itself;
- require every changed file and expected original SHA-256;
- reject incomplete, stale, duplicate, traversal, link, oversized, and
  out-of-scope changes;
- compare scanner output before and after in a disposable static workspace; and
- rank multiple review candidates using observed evidence.

Complete candidate output is still **unverified**. Only the inherited
`transactional_repair35.py` scanner, build, and test gates in an eligible
execution fabric can label it verified. Applying a verified candidate requires a
separate apply authorization and retains stale-input checks, staging, backup,
locking, per-file guards, and rollback.

The unified `--improved-out` export writes only complete inherited improvements
accepted by those proof gates. Static-qualified Repair Director output stays in
the report as an unverified review artifact and is not exported by that flag.

The default director path does not invoke a model/provider, import target code,
run target code, or apply a change. Including full candidate source in public
JSON is an explicit output choice because source can contain sensitive material.

```sh
python3 detector/repair_director41.py . --issue "replace the supported unsafe call" --format json
python3 detector/attestor41.py . --candidate-json candidate.json --include-candidate-source --format json
```

## Defensive security improvements

### Supply-chain trust

`supply_chain_trust41.py` creates bounded local dependency graphs from supported
lock and manifest formats. It emits an edge only when local material identifies
both endpoints; it does not install, resolve, or import dependencies. Every graph
reports parser exactness and gaps.

Accepted offline OSV snapshots are content-addressed, sequence-checked, and
HMAC-authenticated. Importing a snapshot is not a live vulnerability refresh and
HMAC is not a public-key signature.

The inherited supply-chain path received two fail-closed corrections:

- package-lock root edges now require an actual graph root node; and
- an external `false`/unreachable result can no longer produce VEX
  `not_affected` by itself.

CycloneDX VEX and OpenVEX use a non-affected disposition only after a verified,
content-addressed, exhaustive reachability proof for the exact component.
Everything else stays under investigation or unknown.

### Secret lifecycle

`secret_lifecycle41.py` analyzes the working tree and explicitly caller-supplied
staged diffs, history exports, ZIP/TAR archives, and OCI-layer material. It
enforces artifact, member, finding, per-file, and total-byte limits and rejects
unsafe archive traversal/link shapes.

Findings identify the secret class and location without returning the secret,
its prefix or suffix, a reversible encoding, or a hash of the secret. A report
does not prove revocation or absence from unprovided Git history, registries,
backups, build logs, or remote systems.

### Security Verification Lab and execution fabric

`security_lab41.py` defines fixed fuzz, sanitizer, mutation, and
crash-minimization experiment contracts. It is deny-by-default and has no host
runner. An experiment requires explicit authorization, a caller-configured
digest-pinned image, an eligible rootless Linux Docker/Podman fabric, a
content-addressed scope, and a disposable workspace.

The execution fabric now adds `--pull=never` and rejects ambient Docker/Podman
host/context selectors that could redirect a probe or run to a remote daemon.
Existing protections remain: no network, read-only root, dropped capabilities,
`no-new-privileges`, non-root user, resource limits, bounded output, timeout
cleanup, and no weaker host fallback.

Authorized lab experiments can execute selected target/toolchain material inside
that container. The ordinary Attestor 4.1 maximum scan does not authorize or start a
lab experiment; it reports the capability as not run.

## Truth Guard 3

`truth_guard41.py` is the Attestor 4.1 public evidence boundary. For each bindable
finding it records:

- the complete source-file SHA-256;
- an exact bounded byte range and digest of those bytes;
- rule, configuration, analyzer, and input-manifest identities; and
- a deterministic evidence-ledger and report digest.

Fresh verification can re-read the requested scope and reject stale source,
modified evidence, inconsistent counts, scope changes, and unsupported report
claims. Secret-like values are recursively redacted before the public boundary.
Truth Guard does not turn a zero-finding or partially covered scan into proof that
the repository is correct or secure.

Optional HMAC-SHA256 provides shared-key authentication:

```sh
python3 detector/superattestor.py --attestor41 . \
  --truth-key-file report.key --truth-key-id release-ci --format json
```

This dependency-free build does not implement public-key signatures. HMAC does
not provide non-repudiation, public verification, signer identity, or key
transparency. Use an external signing system if those properties are required.

## Responses, Q&A, UI, and editor

`response41.py` builds its fact model only from a freshly verified Truth Guard 3
document. It supports `professional`, `concise`, `mentor`, `direct`, `executive`,
`classic`, and `technical` styles. Report-scoped Q&A cites evidence IDs and
abstains when the report does not support an answer.

The loopback workbench now defaults to Attestor 4.1 and exposes explicit 4.0/3.5/3.0
compatibility choices. Its posture card is `Unrated` when coverage is unavailable
and `Partial` when gaps exist; it does not display a strong posture solely because
the loaded subset has no findings. Research Mode is a CLI surface in this release
and is not silently activated by the workbench.

`attestor_lsp41.py` provides bounded diagnostics for in-memory editor buffers and
declared workspace roots. It never writes source and never sends
`workspace/applyEdit`; any candidate change is a consent-gated preview. Live LSP
diagnostics are a bounded deterministic editor core, not the full maximum report.

## AttestorBench 4.1

`attestorbench41.py` evaluates an operator-supplied held-out corpus against supplied
observations for three lanes: Attestor-only, model-only, and hybrid. It computes:

- case and rule precision, recall, F1, and false-positive rate;
- Brier score and ten-bin expected calibration error;
- median, p95, and maximum latency and peak memory;
- observed cost, completion, timeout, and failure rates;
- stochastic repeat disclosure; and
- source-hash overlap against caller-supplied reference hashes.

The release gate requires at least 1,000 held-out cases, positive and clean cases,
complete lanes, repeated stochastic lanes, a performed reference-overlap audit,
and no detected reference overlap. AttestorBench does not manufacture cases, run
models, or fill missing records.

```sh
python3 detector/attestorbench41.py \
  --corpus held-out.json --results observed.json \
  --reference-hashes training-hashes.json
```

## Research Mode for non-coding questions

Research Mode is deliberately separate from code analysis. The offline call:

```sh
python3 detector/superattestor.py --research "What does the public evidence say?" --format json
```

returns `network-authorization-required`; it does not perform a search. Live
search requires both an explicit flag and an environment-provided Brave key:

```sh
# Set BRAVE_SEARCH_API_KEY in the trusted caller environment first.
python3 detector/superattestor.py --research "Compare the latest public reports" --online --format json
python3 detector/superattestor.py --research "Compare the underlying pages" --online --fetch-pages --format text
```

`BRAVE_API_KEY` is accepted as a compatibility alias. The provider token is sent
only in the authentication header and is not added to the report.

The mode performs bounded query planning, result deduplication/ranking, source-ID
assignment, and short extractive evidence selection. Excerpts are limited to 25
words and 240 characters. Possible numeric or negation disagreements are flagged
lexically and left for human adjudication. Search snippets remain weaker evidence
when pages are not fetched or page retrieval fails.

`--fetch-pages` accepts only public HTTP(S) URLs. It rejects credentials,
non-default ports, control characters, private/reserved IP addresses, invalid DNS
answers, and unsafe redirects; it pins the validated address while preserving TLS
hostname verification. Robots, time, redirect, content-type, response-size, and
extraction limits apply.

Attestor does not submit forms, log in, bypass authentication or paywalls, access
private networks or dark-web services, or add a default result cache/persistence
layer. Provider behavior and storage rights remain outside Attestor's control.

The implementation follows Brave's official
[Web Search endpoint guide](https://api-dashboard.search.brave.com/app/documentation/web-search/get-started)
and [authentication guide](https://api-dashboard.search.brave.com/documentation/guides/authentication).
Page policy follows the matching model in
[RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html). Review the applicable
[Brave Search API terms](https://api-dashboard.search.brave.com/app/documentation/general/terms-of-service)
before storing or redistributing provider results.
SuperAttestor also refuses a requested live-research `--out` write when the active
provider plan does not declare result retention as allowed.

Research output is extractive public evidence, not independent fact verification,
professional medical/legal/financial advice, or a substitute for reviewing the
linked primary sources. Search indexes and snippets may be stale, incomplete, or
misleading.

## Compatibility

Attestor 4.0, 3.5, and 3.0 remain available without relabelling their schemas or
evidence boundaries:

```sh
python3 detector/superattestor.py --attestor40 . --format json
python3 detector/superattestor.py --attestor35 . --format json
python3 detector/superattestor.py --attestor3 . --format json
```

Existing specialized modes such as `--semantic`, `--supply-chain`, `--improve`,
`--workspace`, `--mayhem`, and `--cybermayhem` remain available. Use
`--attestor41` when the unified 4.1 maximum report and Truth Guard 3 boundary are
required.

The inherited precision catalog still validates 15,000 precision-flow entries,
and the inherited aggregate documentation records 15,313 catalog entries. Those
numbers describe catalogued specifications, not universal safety, defect recall,
or an equal number of compiler-grade analyses. Attestor 4.1 does not fabricate a new
rule count for its graph, correctness, supply-chain, or lifecycle passes.

## Known limitations

- Static analysis can miss defects, report candidates that do not reproduce at
  runtime, and cannot infer unstated product intent.
- Python semantic evidence is parser-derived; other adapters vary and report
  their own evidence level and gaps.
- Deep correctness is bounded. Runtime scheduling, production configuration,
  database state, and remote service behavior are not observed by default.
- Exact-file maximum analysis is deliberately not widened to its parent tree, so
  repository-only 4.1 passes are reported unavailable for that scope.
- Offline advisory results are only as current and trustworthy as the imported
  snapshot and key handling.
- Secret scanning cannot prove rotation, revocation, or absence from material the
  caller did not supply.
- Repair candidates are not verified merely because they parse, scan better, or
  rank first. Scanner, build, and test gates are still mandatory for the verified
  label.
- HMAC is a shared-key integrity/authentication mechanism, not a public signature.
- Research Mode covers the normal public web only and depends on the configured
  provider and accessible public pages.
- No zero-finding result is a universal claim that code is error-free or secure.

Release verification results, skipped checks, environment details, and package
hashes belong in `VERIFICATION_4.1.md`; this document intentionally does not
claim a test passed until that verification record is produced.
