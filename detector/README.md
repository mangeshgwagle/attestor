# Attestor 4.1.4 profile-bound coding, repair, security, and research

`attestor414.py` is the current profile-bound maximum orchestrator. It wraps the
replay-verified 4.1.3 compatibility engines with one of three immutable policies:
`cockroach-janta-party` (maximum), `south-park` (balanced default), or
`gruppe-sechs` (lightweight). The profile controls selected components and
stage-specific resource ceilings; it never controls permissions, source
binding, offline defaults, fail-closed behavior, or Truth Guard requirements.

Cockroach Janta Party alone carries the custom `C3` response-language tier.
`C3` is Attestor-specific shorthand for an evidence-dense advanced technical
register, not an official CEFR level or proficiency certification. South Park
and Gruppe Sechs retain the existing `response41.py` response behavior. The
language policy is part of the canonical profile digest and is replay-checked
against the report response envelope, analyzer identity, structured Q&A, SARIF,
rendered header, and verified workbench result descriptor. It cannot be selected
as a request override and grants no permission.

The profile fields `max_files`, `max_file_bytes`, and `max_total_bytes` apply
to the `coding-static` worker's immutable snapshot, and `max_graph_nodes`
applies to that worker's semantic graph. They are not global limits for every
inherited 4.1.3 analyzer. Each inherited analyzer retains separately reported
internal caps, and its limit hits or omitted coverage remain explicit gaps.

## Cockroach-only local file and database control

`cjp_control414.py` provides a separate, exact-file route available only to the
canonical `cockroach-janta-party` profile. It is default-deny and does not turn
the profile's custom C3 language register into authority. The caller must supply
a strict request document and pass `--confirm-cjp-permission` for that invocation.
The resulting authorization is short-lived, bound to the exact local root,
relative paths, file SHA-256 values, action, stated organization and purpose,
and is consumable once only by the in-memory registry that issued it.

This route is suitable for local copies supplied by an authorized TCS/Tata
Consultancy Services custodian. The custodian could be the user's uncle, but
kinship alone grants no authority. Attestor records an issuer assertion and
explicitly reports that identity and legal authority were not independently
verified. It cannot determine that the sender is a TCS employee or that a file
may legally or contractually be edited.

The allowlisted request actions are:

- `inspect-files`: return content-free file identity metadata (relative path,
  SHA-256, size, suffix, and executable bit);
- `analyze-database`: inspect a checkpointed, sidecar-free SQLite file through
  a private immutable read-only snapshot and report schema metadata only, or
  lexically classify bounded UTF-8 SQL text without executing it;
- `preview-file-edit`: validate exact complete replacement bytes, stale source
  hashes, supported syntax where available, and redacted credential risk, then
  return a bounded diff when it is safe to emit.

SQL lexical classification is not a dialect parser, migration validator, or
live database connection. SQLite inspection does not query application rows,
scan application pages for integrity, or return row values. SQLite files are
read-only in this control route.

Application is a separate second phase. A preview-only run returns
`preview.preview_evidence_sha256`. A later apply run must repeat the unchanged
request and both confirmations, and supply that exact lowercase digest:

```sh
python3 superattestor.py --cjp-control --confirm-cjp-permission --format json -- permission-request.json
python3 superattestor.py --cjp-control --confirm-cjp-permission --apply-cjp-edit --confirm-cjp-apply --cjp-preview-evidence-sha256 <64-lowercase-hex-digest> --format json -- permission-request.json
```

The apply run re-authorizes and re-hashes the exact scope, recomputes the
preview, and refuses stale or mismatched evidence. Preview evidence binds both
root identities, the complete candidate, and per-file before/after hashes
independently of truncated or withheld display diffs. Application uses a
root-wide cooperative lock, a fresh exclusive transaction directory under an
existing explicit backup root, staged complete replacements, root/file identity
guards, atomic replacement, and bounded rollback attempts with reported errors.
Permission and result history remain session-only. Transaction reports expose
`cleanup_complete` and bounded, terminal-safe `cleanup_errors`; an applied edit
is not falsely relabelled as failed when only later cleanup fails, and the CLI
returns a warning exit in that case.

There is no TCS account, corporate-network, corporate-service, live-database,
credential, administrator/elevation, arbitrary shell/process, registry/service,
persistence, or drive-wide authority. Supplied SQL, migrations, and target code
are never executed. Artifacts with Attestor's blocked executable/system suffixes
are refused. See
[`../CJP_LOCAL_CONTROL_4.1.4.md`](../CJP_LOCAL_CONTROL_4.1.4.md) for the exact
request and candidate schemas.

## Private escape-lab simulation

`escape_lab414.py` is a sealed CJP defensive exercise built from six fixed,
pure in-memory policy graphs. Five graphs contain a planted authorization
mistake; the reference graph is contained. Attestor reports the exact synthetic
path, a compiled explanation of the defect, and a defensive mitigation.

```sh
python3 superattestor.py --escape-lab --format text
python3 superattestor.py --escape-lab --escape-scenario broker-confused-deputy --format json
```

This route accepts no arbitrary scenario, command, source, path, URL, payload,
or plugin. It performs no host file operation, deletion, process or shell launch,
network access, target-code execution, persistence, permission change, or real
escape attempt. It is separate from the runtime and execution labs. UI results
are session-only, and the prompt/path control is disabled for this mode.

The presentation-layer CJP deletion joke has been removed. Automatic deletion
authority and probability are 0%, the report states that through its safety
controls rather than through a punchline, and the local-control permission
contract is unchanged. The complete contract is in
[`../PRIVATE_ESCAPE_LAB_4.1.4.md`](../PRIVATE_ESCAPE_LAB_4.1.4.md).

The 4.1.4 layer preserves findings while `adjudication414.py` labels the supplied
evidence as supported, contested, or insufficient. It does not infer
contradictions from prose and does not treat the existence of a cited source line
as proof that the diagnostic is correct. `validation_opportunities_414` proposes
bounded next checks without generating commands or executing the target.

`attestor41.py` remains the 4.1.3 compatibility orchestrator. Its default path is offline
static analysis: it verifies the inherited Attestor 4.0 report, runs coding and
security passes in bounded child processes, merges normalized findings, prepares
review-only repairs, and places the public report behind Truth Guard 3. It does
not import or execute target code, contact the network, or apply a candidate.
Exact-file scope is not silently widened to the containing directory; unavailable
repository-level evidence is reported as a coverage gap.

Version 4.1.4 preserves the stable `/4.1` compatibility schemas, `*41.py` module names, and
`--attestor41` command-line mode while advancing current runtime and presentation
through the new `--attestor414 --variant <slug>` path. `--attestor413` and `--attestor41`
continue to route to the historical 4.1.3 maximum orchestrator.

## Inherited Attestor 4.1.3 analysis core

- `analysis_snapshot41.py` captures one immutable, content-addressed, symlink-
  rejecting view of eligible source within explicit file and byte limits. The
  semantic, correctness, and declarative-rule passes consume the same bytes.
- `semantic_graph41.py` uses CPython's parser for Python symbols, imports, calls,
  data dependencies, and bounded interprocedural taint witnesses. Its
  JavaScript/TypeScript evidence is explicitly structural and lexical, not
  compiler-grade.
- `deep_correctness41.py` reports bounded Python concurrency, resource-lifetime,
  and async-task candidates. It also compares supported API, schema, and migration
  formats only when an explicit immutable baseline is supplied. Static candidates
  are not runtime proof.
- `semantic_rule_sdk41.py` evaluates data-only `ast-call`, `ast-node`, and
  `flow-to-sink` rules. Packs require bounded metadata and positive/negative
  fixtures, have stable content digests, may use HMAC-SHA256 authentication, and
  cannot load executable plugins.
- `bounded_worker41.py` runs fixed internal coding/security actions with sanitized
  process state, input/output/time limits, and available OS resource limits. It
  executes Attestor analyzers, not target programs; platform limitations remain in
  the returned boundary evidence.

## Repair, security, and evidence contracts

- `repair_director41.py` creates deterministic mechanical Python candidates or
  ingests complete multi-file candidate JSON. It enforces path, completeness,
  stale-source SHA-256, file-count, and byte limits, then ranks bounded static
  comparisons. A candidate is labelled **unverified** until the inherited
  transactional scanner, build, and test gates pass in an eligible execution
  fabric. Application requires separate authorization after verification.
  SuperAttestor's `--improved-out` writes only complete inherited improvements that
  those proof gates accepted; it never writes a merely static-qualified 4.1
  review candidate into a source tree.
- `supply_chain_trust41.py` builds exact local dependency edges only when bounded
  lock/manifest data identifies both endpoints. It imports authenticated offline
  OSV snapshots without live package resolution. Legacy VEX output now permits
  `not_affected` only for a verified, content-addressed, exhaustive unreachable
  proof; ambiguous reachability remains under investigation.
- `secret_lifecycle41.py` scans the working tree plus explicitly supplied staged
  diffs, history exports, archives, and OCI-layer material. Findings do not expose
  secret values, prefixes/suffixes, reversible encodings, or hashes of the secret.
- `security_lab41.py` has fixed fuzz, sanitizer, mutation, and crash-minimization
  experiment contracts. It is deny-by-default, has no host runner, requires an
  eligible rootless execution fabric and a digest-pinned image, and uses disposable
  workspaces. The fabric rejects ambient remote container selectors and adds
  `--pull=never`; it does not silently fall back to weaker host execution.
- `attack_surface413.py` performs bounded, content-addressed, static web/API
  attack-surface analysis. It emits evidence-labelled entry points, sinks,
  graph paths, and threat-model factors, but neither attempts exploitation nor
  executes, imports, writes, or contacts the target.
- `security_posture413.py` passively scans caller-selected artifacts for bounded
  cloud, container, workflow, IAM, dependency, secret-lifecycle, SBOM, and binary
  metadata evidence. Secret values are never returned or hashed, and unsupported
  or truncated evidence remains an explicit gap.
- `security_validation413.py` defines digest-bound sandbox plans, exact expiring
  one-use authorizations, chained verified-repair gates, project-namespaced
  security regression memory, and evidence-state claim ledgers. These contracts
  do not self-authorize, retain permission, or apply changes.
- `truth_guard41.py` implements Truth Guard 3. A bindable finding carries the
  complete file SHA-256, exact byte range, evidence digest, and analyzer/config/
  input identities. Fresh verification rejects stale source and report tampering.
  Optional HMAC-SHA256 authenticates a shared-key boundary; this zero-dependency
  build has no public-key signature and makes no non-repudiation claim.
- `response41.py` renders professional, concise, mentor, direct, executive,
  classic, or technical output and supports report-scoped Q&A. It uses only a
  freshly verified Truth Guard 3 fact model, includes evidence IDs, and abstains
  from unsupported answers.
- `attestorbench41.py` validates operator-supplied held-out cases and observed
  Attestor-only, model-only, and hybrid records. It calculates classification,
  calibration, latency, memory, cost, completion, stochastic-repeat, and source-
  overlap metrics. It neither creates a benchmark corpus nor invokes a model.

## Non-coding public-web Research Mode

`research_engine41.py` is separate from code analysis. Without `--online` it
returns `network-authorization-required` and does not call a search provider.
With explicit authorization it uses Brave's documented
[Web Search endpoint](https://api-dashboard.search.brave.com/app/documentation/web-search/get-started)
and [subscription-token header](https://api-dashboard.search.brave.com/documentation/guides/authentication).
Provide the token as `BRAVE_SEARCH_API_KEY`; `BRAVE_API_KEY` is accepted as a
compatibility alias. The token is not included in the report.

The engine plans bounded queries, deduplicates and ranks results, emits source
IDs and short extractive passages, and flags possible lexical disagreements for
human adjudication. `--fetch-pages` additionally retrieves selected public pages,
validates DNS and every redirect against private/reserved-address SSRF, applies
response, time, redirect, and byte limits, and respects
[RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)-style robots rules. It
does not access private networks, dark-web services, paywalls, logins, credentialed
content, or forms. Attestor does not add a default result cache or persistence layer;
provider-side permissions and retention remain governed by the applicable
[Brave Search API terms](https://api-dashboard.search.brave.com/app/documentation/general/terms-of-service).
If a live provider plan does not affirm that retention is allowed, SuperAttestor
refuses a requested research `--out` write.

Research output is deterministic extractive evidence, not an independent factual
proof or professional advice. Search snippets can be incomplete or stale, page
retrieval can be refused by robots, and disagreement detection is lexical.

## Permissioned pathless computer scan

`computer_scan41.py` can discover eligible local code projects without requiring
the caller to supply a path. It is default-deny: `--computer-scan` alone returns
an authorization-required report and performs no discovery. Every actual run
must include `--authorize-computer-scan`; the loopback UI represents that as an
unchecked checkbox which is cleared after the run.

The default `home` scope searches within the current user's home folder. The
`fixed-drives` scope is an explicit broader choice covering local fixed drives.
Both scopes enforce directory, file, project, and depth budgets, refuse
links/reparse points and cross-filesystem mounts, and skip protected system,
browser-profile, credential, and cache areas. Selected-project analysis remains
subject to Attestor's ordinary file-size and aggregate-byte boundaries. Discovery
does not use the network, import or execute discovered code, write source, or
apply a change. `--computer-improve` requests only bounded review candidates; it
does not authorize an apply or source write. Project selection and every
unvisited or refused area remain visible as coverage gaps. The workbench keeps
computer-scan results session-only by default; retaining one requires an explicit
CLI `--out` path.

```sh
python3 superattestor.py --computer-scan --authorize-computer-scan --computer-scope home --computer-max-projects 3 --format json
python3 superattestor.py --computer-scan --authorize-computer-scan --computer-scope fixed-drives --computer-max-projects 6 --computer-improve --format json
```

## Inherited Attestor 4.0 boundary

`engineering_engine40.py`, `security_fabric40.py`, `truth_guard40.py`, and
`response40.py` remain available through `attestor40.py` and
`superattestor.py --attestor40`. Their bounded suggestions remain unverified until a
concrete candidate passes transactional scanner, build, and test gates. Truth
Guard 2.1 remains the 4.0 public response boundary and never turns static silence
into a claim that no defects exist.

The inherited 3.5 layer adds `symbolic_engine35.py`, `polyglot_ir35.py`,
`git_intelligence35.py`, `supply_chain35.py`, `calibration35.py`,
`execution_fabric35.py`, `transactional_repair35.py`, `truth_guard35.py`, and
`response35.py`. Their contracts are intentionally fail-closed: bounded symbolic
and lexical analysis reports its gaps; Git is read-only; confidence needs verified
labels; container execution needs explicit authorization and proven hardening;
repairs are dry runs unless separately apply-authorized; and all public maximum
reports must pass Truth Guard 2.

Verified remediation is deliberately narrower than detection: supported Python
AST shapes can produce a complete improved source and diff, while ambiguous or
unproven changes are refused. Preview is the default and never edits the target.
Selected tests and any apply operation require separate explicit authorization.

`truth_guard35.py` is the Attestor 3.5 public response boundary. It recursively
redacts the report, independently rebuilds the claim audit and content-addressed
evidence chain, verifies optional HMAC authentication, and withholds any document
that no longer matches. It also consumes the inherited `truth_guard.py` checks
for counts, locations, repair proof bundles, coverage, and abstention. Unsigned
local output is integrity-verified but explicitly not authenticated for a trust
boundary; `scan_clean` is never presented as runtime or behavioral correctness.

The previous 2.3 foundation includes a unified
multi-language workspace engine (`scanengine.py`), cross-file repository
intelligence (`repo_intel.py` / `projectbrain.py`), differential mutation testing,
transactional patch verification, guarded model-assisted generation, and an
enforceable CI quality gate. Static analysis remains offline and dependency-free;
external syntax tools and any generated-code execution are explicit opt-ins.

The inherited catalog contains **15,313 entries**: 64 core, 24 native,
23 extended-language, 202 advanced 2.2 entries, and 15,000 precision-flow 2.3
entries. The precision pack is a semantic matrix of 25 documented framework
profiles, 12 request channels, and 50 dangerous operations per language. It is
indexed by active framework/language, materialized lazily, and validates all IDs,
fingerprints, metadata, source fixtures, and sink fixtures. Semantic AST, taint,
graph, grading, and compiler checks add analysis beyond that catalog count. The
entry count is not a claim of universal coverage or 15,313 independent analyzers.

Fast paths:

```sh
python3 superattestor.py --attestor414 .. --variant south-park --format json
python3 attestor414.py .. --variant "Cockroach Janta Party" --issue "split the oversized service" --format text
python3 superattestor.py --attestor414 .. --variant gruppe-sechs --response-style technical --format text
python3 superattestor.py --research "Compare the public evidence" --online --format json
python3 superattestor.py --research "What changed this month?" --online --fetch-pages --format text
python3 superattestor.py --computer-scan --authorize-computer-scan --computer-scope home --computer-max-projects 3 --format json
python3 research_engine41.py "Summarize the public sources" --online --fetch-pages --format json
python3 repair_director41.py .. --issue "remove the supported unsafe construct" --format json
python3 attestorbench41.py --corpus held-out.json --results observed.json
python3 superattestor.py --attestor413 .. --format json  # 4.1.3 compatibility mode
python3 superattestor.py --attestor40 .. --format json  # compatibility mode
python3 superattestor.py --attestor35 .. --format json  # compatibility mode
python3 superattestor.py --attestor3 .. --format json  # compatibility mode
python3 attestor35.py .. --format text
python3 superattestor.py --improve app.py --format json
python3 superattestor.py --improve app.py --improved-out ../attestor-improved
python3 superattestor.py --semantic .. --format json
python3 superattestor.py --supply-chain .. --format spdx
python3 superattestor.py --repository-memory .. --out memory.json
python3 attestor_lsp41.py
python3 ci_integration.py .. --diff-from origin/main --format github
python3 superattestor.py --workspace .. --format json
python3 superattestor.py --mayhem .. --response-style professional
python3 superattestor.py --cybermayhem .. --format sarif
python3 scanengine.py .. --format sarif
python3 qualitygate.py .. --format markdown
python3 advanced_rules.py --self-test
python3 precision_catalog.py --self-test
python3 security_posture.py .. --format sarif
python3 attestor.py --self-test --seed 0
```

The original personalities remain available through `attestor.py`; machine-facing
automation should use `attestor414.py`, `superattestor.py --attestor414 --variant <slug>`,
`scanengine.py`,
`ci_integration.py`, or `qualitygate.py`. Use `--attestor40`, `--attestor35`, or
`--attestor3` only when an explicit compatibility report is required. Use
`--attestor413`/`--attestor41` only for an explicit 4.1.3 compatibility report.

Attestor finds the bugs real small/medium-company codebases actually ship — across
**C, C++, Haskell, Python and JavaScript/TypeScript**, plus leaked secrets in
**any** file — and tells you
about them in one of his **two personalities**. He (yes, `he` has a gender) does
**not** get to pick which one wakes up, and neither do you: it's random every run.
Both faces report the *same* findings; they just have very different mouths. One is
genuinely kind (modelled on a real, very patient friend named Attestor); the other
hates you personally. Profanity is **on by default** for the rude one (`--sfw`
muzzles it). The legacy `attestor.py --online` path checks code references through
GitHub and configured Google search; it is separate from the 4.1 non-coding
Research Mode documented above.

```
$ python3 attestor.py --severity HIGH realworld/
right. fuck. it's the bad one. sit down and look at what you've done, you muppet.

realworld/upload.c:13  [HIGH] scanf-unbounded
   what in the actual fuck, line 13: an unbounded %s lets input run past the buffer -- a classic stack smash. did you write this with your elbows?
   > scanf("%s", name);
   do this, you walnut: give %s a field width (e.g. %63s) or use fgets; never read unbounded input into a fixed buffer.
...
fuck you, you fucking knobhead, and fuck this repo specifically.
```

Under the attitude is the real engine ([`detect.py`](detect.py)) — dependency-free,
comment/string-aware, declaration-tracking static analysis. Attestor is the face;
`detect.py` is the brain and stays clean (and profanity-free) for CI.

## Meet him

```sh
python3 attestor.py --meet
```

| | |
|---|---|
| **AttestorVonLuneberg (the helpful one)** | the genuinely kind one — gentle, encouraging, quietly into grenadiers and old Lüneburg, never once makes you feel stupid (modelled on the real Attestor) |
| **attestor (fuck you, you fucking knobhead)** | hates you personally and has receipts; full profanity, all of it aimed at your code |

## Run him

```sh
python3 attestor.py                      # scan the bundled corpus, random persona
python3 attestor.py src/ app.py          # scan your own code (recurses)
python3 attestor.py --severity HIGH      # only the serious stuff
python3 attestor.py --deep               # higher-recall rules (noisier)
python3 attestor.py --online             # consult the internet for references
python3 attestor.py --deep --online      # think hard AND count how many others hit this
python3 attestor.py --sfw                # bleep the profanity (for the workplace)
python3 attestor.py --seed 7             # pin the persona + wording (reproducible/CI)
python3 attestor.py --json               # plain machine output (no persona; +refs if --online)
python3 attestor.py --sarif              # SARIF 2.1.0 for GitHub code scanning / CI
python3 attestor.py --meet               # who is Attestor?
python3 attestor.py --self-test          # prove he finds every planted + real-world bug
python3 attestor.py --list-rules
```

Exit code is the number of findings (so CI fails on a regression); `--self-test`
exits 0 only if every bug in the corpus was found.

```sh
python3 detect.py            # the plain engine, no personality (same detection)
python3 test_detector.py     # engine tests
python3 test_attestor.py         # persona-layer tests
```

## What he finds

**Real-world (the stuff teams ship):**

| Rule | Langs | Sev | Pattern |
|---|---|---|---|
| `hardcoded-secret` | any file | HIGH | password / API key / AWS key / private key committed in source or `.env` |
| `py-sql-injection` | Python | HIGH | query built with f-string / `%` / `.format` / concatenation |
| `py-mutable-default` | Python | MED | `def f(x=[])` shared across calls |
| `py-bare-except` / `py-except-pass` | Python | MED | swallowed exceptions |
| `py-is-literal` | Python | MED | `x is 0` / `is "..."` (identity vs value) |
| `py-eq-none` / `py-eq-bool` | Python | LOW | `== None` / `== True` |
| `unsafe-libc` | C/C++ | HIGH | `gets`/`strcpy`/`strcat`/`sprintf` |
| `scanf-unbounded` | C/C++ | HIGH | `scanf("%s")` with no width |
| `command-exec` | C/C++ | MED | `system`/`popen`/`exec*` |
| `float-equality` | C/C++ | MED | `==` / `!=` on floating point |
| `empty-catch` | C++ | MED | `catch (...) {}` |
| `assign-in-condition` | C/C++ | MED | `if (x = y)` |
| `c-return-local-address` | C/C++ | HIGH | returning `&local` / a local array (dangling pointer) |
| `c-strncpy-truncation` | C/C++ | MED | `strncpy` that may not NUL-terminate |
| `py-requests-no-timeout` | Python | MED | HTTP request with no `timeout=` (can hang forever) |
| `py-tempfile-insecure` | Python | MED | `tempfile.mktemp()` (TOCTOU race) |

**Security (the David-Bombal end of things):**

| Rule | Langs | Sev | The pattern |
|---|---|---|---|
| `tls-verify-disabled` | Python/JS | HIGH | `verify=False`, `rejectUnauthorized: false`, `CERT_NONE` |
| `dangerous-eval` | Python/JS | HIGH | `eval`/`exec`/`new Function` on non-literals |
| `format-string` | C/C++ | HIGH | `printf(user)` — non-literal format string |
| `py-yaml-load` | Python | HIGH | `yaml.load()` without a safe Loader |
| `py-subprocess-shell` | Python | MED | `subprocess(..., shell=True)` |
| `py-insecure-deserialize` | Python | MED | `pickle.loads` on untrusted data |
| `weak-hash` | Py/C/C++/JS | MED | MD5 / SHA-1 for security |
| `debug-enabled` | Python | MED | `DEBUG = True` / Flask `debug=True` |

**JavaScript / TypeScript:**

| Rule | Langs | Sev | The pattern |
|---|---|---|---|
| `js-loose-equality` | JS/TS | MED | `==` / `!=` (type coercion); use `===` |
| `js-innerhtml` | JS/TS | MED | `innerHTML =` / `document.write` (XSS sink) |
| `js-settimeout-string` | JS/TS | MED | `setTimeout("code", …)` (hidden eval) |
| `js-var` | JS/TS | LOW | `var` instead of `let`/`const` (deep) |

**Subtle / "almost no-one catches" (the planted corpus):** `unsigned-underflow`,
`strict-aliasing`, `signed-overflow-check`, `sizeof-pointer-arg`,
`map-operator-insert`, `object-slicing`, `rangefor-copy`, `vector-bool-proxy`,
`c-realloc-leak`, `c-memcmp-padding`, `cpp-use-after-move`,
`c-free-stack-address`, `c-malloc-strlen-no-nul`, `cpp-return-cstr-local`,
`cpp-delete-array-mismatch`, `hs-partial-function`, `hs-int-overflow`, `hs-lazy-foldl`, `hs-lazy-io`, `hs-lazy-error-field`.

**Deep-only (`--deep`, higher recall / more noise):** `weak-rng`,
`py-assert-validation`, `js-var`, `py-bind-all-interfaces`, `insecure-http-url`,
`todo-fixme`.

## SARIF / CI

`--sarif` emits SARIF 2.1.0, the format GitHub code scanning and most CI dashboards
ingest, so Attestor can gate merges like any professional analyzer:

```sh
python3 detector/attestor.py --sarif --severity HIGH src/ > attestor.sarif
# then upload attestor.sarif via github/codeql-action/upload-sarif, or read it in CI
```

Exit code is the finding count, so `attestor.py --severity HIGH || exit 1` fails a build
on any HIGH.

`python3 attestor.py --list-rules` prints the original core engine rules.
`python3 precision_catalog.py --list-rules` prints the 15,000 precision-flow
specifications, and `python3 codearena.py --json` reports the combined catalog.

## Legacy code-reference internet mode (`attestor.py`)

This inherited mode enriches code findings. It is not Attestor 4.1.3 Research Mode and
does not answer general non-coding questions.

- **`--deep`** turns on the higher-recall rule tier *and*, in online mode, asks the
  web how widespread each problem is.
- **`--online`** routes through the session's egress proxy. Attestor proves he's really
  connected (he prints a live GitHub *zen* quote), attaches authoritative
  references (CWE ids, language docs), and tries to reach each one — honestly
  tagging `reachable`, `blocked (policy)` when the egress policy denies a host, or
  `offline`. In `--deep --online` he reports real **GitHub** result counts, e.g.
  *"~1,825,306 issues mention 'SQL injection'"* — so when he says he checked many
  results, he means it. All network calls are bounded and degrade gracefully: the
  net failing never crashes or hangs a scan.
- **Google search** uses the official **Custom Search JSON API** (the ToS-compliant
  way to query Google programmatically). Set `GOOGLE_API_KEY` and `GOOGLE_CX`
  (a [Custom Search Engine](https://programmablesearchengine.google.com/) id) in
  the environment and `--deep --online` adds Google result counts + the top link
  alongside GitHub. Without those, Attestor says so plainly rather than faking it; he
  never scrapes `google.com` (which the egress policy blocks anyway).

  ```sh
  export GOOGLE_API_KEY=...    # https://developers.google.com/custom-search/v1/overview
  export GOOGLE_CX=...         # your programmable search engine id
  python3 attestor.py --deep --online --severity HIGH src/
  ```

## He can write code too (`codegen.py`)

Attestor doesn't only *find* bugs — he can scaffold a whole **production-shaped**
service. `codegen.py` is a deterministic code generator (the Rails-scaffold /
OpenAPI-codegen family, not an LLM): give it a spec of resources and it writes a
complete, **runnable, zero-dependency** Python service. Not just CRUD — the full
stack:

- **model** (dataclass + validation, email-format checks) → **repository**
  (parameterized SQLite: `count`/`exists`/per-field finders, bulk create,
  transactions, and **safe dynamic filtering/sorting** — column whitelist +
  bound values) → **service** (validation + pagination + **cache-aside**) →
  **HTTP handler** → **`app.py`** (routing, per-client **rate limiting**, request
  ids, `/health`, `/metrics`, `/openapi.json`, `/auth/*`, request logging)
- real **`security.py`** — PBKDF2-HMAC-SHA256 password hashing + hand-rolled
  **HS256 tokens** (stdlib `hmac`/`hashlib`, no dependencies) — wired end-to-end
  through **`accounts.py`** (register/login) with an **optional Bearer-token guard**
  on writes (`REQUIRE_AUTH`)
- **`cache.py`** (thread-safe TTL cache), **`metrics.py`** (request counters +
  Prometheus text), **`ratelimit.py`** (token bucket), **`retry.py`** (backoff
  decorator), **`validators.py`**, **`pagination.py`**, **`errors.py`** (typed API
  errors), **`middleware.py`**, **`openapi.py`**, **`health.py`**
- a **management CLI** (`manage.py migrate|seed|routes|openapi|serve`), a
  **client**, a **seed** script, **unit + integration tests**, a **CI workflow**,
  **Dockerfile**, **pyproject.toml**

It also ships a **curated internal "batteries" library** — distinct, real
engineering, *not* per-resource repetition: a safe fluent **query builder**, a
versioned **migration runner**, a **path router**, a **DI container**, an **event
bus**, a thread-pool **job queue**, a **circuit breaker**, **structured JSON
logging**, a **Result** type, and core **data structures** (LRU cache, ring
buffer, trie, priority queue) — each with its own passing tests.

```sh
python3 codegen.py --out ./svc --check    # generate, then let Attestor review the result
python3 codegen.py --resources 20 --check # dial the size: ~10,600 lines, 285 tests
python3 codegen.py --spec myspec.json      # your own resources
python3 codegen.py --stdout-only           # just report the line count
```

The default 4-resource demo emits **~3,850 lines across ~82 files**. And it scales:
`--resources N` keeps the fixed library and adds ~425 lines per resource, so
**`--resources 20` emits ~10,600 lines across ~162 files with a 285-test suite.**
The recorded generator checks are designed around secure defaults — secrets from
the environment, parameterized SQL (whitelist + bound values), HTTP timeouts,
PBKDF2 (never md5/sha1), no `eval`, no bare excepts, no dead code — and in the
recorded fixtures **both enabled Attestor engines reported zero findings** while the
generated service's **own test suite passed** (threaded integration tests boot the real server, drive CRUD over
HTTP, and prove the auth guard blocks then allows). All asserted in `test_codegen.py`.

```
$ python3 codegen.py --resources 20 --out ./svc --check
AttestorVonLuneberg wrote 10611 lines across 162 files into ./svc/  (20 resources)
...that's over a thousand lines. He'd like that noted.
[check] Attestor reviewed his own output: 0 findings.
```

**Honest footnote:** those ~10,600 lines are ~1,600 of *distinct* library plus
`20 × ~425` lines of *near-identical* per-resource code. It's all real, runnable,
tested and clean — but scale past the library is a template being stamped, not
novel logic. 10k lines of scaffold ≠ 10k lines an engineer reasoned out, and Attestor
won't pretend otherwise.

## You can talk to him in English (`nl.py`) — honestly

A **real** natural-language→code path is an LLM, and Attestor doesn't have one (no API
key that works, no model). `nl.py` is the honest approximation: a **bounded intent
parser**, not understanding. It recognizes a fixed vocabulary and maps it to code
Attestor genuinely produces — and it refuses, out loud, when a request falls outside
that grammar. Pattern-match in, real code out, or "I don't know that one." Never a
hallucinated answer.

```sh
python3 nl.py "make a rest api for Book with fields title, author, year (int)" --out ./svc
python3 nl.py "write fibonacci"
python3 nl.py "review codegen.py"
```

- **Scaffold** (the genuine win): plain English → a parsed resource spec →
  `codegen`. *"create a rest api for Book with fields title, author, year (int),
  price (float)"* becomes a **1,770-line service whose own 44 tests pass** — no
  rigid JSON required.
- **Snippet**: *"write fibonacci"* (also factorial, palindrome, reverse a string,
  fizzbuzz, gcd, prime, binary search) returns a vetted implementation from a
  **curated library** — labelled as *recognition, not reasoning*. Ask for the 9th
  problem it doesn't know and it gives you nothing, on purpose.
- **Review**: *"find bugs in x.py"* runs the detector (both engines on Python).
- **Anything else**: an honest refusal listing what it *does* understand — because
  faking comprehension it doesn't have would be the one thing Attestor never does.

Offline `nl.py` alone is still honest: without a provider key it only parses the
bounded things it recognizes, and refuses everything else. With `--brain`,
`superattestor.py`, `forge.py`, or `curry.py`, novel requests go through the
multiplied path instead: provider APIs write, Attestor statically reviews, the
crucible runs the code, and request-specific smoke tests check common algorithm
behavior before anything is accepted. `codebench.py` now keeps those two truths
separate: direct Attestor-alone generation is 0/6; Attestor+APIs is a verified coding
loop rather than blind model output.

### One door for everything: `superattestor.py`

All of the above behind a single command. Give it *anything* — a file, a
directory, a GitHub link, or plain English — and it picks the right power:

```sh
python3 superattestor.py detect.py                                   # deep read (10 passes)
python3 superattestor.py "make an api for Book with fields title"    # scaffold
python3 superattestor.py "write a red-black tree" --out rbt.py       # forge (needs a key)
python3 superattestor.py https://github.com/o/r/blob/main/app.py     # fetch + review + improve
```

Its brain is the full configured sibling chain: Groq -> OpenRouter -> Mistral ->
Gemini -> OpenAI, with local Ollama available as a private backstop when
`OLLAMA_MODEL` is set. With a sibling awake, novel requests go through the
**forge loop** (LLM writes, both engines verify, behavior checks run, repair
until clean); with no key, every offline power still works and unknown requests
get an honest refusal, never a faked answer. "Super-intelligent" is the
marketing name; one dispatcher over a deterministic toolkit plus optional
LLM providers is the truth.

### The multiplication: `forge.py` — the model writes, Attestor verifies

This is the payoff of having both halves. `nl.py --brain` lets an LLM *write*;
`forge.py` closes the loop so the LLM writes code that Attestor has actually *checked*:

```
the LLM (Groq/Qwen, ...)         GENERATES the code
Attestor's two engines               STATIC-VERIFY it (regex detect + AST deepscan)
the safe mechanical issues       get AUTO-FIXED
the crucible (crucible.py)       RUNS it in a bounded subprocess -- does it work?
request-specific smoke tests     CHECK common algorithm/data-structure behavior
whatever fails (static/run/behavior) goes BACK to the LLM to REPAIR
...loop until it's clean, runs, and passes known behavior checks (or the rounds run out).
```

The **third leg is execution** (`crucible.py`): static analysis proves the code
*looks* right; the crucible proves it *runs* right. That closes the one gap static
analysis can never close on its own — a subtle logic bug is valid code that
executes wrong, and only running it catches that. The crucible runs candidates in
a **bounded** subprocess (fresh temp dir, hard timeout, no shell) — that bound is
deliberate and stays; running generated code with *no* limit is how you brick a
machine, not a feature. `forge --no-run` drops back to static-only if you want it.

```sh
python3 forge.py "an LRU cache class with a TTL" --rounds 4 --out lru.py
```
```
round 1: model wrote 24 lines; auto-fixed: == None -> is None; Attestor -> 2 static issue(s) -> back to the model
round 2: model wrote 27 lines; Attestor -> static-clean but CRASHED (NameError) -> back to the model
round 3: model wrote 29 lines; Attestor -> clean AND runs
RESULT: Attestor-verified -- zero findings from both engines, and it actually runs.
```

Why it *multiplies* rather than adds: the LLM's weakness (stochastic, ships bugs)
is exactly Attestor's strength (deterministic verification), and Attestor's weakness (can't
write novel code) is exactly the LLM's strength. Neither half does this alone. The
LLM brings the ideas; Attestor brings the ground truth. Needs a working key; if the
model 429s mid-loop, forge stops and hands back the best verified version so far.
The loop/repair orchestration is fully tested offline (`test_forge.py`) with a
scripted stand-in for the model.

### Set your keys once (`keys.env`)

Instead of `export`/`$env:` every session, put your keys in a file. Copy the
template, fill in what you have, and every tool reads it automatically:

```sh
cp keys.env.example keys.env      # then edit keys.env
# GROQ_API_KEY=gsk_...
# OLLAMA_MODEL=qwen2.5-coder
python3 superattestor.py "write a trie" --curry
```

`keys.env` is **gitignored** — your keys never leave your machine. A real shell
env var still wins over the file, so CI and one-offs keep working. (`brain.py` and
`gemcheck.py` load it on startup; `ATTESTOR_ENV_FILE=/path` points elsewhere.)

### The thick curry: `curry.py` — every model cooks, Attestor serves the best

`forge.py` trusts one model and repairs it. `curry.py` is the **ensemble**: it asks
*every* configured provider (Groq/Qwen, OpenRouter, Mistral, a local Ollama leaf…)
the same request, then Attestor **tastes each dish with all three senses** — the regex
detector, the deepscan AST engine, and the crucible (*does it actually run?*) —
scores them, and serves the cleanest.

```sh
python3 curry.py "a function that flattens a nested list"
python3 superattestor.py "an LRU cache" --curry        # the pot, via the one door
```
```
  cook         findings runs    lines
  ----------------------------------------
  qwen         0        yes     5  <- served
  mistral      1        yes     2
  ollama       0        NO      1
RESULT: served qwen's dish -- clean and it runs.
```

It's an ensemble, **not a vote** — the winner is the dish with the fewest problems
that *still runs*, not the most popular answer. (Notice: qwen and ollama both had
zero static findings, but only qwen's actually *ran* — that's the crucible earning
its place on the tasting panel.)

**The local leaf — Ollama** (`OLLAMA_MODEL`): models running on *your own machine*
via `ollama serve` — **no key, no rate limit, never a 429, fully private**. It sits
last in the fallback chain as the backstop that always answers when every cloud
tier is throttled:

```sh
ollama pull qwen2.5-coder        # once
export OLLAMA_MODEL=qwen2.5-coder # + OLLAMA_HOST to relocate the server
python3 superattestor.py "write a trie"   # now the local leaf is in the pot
```

### Bolt on a real brain (`brain.py`) — optional, bring your own key

If you *do* have a working LLM key, `brain.py` gives Attestor a real natural-language
brain. It holds **five providers at once** — **Groq, OpenRouter, Mistral, Gemini,
and OpenAI** (all OpenAI-compatible except Gemini) — and runs them **alongside**
each other two ways:

- **fallback** (default): try them in reliability order — **Groq → OpenRouter →
  Mistral → Gemini → OpenAI** — so a 429/404 on any one **cascades to the next**,
  and if all are down it drops back to the deterministic parser. This *is* the fix
  for Google's stingy free-tier 429s: the throttle just falls through to a sturdier
  free tier automatically.
- **compare**: ask *every* configured provider and show all answers side by side.

```sh
export GROQ_API_KEY=...        # + GROQ_MODEL       (default llama-3.3-70b-versatile;
                               #   GROQ_MODEL=qwen/qwen3-32b for the Qwen sibling)
export OPENROUTER_API_KEY=...  # + OPENROUTER_MODEL (free models use a ':free' tag,
                               #   e.g. qwen/qwen-2.5-coder-32b-instruct:free)
export MISTRAL_API_KEY=...     # + MISTRAL_MODEL    (MISTRAL_MODEL=codestral-latest for code)
export GEMINI_API_KEY=...      # + GEMINI_MODEL     (default gemini-2.0-flash)
export OPENAI_API_KEY=...      # + OPENAI_MODEL     (e.g. gpt-4o)
python3 nl.py "write a trie" --brain
python3 forge.py "an LRU cache" --model qwen/qwen3-32b   # just Qwen + Attestor
python3 brain.py "reverse a linked list" --compare       # every provider, side by side
```

**Why more free tiers = fewer 429s:** each of Groq/OpenRouter/Mistral has a
free tier far more forgiving than Gemini's, and the fallback chain hops to the next
the instant one throttles. All are wired with the *verified* endpoints (e.g. Groq
is `https://api.groq.com/openai/v1` — not `https://groq.com`, the URL a certain
chatbot likes to hallucinate). No SDKs — raw HTTPS via `urllib`, keys from the
environment, fully tested offline. Live-call reachability varies by sandbox:
**Gemini's endpoint is on this environment's egress allowlist**, while the others
are reachable from a normal machine but blocked in this particular sandbox.

## He reviews a whole codebase and writes a report (`audit.py`)

Point Attestor at a **directory of source you legitimately have** — a repo you were
added to, a zip a client handed you — and he runs **both engines over the entire
tree** (the regex detector across C/C++/Haskell/Python/JS + secrets, and the
deepscan AST analyzer on the Python), aggregates it, and writes a report you can
hand to a team.

```sh
python3 audit.py ./their_repo                                  # summary + findings
python3 audit.py ./src --severity HIGH --format md --out review.md   # a markdown deliverable
python3 audit.py ./src --format sarif > review.sarif           # for CI / code scanning
python3 superattestor.py ./their_repo                              # same, via the one door
```

```
Code review -- ./their_repo
================================================================
scanned 4 files; 7 finding(s) in 4 file(s)
  HIGH 4   MEDIUM 2   LOW 1

most common issues:
     1  hardcoded-secret       1  unsafe-libc       1  undefined-name  ...
files needing the most attention:
     3  src/svc.py       2  app.js       1  config.env
```

`--format md` produces a Markdown report (summary table, most-common-issues table,
top files, every finding grouped by file); `--format sarif` emits SARIF 2.1.0 for
GitHub code scanning. Exit code is the finding count, so it gates CI like any
analyzer. This is the clean, defensible way to review someone else's code: you were
*given* the source, and Attestor tells you what's wrong with it — no reaching into
anyone's private systems required.

## He reviews live websites too (`webscan.py`)

Point Attestor at a **live company website** and he reads the public front-end it
serves your browser — the exact HTML/JS you'd see in *View Source* — explains how
the page is built, finds the bugs in its JavaScript, and (with a brain wired up)
hands back corrected code.

```sh
python3 webscan.py https://example.com
python3 webscan.py https://example.com --scripts 3            # also fetch linked .js
python3 webscan.py https://example.com --brain --out fixed.js  # corrected code
python3 superattestor.py https://example.com                       # same, via the one door
```

```
how https://acme.example is built
============================================================
title       : Acme Corp
inline JS   : 1 block(s)   linked JS : 1 file(s) from cdn.acme.com   forms : 1

JavaScript bugs Attestor found (5):
  inline-script[0]:3 [MEDIUM] js-innerhtml: use textContent, or sanitize ...
  inline-script[0]:4 [HIGH]   dangerous-eval: parse/dispatch explicitly ...
  inline-script[0]:5 [MEDIUM] js-settimeout-string: pass a function reference ...
markup smells:
  [inline-event-handler x2] ... blocked by a strict Content-Security-Policy ...
  [mixed-content x1] resource(s) loaded over http:// ...
```

Scope, honestly: this GETs one **public** page (and, with `--scripts`, a bounded
number of the `.js` files it links) and reviews what comes back — the same code
your browser already downloads. No login, no bypass, no private data, no write
requests; **server-side code is not visible from the outside and is not touched.**
Attestor's deep AST read and auto-fixer are Python-only, so on JavaScript he *reports*
and (with `--brain`) *rewrites*, rather than mechanically patching. Parsing +
review are tested offline (`test_webscan.py`); the live fetch works from any normal
machine (blocked only inside a restricted-egress sandbox).

## He can read the world's code too (`harvest.py`)

`harvest.py` sends Attestor to **GitHub**. Give it **either a direct file link or a
code-search query**: it fetches the file, reviews it with **both engines** (the
regex detector, and for Python the deepscan AST analyzer), applies the handful of
**safe mechanical fixes** automatically, flags the rest for a human, and writes an
improved copy — citing the source repository and license. It uses only the GitHub
API (auth via `GITHUB_TOKEN`); **no Anthropic key required**.

```sh
# paste a link -- reviews and improves that exact file
python3 harvest.py https://github.com/owner/repo/blob/main/app.py
python3 harvest.py https://raw.githubusercontent.com/owner/repo/main/x.py --print

# or search, and Attestor picks a matching file
python3 harvest.py "verify=False" --lang python
python3 harvest.py "strcpy(" --lang c --pick 1 --print
```

```
Fetched acme/widgets/client.py directly from the link:
  source : acme/widgets/client.py
  license: MIT
  Attestor found 8 issue(s); auto-fixed 5, 3 left for a human.
  auto-fixes: == None -> is None x1; bare except -> except Exception x1;
              verify=False -> verify=True x1; md5 -> sha256 x1; debug=True -> debug=False x1
    line 7  [MEDIUM] py-requests-no-timeout: always pass timeout=...
    line 10 [MEDIUM] py-except-pass: at least log the exception...
    line 15 [HIGH]   undefined-name: check for a typo, a missing import...  ← only the AST engine sees this
  wrote improved file -> attestor_harvest/client.py
```

Auto-fixes are limited to unambiguous, mechanical rewrites (`== None` → `is None`,
`verify=False` → `verify=True`, `md5` → `sha256`, bare `except:` →
`except Exception:`, `DEBUG=True` → `DEBUG=False`); everything riskier is reported,
not silently rewritten. It fetches at runtime and writes locally — it does not
redistribute anyone's code, and it prints the license so you can respect it.
(A blocked-egress sandbox may 403 the live fetch; the parse/review/improve/write
path is fully covered by `test_harvest.py`.)




## He forges new detector-rule candidates (`ruleforge.py`)

Rule Forge is Attestor's safe self-improvement lane for the detector itself. Feed it a
local file, a GitHub file URL, or a GitHub code-search query; it mines suspicious
bug shapes, generates candidate `@rule` code, generates positive and negative
tests, and only marks a candidate proven when the bad sample is caught and the
clean sample stays quiet. It writes reviewable artifacts instead of silently
patching `detect.py`.

```sh
python3 ruleforge.py app.py --out-dir attestor_ruleforge
python3 ruleforge.py "parseInt(" --lang javascript --limit 3 --out-dir attestor_ruleforge
python3 superattestor.py --ruleforge "timeout=None" --lang python --out attestor_ruleforge
```

Promotion is still disciplined: inspect the generated snippets, apply the rule,
and run the full suite. Attestor gets sharper by proof, not by vibes.

## He gates model patches (`patchforge.py`)

Patch Forge is the risky-fix lane. Attestor first applies the safe mechanical fixes;
for every remaining finding, he asks the configured API model(s) for a complete
replacement file. A patch is accepted only after it passes Attestor's static scan,
`crucible.py`, request-aware behavior checks when available, and any regression
commands you provide.

```sh
python3 patchforge.py app.py --request "merge sorted lists" --out fixed.py
python3 superattestor.py --patchforge app.py --out fixed.py
```

No key means no fake patch. A model proposal that fails any gate is rejected.

## He makes bug reproducers (`reproducer.py`)

Bug Reproducer turns a finding into a tiny file plus a `unittest` that proves the
same rule still fires. It greedily removes lines while preserving the finding, so
you get a small runnable witness for debugging, issue reports, or Patch Forge.

```sh
python3 reproducer.py app.py --out-dir attestor_reproducer
python3 superattestor.py --reproduce app.py --out attestor_reproducer
```

## He reads whole projects (`projectbrain.py`)

Project Brain analyzes a tree instead of a single file: imports, call graph,
environment/config usage, API routes, database query sites, dead-code candidates,
and suspicious request-to-sink flow candidates.

```sh
python3 projectbrain.py .
python3 superattestor.py --projectbrain .
```

## He attacks his own output (`mutation_gauntlet.py`)

Mutation Gauntlet injects subtle bugs into Python code and checks whether Attestor's
static rules or behavior tests catch them. Any surviving mutant becomes a new
rule target for Rule Forge.

```sh
python3 mutation_gauntlet.py generated.py --request "write fibonacci"
python3 superattestor.py --gauntlet generated.py
```

## He scores and remembers (`confidence.py`, `fixmemory.py`, `codearena.py`)

Every finding now carries severity plus confidence, exploitability, and
`safe_to_autofix` status in human, JSON, and SARIF output. Fix Memory records
safe repair patterns seen repeatedly by `evolve.py` into an inspectable JSON
memory. Code Arena prints the dashboard: rule count, planted-bug recall, false
positives, generated-code cleanliness, forge success rate, evolve improvements,
and mutation-gauntlet catch rate.

```sh
python3 codearena.py
python3 fixmemory.py
python3 superattestor.py --arena
python3 superattestor.py --fixmemory
```

## He carries Darwin payloads (`darwin.py`)

Darwin is now merged as a portable Attestor module. The original Darwin archive had
hard-coded `F:\temp` paths, a syntax error in the export tool, README/CLI drift,
and a server tied to one directory. Attestor's wrapper fixes those: the payload data
is bundled under `darwin_payloads/`, commands use `argparse`, exporters are
syntax-checked, and the local web UI serves from the bundled directory.

```sh
python3 darwin.py stats
python3 darwin.py list
python3 darwin.py search "graphql" --limit 10
python3 darwin.py show "API Security" --limit 20
python3 darwin.py export "SQL Injection" --format csv --out sql_payloads.csv
python3 darwin.py serve --port 8080

python3 superattestor.py --darwin search graphql --limit 10
python3 superattestor.py "darwin show API Security"
```

This is a defensive research payload library. Attestor stores and searches payloads;
he does not attack targets for you.

## He evolves harvested GitHub code (`evolve.py`)

This is the self-improving coding loop in one command: Attestor pulls code from
GitHub, reads it in repeated structural passes, applies the safe fixes he can
prove, re-scans the improved version, and repeats until the file stabilizes.

```sh
python3 evolve.py https://github.com/owner/repo/blob/main/app.py --out-dir evolved
python3 evolve.py "verify=False" --lang python --limit 3 --cycles 5
python3 superattestor.py --evolve "verify=False" --lang python --out evolved
```

Each output file keeps provenance (`repo/path`, URL, license), records the fixes
that were applied, and lists whatever still needs a human or a brain-backed forge
pass. Honest boundary: Attestor improves the harvested code; he does not silently
rewrite his own detector rules unless you explicitly edit Attestor himself.

## He reads a file deeply, then improves it (`comprehend.py`)

`comprehend.py` is the "read it 10–15 times, form a clear picture, then make it
better" idea — done honestly. Point it at a file (path **or** GitHub URL) and it
reads in a sequence of **real passes** — skim the shape → parse to an AST → trace
dependencies → map definitions → measure complexity → check documentation → build
the call graph → scan for known bug patterns → scan for semantic bugs → find safe
fixes — then prints the **picture it formed**, what needs work, and applies the
mechanical fixes it's sure of.

```sh
python3 comprehend.py detect.py
python3 comprehend.py messy.py --fix --out clean.py
python3 comprehend.py messy.py --brain          # + real-LLM suggestions if a key is set
```

```
Attestor read messy.py in 10 passes:
  read  1  skim the shape             30 lines (23 code, 7 blank/comment)
  read  2  parse to a syntax tree     parses cleanly
  read  5  measure complexity         hottest path: fetch_user (cyclomatic 4)
  read  9  scan for semantic bugs     4 issue(s) from the AST engine
  ...
  → forms the structural picture (imports, defs, call graph, hot spot),
    lists 9 issues (incl. an AST-only undefined-name), auto-fixes 5.
```

**The honest word is "structural."** More passes build a richer model of *how the
code is assembled* — genuine comprehension of structure — and catch the bug
classes the engines know. They do **not** grant understanding of *intent*, and the
auto-fixes are mechanical. For deeper, novel improvements it hands off to a real
model: `--brain` asks Gemini/OpenAI (via `brain.py`) once you have a working key.
So the pipeline is: **deterministic deep-read (always) → real-LLM improvement
(optional).** Covered offline by `test_comprehend.py`.

## How does he compare to an LLM? (`benchmark.py`)

You can't really put Attestor head-to-head with a frontier LLM (GPT-5.5, Claude, …)
on "coding" in general — they're **different kinds of tool**. Attestor is
deterministic static analysis + template scaffolding; an LLM is a reasoning model
that writes novel code from a prompt. On open-ended "here's a task, write it" work
the LLM wins and Attestor isn't even a competitor — and `benchmark.py` says so out loud.

But on a handful of **narrow, objective axes** a fair fight exists, and you don't
need the model in hand: measure Attestor, then paste the LLM's number from a public
leaderboard (SWE-bench Verified, HumanEval, LiveCodeBench, Aider polyglot) or a
friend with access.

```sh
python3 benchmark.py          # the scorecard (Attestor's column filled, LLM's blank)
python3 benchmark.py --json   # machine-readable metrics
```

| metric | Attestor | GPT-5.5 |
|---|---|---|
| Bug-detection recall (labelled corpus) | **100%** (42/42) | ? |
| False positives on the generated clean corpus | **reported by this run** | ? |
| Determinism (same input → same output) | **yes** | no (stochastic) |
| Cost per run | **$0.00** | $ per token |
| Latency (full corpus scan) | **hardware/sample-specific; emitted by `benchmark.py`** | seconds |
| Runs fully offline / air-gapped | **yes** | needs egress |

…and the rows Attestor simply **can't** play (novel logic from a spec, understanding
intent, non-boilerplate algorithms, SWE-bench-style generation) are listed as
LLM wins, because pretending otherwise would be dishonest. Compare them only on
the fair rows; anywhere else is apples-to-oranges.

**"…and *coding*?"** — the pointed version of the question gets its own honest,
measured answer in **`codebench.py`**. It runs Attestor against four coding axes:

```sh
python3 codebench.py     # the coding scorecard
```

| coding axis | Attestor | GPT-5.5 |
|---|---|---|
| **Direct generative** -- Attestor alone, no provider API | **0/6** | ~all |
| **Attestor + APIs** -- forge/curry: provider writes, Attestor verifies behavior | **gate-tested offline** | model-dependent |
| **Scaffolding** -- structured spec -> whole service | **1/1** (compiles, clean) | flexible but non-deterministic |
| **Mechanical bug-fixing** -- known defect classes | **4/4** (0/1 when it needs *reasoning*) | broad |

The honest split is now sharper: **Attestor alone** still scores ~0 at novel
plain-English code generation. **Attestor multiplied with provider APIs** is the
new coding path: the model proposes code, then Attestor rejects anything that fails
static review, import/runtime checks, or request-specific behavior tests.
Different jobs: direct Attestor is deterministic review/scaffolding; Attestor+APIs is
a verified coding loop.

## How he stays precise (low false positives)

- **Comment/string blanking** runs first (per language, including Python triple
  quotes), preserving line/column numbers, so he only ever flags real code — never
  the bug described in a comment. Secrets are the deliberate exception (they live in
  string literals, so that rule reads raw lines).
- **Declaration tracking** scopes the fuzzy rules: `unsigned-underflow` only on
  names declared unsigned, `map-operator-insert` only on `std::map` vars,
  `object-slicing` only on classes with `virtual`, `sizeof-pointer-arg` only on real
  pointer parameters. Unquoted `.env` secret matching is restricted to text/config
  files so it can't fire on code like `pw = get_pw()`.
- The test suite asserts **zero findings** on clean, corrected C/C++/Haskell/Python.

## He actually reads Python (`deepscan.py`)

`detect.py` matches patterns line by line. `deepscan.py` does something different:
it parses Python to an **AST** and reasons about *structure* — scopes, control
flow, the call graph, which names are bound where. That buys two things regex
can't.

**1. It explains how the code works** (`--explain`): module purpose, imports,
every class/function with its signature and **cyclomatic complexity**, the
intra-module **call graph**, and the single hottest (most complex) path to read
first.

```sh
python3 deepscan.py harvest.py --explain
```
```
how harvest.py works
============================================================
purpose : harvest.py -- Attestor goes to GitHub, reads real code, and improves it.
size    : 172 lines (139 of code)
top-level functions (6):
  def improve(content)  [complexity 3]
  def main(argv=None)   [complexity 15]
call graph (who calls whom, within this module):
  main -> fetch
  main -> improve
hot spot : main is the most complex path (cyclomatic complexity 15) -- read it first.
```

**2. It finds bugs regex fundamentally cannot** — both the common and the very
rare:

| Rule | Sev | What it catches (and why it's an AST job) |
|---|---|---|
| `undefined-name` | HIGH | a name used but never bound / imported / passed in *anywhere in the module* — a would-be `NameError` (needs whole-module name binding, not a line) |
| `assert-tuple` | HIGH | `assert (cond, "msg")` — a non-empty tuple is **always truthy**, so the assert never fires (the classic silent test) |
| `return-in-finally` | MED | a `return`/`break` in a `finally` **swallows the exception in flight** (needs to know the statement is in the finally *block*, skipping nested defs) |
| `dict-duplicate-key` | MED | `{"a": 1, "a": 2}` — the first value is silently dropped |
| `except-unordered` | MED | `except Exception` before `except ValueError` — the specific handler is **dead** (needs the exception hierarchy) |
| `redefined-function` | MED | same name `def`'d twice in a scope — the first is shadowed (skips `@property`/`@x.setter`) |
| `unreachable-code` | MED | a statement after `return`/`raise`/`break`/`continue` |
| `self-comparison` | MED | `x == x` (a typo) — but **not** `x != x`, the deliberate NaN check |
| `float-equality` | MED | `x == 0.5` on a float literal |
| `unused-import` | LOW | imported, never referenced (bails on `*`-imports it can't reason about) |
| `shadow-builtin` | LOW | `list = ...`, a param named `id`, etc. |
| `syntax-error` | HIGH | the file doesn't parse — reported cleanly instead of crashing |

It's precise on purpose: it skips the NaN `!=` idiom, honours `__all__`, treats
`except X as e` as a real binding, and **bails entirely** on `exec`/`eval`/`globals`
(where names can appear from nowhere) rather than cry wolf. On the whole detector
codebase it reports **zero** false positives (asserted in `test_deepscan.py`) —
it did find one genuine dead import in Attestor's own `online.py`, which is now gone.

Attestor wires it in automatically: **`attestor.py --deep` on a `.py` file** layers these
AST findings on top of the regex engine (overlapping rules are suppressed so
nothing is reported twice).

```sh
python3 deepscan.py path/to/file.py             # findings
python3 deepscan.py path/to/file.py --explain    # how it works + findings
python3 deepscan.py src/ --min-severity HIGH     # recurse a tree
python3 attestor.py --deep app.py                     # same AST read, in persona
python3 test_deepscan.py                          # 35 tests, all offline
```

## He measures maintainability (`metrics.py`)

detect and deepscan find *bugs*. `metrics.py` measures the thing a reviewer sees
first — *is this function too much?* Per function/method (nested and `async`
included) it reports:

- **cyclomatic complexity** (McCabe) — the number of independent paths.
- **cognitive complexity** (SonarSource) — how hard the code is to *follow*. Every
  control-flow break scores +1, and a break nested inside others costs +1 more per
  level, so deep code hurts more than flat code with the same branch count. This is
  the sharper signal: two functions can share a cyclomatic number of 8 while one
  reads straight down and the other is a pyramid — cognitive complexity tells them
  apart.
- **nesting depth**, **length**, and **argument count**.

Exit code = functions over threshold, so CI gates on it like detect.py.

```sh
python3 metrics.py app.py                 # per-function report
python3 metrics.py src/ --max-cognitive 12
python3 metrics.py app.py --top 5         # the 5 gnarliest, ignore thresholds
```

## The verdict: one letter, every engine (`grade.py`)

`grade.py` is the capstone. It runs detect + deepscan + metrics over a file or
tree and fuses them into a single **A–F grade and 0–100 score**, then tells you
*what to fix first* — serious findings, then the gnarliest functions, ranked by
impact. Correctness dominates: real findings can sink a file to F, while
complexity alone caps out around a D (a bug-free but dense module is a maintenance
risk, not a failure). The exit code is the number of files below the pass grade,
so one command gates a whole tree.

```sh
python3 grade.py app.py                   # full breakdown + fix-first list
python3 grade.py src/ --pass B            # CI gate: nothing ships below a B
python3 grade.py src/ --json              # machine-readable
python3 superattestor.py --grade src/         # same, in persona (or the UI's Code Grade)
```

An earlier build of this also reported a Halstead maintainability index; it was
cut because that formula conflates file *size* with quality — it scored clean,
well-factored modules "unmaintainable" for merely being long, the exact false
alarm Attestor refuses to raise. Cognitive complexity carries that signal honestly.

## The same quality suite, for C / C++ / Assembly (the `native*` engines)

Everything above (find bugs → measure complexity → grade → review a change) also
exists for native code, no compiler required. Each blanks comments and string/char
literals first, so a keyword in a literal never trips a rule.

- **`nativescan.py`** — the long C/C++/Assembly bug net: `gets`/`strcpy`/`sprintf`,
  format-string bugs, `system()` on a variable, assignment-in-condition,
  `sizeof(pointer)` in `memset`/`memcpy`, returning the address of a local,
  `strlen()` in a loop, C++ slicing catches, `delete this`, C-style casts, a
  duplicate assembly label, and more — each with a severity and a fix.
- **`nativemetrics.py`** — cyclomatic *and* cognitive complexity per function
  (brace matching for C/C++, labels for assembly).
- **`nativegrade.py`** — one A–F grade per file, fusing nativescan + polyglot +
  nativemetrics, with a ranked fix-first list. Correctness dominates; complexity
  alone caps at a D. Exit code = files below the pass grade.
- **`nativereview.py`** — reviews a *change*: old vs new file, reports only the
  findings the diff INTRODUCED (matched by rule + source-line text, so moving code
  never looks like a new bug) plus the grade delta. Exit code = introduced
  findings, so a bad C/C++ PR fails CI.
- **`nativetestgen.py`** — scaffolds a compilable C/C++ test harness from a source
  file: one stub per function, inputs wired and zero-initialised, a TODO where the
  expected value goes. (No oracle, so it builds the structure; you supply truth.)
- **`nativepool.py`** — `--jobs N` (0 = all cores) on the scanners: the per-file
  work is embarrassingly parallel, so a big native tree grades in a fraction of
  the wall-clock time.

```sh
python3 nativegrade.py src/ --pass B --jobs 0        # gate a native tree at B, all cores
python3 nativereview.py old/parser.c new/parser.c    # what did this change break?
python3 nativescan.py kernel.c --min-severity HIGH   # only the serious stuff
python3 nativetestgen.py math.c > test_math.c        # scaffold the tests
```

## Honest limitations

Attestor is a fast, line/regex engine with lightweight scoping — not a full parser or
data-flow analyzer. Pointer parameters are tracked per file (not per function),
deeply nested generics can slip past the declaration scanners, and the Haskell
`--` comment/operator split is simple. He errs toward silence and pairs every
finding with the compiler flag, sanitizer, or language feature that confirms it.

`deepscan.py` closes part of that gap for **Python** — it's a real AST analyzer,
not regex — but it deliberately reasons at module granularity (name binding is
over-approximated across the whole module, not resolved per-scope with shadowing),
so it favours silence over false alarms: it will miss some real bugs rather than
invent fake ones. It is not a type checker or a data-flow engine.
