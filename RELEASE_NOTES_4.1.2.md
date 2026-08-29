# Attestor 4.1.2 release notes

Attestor 4.1.2 is a hardening release for the evidence-bound 4.1 family. It keeps
the existing `--attestor41` command, `*41.py` module names, Truth Guard 3 contract,
and `/4.1` report schemas. Runtime, UI, LSP, extension, release-manifest, and
human-facing version fields now identify the product as `4.1.2`.

The release does not claim that static analysis proves a program safe or that
all defects have been found. Coverage gaps, refused inputs, cancellations,
unavailable evidence, and output limits remain part of the public result.

## Accuracy and evidence integrity

- AttestorBench no longer treats failed, timed-out, cancelled, or skipped records as
  completed quality observations. Case and rule collections are validated as
  exact bounded lists, reference hashes must be bounded SHA-256 hex values, and
  within-case repeat disagreement is reported explicitly.
- Truth Guard checks the final guarded document against its public byte limit
  after ledger and evidence material are attached. Oversized public output is
  refused rather than emitted as a nominally verified report.
- Evidence-locked responses escape terminal control, bidi, and escape sequences;
  normalize unknown severities consistently; and add an aggregate citation when
  a report has more claims than can be listed individually.
- Evidence history is namespaced by normalized project root so identical finding
  fingerprints from different projects cannot share triage or suppression state.
  Database-size enforcement is transactional, clearing history also clears its
  policy rows, and canonical research exports use the research verifier.
- A computer-wide scan now records excluded, linked/reparse, cross-filesystem,
  and unreadable areas as coverage gaps. One malformed project result is isolated
  instead of aborting every selected project.

## Bounded coding and editor analysis

- The deep analyzer consumes the same immutable snapshot as the other 4.1
  analyzers and is invoked once per worker request. Semantic data-flow and public
  deep-correctness collections stop at their configured budgets and add explicit
  gap records instead of building unbounded hidden intermediates.
- Snapshot traversal now bounds entries per directory and total gap records.
  File identity is compared before, during, and after reads so changed or linked
  inputs are rejected from the captured evidence view.
- Workspace LSP requests have lock-protected cancellation state with terminal
  cleanup, so request IDs can be reused safely. The stdio reader can accept
  `$/cancelRequest` while analysis is running, and workspace diagnostics apply an
  aggregate byte budget with `attestorCoverage` metadata when results are partial.
- The VS Code extension and its allowlisted server bundle are versioned 4.1.2.
  The generated server manifest binds every bundled file to its exact byte count
  and SHA-256 digest; the extension still provides preview-only edits and never
  calls `workspace.applyEdit`.

## Defensive-security hardening

- ZIP and TAR inspection counts every archive header before deciding whether to
  skip it, enforces read-time expansion limits, rejects encrypted or linked
  members where applicable, and refuses ZIP/TAR polyglots as OCI layers.
- Release verification independently validates manifest structure, canonical
  path ordering, counts, byte totals, manifest digest, duplicate/case-colliding
  names, unsafe paths, encrypted entries, non-regular metadata, unexpected
  entries, and per-file content digests.
- Release-tree auditing rejects secret-bearing environment variants such as
  `.env.production` and `.env.local` while permitting explicitly named template
  examples. Cross-platform unsafe path components are refused.
- Supply-chain manifest identities are computed from the exact raw UTF-8 bytes,
  so newline normalization cannot preserve a stale manifest digest. The graph
  digest now includes the normalized analysis root, binding a graph to its scope,
  and display-facing graph/advisory fields visibly escape terminal and bidi
  controls rather than emitting them literally.
- Offline OSV snapshots and authenticated semantic rule packs use domain-separated
  HMAC inputs which bind the schema, purpose, algorithm, trusted `key_id`, and
  payload SHA-256. Relabelling a valid tag under another key identifier therefore
  fails authentication even when two identifiers resolve to the same key bytes.
- Semantic rule-pack files are decoded as bounded UTF-8 strict JSON and reject
  duplicate object keys instead of accepting the JSON parser's last value. The
  semantic-result verifier now checks the exact report, finding, gap, budget,
  pack, digest, and static-execution shapes; display fields also reject raw
  terminal/bidi controls.
- Final boundary checks stream manifest reads through a hard byte cap, require
  exact HMAC-envelope fields, fail closed on recursively malformed graphs, and
  append terminal escape sequences atomically so an output cap cannot cut an
  escape token. Previously HMAC-signed OSV snapshots and semantic rule packs
  must be re-signed because the authenticated message now binds its domain and
  `key_id` as well as its payload digest.
- The Repair Director reuses the transactional repair path validator, including
  Windows device-name and portability rules. Provider JSON rejects duplicate or
  recursively unbounded structures, and provider/baseline files are size-checked
  before and during reads.
- The secret-lifecycle privacy verifier accepts only its bounded known evidence
  shape; raw secret material is rejected instead of being silently carried into
  a supposedly redacted report.

## Research, CLI, and workbench behavior

- Robots handling follows RFC 9309 product-token matching rather than substring
  matching, compares normalized URI octets for rule specificity, and permits the
  implicit `/robots.txt` retrieval needed to obtain the policy itself.
- JSON CLI mode keeps stdout to one JSON document; persistence notices are sent
  to stderr. Research reports are not added to durable UI history unless the
  provider explicitly affirms retention permission.
- Report-producing UI jobs refuse stdout beyond the 4 MiB boundary as a failed,
  partial result instead of parsing an apparently clean tail. History responses
  include fresh verification state, and the workbench preserves project identity
  when presenting historical or computer-scan results.
- Current response, research, repair, computer-scan, UI, LSP, and help text now
  say Attestor 4.1.2. Historical 4.1 reports and compatibility labels retain their
  original identity.

## Verification status

The final post-change detector discovery ran **1,310 tests: 1,295 passed, 15
expected skips, and 0 failures or errors** in 206.295 seconds. Attestor's seeded
corpus check detected all **42/42** planted bugs. The 202-rule advanced catalog,
15,000-rule precision catalog, Python worker verification, and JavaScript syntax
checks also passed.

The isolated coding and security self-scans completed with their internal
digests verified. They retain explicit coverage gaps and deliberately detect
credential-like fixtures in bundled test, payload, and known-vulnerable sample
corpora; these are not relabelled as a zero-finding result. Exact evidence,
limitations, packaging procedure, and sidecar boundary are recorded in
`VERIFICATION_4.1.2.md`. The final archive SHA-256 and full source manifest remain
adjacent to the archive because an archive cannot contain its own final digest.

## Stable compatibility boundaries

- Maximum report schema: `attestor-maximum/4.1`
- Computer-scan schema: `attestor-computer-scan/4.1`
- Research schema: `attestor-research/4.1`
- Current CLI flag: `--attestor41`
- Current maximum module: `attestor41.py`
- Current LSP module: `attestor_lsp41.py`

The default coding/security path remains offline and does not execute target
code. Research network access, verification-lab execution, and source application
remain separate explicit authorizations. HMAC-SHA256 authenticates a shared-key
boundary when configured; it is not a public-key signature or non-repudiation.
