# Attestor 4.1.2 verification record

This record describes the Attestor 4.1.2 source used to build the adjacent release
archive. Results are bounded evidence from this build, not a guarantee that no
defect, vulnerability, or undiscovered project exists.

## Environment

- Verification date: 2026-07-22
- Host: Windows
- Python: 3.12.13 (bundled isolated runtime)
- JavaScript checks: Node.js 24.14.0 (bundled runtime)
- Product version: `4.1.2`
- Maximum-report schema: `attestor-maximum/4.1`
- Computer-scan schema: `attestor-computer-scan/4.1`
- Research schema: `attestor-research/4.1`

## Automated tests

The final full discovery command was equivalent to:

```text
ATTESTOR_NODE=<bundled-node> python -B -m unittest discover -s detector -p "test_*.py"
```

Result: **1,310 tests run; 1,295 passed, 0 failed, 0 errors, and 15
skipped** in 206.295 seconds, with exit code 0. Skips remained explicit and
included unavailable Windows link privileges and separately optional host/tool
integration. No skipped check was counted as passed.

An earlier run encountered two anomalous Git subprocess deadlines while the host
clock reported impossible elapsed values. The affected 14-test Git module then
passed with 13 successes and its one expected link skip in 8.303 seconds, and the
complete clean run above passed afterward.

Focused post-fix verification also included:

- security boundary regressions: 40 run, 39 passed, 1 expected link skip;
- version and VS Code bundle gates: 13 passed, 0 skipped;
- promotion, CLI, LSP, research, Truth Guard, and UI gates: 122 passed, 2
  expected skips;
- snapshot regressions: 7 passed;
- UI regressions: 59 passed;
- computer scan: 16 run, 15 passed, 1 expected link skip;
- transactional repair: 16 run, 15 passed, 1 expected link skip; and
- Repair Director: 12 run, 11 passed, 1 expected link skip.

`node --check` accepted `detector/ui/ui23.js`, the VS Code extension, and the
server-staging script.

## Detector and catalog evidence

The seeded Attestor corpus check considered 19 files, produced 48 findings, and
detected **42/42 planted bugs**. The Advanced catalog self-check accepted 202
rules with zero errors. The Precision catalog self-check materialized exactly
15,000 rules across 25 profiles and five language groups, with zero errors.
These inventory totals are not claims of 15,202 independent compiler-grade
analyses or perfect recall.

## Isolated self-scan evidence

The final coding worker completed with its wrapper, result, snapshot, semantic
graph, and deep-correctness digests verified. It captured 308 files and
4,824,158 bytes, reported zero deep-correctness findings, and recorded no target
execution/import, network access, or filesystem write.

It also reported its limitations instead of claiming complete coverage. The
4,560,962-byte defensive payload catalog exceeded the 2 MiB per-file snapshot
limit, and no compatibility baseline was supplied. Its 561 semantic graph gaps
comprised 252 conservative control-flow merges, 253 not-fully-interprocedural
parameter-taint cases, 46 unsupported-language cases, 6 bounded JavaScript
structural cases, 3 unavailable JSON semantic-adapter cases, and the one
oversized file.

The final security worker completed with its wrapper and internal digests
verified and no target execution, network, Git, or source write. It reported 44
credential-pattern detections: 1 critical, 26 high, and 17 medium. All were in
bundled detector tests, defensive payload data, or intentionally vulnerable
`realworld` samples. Values stayed withheld. This is intentionally reported as
44 fixture/sample detections, not rewritten as a zero-finding security scan.

Supply-chain analysis was unavailable because this source tree supplied no
supported dependency manifest or resolved graph. Bazel, Maven, Gradle, and live
registry resolution remained explicitly unavailable rather than inferred.

On Windows, the worker's wall-clock boundary is enforced but standard-library
per-process memory isolation and kernel network sandboxing are unavailable. The
offline worker contract disables network use and the report records its effects;
this is not represented as a kernel-enforced sandbox.

## Errors found and fixed

Verification and adversarial review found real defects before this final state.
Regression-covered fixes include:

- failed, cancelled, timed-out, or skipped benchmark records no longer improve
  quality scores;
- terminal, bidirectional, and control characters are escaped at every reviewed
  response, graph, advisory, and path display boundary;
- oversized final Truth Guard/UI output fails closed instead of presenting a
  truncated or falsely clean report;
- evidence history is project-root scoped, size enforcement is transactional,
  and clearing history also clears its policy rows;
- computer scanning exposes excluded, linked, cross-filesystem, unreadable, and
  limit-truncated coverage and isolates malformed project results;
- snapshot capture, semantic collections, diagnostics, provider input, archive
  expansion, and packaging reads all have verified bounds;
- LSP cancellation state is concurrency-safe and aggregate diagnostics carry
  explicit partial-coverage metadata;
- repair paths reject portable Windows device aliases, Unicode-normalization and
  case collisions, links, and oversized components;
- release verification independently rejects missing, duplicate, extra,
  case-colliding, unsafe, encrypted, linked, or content-mismatched entries;
- supply-chain identities bind exact raw manifest bytes and the normalized graph
  root; and
- authenticated OSV snapshots and semantic packs use strict, domain-separated,
  key-ID-bound envelopes, while semantic JSON rejects duplicate keys and
  recursively malformed reports fail closed.

Previously HMAC-signed OSV snapshots and semantic packs must be re-signed for
4.1.2 because the authenticated message now binds its domain and signer identity.

## Release package evidence

The source and copied release tree are independently audited. The audit rejects
forbidden caches, virtual environments, build output, transcripts, bytecode,
links, case collisions, unsafe paths, secret-bearing environment variants, and
release-boundary violations. Their canonical manifests must match before an
archive is built.

Packaging performs two independent deterministic builds with sorted entries,
fixed timestamps, normalized modes, bounded sizes, CRC checks, and per-file
SHA-256 verification. Promotion requires byte-identical archive SHA-256 values
and a successful independent archive verification. The exact canonical manifest,
verification booleans, and final archive SHA-256 are stored next to the archive
in `Attestor 4.1.2.manifest.json` and `Attestor 4.1.2.zip.sha256`. They are deliberately
external: an archive cannot truthfully contain its own final digest without
changing that digest.

## Deliberate limits

- Static findings are review evidence, not proof of exploitability.
- No-finding results do not prove absence of defects, secrets, or hallucination.
- Bounded pathless discovery does not inspect every file on a computer.
- Refused, unreadable, excluded, unmounted, or limit-truncated areas remain gaps.
- Non-Python adapters may be lexical or structural rather than compiler-grade.
- Live advisories, deployed state, runtime behavior, builds, fuzzing, and
  performance require separately supplied evidence or explicit authorization.
- Review-only improvements are never applied until a concrete candidate passes
  configured scan/build/test proof gates and the operator approves that patch.
