# Attestor 4.1.3 verification record

This record describes the Attestor 4.1.3 source used to build the adjacent release
archive. Results are bounded evidence from this build, not a guarantee that no
defect, vulnerability, hallucination, or undiscovered project remains.

## Environment

- Verification date: 2026-07-26
- Host: Windows, UTC+05:30
- Python: 3.12.13 (bundled isolated runtime)
- JavaScript checks: Node.js 24.14.0 (bundled runtime)
- Product version: `4.1.3`
- Maximum-report schema: `attestor-maximum/4.1`
- Computer-scan schema: `attestor-computer-scan/4.1`
- Research schema: `attestor-research/4.1`

## Automated tests

The final complete discovery command was equivalent to:

```text
ATTESTOR_NODE=<bundled-node> python -B -m unittest discover -s detector -p "test_*.py" -v
```

Result: **1,385 tests run; 1,368 passed, 0 failed, 0 errors, and 17
skipped** in 370.681 seconds, with exit code 0.

The skips were explicit: 15 tests required Windows link/symlink privileges that
were unavailable, and two live-network integration tests remained disabled
without `ATTESTOR_LIVE_TESTS=1` and their required provider credentials. No skipped
check was counted as passed.

Focused post-fix verification included 27 Attestor 4.1.3 orchestration tests: 26
passed and one Windows link-privilege test skipped. These cover strict component
selection, worker digest-chain replay, compact public-report boundaries, omitted
field commitments, exact embedded-child links, stale/tampered report refusal,
HMAC replay, file-scope containment, and fail-closed compatibility behavior.

The final JavaScript and editor gates also passed:

- `node --check detector/ui/ui23.js`;
- `node --check integrations/vscode/extension.js`;
- `node --check integrations/vscode/scripts/stage-server.js`; and
- 8/8 VS Code integration tests in 7.397 seconds.

## Detector and catalog evidence

The seeded Attestor corpus self-test considered 19 files, produced 48 findings, and
detected **42/42 planted bugs**. The Advanced catalog self-check accepted 202
rules across 20 languages with zero errors. The Precision catalog self-check
materialized exactly 15,000 rules across 25 profiles and five language groups
with zero errors.

These inventory totals are not claims of 15,202 independent compiler-grade
analyses, perfect precision, perfect recall, or immunity from model
hallucination.

## Exact self-scan evidence

Attestor 4.1.3 scanned the complete `detector` directory with improvements and cache
disabled and with inherited engineering and security-fabric analysis selected.
The guarded report completed with:

- status `action-required`;
- 1,019 findings and 41 bounded attack paths;
- zero component/runtime errors and an empty error collection;
- 5,737,417 canonical public bytes and 319,133 recursive JSON nodes; and
- fresh, verified Truth Guard 3 evidence.

No HMAC key was supplied for this local pass, so the report is correctly labeled
integrity-verified rather than authenticated.

All compact report boundaries independently verified:

| Projection | Public bytes | Verified source bytes | Result |
| --- | ---: | ---: | --- |
| coding worker | 4,439 | 27,272,493 | verified; four child links matched |
| engineering | 6,998 | 5,432,296 | verified |
| security fabric | 6,285 | 144,809 | verified |
| security-static worker | 3,506 | 10,437 | verified; two child links matched |
| semantic graph | 54,038 | 27,227,763 | verified |
| Truth Guard 2 compatibility audit | 3,888 | 7,255,343 | verified |

The compatibility source state is `partial` because its older independent-claim
adapter used the declared deterministic bounded view. The complete compatibility
source digest, component contracts, evidence chain, outer report identity, and
optional authentication boundary remain bound.

Both worker reports replayed their original result and bounded-wrapper digest
chains during generation. Their public records explicitly state that the
omitted original wrapper is required for independent replay. Public SHA-256
self-digests provide integrity binding; origin authentication requires a
separately verified outer Truth Guard 3 HMAC.

Self-scan findings were retained and classified rather than erased:

- 173 came from tests, defensive payloads, or deliberately vulnerable samples;
- 774 were maintainability review heuristics: 443 branch-complexity, 277
  nested-loop, 37 long-parameter-list, and 17 unbounded-loop reviews; and
- 72 were remaining syntactic/security patterns, overwhelmingly self-matches in
  rule definitions, documentation, and embedded buggy examples.

One dependency-cycle observation remains a plausible architecture review item.
It is not represented as a proven runtime defect. The final self-scan
demonstrated no new unintended implementation error.

The first compact scan completed successfully. A second aggregation-only replay
also completed with identical metrics but took 749.807 seconds under host
contention, exceeding the requested ten-minute collection target. That timing
overrun is recorded rather than hidden; it caused no verifier failure and made
no file changes.

## Real-world smoke evidence

The canonical Attestor 4.1.3 smoke pass analyzed the deliberately buggy `realworld`
fixture with cache and improvements disabled. It returned `action-required`,
19 planted-fixture findings (5 critical, 13 high, and 1 medium), zero internal
errors, zero truncated findings, and 49 explicit coverage gaps.

Truth Guard 3, Attack Surface 4.1.3, Security Posture 4.1.3, Security Validation
4.1.3, and the Security Command Center all independently verified. The planted
fixture findings are not defects in Attestor itself.

## Genuine errors found and fixed

Adversarial review and Attestor's own scans found real, unintentional defects before
this final state:

- the workbench could relabel a historical Attestor 4.1.2 record as 4.1.3;
- a 201,789-node, 6,145,703-byte compatibility document exceeded the older
  100,000-node independent-claim adapter despite remaining inside its byte
  boundary;
- duplicated semantic and compatibility evidence expanded the unguarded maximum
  report to 70,605,239 bytes and 2,514,941 nodes, beyond the unchanged 32 MiB
  public boundary;
- a legacy proof-boundary failure could prevent independent 4.1.3 security
  evidence from being returned;
- early compact verifiers could skip a wrong-schema slot, under-bind a separately
  projected child, accept an evidence-empty compatibility projection, or fail to
  mark a digest-only retained field as requiring its original;
- worker replay wording initially overstated what an unsigned public projection
  could independently establish; and
- the first strict layout rejected a valid request that intentionally omitted
  inherited engineering and security components.

The final implementations use bounded independent validation, exact
field/omission commitments, original and embedded child identities, complete
worker replay chains at generation time, strict expected-slot layouts, honest
integrity-versus-authentication labels, and explicit `not-run` alternatives.
Regression tests cover each defect above.

The clean full suite and final self-scan found no additional demonstrated
implementation error. This is not proof that none remains.

## Release package evidence

Release promotion audits both the source tree and copied release tree. The audit
rejects caches, virtual environments, build output, transcripts, bytecode,
links/reparse points, case-colliding or unsafe paths, secret-bearing environment
variants, and release-boundary violations. Their canonical manifests must match.

Packaging performs two deterministic builds with sorted entries, fixed
timestamps, normalized modes, bounded sizes, CRC checks, and per-file SHA-256
verification. Promotion requires byte-identical archive SHA-256 values and an
independent archive verification.

The final canonical manifest, verification results, and archive SHA-256 are
stored beside the archive in `Attestor 4.1.3.manifest.json` and
`Attestor 4.1.3.zip.sha256`. They are deliberately external: an archive cannot
truthfully contain its own final digest without changing that digest.

## Deliberate limits

- Static findings and attack paths are review evidence, not proof of
  exploitability.
- A no-finding result does not prove absence of defects, secrets, or
  hallucination.
- Bounded pathless discovery does not inspect every file on a computer.
- Refused, unreadable, excluded, unmounted, or limit-truncated areas remain gaps.
- Non-Python adapters may be lexical or structural rather than compiler-grade.
- Live advisories, deployed state, runtime behavior, builds, fuzzing, and
  performance require separately supplied evidence or explicit authorization.
- Review-only improvements are never applied until a concrete candidate passes
  configured scan/build/test/security gates and the operator approves that exact
  patch.
