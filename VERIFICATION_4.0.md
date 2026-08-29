# Attestor 4.0 verification record

This record describes the Attestor 4.0 source used to build the adjacent release
archive. Results are bounded evidence from this build, not a guarantee that no
defect or vulnerability exists.

## Environment

- Verification date: 2026-07-13
- Host: Windows, Python 3.11
- JavaScript checks: bundled Node.js 24.14.0
- Deterministic product version: `4.0.0`

## Automated tests

The final full discovery command was:

```text
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest discover -s detector -p "test_*.py"
```

Result: **1,065 passed, 0 failed, 0 errors, 7 skipped** in 177.638 seconds.
The skips were six symbolic-link containment tests that this Windows account
could not create without link privileges, plus one deliberately opt-in live
provider test (`ATTESTOR_LIVE_TESTS=1`). No skipped check was reported as passed.

The suite includes the 4.0 Engineering Intelligence, Security Fabric, component
forgery/contradiction, critical-finding cap, exact single-file scope, Truth Guard
2.1, review-only improvement result, response, compatibility routing/export,
workbench, loopback HTTP/CSP, LSP, self-contained VS Code bundle, release archive,
and global version-contract regressions.

Focused JavaScript/UI/LSP/VS Code verification with the bundled Node runtime ran
34 tests with 34 passes. `node --check` also accepted the workbench, extension,
and staging scripts. The staged VS Code server bundle was reproduced and its
allowlist, sizes, SHA-256 values, isolated imports, and tamper refusal were tested.

## Detector and catalog evidence

- Planted bug corpus: **42/42 detected** across 19 files.
- Advanced 2.2 catalog: **202 rules**, all self-test fixtures valid.
- Precision-flow 2.3 catalog: **15,000 materialized rules**, all catalog checks
  valid. This number is inventory, not a recall or correctness claim.
- Generated clean corpus: **4,092 lines / 83 files**, with **0 regex findings and
  0 AST findings** in the recorded benchmark run.
- Recorded full-corpus benchmark latency: **106.9 ms** on this host. Latency is
  hardware- and sample-specific.

## Attestor 4.0 self-checks

Security Fabric scanned the new `attestor40.py`, `truth_guard40.py`, `response40.py`,
`engineering_engine40.py`, and `security_fabric40.py` modules individually after
the final detector fixes: all five returned `clean`, zero findings, zero component
errors, and explicit coverage limitations.

Earlier self-checks found four false-positive classes: unrelated long rule-name
literals near words such as `secret`, Python source containing the literal
`openapi`, SHA-pinned GitHub Actions with a trailing version comment, and a
dependency-free package being told to create a lockfile. The entropy rule now
requires an actual credential assignment, the OpenAPI rule requires a JSON/YAML
contract candidate, commented full-SHA action pins remain recognized, and lock
requirements depend on declared package dependencies. Regression tests cover all
four cases.

A bounded command-injection fixture produced a `CRITICAL`
`fabric40-command-injection` finding, a review-only improvement plan with the
specific `shell=False`/argument-vector guidance, a verified Truth Guard 2.1
ledger, and a response that displayed the plan without calling it a verified
patch.

## Integrity, scope, and execution checks

- Truth Guard 2.1 rejected forged component versions, roots, statuses, counts,
  digests, completion states, and contradictory execution sections.
- A late critical finding survived 4,000 lower-severity rows and appeared in
  findings, priority, counts, and SARIF output.
- Exact file requests did not read sibling dependency manifests/lockfiles or
  repository-wide Git evidence; the missing workspace context became a gap.
- Empty component requests did not start compatibility analysis and reported both
  4.0 static analyzers as not executed.
- Missing CLI configuration files returned the bounded class-only safe error and
  exit code 2 without a traceback or path disclosure.
- Default 4.0 analysis is offline and static. The recorded smoke report stated
  `target_code_executed=false`, `selected_tests_executed=false`,
  `changes_applied=false`, and `host_execution_fallback=false`.

## Workbench/browser boundary

Automated workbench tests verified the loopback-only server, per-launch token,
origin/fetch-metadata checks, strict CSP, external local assets, text-only report
rendering, bounded limitation lists, responsive/accessibility contracts, and
correct 4.0/3.5/3.0 export identity. Live HTTP asset and CSP checks passed.

The in-app browser had no attached webview in this task, so visual browser
automation could not be performed and is not claimed. This is a verification
limitation; the automated markup, HTTP, and JavaScript behavior checks remain
recorded above.

## Release package evidence

The shipped tree is audited before archiving and the archive is built with fixed
timestamps, sorted entries, normalized modes, and no symlinks. Verification
rejects extra/missing entries, traversal, unsafe cross-platform names, excessive
entry/file/total sizes, CRC or digest mismatches, caches, virtual environments,
build output, transcripts, and compiled bytecode.

The final archive SHA-256 and exact manifest are intentionally stored next to the
archive in `Attestor 4.0.zip.sha256` and `Attestor 4.0.manifest.json`; an archive cannot
truthfully contain its own final hash without changing that hash. The external
manifest is the authoritative package-evidence record.

## Deliberate limits

- Static findings are review evidence, not proof of exploitability.
- No-finding results do not prove absence.
- Non-Python structure is often bounded lexical/parser evidence rather than
  compiler-grade type, binding, macro, or dispatch resolution.
- Live advisories, deployed cloud state, runtime paths, builds, tests, fuzzing,
  and performance behavior require separately supplied evidence or authorization.
- Review-only plans are not accepted code. Only a concrete candidate that passes
  the configured scan/build/test proof gates may be labeled verified.
