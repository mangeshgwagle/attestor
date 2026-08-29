# Attestor 3.0 verification record

Verification date: 2026-07-13 (Asia/Calcutta, UTC+05:30)

Environment used for the recorded Windows run:

- Microsoft Windows NT 10.0.26200.0
- Python 3.11.9
- bundled Node.js v24.14.0 for JavaScript syntax checks

## Full compatibility suite

Command:

```text
cd detector
python -B -m unittest discover -s . -p "test_*.py"
```

Result:

```text
Ran 817 tests in 119.044s
OK (skipped=3)
planted bugs expected: 42
planted bugs detected: 42
```

The three skips were environment/authorization dependent: the opt-in live GitHub
API test, a Windows account without symlink creation privilege, and the test that
looks for `node` on the normal system PATH. The same VS Code and workbench scripts
were parsed successfully with the bundled Node.js executable.

## Catalog and generator proofs

- Original detector self-test: 42/42 planted bugs detected.
- Advanced catalog self-test: 202/202 rules validated, no catalog errors.
- Precision-flow self-test: 15,000/15,000 rules materialized and validated across
  25 framework profiles, 12 source channels per profile, 50 sinks per language,
  and five languages; no catalog errors.
- Code generator check: 83 files / 4,092 lines generated, 73 Python files
  compiled, generated tests passed, and detector/deepscan reported zero findings.

## Truth Guard and model-grounding proofs

The focused deterministic truth and typed-model suites reported:

```text
test_truth_guard30: 30/30 passed
test_brain_truth30: 9/9 passed
```

The adversarial cases cover forged counts, files, lines, rules, clean states,
coverage, advisory status, report hashes, repair evidence, skipped probes,
credential material, empty model responses, and string booleans such as
`accepted="false"`. Unsupported or contradictory claims are abstained/refuted;
the validator itself has no model, network, shell, dynamic-code, target-execution,
or workspace-write capability.

## Attestor 3 production self-scan

Fifteen new or materially upgraded production surfaces were scanned together with
deep rules and real Python compiler checks:

```text
status=clean files=15 issues=0 errors=0 skipped=0
tool_checks=15 tool_failures=0
```

The checked set included Truth Guard, typed model provenance, Forge/Patch Forge,
model-assisted repair adapters, the maximum orchestrator, response engine, rule
SDK, security posture, release hardening, UI server/client, and dispatcher paths.

Attestor found and helped expose issues during development before this clean pass.
These included fake renderer counts/statuses/locations being accepted, the string
`accepted="false"` being treated as truthy, empty model output scoring as verified,
Patch Forge accepting deletion/API loss or treating absent tests as passed,
rejected Forge/Webscan source reaching output files, selected tests being reported
as never executing the target, zero-file/partial/advisory-unavailable runs saying
clean, report SHA-256 not being checked before rendering, source-line evidence
echoing secrets, single-file security scans including vulnerable siblings, JSON
reports being corrupted by appended stderr, and release audits not enforcing
source-tree size limits. Each was corrected and regression-tested.

## Whole-program analysis

The final full `detector/` semantic pass reported:

```text
files discovered: 167
Python modules: 163
classes: 277
functions: 2,448
calls: 19,638
resolved calls: 3,993
entrypoints: 70
reachable functions: 1,045
semantic findings in Attestor's own detector: 0
parse errors: 0
operational errors: 0
```

One 4.56 MiB non-source Darwin payload JSON file exceeded the semantic engine's
per-file analysis boundary and was explicitly reported as skipped, so the overall
repository status was honestly `partial`, not falsely `complete`.

## Secret-material audit

The value-redacting Secret Guard scanned 111 production/release text files after
excluding named tests/fixtures, the intentional vulnerable `realworld/` corpus,
and the defensive Darwin payload research corpus:

```text
production_files_scanned=111 findings=0
```

The excluded test/corpus files intentionally contain synthetic credential shapes
that prove Attestor's secret detectors. No such finding appeared in production code,
configuration, documentation, or integration files.

## Browser and UI verification

The real loopback server and in-app browser path were exercised, not merely read
as static files:

- page title: `Attestor 3.0 Maximum Engineering Workbench`;
- current engine: Attestor 3.0, connected locally;
- precision capacity exposed: 15,000 rules;
- single-file maximum run: 11 findings, all bound to the requested file, and one
  accepted partial improvement (`complete=false`, 4 resolved, 7 remaining);
- Truth Guard card: `Verified`, 14 grounded claims, 0 contradictions;
- accepted result showed the full improved source and unified diff while the
  overall status remained `improved-with-review`;
- compiler diagnostics were kept separate from structured JSON, so they could not
  zero out parsed findings or Truth Guard state;
- the original fixture remained byte-for-byte semantically unchanged with
  its insecure constructs, proving the UI run was a dry run;
- desktop and 390x844 responsive layouts rendered correctly;
- browser console warnings/errors: 0; and
- server/UI contract tests: 32/32 passed, including loopback, Host/Origin/token,
  CSP, bounded job API, no-inline-script, no-unsafe-DOM, accessibility, and
  responsive contracts.

## Supply-chain and interoperability checks

The focused supply-chain suite ran 25 tests with one Windows symlink-privilege
skip and no failures. Generated artifacts were shape/referentially validated for:

- CycloneDX 1.7 SBOM;
- SPDX 3.0.1 JSON-LD Software SBOM;
- explicitly legacy SPDX 2.3 JSON;
- CycloneDX VEX and OpenVEX; and
- SLSA provenance v1 predicate-shaped local evidence.

The LSP test suite verified bounded LSP 3.18 framing, unsaved-buffer diagnostics,
code actions without WorkspaceEdit, accepted improvement previews, rejected-source
withholding, error redaction, and shutdown lifecycle.

## Release hardening

Before packaging, the release tree was audited for caches/bytecode, forbidden
secret files, logs, symlinks, case collisions, and enforced per-file/file-count/
total-size boundaries. The final ZIP
is built with fixed timestamps, normalized permissions, sorted paths, and a
versioned prefix. A second independent build must have the same SHA-256, and the
archive verifier must match every uncompressed entry to the final manifest.

The companion `Attestor 3.0.zip.sha256` records the final archive digest. The digest
cannot be embedded inside the archive without changing the archive itself.

## Assurance boundary

These results prove the recorded checks passed; they do not prove that Attestor or a
scanned project contains no unknown defect. Python receives the deepest
whole-program semantics and deterministic remediation in 3.0. Other languages
receive the existing deterministic analysis plus available compiler/parser
front ends. Runtime Lab explicitly refuses to claim kernel-grade isolation on a
host that cannot provide it.
