# Attestor 3.5 verification record

Verification date: 2026-07-13

Product version: `3.5.0`

Environment used for this record: Windows, Python 3.11.9, bundled Node.js
v24.14.0. Attestor remains cross-platform, and the CI workflow targets Python
3.11/3.13 on Windows and Linux.

## Release outcome

The verified source tree passed the complete unit/corpus suite, the 3.5-focused
subsystem suite, two independent static detectors, Python syntax parsing, secret
analysis, JavaScript syntax validation, a real loopback UI workflow, and the 3.5
CI orchestration smoke. Release archives are created twice and must be byte-for-
byte identical before delivery.

The final archive digest and content manifest are deliberately external to the
archive to avoid a self-referential hash. They are delivered beside the ZIP as:

- `Attestor 3.5.zip.sha256`
- `Attestor 3.5.manifest.json`

## Automated evidence

### Complete repository suite

Command:

```text
python -B -m unittest discover -s detector -p "test_*.py"
```

Result:

- 959 tests passed in 145.945 seconds (147.9 seconds wall time).
- 0 failures and 0 errors.
- 6 real-filesystem symlink tests were skipped because this Windows account
  cannot create the required links.
- The planted-bug self-test detected 42 of 42 expected bugs across 19 corpus files.

### Post-hardening 3.5 subsystem gate

The final targeted gate covered Attestor 3.5 routing, authenticated and unsigned
Truth Guard 2 reports, response abstention, release hardening, workbench/server
contracts, execution fabric, transactional repair, current orchestration, nested
Git impact, and bounded symbolic analysis.

Result: 162 tests passed in 38.196 seconds, with 2 Windows symlink skips and no
failures or errors.

Additional focused evidence included:

- Execution fabric plus transactional repair: 28 passed, 1 Windows symlink skip.
- Symbolic engine plus orchestration transport: 47 passed; the 16 MiB aggregate
  input limit, 16 MiB output limit, 45-second worker limit, and worker digest were
  confirmed.
- Nested-project Git namespace/remapping and failed-core completion regressions
  passed in the complete and targeted gates.

### Static, syntax, and secret gates

Fourteen production Python surfaces were checked after the final changes:

- Deep `scanengine` analysis with external tools disabled: `status=clean`, 14
  files, 0 findings, 0 errors, 0 skipped.
- Independent `detect.py --deep --json`: `[]`.
- Python AST parsing: 14 of 14 parsed.
- Contextual secret guard: 0 findings.
- `node --check detector/ui/ui23.js`: passed with bundled Node.js v24.14.0.

The `scanengine tools=True` Node adapter was not counted as passed on this host:
the desktop application executable was selected instead of the bundled Node
runtime and failed before syntax analysis. JavaScript syntax was therefore
checked directly with the configured bundled Node binary.

### Current-orchestrator CI smoke

The 3.5 smoke analyzed `realworld/app.js` through the bounded polyglot component,
verified schema/version, no target or host-fallback execution, Truth Guard 2
integrity, and privacy of internal memory fields.

Result: `status=no-findings-with-gaps`, `polyglot_files=1`, all assertions passed.

## Browser verification

The local server was launched on loopback and controlled through the in-app
browser at desktop and 390-by-844 mobile viewports.

Verified behavior:

- Title and selected engine identify Attestor 3.5.
- The 3.5 assurance matrix and calibration, execution-fabric, evidence-ledger,
  symbolic, polyglot, dependency, and Git states render without console errors.
- Mobile layout had no horizontal overflow and kept the primary actions usable.
- A real UI Attestor 3.5 scan of `realworld/app.js` completed with 7 findings.
- The page showed `Verified integrity` and `local integrity only`, avoiding an
  authentication claim for an unsigned local report.
- The UI showed unavailable container/calibration states and refused remediation
  honestly instead of silently weakening policy or claiming an unproven fix.
- Browser console warnings/errors: 0.

## Security claims exercised

- Failed or error-bearing inherited components cannot be listed as complete.
- Git changes under a nested project are scoped and remapped into the semantic
  database namespace; unrelated repository-root changes do not become false impact.
- Symbolic input, output, wall time, states, steps, contexts, and files are bounded,
  and a hit limit becomes an explicit coverage gap.
- Direct container execution mounts the supplied workspace read-only.
- Writable verification uses a bounded, link-free disposable copy that is deleted.
- No eligible rootless hardened Linux runtime means refusal; there is no host
  execution fallback.
- Truth Guard 2 independently rebuilds claim and evidence audits. Unsigned output
  is labeled integrity-only; HMAC-SHA256 authentication is available for trust
  boundaries and is exercised by tests.
- Transactional repair remains dry-run by default and requires separate execution
  and apply authorizations, mandatory scanner/build/test hooks, stale guards, and
  rollback evidence.

## Honest limitations

- Static, symbolic, and lexical evidence cannot prove absence of every defect or
  practical exploitability.
- Python symbolic analysis is AST-based. Polyglot IR is bounded lexical analysis,
  not compiler-grade type, macro, overload, reflection, or dispatch resolution.
- Git blame is candidate attribution, not historical causality proof.
- Real rootless Linux container execution was unavailable on this Windows host;
  hardened argv, timeout, cleanup, mount, transcript, and refusal paths were tested
  adversarially with controlled process/runtime doubles. Linux CI is expected to
  exercise real symlink behavior.
- Rollback-based multi-file application cannot be mathematically atomic across a
  host crash or a non-cooperating external writer.
- Catalog size is not a recall, precision, correctness, or security guarantee.

## Reproduction

From the release root:

```text
make verify35
python -B detector/attestor35.py realworld/app.js --component polyglot-ir --no-improve --format json
python -B detector/release_hardening.py .
```

For an authenticated report crossing a trust boundary:

```text
python -B detector/superattestor.py --attestor35 . --format json \
  --truth-key-file report.key --truth-key-id release-ci
```
