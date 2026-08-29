# Attestor Enterprise Security Lab 4.2

This is a deliberately small, offline and zero-incremental-cost measurement
lab. It exercises Attestor's real local detector against synthetic source held in
memory. It is not a TCS product, TCS policy, independent benchmark, penetration
test, operating-system sandbox, enterprise authorization system or permission
to inspect any organization's material.

## Cost and data boundary

The lab uses Python's standard library and the detector already included with
Attestor. It has no paid API, subscription, cloud resource, external model,
telemetry, package installation or additional runtime dependency. Reports state
provider and incremental service cost as USD 0. Existing hardware, electricity,
operating-system and internet-access costs are outside that statement.

The three public commands accept no repository or network target. They use only
the bundled synthetic fixtures and write only to standard output:

```text
attestor lab benchmark --format text|json
attestor lab isolation --format text|json
attestor lab self-test --format text|json
```

The root launcher starts the fixed lab child under Python isolated mode. The lab
does not start another process, execute or compile target source, use a scan
cache, contact a host, or apply a repair.

## What is measured

`benchmark` contains six cases: one vulnerable and one clean control for each
of CWE-78 command injection, CWE-89 SQL injection and CWE-94 code injection.
The Java cases require data flow across two files; the Python pair distinguishes
`eval` from structured JSON parsing. Labels live outside the source presented
to the analyzer. Each case is scored once as TP, TN, FP or FN, with aggregate
and per-CWE precision, recall, F1 and accuracy.

This tiny paired corpus is a regression measurement, not evidence of real-world
accuracy. A later independently sourced evaluation can use the free OWASP
Benchmark and public-domain NIST Juliet material after their exact versions,
licenses, expected-result manifests and archive hashes are reviewed. Those
datasets are not downloaded or bundled by this command.

`isolation` analyzes two in-memory synthetic tenants independently. Each gets a
different input manifest and a different finding token. Canary source values
are absent from both reports, tokens do not cross, and each nested report is
verified. This proves logical report separation in this process only; it does
not prove OS, storage, identity or production multi-tenant isolation.

## Evidence and verification

Reports omit source, snippets and absolute paths. A finding contains only its
canonical relative path, file SHA-256, manifest SHA-256, rule id, detector
version, CWE, line number, evidence SHA-256 and tenant-bound finding SHA-256.
Manifests also bind byte and line counts, coverage eligibility and every input
file digest. The verifier rebuilds and pins the exact bundled benchmark and
tenant manifests before accepting corpus or canary claims. Derived metrics,
case outcomes, isolation checks and nested report digests are recomputed by
`verify_report()`. Injected detector test doubles are marked untrusted, limited
to the reviewed rule taxonomy and forced to an incomplete status.

SHA-256 provides deterministic integrity, not authorship, identity or
non-repudiation. A future enterprise deployment would require signatures from
an approved enterprise key and an isolated runner.

## Exit status

- `0`: complete experiment and all bundled gates passed.
- `1`: complete measurement but a quality gate missed.
- `2`: invalid command or bounded input.
- `3`: incomplete coverage; this outranks findings.
- `4`: operational failure or a generated report that did not verify.

## Validation

Run the contract tests without creating bytecode or a test cache:

```text
python -B -m unittest discover -s experiments/enterprise_security42/tests -p "test_*.py"
```

The tests block network and subprocess APIs, check deterministic output,
recompute evidence and report digests, mutate report leaves, verify confusion
totals, exercise incomplete precedence, reject nonlogical paths and test that
synthetic target code is never executed.
