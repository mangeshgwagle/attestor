# Attestor 4.0 release notes

Attestor 4.0 is a separate release built from the verified 3.5 source. The 3.5 and
3.0 packages and command routes remain available as compatibility surfaces.

## Current entry points

```sh
python3 detector/superattestor.py --attestor40 . --format json
python3 detector/attestor40.py . --format text
python3 detector/attestor40.py . --issue "describe the requested change" --format json
```

The local workbench starts with `Start_Attestor_UI.bat` and defaults to the Attestor 4.0
mode. `--attestor35` and `--attestor3` select the older contracts explicitly.

## Engineering Intelligence

`engineering_engine40.py` adds a deterministic, bounded engineering report:

- repository structure and dependency/impact evidence;
- architecture boundary and refactoring candidates;
- unit, integration, property, mutation, contract, concurrency, and regression
  test strategy derived from observed code signals;
- debugging and minimal-reproducer guidance tied to evidence;
- performance, resource, concurrency, cancellation, and transaction checks;
- API, manifest, persistence, and migration-contract checks where supported;
- a staged issue-to-delivery plan with explicit scanner, build, and test gates;
- source, parser, language, and resource coverage gaps.

The engine does not describe lexical indexing as compiler-grade resolution, does
not describe a plan as an implementation, and does not describe a generated
candidate as correct. Existing verified full-source improvements remain available
and are returned in the maximum report when their proof bundle passes.

## Security Fabric

`security_fabric40.py` adds a unified defensive security layer covering evidence
available from the local tree:

- threat model, trust-boundary, entry-point, and attack-surface evidence;
- authentication, authorization, session, token, and cryptographic mistakes;
- SQL/command/template injection, XSS, SSRF, unsafe deserialization, path
  traversal, redirect, archive, and upload concerns;
- API security, CORS, cookie, and response-header checks;
- hard-coded credentials, sensitive logging, privacy and retention signals;
- Dockerfile, Compose, Kubernetes, CI, Terraform, and cloud/IaC misconfiguration;
- lockfile, manifest, integrity, dependency-graph, SBOM, and supply-chain state;
- severity/risk prioritization and evidence-linked remediation.

Security Fabric is static, offline, and defensive. It does not exploit targets,
execute repository code, install packages, resolve live advisories, contact the
network, or claim that a finding is practically exploitable. Exact dependency and
advisory claims retain the signed-snapshot and content-addressed proof policies
from Attestor 3.5.

## Verified delivery

The 4.0 report exposes an explicit delivery sequence:

1. scope the requested issue;
2. collect and hash evidence;
3. create an implementation and test plan;
4. produce or receive a concrete candidate;
5. scan it on a disposable workspace;
6. run separately authorized build and test hooks in the eligible execution
   fabric;
7. review API and security regressions;
8. apply only with separate authorization;
9. retain stale-input guards, backups, and rollback.

Dry-run remains the default. Target code has no host-execution fallback. Missing
scanner, build, or test hooks cannot be silently downgraded.

## Truth Guard 2.1 and responses

`truth_guard40.py` preserves recursive secret redaction, bounded deterministic
JSON, independently rebuilt counts and finding claims, content-addressed evidence,
tamper detection, and optional HMAC-SHA256 authentication. The 4.0 IDs and schema
are separate from the inherited 3.5 ledger.

`response40.py` renders only a valid 2.1 ledger. It leads with the observed
outcome, distinguishes detector evidence from verified repair results, includes
Engineering and Security Fabric state, lists unknowns, and never upgrades “no
findings from completed checks” into “no bugs” or “secure.”

The 4.0 boundary independently validates each component's exact version, selected
root, status allowlist, finding count, coverage shape, content digest, and every
static execution/assurance section. Contradictory target-execution, network, or
write claims fail closed. Severity sorting happens before the global output cap,
so a late critical finding cannot be discarded behind lower-severity rows.

New Engineering/Security findings return bounded review-only improvement plans
with concrete guidance. They remain unaccepted and contain no invented source or
diff unless a deterministic candidate passes the mandatory repair gates.

## Workbench and editor integration

- Attestor 4.0 is the current workbench version and maximum mode.
- Engineering and Security Fabric cards show their status, counts, evidence,
  verification state, coverage gaps, and limitations.
- Report-derived content uses text-only DOM writes under the existing CSP.
- The server remains loopback-only with a per-launch token, strict origin and
  fetch-metadata checks, bounded jobs, cancellation, and output limits.
- The LSP and VS Code bridge advertise 4.0 while retaining explicit compatibility
  handling for older routes and continue to require Workspace Trust. The VS Code
  package includes a hash-verified, self-contained server bundle.
- Compatibility exports derive identity from the actual report schema/mode, so a
  3.5 or 3.0 report is never relabeled as 4.0 by the selected UI package.

## Scope and release hardening

- Exact single-file requests do not silently widen dependency or Git evidence to
  sibling files; unavailable workspace context is reported as a coverage gap.
- Component input, finding output, attack paths, and evidence documents have
  explicit size/count boundaries.
- Release verification rejects excessive ZIP entries, traversal, control/ADS and
  Windows-reserved names cross-platform, symlinks, caches, virtual environments,
  build output, and unexpected archive members.

## Compatibility

Attestor 4.0 inherits the 3.5 symbolic engine, polyglot IR, Git intelligence, exact
lockfile graph, execution fabric, calibration, transactional repair, and all 3.0
and earlier scanners. The explicit 15,313-rule catalog remains intact. That count
is inventory, not a claim of recall, correctness, or absence of vulnerabilities.

## Deliberate limitations

- Static analysis cannot prove that no bugs or vulnerabilities exist.
- Most non-Python polyglot structure remains bounded lexical/parser evidence;
  external compiler adapters are opt-in and their absence is reported.
- Arbitrary feature implementation still needs a concrete candidate producer;
  Attestor verifies candidates but does not treat generation as proof.
- Runtime, integration, fuzz, and performance claims require separately
  authorized execution in an eligible isolation fabric.
- Security Fabric does not perform live vulnerability lookup unless a separately
  authenticated offline advisory snapshot is supplied through the inherited
  supply-chain interface.
- HMAC authentication establishes integrity and producer-key possession, not the
  factual correctness of every detector.

See `VERIFICATION_4.0.md` for the exact completed test, self-scan, browser, and
release-package evidence for this build.
