# Attestor 4.1.3 release notes

Attestor 4.1.3 is a major defensive-security, code-review, and evidence-integrity
upgrade for the stable Attestor 4.1 family. It keeps the existing `--attestor41`
command, `*41.py` module names, Truth Guard 3 contract, and `/4.1` report
schemas. The new `--attestor413` spelling selects the same current engine.

The release adds two independently verifiable static-security reports, a
permission-bound validation and repair coordinator, regression memory, and a
Security Command Center. It does not claim that static analysis proves software
safe, that a reported path is exploitable, or that every defect has been found.
Unknown, unavailable, partial, refused, and limit-truncated evidence stays
visible.

## Cross-service attack-surface analysis

- `attack_surface413.py` builds a bounded, deterministic, cross-file attack graph
  from passive source evidence. It identifies candidate entry points, trust
  boundaries, sources, sinks, controls, and multi-step paths without importing or
  executing target code.
- Web and API coverage includes candidate IDOR, SQL/command/code injection, SSRF,
  CSRF, permissive CORS, weak cookie settings, JWT/OAuth mistakes, redirect
  handling, request-smuggling indicators, and framework/OpenAPI routes.
- Findings include exact source bindings and an evidence state. Exploitability is
  a bounded evidence-grounded score and band, not a claim that Attestor exploited the
  target.
- Report verification independently checks schema, limits, canonical ordering,
  source bindings, graph references, summaries, and the report digest.
- Traversal, file count, byte count, route count, graph size, attack-path count,
  evidence, and public output are all bounded. Coverage lost to a boundary is
  reported as a gap.

## Cloud, IaC, supply-chain, and secret posture

- `security_posture413.py` adds passive checks for Dockerfiles, Kubernetes,
  Terraform, GitHub Actions, IAM policy, TLS/cryptography, package and lock
  metadata, install scripts, suspicious repository artifacts, and bounded binary
  metadata/strings.
- It produces bounded SBOM-style component evidence, lock-drift and
  dependency-confusion indicators, provenance observations, secret-lifecycle and
  history metadata, and cloud/IaC findings. Missing live registries, deployed
  state, Git history, or dependency resolution remain unavailable rather than
  being guessed.
- Raw detected secret values are neither emitted nor hashed into public reports.
  Evidence contains location and classification metadata only.
- Filesystem discovery uses deterministic bounded directory enumeration,
  same-device containment, link/junction/reparse refusal, regular-file checks,
  descriptor validation, and before/after metadata and content checks to detect
  input changes during analysis.
- Its verifier recomputes canonical structure, identities, totals, limits,
  summaries, and digests instead of trusting producer booleans.

## Permission-bound validation and repair

- `security_validation413.py` supplies strict bounded manifests and a one-use,
  short-lived HMAC approval registry. An approval is bound to the exact project
  root, patch, plan, purpose, and live process registry. It cannot be replayed,
  reissued after use, converted from a string-like truth value, or retained as
  ambient permission.
- Sandbox plans require a digest-pinned image, allowlisted executable and
  arguments, disabled network, a disposable workspace, dropped capabilities,
  `no-new-privileges`, and explicit resource limits. Planning a sandbox does not
  claim that a sandbox was executed.
- Property, boundary, fuzz, differential, and minimization work is represented as
  bounded test-plan data. Attestor does not execute offensive payloads through the
  default static path.
- Candidate repairs pass an ordered proof state machine: static scan, build,
  tests, and security rescan. Every stage is digest-chained and offline by
  default. Missing or failed evidence leaves the candidate unverified.
- Applying a candidate requires a separate one-use approval after proof-gate
  success. Attestor 4.1.3 never treats analysis permission as patch-application
  permission and never enables automatic apply.
- Regression memory is project-namespaced and replay-resistant. It compares
  verified evidence without transferring state across projects or presenting an
  identical replay as new proof.

## Security Command Center and response behavior

- The local workbench includes a dedicated Security Command Center with bounded
  severity metrics, evidence states, attack paths, repair and regression status,
  approval state, automatic-apply state, retained-permission state, and coverage
  gaps.
- UI normalization is bounded and untrusted values are written with safe DOM text
  operations. Integrity labels are downgraded unless the exact loaded historical
  report was freshly verified.
- Evidence-locked responses distinguish `proven`, `inferred`, `unverified`, and
  `unavailable` claims. A `proven` claim requires an explicit allowlisted
  evidence record whose digest still verifies.
- Attestor can answer questions about attack paths, candidate fixes, validation
  state, automatic application, retained permissions, and regression evidence
  from the guarded report. It abstains when the required evidence is absent or
  stale.
- Historical 4.1.2 records retain their original identity in the workbench and
  canonical export flow; they are not silently relabelled as 4.1.3.

## Coding and orchestration

- The 4.1 maximum orchestrator runs coding, security, attack-surface, and posture
  workers as isolated bounded child processes over an immutable source view.
- Every projected worker result replays the original result digest and complete
  bounded-worker wrapper chain before compaction. Public child links bind both
  the original child identity and the exact embedded full/projection envelope.
- High-cardinality semantic, engineering, security, and Truth Guard 2 evidence
  is emitted through fail-closed public projections. Exact field commitments,
  omission counts and digests, source sizes, and replay limitations preserve the
  32 MiB public boundary without silently deleting evidence.
- Truth Guard 2 now uses a deterministic bounded independent-validation view
  when a verified compatibility document exceeds the older 100,000-node adapter
  limit. The complete source report still drives component contracts, its
  evidence chain, source digest, outer report identity, and optional HMAC.
- A legacy Truth Guard proof-boundary failure is isolated as an explicit failed
  compatibility gap so the independent 4.1.3 analyzers can still return their
  evidence. Authorized legacy execution or apply state is reported as uncertain,
  never guessed false.
- New reports must pass their own strict verifiers before they can enter the
  public maximum report. Invalid nested results are quarantined and described as
  gaps.
- Public findings now expose evidence state and bounded exploitability metadata.
  The final report adds validation/test plans, repair pipeline state, regression
  comparison, a claim ledger, and the Security Command Center while remaining
  protected by Truth Guard 3.
- The worker allowlist adds only the two passive 4.1.3 security actions. Default
  operation still performs no target import, target execution, network access,
  source write, automatic repair, or retained authorization.
- The existing 202-rule advanced catalog and 15,000-rule precision catalog remain
  available. Their inventory size is not represented as 15,202 independent
  compiler-grade proofs.

## Editor, CLI, CI, and documentation

- Runtime, response, UI, launcher, VS Code extension, isolated server bundle, CI,
  and documentation identify the current product as Attestor 4.1.3.
- The generated VS Code server bundle remains content-addressed. Extension
  behavior is preview-only and does not silently apply workspace edits.
- `make verify413` is the current gate; `verify41` and `verify412` remain
  compatibility aliases. The 4.1.3 smoke gate verifies Truth Guard and all three
  new nested command/attack/posture reports.
- `--attestor413` is the explicit current spelling. `--attestor41` remains stable for
  existing integrations, and older versioned modes remain explicit compatibility
  surfaces.

## Verification and packaging

The exact final test totals, expected skips, self-scan findings, coverage gaps,
release-tree audit, deterministic-build comparison, and archive verification are
recorded in `VERIFICATION_4.1.3.md`. The archive SHA-256 and canonical per-file
manifest remain beside the archive because an archive cannot contain its own
final digest without changing that digest.

Attestor's self-scan deliberately reports security-like fixtures found in its own
tests, defensive payload catalogs, and known-vulnerable samples. Such evidence is
classified as fixture/sample material rather than being erased to manufacture a
zero-finding result.

Adversarial verification found and fixed genuine, unintentional release defects:

- historical 4.1.2 UI records could be relabelled as 4.1.3;
- a 201,789-node compatibility report exceeded the older 100,000-node
  independent-claim adapter even though the report remained inside its byte
  boundary;
- duplicated semantic and compatibility evidence expanded the unguarded maximum
  report to 70,605,239 bytes, beyond the unchanged 32 MiB public limit;
- early projection verifiers could skip wrong-schema slots, incompletely bind a
  separately projected child, or accept incomplete omission accounting; and
- the first strict layout rejected a valid request that intentionally omitted
  inherited engineering/security components.

Regression tests now cover every item above. The final full suite and exact
self-scan found no additional demonstrated implementation error. This does not
prove that no undiscovered defect remains.

## Stable compatibility boundaries

- Maximum report schema: `attestor-maximum/4.1`
- Computer-scan schema: `attestor-computer-scan/4.1`
- Research schema: `attestor-research/4.1`
- Current CLI spellings: `--attestor413` and `--attestor41`
- Current maximum module: `attestor41.py`
- Current LSP module: `attestor_lsp41.py`

The default coding and security path remains offline and does not execute target
code. Public-web research, verification-lab execution, and source application
remain separate explicit authorizations. HMAC-SHA256 authenticates a shared-key
boundary when configured; it is not a public-key signature or non-repudiation.
