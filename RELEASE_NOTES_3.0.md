# Attestor 3.0 release notes

Attestor 3.0 is a separate major release. Attestor 2.3 is not overwritten by this
package.

## Maximum analysis and improved results

`detector/attestor3.py` combines the workspace scanner, whole-program semantic
analysis, cybersecurity posture, supply-chain evidence, attack paths,
repository memory, and verified remediation into the versioned
`attestor-maximum/3.0` report. `superattestor.py --attestor3` exposes the combined report;
`--improve` emphasizes the error-to-improved-result workflow.

For supported Python findings, Attestor returns the complete improved source and a
redacted unified diff only after the candidate passes all configured gates:

- exact AST-shape transformation;
- parser/compiler validation;
- isolated PatchGuard staging;
- baseline and candidate rescans;
- resolved/new/persistent finding comparison;
- deterministic property, reverse-mutation, and fuzz probes; and
- optional explicitly authorized selected tests.

The default is a dry run. Rejected candidates are marked `refused`, their source
is withheld from normal Attestor 3/UI/LSP improved-result surfaces, and no workspace
file is changed. Explicit application uses atomic backup, stale-state protection,
post-apply verification, and integrity-checked rollback.

The deterministic fix set currently covers narrow Python AST forms for runtime
`eval`, unsafe PyYAML loading, disabled TLS verification, production debug flags,
selected subprocess-shell cases, selected SQLite f-string SQL calls, and
module-level literal secrets. Detection remains much broader than automatic
repair; ambiguous fixes are deliberately refused.

## Truth Guard and model-grounding hardening

`detector/truth_guard.py` adds a deterministic, offline claim-validation layer.
It binds status, counts, findings, files, lines, rules, coverage, artifacts, and
improvements to structured evidence IDs. It detects fake totals, contradictory
clean states, impossible locations, unknown rules, forged verification bundles,
tampered report digests, empty coverage, and unavailable/stale advisory claims.
Unsupported claims are omitted in favor of an explicit abstention. Guarded public
JSON views recursively redact credential-like values and sensitive fields.

Model-assisted paths now preserve provider/model provenance and prompt/response
SHA-256 evidence without retaining failures as content. Forge, Patch Forge,
Curry, Sieve, and Webscan distinguish abstention/refusal from static, runtime,
request-specific behavior evidence, with `verified_improvement` reserved for the
complete repair proof. Empty output cannot score as excellent;
Patch Forge rejects deletion, major erasure, public-API loss, and candidates that
do not reduce the targeted findings; SuperAttestor no longer writes rejected Forge
artifacts.

Response composition no longer regex-mines arbitrary prose or exit codes into
measured finding counts. Only a validated evidence envelope can supply counts,
and only a complete accepted remediation proof bundle can produce the word
`VERIFIED`.

## Whole-program semantic engine

`detector/semantic_engine.py` builds repository-wide Python module/import, class,
function, route, call, control-flow, and data-flow models. Its bounded fixed-point
analysis handles aliases, reassignments, branches, sanitizers, common framework
sources, dangerous sinks, interprocedural summaries, fingerprints, and evidence
chains. It can invoke available safe parser/compiler front ends for supported
non-Python languages when compiler checks are explicitly enabled.

Deep interprocedural semantics in 3.0 are Python-first. Compiler/parser adapters
for other languages validate syntax and provide evidence; they do not imply the
same whole-program precision.

## Cybersecurity and supply chain

`detector/supply_chain_center.py` inventories local manifests without resolving,
installing, importing, or executing dependencies. It emits:

- CycloneDX 1.7 SBOM and VEX;
- SPDX 3.0.1 JSON-LD Software SBOM;
- an explicitly labeled legacy SPDX 2.3 JSON export;
- OpenVEX;
- lockfile, integrity, license, lifecycle-script, repository, CI, container,
  and dependency-risk evidence;
- optional authenticated, expiring offline advisory snapshots with reachability
  context; and
- SLSA-shaped provenance evidence that explicitly does not claim certification.

An absent advisory snapshot is `unavailable`, not clean. An expired snapshot is
`stale`; a non-match means only that no match exists in the supplied snapshot.
Webscan now defaults to HTTPS; plaintext public HTTP requires `--allow-http`.

## Runtime Lab

`detector/runtime_lab.py` provides disposable staging, bounded output/time/memory
policies, executable allowlists, sanitized environments, file-mutation detection,
and separate consent gates for selected tests and direct target execution.
Network and child processes default to denied.

Portable Python startup guards are not kernel-grade hostile-code containment.
When the host cannot enforce the requested isolation, Runtime Lab says so and
refuses unsupported execution instead of claiming a sandbox.

## Rule SDK, memory, IDE, and CI

- `rule_sdk.py` loads declarative bounded literal-matcher packs with required
  metadata, positive/negative fixtures, duplicate rejection, stable SHA-256
  finding fingerprints, performance limits, and optional HMAC-SHA256 pack
  authentication. It does not load dynamic rule code.
- `repository_memory.py` stores relative file hashes, architecture summaries,
  and finding fingerprints. It excludes source, snippets, finding messages,
  rationales, secret values, and absolute paths. Decision events are chained by
  SHA-256 or HMAC-SHA256.
- `attestor_lsp.py` implements bounded LSP 3.18 framing, live diagnostics for unsaved
  buffers, code actions, and accepted improvement previews without WorkspaceEdit.
- `integrations/vscode/` is a dependency-free local bridge that requires VS Code
  Workspace Trust, launches Python without a shell, filters Python injection
  environment variables, and never applies previewed source.
- `ci_integration.py` supports changed-line findings, baselines, escaped GitHub
  annotations, JSON, and SARIF without shell command construction.

## Enterprise and release hardening

- Windows current-user DPAPI credential vault with no plaintext or hash fallback;
- default-deny plugin capability decisions;
- sanitized subprocess environments;
- deterministic release ZIP construction;
- traversal, duplicate-entry, CRC/read, expansion-boundary, and manifest/hash
  verification; and
- case-collision, symlink, cache, bytecode, log, and secret-file release auditing.

## UI and responses

The loopback-only workbench now provides dedicated Findings, Attack Paths, and
Verified Improved Results views. Accepted results show the full source and diff;
refused results show why Attestor would not guess. The overview includes a Truth Guard
card with grounded-claim and contradiction counts. Structured JSON is parsed into
bounded DOM collections using `textContent` only. The existing per-launch token,
Host/Origin checks, strict content type, CSP, connection/job/output limits,
cancellation, and no-store headers remain in place.

`response_engine.py` now leads with outcome, separates verified improvements from
refusals, and avoids claiming that an unaccepted proposal is a fix.

## Compatibility

The original corpus, personalities, 64 core rules, 24 native rules, 23 extended
language rules, 202 advanced rules, and indexed 15,000-rule precision-flow pack
remain available. Existing Attestor 2.x CLI modes continue through `superattestor.py`.

## Honest boundaries

- Static analysis and passing tests cannot prove that software has no defects.
- Only the narrow deterministic Python fix set is eligible for automatic verified
  improvement; other findings receive remediation guidance.
- Attack paths are evidence-backed static models, not proof of exploitability.
- The default run performs no network probing, dependency installation, target
  execution, or workspace modification.
- Live vulnerability intelligence requires a user-supplied authenticated snapshot;
  Attestor does not silently fetch or claim current advisory coverage.
