# Attestor 2.3 verification record

Local verification date: 2026-07-11 (Windows; bundled Python 3.12.13).

## Release gates

| Gate | Result |
|---|---:|
| Full unit/integration suite | 630 run; 629 passed; 1 intentionally skipped |
| Python compile check | passed |
| UI JavaScript syntax checks | `ui22.js`, `ui23.js`, and Darwin `viewer.js` passed |
| Original planted-bug recall | 42 / 42 |
| Advanced rule fixtures | 202 / 202 |
| Precision catalog validation | 15,000 / 15,000; 0 validation errors |
| Explicit catalog inventory | 15,313 unique rules |
| Precision dimensions | 25 profiles; 5 languages; 10 vulnerability families |
| Generated-service benchmark | 4,092 lines; 0 findings |
| Scripted Forge benchmark | 3 / 3 verified repairs |
| Mutation Arena seed | 4 / 4 mutants caught |
| Original live-key copy check | 0 / 3 old live API-key values copied |

The one skipped unit test is the deliberately opt-in live GitHub/network test
(`ATTESTOR_LIVE_TESTS=1`). Network access is not required for deterministic scans.

## Catalog performance and precision

The 15,000-rule catalog is a semantic 25 profile × 12 request-channel × 50
dangerous-operation matrix. It provides 3,000 rules for each of Python,
JavaScript/TypeScript, Java, C#, and PHP, and 1,500 rules for each of ten
vulnerability families. Every rule has a unique stable ID and semantic SHA-256
fingerprint.

Isolated local microbenchmarks measured approximately 300 ms for import under
allocation tracing, 234 ms to materialize all 15,000 rules without tracing,
12.26 MiB peak materialization memory, and 0.25 s to scan a 10,001-line safe
file through the indexed engine. Scans activate only matching framework and
language profiles rather than iterating over the entire matrix.

Positive fixtures validate every catalog dimension. Negative fixtures cover
comments, strings, inactive frameworks, reassignment, recognized sanitizers,
SQL parameter positions, header-channel overlap, and source-span deduplication.

## Own-source security evidence

The final scan-engine smoke test reported:

- engine version `2.3.0`;
- 146 / 146 files scanned;
- 19 findings (6 high, 8 medium, 5 low);
- 0 operational errors;
- 1 intentionally skipped oversized research corpus file;
- exit code 19, representing the finding count rather than a crash.

The contextual cybersecurity-posture smoke test reported:

- schema `attestor-security-posture/2.3`;
- 146 / 146 files scanned;
- 136 verified and 10 unverified files, with 0 failed verifications;
- 11 actionable findings (4 critical and 7 high), all in deliberate secret,
  disabled-JWT, or legacy-TLS fixtures/rule-definition examples;
- 0 suppressed findings and 0 operational errors;
- 34 attack-surface components, 3 trust boundaries, and 4 attack paths;
- 164 legacy SecMax heuristic observations recorded and 0 promoted;
- exact explicit-rule coverage of 15,313.

Static findings are triage evidence, not proof of exploitability. The fixture
findings remain visible rather than being hidden to manufacture a clean score.

## UI and HTTP verification

The real loopback HTTP server was exercised through its secured job API:

- `/health` returned Attestor 2.3 and exactly 15,000 precision rules;
- the UI response carried a same-origin CSP with no inline script or `unsafe-eval`;
- a job submission without the per-launch token was rejected with HTTP 403;
- a real Code Arena job completed with exit code 0;
- a live Cybersecurity Mayhem job accepted cancellation and ended as
  `cancelled` with exit code 130;
- bounded queue, output, timeout, request-size, Host, Origin, and content-type
  contracts passed their integration tests;
- non-loopback binding is unconditionally rejected.

The in-app browser product policy rejected access to the local `127.0.0.1`
page, including read-only inspection. No bypass or alternate browser-control
path was attempted. Visual-browser execution is therefore not claimed here;
route-level HTTP integration plus DOM, accessibility, CSP, responsive-CSS,
pagination, history, comparison, export, cancellation, and camera-lifecycle
contracts were covered by the automated UI suite.

## Release-audit hardening

The audit found and corrected two inherited security problems before packaging:

1. The Darwin payload viewer previously converted untrusted Markdown/payload
   corpus strings into live HTML. The replacement viewer uses external assets,
   a strict CSP, DOM construction, `textContent`, event listeners, and bounded
   previews. It has no `innerHTML`, inline event handler, dynamic-code execution,
   or inline script path.
2. Optional remote UI binding could expose its bootstrap token through the
   health endpoint. Attestor 2.3 is loopback-only; remote use requires an
   operator-controlled authenticated tunnel.

All 64 inherited extractor-machine paths were reduced to category-relative
values. The PayloadsAllTheThings-derived corpus now records provenance and its
MIT notice in `THIRD_PARTY_NOTICES.md`.

## Secret and package hygiene

No live `.env`, `keys.env`, private key, credential archive, certificate, or
likely live provider credential is included. `keys.env.example` contains only
placeholders. Credential-shaped strings in `realworld/`, `test_*.py`, and the
Darwin corpus are deliberately fake vulnerability fixtures. Exact comparison
against the three live API-key values found in the old Attestor 2.1 `keys.env`
confirmed that none was copied into Attestor 2.3.

Generated bytecode, caches, coverage output, and UI diagnostic logs are removed
before archiving. The adjacent `Attestor 2.3.zip.sha256` file records the final ZIP
digest without creating a self-referential archive hash.
