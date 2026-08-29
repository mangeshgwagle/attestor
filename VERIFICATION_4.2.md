# Attestor 4.2 verification record

Verification date: 2026-08-09

> **Status: PASS for the final audited source tree.** The authoritative detector
> run completed with 2,288 tests, zero failures or errors, and 34 explicit
> skips. All 42 planted bugs were detected. The 495-file source tree was
> byte-identical before and after that run. Archive SHA-256 and byte size are
> necessarily recorded outside the archive, in its adjacent `.sha256` delivery
> record, because an archive cannot contain its own final hash.

## Expected release identities

These identities were confirmed by the final run:

| Surface | Expected identity | Required interpretation |
|---|---|---|
| Root `VERSION` | `4.2` | Distribution identity only |
| UI/server distribution | `Attestor 4.2` | Separate `distribution_version` branding |
| Existing analysis engine | `Attestor 4.1.4` | `CURRENT_VERSION` must remain unchanged |
| Existing UI analysis protocol | `4.1.4` | `UI_VERSION`, modes, options, and analysis labels must remain unchanged |
| Current analysis/report schemas | Existing 4.1.4 identities | No relabelling to 4.2; older compatibility schemas retain their own established versions |
| Analyzer build SHA-256 | `27ea912e3441731d81ad6a709469b6c1543f7e6d558639075db5beb69515f70a` | Exact final `detector/detect.py` bytes; staged VS Code copy matches |
| Cockroach Janta Party profile / report | `262e16abfdf436424b598b1cf5b78e58582f280587da4d82f2af3dc68468de00` / `1da087e3ea127254fdfb71c977a2b4ee23ab582d00140eb0c4cb234c1a6e178d` | Bound to the final analyzer build |
| South Park profile / report | `1fbc48a77fab1c7ad52acfb4bca5ed9d031c7633d75341bdd421acf751b591a7` / `196e7e50858c05d6d20b2d54932b1eb7cbba59cd4a908e3df12c77ff529645e2` | Bound to the final analyzer build |
| Gruppe Sechs profile / report | `7b25ea99bd9f118faf6ea6dd23798dc946946c1d7409ef07c8fbb6016a0c1150` / `5958c5e0747c77b7a558602c42d0b6888b16e2bab106cb326aba7926a11bec11` | Bound to the final analyzer build |
| AttestorLang/ATVM schemas | `4.2` | New language-specific identities, not analyzer identities |
| Owner Control schemas | `4.2` | New control-specific identities, not analyzer identities |

## Final source-tree results

All commands below were run against the isolated final tree with bytecode-cache
writes disabled. Skips remain skips; they are not counted as passes.

| Gate | Exact evidence | Result |
|---|---|---|
| Distribution/analysis version separation | From `detector`: `python -B -m unittest -v test_version42 test_ui41 test_attestor_ui test_ui23` | **PASS:** 81 tests in 3.011s; 5 skipped because those JavaScript-in-Python tests could not discover Node; zero failures/errors. The separate direct Node gate below passed |
| AttestorLang focused regression | `python -B -X utf8 -m unittest discover -s integrations\attestorlang\tests -p "test_*.py" -v` | **PASS:** 68 tests in 0.987s; 1 skip because this Windows account cannot create a file symlink; zero failures/errors |
| Owner Control focused regression | `python -B -X utf8 -m unittest discover -s detector -p "test_*control*42.py" -v` | **PASS:** 41 tests in 10.657s; 1 skip because this Windows account cannot create a directory symlink; zero failures/errors |
| AttestorLang and Owner Control isolated CLI smokes | `python -I -B -X utf8 integrations\attestorlang\cli.py --help`; `python -I -B -X utf8 detector\owner_control42.py --help`; Windows `.bat --help` wrappers | **PASS:** exit 0, Python 3.12.10, no traceback; wrappers do not add permission. Unix wrappers were structurally checked but not executed because `sh` was unavailable |
| New production-module self-scan | `python -B detector\detect.py --deep --json FILE` for the 4 Owner Control and 5 AttestorLang runtime modules | **PASS:** 9/9 returned `[]`; zero detector findings |
| Detector masking, Juliet, profile, and staged VS Code reconciliation | From `detector`: `python -B -m unittest test_blank_equivalence42 test_juliet_corpus test_variant414 test_vscode_integration30`; root `python -B detector\restage_bundle.py --check` | **PASS:** 70 tests in 14.156s; 3 platform skips; bundle current with 15 files; exact analyzer digest matched source and staged copy |
| Generated loopback service | From `detector`: `python -B -m unittest -v test_codegen` | **PASS:** 26 tests in 23.608s. Supplemental stress passed 50/50 generated suites, 450 generated tests, and 600 body-bearing rejected POST deliveries |
| Inherited `mc_asm` | `python -B -X utf8 -m unittest discover -s integrations\mc_asm -p "test_*.py" -v` | **PASS:** 51 tests in 1.596s; native verification required both explicit opt-in flags |
| Full detector regression | From `detector`: `python -B -m unittest discover -s . -p "test_*.py"` | **PASS:** 2,288 tests in 294.671s; 34 skips; zero failures/errors. Corpus: 19 files, 51 findings, all 42/42 planted bugs detected. Whole-tree 495-file inventory was byte-identical before/after |
| Python and data syntax | In-memory `compile()` over every `*.py`; strict JSON and safe YAML parsing | **PASS:** Python 3.12.10 compiled 392 files with zero errors; one expected `SyntaxWarning` in planted `realworld/payments.py`; 5 JSON and 1 YAML files parsed |
| JavaScript syntax | Node v25.5.0 `--check` over every shipped `*.js` | **PASS:** 6/6 files; zero diagnostics |
| Documentation links | Local Markdown-target audit after final documentation edits | **PASS:** final audit recorded zero unresolved local targets |
| Release inventory | `python -B detector\release_hardening.py .` plus filename-only runtime-`.env` preflight | **PASS:** 495 source files; no links, case collisions, caches, runtime `.env`, private keys, entitlement caches, databases/WALs, tokens, or unintended verification artifacts. Exact delivery ZIP hash/size is external to avoid self-reference |

## AttestorLang assertions exercised

The normative contract is
[`integrations/attestorlang/SPEC_4.2.md`](integrations/attestorlang/SPEC_4.2.md), with
usage in [`integrations/attestorlang/README.md`](integrations/attestorlang/README.md).
The final evidence covered:

- strict UTF-8 source, the exact `attestor 4.2;` header, one `scene Main`, immutable
  `let`, the fixed `i64`/`text` type boundary, and deterministic refusal beyond
  the 128-level expression/unary parser boundary;
- checked signed 64-bit arithmetic, explicit wrapping instructions, ASR as
  arithmetic shift right, and refusal of invalid shift counts, overflow, and
  division by zero;
- bounded embedded Brainfuck tape behavior, step accounting, pointer traps,
  and virtual input/output capability declarations;
- pinned ten-trit `CRAZY` and `ROTRIT` behavior without claiming general
  Malbolge compatibility or self-modification;
- Shakespeare-style output and A1Z26 notation without claiming compatibility,
  encryption, or extra authority;
- canonical ATVM length/digest checks, strict JSON decoding, opcode and operand
  validation, type/stack/control-flow verification, one terminal `HALT`, and
  rejection of unreachable or malformed bytecode;
- refusal before step zero when `console.write` or `input.read` was not granted;
- deterministic step, stack, tape, input, output, source, instruction, and
  container ceilings; and
- evidence that ATVM data is interpreted only: no arbitrary native bytes,
  executable memory, native compiler, host file access by the VM, shell,
  process, network, clock, random source, FFI, or dynamic-library access.

Passing these assertions establishes the tested MVP contract. It does not
make AttestorLang compatible with ASM, Haskell, Brainfuck, Malbolge, Shakespeare,
C++, A1Z26 implementations, x86, ARM, or any other native ISA.

## Owner Control assertions exercised

The authoritative boundary is
[`OWNER_CONTROL_4.2.md`](OWNER_CONTROL_4.2.md). The final evidence covered:

- restriction to the exact compiled Cockroach Janta Party profile and immutable
  policy identity;
- denial before plan-file access or computer probing when literal per-run
  permission is absent;
- CLI requirement for both `--permission` and the exact reviewed
  `--confirm-plan-sha256`, with unknown, abbreviated, duplicate, malformed,
  linked, replaced, network, or stale inputs failing closed;
- one-use in-memory HMAC capabilities bound to the live registry, session,
  profile, policy, plan, action, authorization kind, 1-through-300-second time
  window, and nonce, including concurrent consumption, expiry, clock rollback,
  wrong-session, wrong-plan, tampering, and cross-registry refusal;
- bounded `system-inventory` without hostname, username, network identifiers,
  or emitted root paths;
- bounded `find-files` metadata, optional single-link regular-file hashing,
  no emitted content, and explicit exclusions/counters for protected,
  sensitive, linked/reparse, hardlinked, cross-filesystem, unreadable, changed,
  and over-limit entries;
- the inherited static `computer-project-scan` refusing reports that claim
  target-code execution, network access, writes, applied improvements,
  elevation, or access-control bypass, while acknowledging that returned local
  project/finding paths are session-sensitive;
- `plan-future-mutations` remaining non-probing and inert with
  `executor: unavailable`, `planned-only`, `mutation_authorized: false`, and
  `mutation_executed: false`; and
- final report verification rejecting any claimed shell, process, network,
  credential-store, persistence, security-disabling, privilege, or filesystem
  mutation effect, even if an attacker recomputes an unkeyed report digest.

Every accepted Owner Control report must state `mutation_executed: false`.
There is no permitted test path that performs a mutation to demonstrate
rollback, because the 4.2 MVP contains neither a mutation executor nor a
rollback subsystem.

## Inherited correction assertions

- Python masking was compared against the prior implementation on awkward
  strings, all readable shipped Python sources, and their prefixes. The edit
  avoids unnecessary three-character slices without changing masking results.
  It changes the exact analyzer/profile/report identities, not their 4.1.4
  schema versions.
- Juliet ZIP preflight still validates canonical paths, collisions, encryption,
  and file types before skipping an oversized member outside lowercase
  `/testcases/`. Selected testcase members retain per-entry, aggregate,
  compression-ratio, and streamed-size enforcement. Skipped scaffolding is
  never decompressed or analyzed.
- Generated loopback services drain only bounded, unambiguous rejected bodies,
  flush responses, strictly validate readiness, and join request handlers
  before closing SQLite. Repeated Windows loopback tests passed without retrying
  state-changing POSTs. This does not prove internet-facing deployment safety.
- The inherited `mc_asm` native C++/x86 differential path remains separate from
  AttestorLang and requires both `--verify` and `--allow-native-execution`; default
  operation never executes emitted native code.

## Threat boundaries and evidence limits

- Attestor 4.2 distribution branding does not change the inherited 4.1.4 analysis
  protocol. New AttestorLang and Owner Control 4.2 schemas are feature-local.
- ATVM validation and deterministic reports are application-level evidence,
  not native-code execution, a general operating-system sandbox, or a proof
  that the interpreter has no implementation defect.
- Owner Control's permission flag is owner attestation, not authenticated OS
  identity or legal authority. There is no privileged broker, background agent,
  durable authorization, or remote-control service.
- Owner Control policy exclusions are defense in depth, not complete secret
  classification. Outputs remain local/session-sensitive, especially project
  scan paths and file metadata.
- Plain SHA-256 identities detect change only when compared with a trusted
  expected value. They are not signatures, authorship proof, malware verdicts,
  or proof of correctness. A copied Owner Control capability/audit document is
  not authority without the original live registry.
- Inventory and analysis ceilings, access rights, filesystem races, platform
  APIs, and conservative exclusions can create explicit gaps. A clean result
  does not prove absence of undiscovered files, defects, credentials, or risk.
- Automated tests, compilation, syntax checks, and static scans do not prove the
  absence of all defects. Failures, aborted runs, warnings, skips, and coverage
  gaps must remain visible in the final record.

## Finalization record

1. Every applicable gate above ran against the isolated final tree with
   bytecode-cache writes disabled.
2. Failures, errors, skips, warnings, durations, and unavailable platform
   capabilities are retained rather than converted into passes.
3. Distribution 4.2 remains distinct from analysis protocol 4.1.4.
4. The audited source tree contained no `__pycache__`, `.pyc`, runtime secret
   file, private key, entitlement cache, database/WAL, token, or unintended
   verification artifact. `realworld/config.env` and the fake `sk_live_` text in
   `realworld/payments.py` are intentional synthetic detector fixtures, not
   credentials; both are covered by planted-corpus tests.
5. The final ZIP is produced twice from this tree with the deterministic release
   builder and both copies are independently verified for exact contents,
   ordering, CRC, prefix, timestamps, file types, modes, size limits, and
   SHA-256 equality. Its final hash and byte size are published beside, not
   inside, the ZIP to avoid a self-referential claim.
6. Digests in this record identify exact bytes when compared with a trusted
   expected value. They are not signatures, authorship proof, or proof of
   correctness.
