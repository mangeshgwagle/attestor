# Attestor 4.2 release notes

Release date: 2026-08-09

Attestor 4.2 is a distribution release. Its two new bounded, opt-in capability MVPs
are AttestorLang with its ATVM interpreter and permission-first Owner Control. It
also carries narrowly scoped correctness, compatibility, and reliability fixes
to inherited components. The existing analysis engine and report protocol are
deliberately not relabelled; they remain Attestor 4.1.4.

The inherited 4.1.5 billing and entitlement subsystem also keeps its own
identity. It remains a Stripe test-mode-only sandbox: Attestor 4.2 does not enable,
authorize, or perform live charges.

## Version boundaries

| Surface | Version in this distribution | Meaning |
|---|---|---|
| Release distribution | Attestor 4.2 | Packaging, release identity, and distribution branding |
| Existing analysis engine and protocol | Attestor 4.1.4 / 4.1.4 | Analyzer selections, modes, and schemas retain their identities; the exact analyzer build and bound profile/report digests move with the behavior-equivalent masking change |
| AttestorLang and ATVM | 4.2 | New language, bytecode-container, and language-run schemas only |
| Owner Control MVP | 4.2 | New permission, policy, inventory, plan, and audit schemas only |
| Billing and entitlements | 4.1.5 test mode | Inherited test sandbox; no live-money activation |

The desktop workbench and server health response expose the Attestor 4.2
distribution identity separately from the 4.1.4 analysis engine/protocol. Attestor
4.2 is not added as an analyzer choice, and no 4.1.4 analysis schema is renamed
to 4.2.

## AttestorLang and ATVM MVP

AttestorLang is a deliberately small deterministic language under
`integrations/attestorlang`. Strict source compiles to verified ATVM bytecode and is
then interpreted within fixed resource ceilings. An `.owb` file is canonical
ATVM data with a length and payload SHA-256; it is never mapped as executable
memory, sent to a native compiler, or executed by the host CPU.

The language is inspired by, but is **not fully compatible with**, any of its
source influences:

- ASM supplies typed stack operations. ASR is an exact signed 64-bit
  arithmetic shift right, with shift counts restricted to 0 through 63.
- Haskell inspires immutable `let` bindings and pure expressions. The MVP does
  not implement Haskell syntax, laziness, type classes, modules, or general
  functional-language compatibility.
- Brainfuck is available only as an embedded command subset with wrapping byte
  cells, a bounded tape, checked pointer movement, bounded input/output, and
  deterministic step accounting.
- Selected Malbolge operations are limited to pinned ten-trit `CRAZY` and
  `ROTRIT` semantics. AttestorLang does not implement Malbolge source encryption,
  self-modification, or general Malbolge compatibility.
- Shakespeare-inspired syntax is limited to `scene Main` and the
  `Actor says number|letter|text(...)` output forms.
- C++-like structure is limited to braces, immutable scoped declarations, and
  fixed `i64` and `text` types. There are no pointers, templates, ABI calls,
  undefined behavior, or native object layout.
- A1Z26 is notation for assembly words and decimal literals. It is not
  encryption or an authorization mechanism.

All structured syntax, embedded ASM, bounded Brainfuck, and A1Z26 forms lower
to the same verified ATVM instruction stream. The MVP accepts exactly one
entry scene named `Main`. Its only virtual capabilities are `console.write`
and `input.read`; effects must be declared in source and granted out of band.
Neither capability grants access to a host terminal, file, process, shell,
socket, credential, native library, clock, random source, FFI, JIT, or
executable memory.

Default and hard runtime boundaries are documented in
[`integrations/attestorlang/SPEC_4.2.md`](integrations/attestorlang/SPEC_4.2.md). The
hard ceilings include 10,000,000 VM steps, 4,096 stack values, 65,536 tape
cells, 1 MiB each of virtual input and output, 100,000 instructions, and a
2 MiB bytecode container. Source expression and unary nesting are each capped
at 128 levels. A selected profile may lower these values but cannot add
authority.

The standalone CLI exists and is the host path boundary:

```powershell
python -I -B -X utf8 integrations\attestorlang\cli.py --help
```

Its exact commands are `check`, `run`, `compile`, `disasm`, `run-bytecode`,
`encode-a1z26`, and `decode-a1z26`. The CLI reads only explicitly named source,
bytecode, and virtual-input values; `compile --out` writes only the explicitly
named output. The ATVM itself receives bounded bytes and never receives a host
path. See
[`integrations/attestorlang/README.md`](integrations/attestorlang/README.md) for the
user guide and the specification above for normative behavior.

## Permission-first Owner Control MVP

Owner Control is a standalone, local, read-only inspection subsystem restricted
to the canonical Cockroach Janta Party profile. It is not a blanket computer
takeover feature, a background agent, or a privileged administration service.

Its exact MVP actions are:

- `system-inventory`: bounded OS, architecture, logical-processor, physical
  memory, and explicitly scoped local fixed-storage facts. It omits hostname,
  username, network identifiers, and root paths.
- `find-files`: bounded metadata discovery under one to eight explicit local
  roots. It returns relative paths, sizes, modification times, suffixes, and
  optional SHA-256 values, but never file contents or absolute roots. Optional
  hashing is capped at 16 MiB per eligible file and 128 MiB in total.
- `computer-project-scan`: the inherited permissioned static project scanner,
  bounded to 1 through 12 projects in `home` or `fixed-drives` scope. It does
  not execute target code, run tests or compiler hooks, apply improvements, or
  request privilege or access-control bypass. Its nested report can contain
  local project and finding paths and must be treated as session-sensitive.
- `plan-future-mutations`: a digest-bound review artifact for up to 12
  allowlisted future operation records. It does not probe the computer. Its
  executor is `unavailable`; its status is `planned-only`; and it grants and
  executes no mutation.

The `policy` and `plan` commands are non-probing. An unconfirmed `run` returns
before opening the named plan or probing computer state. An authorized run
requires the literal per-run `--permission` flag and the exact reviewed
`--confirm-plan-sha256`. It then issues and consumes one short-lived in-memory
HMAC capability bound to the live registry, session, CJP profile, policy,
plan, action, authorization kind, time window, and nonce. The lifetime is
1 through 300 seconds and concurrent consumption permits at most one winner.
Permission and capability state are not persisted.

The standalone CLI and thin root wrappers exist, but Owner Control is not wired
into `superattestor.py` or the web/desktop UI in this MVP:

```powershell
python -I -B -X utf8 detector\owner_control42.py --help
.\Run_Owner_Control_4.2.bat --help
```

```sh
./Run_Owner_Control_4.2.sh --help
```

The wrappers change only to the release root, invoke the isolated CLI, forward
the operator's arguments exactly, and never add `--permission`.

Exact subcommands are `policy`,
`plan {system-inventory,find-files,computer-project-scan,plan-future-mutations}`,
and permission-first `run PLAN_FILE`. The complete request shapes, command
flow, output handling, and boundaries are in
[`OWNER_CONTROL_4.2.md`](OWNER_CONTROL_4.2.md).

Every Owner Control report states `mutation_executed: false`. This release has
no mutation executor, rollback subsystem, arbitrary command or shell
authority, process-launch authority, network authority, credential-store
authority, elevation or access-control-bypass authority, persistence authority,
security-disabling authority, or ability to change files, services, settings,
accounts, or programs. Future-looking operation names in a plan do not create
any of those powers.

## Billing remains test-only

Attestor 4.2 carries forward the 4.1.5 billing and entitlement sandbox without
turning it into a production payment system. Live credentials, live Prices,
live sessions, and live webhook events remain outside the supported boundary.
No final verification should use a real card or make a live Stripe charge.
Production payment activation still requires a separate reviewed release and
merchant, legal, tax, privacy, refund, deployment, secret-management,
monitoring, reconciliation, backup, and incident-response decisions.

## Inherited correctness and reliability fixes

- **Python masking performance with unchanged semantics.** `blank_python` and
  `_comments_python` no longer take a three-character slice at every source
  character. `test_blank_equivalence42.py` keeps the previous implementations
  as references and compares awkward inputs, prefixes, and every shipped Python
  source. This changes exact build bytes, not detector rules or report schemas.
- **NIST Juliet compatibility without weakening selected-input limits.** ZIP
  preflight skips an oversized member only when it is outside lowercase
  `/testcases/` and therefore cannot be selected. Canonical-path, collision,
  encryption, and special-file checks still occur first. Selected testcase
  members retain per-entry, aggregate, compression-ratio, and streamed-size
  enforcement. Large generated `C/testcasesupport/main.cpp` scaffolding no
  longer rejects the usable corpus.
- **Legacy local-gateway ledger transactions.** The separate test-only scan
  gateway serializes ledger read/modify/write transactions across threads,
  `Ledger` instances, and local processes. It rejects linked, reparse, multi-link,
  or identity-swapped state paths; uses unique fsynced atomic stages; verifies
  the adjacent lock-file identity; retries only narrow transient Windows
  replacement failures; and preserves the prior ledger when replacement fails.
  This gateway is not the Stripe billing service and does not enable live money.
- **Generated loopback-service stability.** Generated HTTP services drain only
  bounded, unambiguous bodies for rejected authenticated writes, flush response
  bytes, strictly validate `/health/ready`, and wait for handler threads before
  closing their shared SQLite connection. This fixes the observed Windows
  unread-body socket reset and shutdown race in repeated loopback integration
  runs; it is not a claim of internet-facing production hardening.
- **Inherited `mc.asm` native boundary.** `integrations/mc_asm` is separate from
  AttestorLang. Its native C++/x86 verification path now requires both `--verify`
  and explicit `--allow-native-execution`; default operation does not execute
  generated native code. ATVM remains interpreted data and receives neither
  flag nor native authority.

Because variant evidence binds the exact `detect.py` bytes, these behavior-
equivalent detector changes intentionally move the analyzer, profile, and
selection-report SHA-256 identities even though their schemas remain 4.1.4:

| Evidence identity | SHA-256 |
|---|---|
| Analyzer build | `27ea912e3441731d81ad6a709469b6c1543f7e6d558639075db5beb69515f70a` |
| Cockroach Janta Party profile | `262e16abfdf436424b598b1cf5b78e58582f280587da4d82f2af3dc68468de00` |
| Cockroach Janta Party selection report | `1da087e3ea127254fdfb71c977a2b4ee23ab582d00140eb0c4cb234c1a6e178d` |
| South Park profile | `1fbc48a77fab1c7ad52acfb4bca5ed9d031c7633d75341bdd421acf751b591a7` |
| South Park selection report | `196e7e50858c05d6d20b2d54932b1eb7cbba59cd4a908e3df12c77ff529645e2` |
| Gruppe Sechs profile | `7b25ea99bd9f118faf6ea6dd23798dc946946c1d7409ef07c8fbb6016a0c1150` |
| Gruppe Sechs selection report | `5958c5e0747c77b7a558602c42d0b6888b16e2bab106cb326aba7926a11bec11` |

The VS Code server's staged detector is byte-identical to that analyzer build.
Older reports remain historical evidence and are not silently accepted as
current-build evidence.

## Threat boundaries and limitations

- AttestorLang's verifier, capability model, and resource ceilings are an
  application-level interpreter boundary, not proof of compatibility with ASM,
  Haskell, Brainfuck, Malbolge, Shakespeare, C++, or a native ISA. ATVM bytes
  are never host-native instructions.
- AttestorLang has one `Main` scene, two fixed types, immutable bindings, no host
  API, and no general module, package, FFI, debugger, concurrency, filesystem,
  network, or native-code facility.
- Owner Control permission is an explicit owner attestation, not OS identity,
  ownership, employment, legal-authority, or privilege proof. A process already
  running as the same user can supply the CLI flag. There is no authenticated
  privileged broker or human-confirmation UI in this MVP.
- Plain SHA-256 plan, report, file, and bytecode digests provide integrity
  identities when the expected digest is trusted. They are not signatures,
  authorship proof, malware verdicts, or proof that content is safe. The Owner
  Control capability HMAC is useful only with its original live in-memory
  registry.
- Owner Control rejects or skips protected directories, sensitive filenames,
  links/reparse points, multi-link files, cross-filesystem entries, network or
  removable roots, and out-of-bound work. The denylist is conservative but not
  a complete secret classifier. An innocently named file can still contain
  confidential data.
- Inventory and static-scan coverage depends on OS APIs, filesystem behavior,
  access rights, configured ceilings, and exclusions. Partial or apparently
  clean output is not proof that a computer, drive, or project is completely
  inventoried or safe.
- Owner Control has no rollback because it has no mutation executor and changes
  nothing. An inert 4.2 mutation plan must never be treated as permission for a
  future executor.
- Billing is test-mode-only and cannot be described as live-money verified.
- The legacy gateway ledger is a local JSON/test implementation with same-host
  serialization, not a distributed database or a production billing ledger.
- Generated-service integration tests exercise a bounded loopback scaffold;
  they do not prove public-network deployment safety.
- An oversized non-testcase Juliet member that is skipped is never opened or
  content-inspected. Testcase members that may be selected remain fully bounded.

## Verification status

**Completed verdict: PASS with 34 recorded skips.** The frozen final source tree
contained 495 files. Its full detector regression ran 2,288 tests in 294.671
seconds with no failures or errors, and the planted corpus detected all 42 of 42
expected bugs. Exact commands, focused-suite evidence, skip reasons, containment
assertions, source inventory, and deterministic packaging evidence are recorded
in [`VERIFICATION_4.2.md`](VERIFICATION_4.2.md). The final archive byte hash is
published outside the archive in its delivery record or `.sha256` sidecar so the
archive does not attempt to contain a hash of itself.
