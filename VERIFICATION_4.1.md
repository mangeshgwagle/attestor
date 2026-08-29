# Attestor 4.1 verification record

This record describes the Attestor 4.1 source used to build the adjacent release
archive. Results are bounded evidence from this build, not a guarantee that no
defect, vulnerability, or undiscovered project exists.

## Environment

- Verification date: 2026-07-18
- Host: Windows
- Python: 3.12.13 (bundled isolated runtime)
- JavaScript checks: Node.js 24.14.0 (bundled runtime)
- Product version: `4.1.0`
- Maximum-report schema: `attestor-maximum/4.1`
- Pathless-scan schema: `attestor-computer-scan/4.1`

## Automated tests

The final full discovery command was equivalent to:

```text
ATTESTOR_NODE=<bundled-node> python -B -m unittest discover -s detector -p "test_*.py"
```

Result: **1,261 passed, 0 failed, 0 errors, 18 skipped** in 197.303
seconds. Skips remained explicit and included unavailable Windows symlink
privileges, the unavailable host C compiler, and separately opt-in live-provider
checks. No skipped check was reported as passed.

The new pathless-computer boundary contributes 25 focused regressions across the
core scanner, SuperAttestor CLI, and workbench. They cover default denial before root
enumeration, exact-boolean consent, local fixed-drive selection, sensitive-area
exclusions, cross-filesystem and link refusal, traversal/project/finding limits,
terminal-control escaping, analyzer failures and contradictory effects, no path
argument, no automatic apply, session-only workbench results, and non-zero CLI
refusal. One link-creation test was skipped because this Windows account could
not create the test symlink.

`node --check` accepted `ui22.js`, `ui23.js`, the VS Code extension, and the
server-staging script. The Python suite also exercised the loopback-only UI,
session token, origin/fetch-metadata checks, CSP, bounded job queue, cancellation,
durable evidence for ordinary scans, and verified export replay.

## Permission and pathless-scan evidence

A live command-line run of `--computer-scan --format json` without the authorization
flag returned `authorization-required` and exit code 2. Its evidence recorded:

- zero roots, directories, files, projects, and analyses;
- `discovery_started=false` and `analysis_started=false`;
- no target execution, network access, source write, or applied improvement; and
- no OS privilege elevation or access-control bypass.

Authorization is application-level read consent for one invocation. It does not
grant UAC/admin rights, bypass Windows ACLs, persist a permission, or make an
unreadable directory readable. Home scope is the narrow default; all-local-fixed-
drives is a visibly broader choice. Network/removable roots, cross-filesystem
mounts, links/reparse points, protected system areas, browser profiles,
credentials, caches, dependencies, and generated output are refused or skipped.

Discovery is metadata-first and bounded. Selected projects are then analyzed
statically with tests, compiler hooks, caches, target imports/execution, network
access, source writes, and repair application disabled. `--computer-improve`
returns allowlisted review summaries only. Candidate source, raw secrets, build
logs, and arbitrary analyzer fields do not cross the compact computer-report
boundary. The workbench does not automatically add broad computer-scan paths to
durable history; the CLI writes a report only when the operator supplies `--out`.

## Detector and catalog evidence

The full suite's planted corpus scan considered 19 files, produced 48 total
findings, and detected **42/42 planted bugs**. The Advanced 2.2 catalog contains
202 entries and the Precision Flow 2.3 catalog materializes 15,000 entries. These
are rule inventories, not claims of 15,202 independent compiler-grade analyses or
perfect recall.

The Attestor 4.1 maximum layer additionally supplies immutable snapshots, a shared
semantic graph, deep correctness adapters, signed semantic rule packs, bounded
worker isolation, supply-chain and secret-lifecycle evidence, Repair Director,
Truth Guard 3, evidence-locked responses, AttestorBench, LSP/editor diagnostics, and
separately authorized public-web research.

## Attestor self-checks and errors found

The final isolated coding worker scanned the detector tree, completed its digest
verification, and returned **zero deep-correctness findings**. It explicitly
reported two coverage limits: no compatibility baseline was supplied and the
4,560,962-byte defensive payload corpus exceeded the per-file snapshot limit.
Its execution evidence recorded no target execution, import, network access, or
filesystem write.

The isolated security worker also completed and verified. Its 41 secret-lifecycle
alerts all resolved to deliberate fake credential fixtures or the defensive
payload corpus; a separate per-module review found **zero production-module secret
matches**. Values remained withheld.

Verification and review did find defects before this final state. The fixes are
covered by regressions:

- crafted filenames could have placed terminal or bidirectional controls in the
  computer-scan text renderer;
- a child analyzer that returned a failed/stale report could have been counted as
  a completed project;
- broad computer-scan paths would have inherited the workbench's ordinary durable
  history behavior without separate retention intent;
- an authorization-required CLI report initially returned success exit code 0;
- three native-grade unit tests accidentally depended on a compiler being present
  despite separate fail-closed compiler-absence coverage; and
- an aborted local export client could produce a server traceback, while the
  verified-export test used a brittle three-second deadline.

Earlier 4.1 self-review also made process reaping explicit in the crucible helper
and replaced cross-method semaphore ownership in the UI server with a locked
connection counter. The final full suite and self-scan ran after these fixes.

## Release package evidence

The source tree is audited before archiving. The audit rejects forbidden caches,
virtual environments, build output, transcripts, compiled bytecode, links,
case-colliding names, unsafe traversal names, and release-boundary violations.
The archive is built deterministically with sorted entries, fixed timestamps,
normalized modes, bounded sizes, CRC checks, and per-file SHA-256 verification.

The final archive SHA-256 and exact manifest are stored next to the archive in
`Attestor 4.1.zip.sha256` and `Attestor 4.1.manifest.json`. They are deliberately external:
an archive cannot truthfully contain its own final digest without changing that
digest.

## Deliberate limits

- Static findings are review evidence, not proof of exploitability.
- No-finding results do not prove absence of defects or secrets.
- Bounded pathless discovery does not inspect every file on a computer.
- Refused, unreadable, excluded, unmounted, or limit-truncated areas remain gaps.
- Non-Python adapters may be lexical/structural rather than compiler-grade.
- Live advisories, deployed state, runtime behavior, tests, builds, fuzzing, and
  performance require separately supplied evidence or authorization.
- Review-only improvements are not accepted code until a concrete candidate passes
  the configured scan/build/test proof gates.
