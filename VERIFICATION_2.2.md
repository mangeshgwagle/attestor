# Attestor 2.2 verification record

Local verification date: 2026-07-11 (Windows, Python 3.11).

| Gate | Result |
|---|---:|
| Full unit/integration suite | 587 passed, 1 intentionally skipped |
| Planted-corpus recall | 42 / 42 (100%) |
| Advanced rule fixtures | 202 / 202 passed |
| Explicit catalog inventory | 313 unique rules |
| Generated-service benchmark | 4,092 lines, 0 regex/AST findings |
| Scripted Forge benchmark | 3 / 3 verified repairs |
| Mutation Arena seed | 4 / 4 mutants caught |
| Detector workspace scan | 133 files, 0 operational errors |
| Original live-key value copy check | 0 copied secret values |

The one skipped unit test is the deliberately opt-in live GitHub/network test
(`ATTESTOR_LIVE_TESTS=1`). Available native compilers were exercised by the remaining
native grading, generation, and Patch Guard tests.

## Browser QA

The real local UI was exercised through a browser against the loopback server:

- health/token initialization and mode capability gating;
- 26 action modes and response-style persistence;
- live workspace scan and Coding Mayhem execution;
- bounded running state and real process-tree cancellation;
- history, search filtering, and result comparison;
- UTF-8 output on Windows;
- zero captured browser console warnings/errors.

## Cross-platform CI definition

`.github/workflows/ci.yml` defines Windows and Ubuntu jobs for Python 3.11 and
3.13. It uses read-only repository permissions, disables persisted checkout
credentials, pins third-party actions to full commit SHAs, runs the full test
suite, runs both detector self-tests, performs a dry workspace scan, and uploads
the deterministic quality-gate artifact. This local verification record does not
claim that the hosted workflow has run until the repository is pushed to GitHub.
