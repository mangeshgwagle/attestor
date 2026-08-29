# Attestor 4.1.5 release notes

Release date: 2026-08-09

Attestor 4.1.5 adds a real, end-to-end **test-mode** billing and entitlement
architecture and corrects production defects found while reviewing the supplied
4.1.4 archive. It does not enable live charges. Existing analysis and report
schemas deliberately remain at 4.1.4; the distribution version is 4.1.5.

## Billing and entitlement system

- Added an isolated FastAPI billing service under `services/billing_api`.
- Added authenticated Stripe-hosted Checkout and Customer Portal session
  creation. Prices, currency, quantities, Product, redirect URLs, and plan are
  server configuration and cannot be supplied by a client.
- Sealed both test subscription contracts: `attestor_workstation` is exactly USD
  $250.00 monthly and Pro/Old Money (`old_money`) is exactly USD $200.00 weekly.
  Their dedicated Checkout routes accept only server-configured Stripe Prices;
  startup, Checkout, and entitlement-granting subscription webhooks verify the
  exact ID, amount, currency, interval, and interval count. The previously
  created $200 monthly Old Money Price and every other mismatch fail closed.
  Webhook state and Ed25519 tokens preserve the selected tier; a desktop
  product-plan/token-plan mismatch also fails closed.
- Added PostgreSQL models and an Alembic initial migration for accounts,
  customer mappings, subscriptions, webhook identities, and minimal audit
  records. SQLite is accepted only by isolated tests.
- Added signed-raw-body webhook verification, strict event schemas, duplicate
  event idempotency, older-event protection, transactional entitlement updates,
  and fail-closed handling of live or wrong-version events.
- Pinned every Stripe SDK request and accepted webhook fixture to the documented
  `2025-06-30.basil` API contract.
- Added hard sandbox stops for `sk_live_`/`rk_live_` credentials, live Prices,
  live Checkout sessions, and live webhook events.
- Added bounded ASGI request bodies, absolute body-read timeouts, rejection of
  every Transfer-Encoding, and exact Content-Length rules for signed webhooks.
- Added server-only Ed25519 entitlement signing. No private key or key-generation
  endpoint ships with Attestor.
- Added a strict desktop verifier with canonical JSON/base64url parsing, exact
  claims, public-key/KID rotation, account and audience binding, 32-day maximum
  token lifetime, and explicitly selected offline grace capped at seven days.
- Added a desktop billing client with `checkout`, `portal`, `refresh`, and
  `status`. It refuses redirects, proxy environment variables, oversized or
  compressed responses, non-HTTPS remote APIs, non-Stripe hosted URLs, and API
  keys in command arguments. Its cache is verified and atomically stored outside
  the Attestor package.
- Added a central hardware-aware feature policy with an immutable feature
  registry. The policy classifies the computer locally into a coarse low, mid,
  or high class and does not accept a caller-supplied hardware report. Any
  feature registered as subscription-gated is waived locally for low/mid
  hardware; high hardware must supply a raw signed entitlement token that the
  policy verifies internally against the expected account and audience.
  Unknown-memory systems fail free into the low class, no hardware measurements
  are transmitted, and availability and resource-safety ceilings remain
  separate from subscription policy.
- Added loopback sandbox launchers, operator documentation, pinned dependency
  files, a non-root container definition, service migrations, and a separate CI
  job.

## Correctness and security fixes

- Fixed Windows/OneDrive secure-read false positives caused by comparing path
  and descriptor `st_ctime_ns` values that can legitimately differ. Path-to-path
  replacement checks retain the creation-time signal.
- Fixed planner verification passing an absolute path to an API that requires a
  normalized project-relative path.
- Fixed planner rescans treating scanner exceptions as proof that a finding was
  absent. Unknown rescan state now rolls back instead of reporting success.
- Fixed Git publishing committing unrelated pre-staged files. Publishing now
  requires an initially empty index, checks the staged set, and suppresses local
  commit/push hooks through an empty hooks path and `--no-verify`.
- Fixed force-clean generation deleting databases, SQLite files, logs, or
  ordinary projects inferred from generic filenames. Cleanup now requires an
  Attestor-owned inventory marker and preserves unproven content.
- Fixed model patch review accepting destructive whole-file replacement or a fix
  to the wrong duplicate finding. It now enforces retention, bounded edits,
  Python callable-surface preservation, and removal of all targeted occurrences.
- Replaced direct model-candidate writes with source-hash binding, durable
  backups, same-directory atomic replacement, permission preservation,
  post-write verification, and verified rollback.
- Bound profile history identity to the SHA-256 of the core `detect.py` engine.
  Findings from builds whose core detector changes are no longer compared as
  though they came from the same engine. Changes elsewhere in the orchestration
  layer still require their own schema or identity decision.
- Fixed the local gateway's non-persisted quota rollover, concurrent reservations,
  missing active-scan accounting, ambiguous HTTP framing, slow-body thread
  exhaustion, webhook race/idempotency behavior, live-mode acceptance, and port
  collision with the UI. Its default is now `127.0.0.1:8791`.
- Hardened model-supplied regular expressions with structural checks plus
  killable timeout-isolated evaluation workers.
- Hardened Attestor4Kids prank creation and cleanup against symlinks, reparse points,
  hardlinks, nonregular files, replacement races, and unsafe manifest updates.
- Hardened VS Code bundle restaging against traversal, duplicate/case-colliding
  manifest paths, symlinks/reparse points, and out-of-tree writes; restaged the
  previously stale detector bundle.
- Hardened Juliet ZIP ingestion with entry, member, aggregate, source archive,
  and compression-ratio limits; streaming reads; and rejection of encryption,
  traversal, nonregular files, and Unicode/case collisions.
- Corrected the explicit security-rule inventory expectation from 15,338 to the
  actual 15,341 rules.
- Corrected model documentation: Attestor ships a small 4096-128-1 learned ranking
  gate (524,545 parameters), not a generative model, and its training utility is
  present under `integrations/gate_trainer`.
- Corrected reproducible release defaults and archive prefix to 4.1.5.
- Expanded release auditing so deterministic packaging refuses private-key,
  credential JSON, database/WAL, bearer-token, and entitlement-cache artifacts
  even if an operator accidentally leaves them inside the source tree.
- Made the invalid-signature policy regression deterministic by changing an
  actual decoded Ed25519 signature byte. The former final-character rewrite
  could occasionally reproduce the original canonical Base64url token.
- Fixed all six profile launchers under Python isolated mode. `superattestor.py`
  now restores only its resolved, trusted detector directory before importing
  local modules, rather than failing startup with `ModuleNotFoundError`.

## Verification added

- 109 passing billing-service checks (plus 7 capability/opt-in skips) exercise
  API authentication, fixed Price selection,
  Stripe SDK argument compatibility without network access, framing and timeout
  boundaries, signed webhooks, live-mode rejection, transactional state,
  migration bootstrap, and desktop-verifier-compatible signing.
- 69 desktop client and entitlement tests (one Windows capability skip) cover
  hostile tokens/responses,
  key rotation, account binding, cache safety, redaction, URL restrictions,
  expiry, and offline grace.
- 20 gateway tests cover quota transactions, concurrency, raw HTTP framing,
  deadlines, bounded workers, webhook ordering, and sandbox-only configuration.
- Additional regression tests cover planner rollback, Git index isolation,
  destructive patch refusal, safe model apply, database/log preservation,
  analyzer-build identity, regex worker termination, filesystem links/reparse
  points, restaging boundaries, hostile archives, and isolated-mode startup.
- Eleven hardware/feature-policy tests cover low/mid waivers, high-tier signed
  access, unknown-memory fail-free behavior, immutable/unknown feature policy,
  local-only hardware classification, and rejection of injected reports,
  caller-supplied subscription flags, dictionary-shaped claims, invalid
  signatures, wrong accounts, invalid plans, future tokens, and expired tokens
  outside the bounded offline-grace policy.
- Direct billing and test dependencies are version-pinned. The release
  verification records the resolved-environment dependency audit and complete
  regression results; operators should additionally lock transitive wheels for
  their deployment platform.

## Deliberate boundaries

- This build can execute end-to-end Stripe test transactions but cannot take
  real money. Live activation requires a separate reviewed build plus merchant,
  pricing, country/currency, tax, legal, privacy, refund, deployment, monitoring,
  and incident-response decisions.
- Attestor remains local/open code. This sandbox supplies an entitlement decision
  API but does not wire it into, disable, or paywall any existing Attestor command;
  every currently registered feature is free and there is no production
  paywall call site. If a subscription-gated feature is registered later, the
  central policy makes its capability free on low/mid hardware. The waiver does
  not fabricate subscriber identity, plan state, portal access, or support
  benefits, and it never bypasses resource or safety limits. This remains a
  cooperative gate, not tamper-proof DRM against a user who controls and can
  modify the client. Strong enforcement must occur at a server-owned service
  boundary.
- No real Stripe API call, live webhook, real card, production PostgreSQL server,
  or secret manager was used during automated verification. Network-facing
  tests use fakes or monkeypatches; deployment testing remains an operator step.
- A correctly priced, account-mapped subscription created directly in the
  Stripe sandbox can grant without traversing Attestor Checkout. That supports
  deliberate administrative subscriptions but is not Checkout-origin proof.
  Exact catalog-Price validation also does not prove cash collected after a
  trial or discount; a live design must choose and enforce those policies.
- The payment subsystem does not upload source code or scan contents.
