# Attestor 4.1.5 verification record

Verification date: 2026-08-09

This record covers the final Attestor 4.1.5 source tree, including the Stripe
test-mode billing sandbox and its two sealed contracts. `attestor_workstation`
requires a server-selected Price of exactly USD 25,000 cents, currency `usd`,
recurring interval `month`, and interval count `1`; Pro/Old Money (`old_money`)
requires USD 20,000 cents, currency `usd`, recurring interval `week`, and
interval count `1`. No live credential, payment, card, private signing key,
production database, or production Stripe request was used.

## Executed results

- Full detector discovery from `detector` with Python 3.12.10:
  **2,228 tests completed successfully**, with 33 documented
  platform/capability skips, in 279.469 seconds. The same run scanned 19
  planted-corpus files, emitted 51
  findings, and detected all **42/42** expected planted bugs.
- A focused feature-policy, gateway, entitlement, and desktop-client run
  completed **100 tests**, with one Windows capability skip.
- Billing service with the pinned verification dependencies: **109 passed** and
  7 capability/opt-in skips (116 collected) in 11.08 seconds. These checks use
  fake or monkeypatched Stripe operations and make no Stripe network request.
- Real database supplement: **2/2 passed** in 5.85 seconds against a disposable
  loopback PostgreSQL 17.6 container pinned to image digest
  `sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3`.
  The uniquely named container was removed after the run.
- Desktop entitlement verifier and billing client: **69 tests passed**, with
  one Windows filesystem-capability skip, in 1.273 seconds.
- Independently discovered integration suites: **103 tests passed**, with two
  Windows symlink-capability skips. Breakdown: gate trainer 11, MC assembler
  49, Attestor Chat 21, Attestor Reason 14, and Attestor4Kids 8.
- VS Code server restaging reported current for all 15 staged files.
- Node.js 25.5.0 parsed all six JavaScript files with `--check` and emitted no
  syntax diagnostic.
- In-memory compilation read 368 Python files with zero compile errors. The
  intentional planted fixture `realworld/payments.py` emitted its expected
  `is 0` syntax warning. One YAML file and five JSON files parsed successfully.
- All 27 local targets referenced across 33 Markdown files resolved.
- `pip check` reported no broken requirements. `pip-audit` 2.10.1 reported no
  known vulnerability in the exact recursive `requirements-verify.txt` set.

## Sealed Price-contract security assertions

Focused tests prove that:

- only exact authenticated POST routes exist for `attestor_workstation` and
  `old_money`; an arbitrary plan path is 404 and both routes require an empty
  body plus an idempotency key;
- the desktop maps `old_money` only to
  `/v1/checkout-sessions/old-money`, and a response naming another plan is
  rejected;
- the client cannot submit an amount, currency, quantity, Product, or Price;
- changing either plan's amount, currency, interval, or interval count prevents
  customer/session creation and returns a fail-closed error;
- exactly $250 monthly is accepted for `attestor_workstation`, exactly $200 weekly
  is accepted for `old_money`, and the superseded $200 monthly Old Money Price
  is rejected before customer or Checkout session creation;
- configured Prices are preflighted before the API serves requests, and a
  subscription webhook with missing, mixed, or contract-mismatched Price data
  cannot grant or preserve an entitlement;
- authoritative subscription webhooks recognize only the two configured Price
  IDs, preserve the selected tier, and prefer an active `old_money`
  subscription when both tiers are active;
- the server signs token plan `old_money`, the desktop verifier accepts that
  exact signed plan, and response/token plan disagreement prevents cache
  replacement; and
- the workstation product still maps to token plan `high`, while Old Money maps
  to token plan `old_money`.

## Hardware-waiver security assertions

Focused tests and source review prove that:

- the central feature registry is immutable, unknown feature names fail closed,
  and all currently registered features are free, so this release has no
  production paywall call site;
- hardware classification is performed locally and exposes only low, mid, or
  high; callers cannot inject a hardware report or a `requires_subscription`
  flag, and no hardware measurements are transmitted;
- a feature registered as subscription-gated is available to low/mid hardware
  through a local capability waiver, while high hardware must provide a raw
  Ed25519-signed token that the feature policy verifies internally against its
  key ring, expected account, audience, plan, chronology, and bounded
  offline-grace rules;
- a dictionary or caller-constructed access decision cannot replace the raw
  signed token; invalid signatures, wrong accounts, invalid plans, future
  tokens, and expiration outside policy fail closed; and
- the invalid-signature regression flips a decoded signature byte rather than
  replacing a Base64url character that could already have the same value; the
  corrected check denied in 20/20 repeated focused runs; and
- the low/mid waiver grants feature capability only. It does not invent a paid
  subscription, subscriber identity, support benefit, or portal entitlement,
  and resource, concurrency, and safety limits remain enforced independently.

## Review notes

Attestor's deep static scan produced no LOW-or-higher finding in seven of the eight
new billing/entitlement modules. It labeled the literal canonical PEM header
`-----BEGIN PRIVATE KEY-----` in `app/entitlement_signer.py` as a hardcoded
secret. That literal is a format sentinel used to reject noncanonical key
files; it contains no key bytes or credential and is therefore a reviewed false
positive. No private key is present in the distribution.

A preliminary detector run under an external dependency virtual environment
was discarded because its child-process launcher could not start the base
interpreter, causing cascading Crucible failures. The affected 102 runtime
tests passed under the valid system interpreter. A separate current-working-
directory assumption in the cross-process cache-lock regression was corrected;
that focused test and the subsequent authoritative 2,228-test run passed.

All three Windows profile launchers completed `--help` with exit code zero
under Python isolated mode after the trusted detector-path fix. The UI's
isolated entry point also completed successfully. A dedicated subprocess test
now preserves that boundary; a Unix `sh` executable was unavailable on this
Windows host, so the structurally identical `.sh` wrappers were not directly
executed here.

## Deliberate limits

This is still a Stripe **test-mode-only** implementation. It rejects live
credentials, live Prices, live sessions, and live webhook events. The two paid
plans produce authenticated entitlement decisions, but Attestor 4.1.5 does not
disable or paywall an existing feature: every current feature registry entry is
free and there is no production paywall call site. A future subscription-gated
entry is capability-waived on low/mid hardware without manufacturing subscriber
status; resource and safety controls are separate and remain active. The
sandbox CLI takes an operator-supplied public trust key; a production client
would need a pinned vendor public root and origin. Real-money activation needs a
separate reviewed release plus legal, tax, privacy, refund, monitoring, backup,
reconciliation, and incident-response work.

A correctly priced and account-mapped subscription created directly in Stripe
can grant without an Attestor Checkout session; this sandbox treats that as an
administrative subscription path, not proof of Checkout origin. Exact catalog
Price validation likewise does not prove final cash collection when a trial or
discount applies. A live design must choose and persist explicit origin,
payment-evidence, trial, coupon, proration, and grandfathering policies.
