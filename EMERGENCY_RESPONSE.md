# Emergency Defensive Response — Design

**Status: BUILT.** `detector/emergency_response42.py`, 55 tests passing
(`detector/test_emergency_response42.py`). Every safety property below is
enforced in code and asserted by a test, not promised in prose.

---

## 0. The central design decision

This capability **decides, authorizes, and records** an emergency response and
emits a scoped **response plan**. It does not reconfigure a firewall, take a
host offline, or put a packet on a wire.

Real enforcement stays with the systems the organization already operates — the
WAF, the load balancer, the SDN controller, the orchestrator. Attestor hands
them an authorized, bounded, audited instruction with a named rollback.

Three things follow, and they are why the design is safe rather than merely
careful:

1. It stays inside Attestor's standing invariant — no target execution, no
   network. The module imports no socket, no HTTP client, no subprocess. A test
   (`test_no_io_capability_is_imported`) asserts this mechanically, because the
   entire safety argument rests on it.
2. A mistake produces a *refused or unexecuted plan*, not an outage. The
   blast radius of a bug in this controller is a log entry.
3. The one genuinely dangerous idea in the brief — an aggressive network
   response — can exist as a **complete simulation** without ever becoming a
   live weapon, because there is no code path from a decision to a packet.

**On the aggressive tier.** You asked that anything crossing a safety boundary
be replaced with a defensive simulation. It is, structurally:

- No threat ladder names it. The strongest response the decision logic will ever
  recommend against real infrastructure is hard isolation of an asset the
  organization owns.
- `authorize()` caps at tier 3; tier 4 is unreachable through the emergency path.
- `dispatch()` refuses it against any non-synthetic asset.
- `Asset` refuses to register a real asset with `max_tier=4`.
- It runs only through `simulate()`, only against assets marked synthetic and
  owned by `synthetic-lab`.

Five independent barriers, each separately tested. This is not a tool that
attacks anyone; it is a tool that rehearses.

---

## 1. Architecture

```
 evidence (signals, scanner findings, telemetry digests)
        │
        ▼
 ┌──────────────────┐   registry of explicitly authorized assets
 │   CONTROLLER     │◄──  Asset(id, owner, scopes, max_tier,
 │  state machine   │      collateral_tolerance, is_synthetic)
 │  decision ladder │
 │  safeguards      │
 └────────┬─────────┘
          │ emits
          ▼
   ResponsePlan  ──►  external enforcement point  (outside this module)
          │           WAF / LB / SDN / orchestrator
          ▼
   AuditChain (append-only, hash-chained, tamper-evident)
```

**The registry is the scope boundary.** An `Asset` declares explicit prefix
scopes — a CIDR string, a hostname, a segment id. A bare `*` is refused at
construction. A target that matches no asset is refused; a target matching *two*
assets is also refused, because an ambiguous target is a misidentification risk
and guessing is the failure mode that hurts people. There is no code path by
which arbitrary third-party infrastructure becomes a valid target.

---

## 2. Authorization state machine

```
        declare_emergency          authorize
  NORMAL ─────────────────► ARMED ───────────► AUTHORIZED
    ▲                         │                    │
    │                         │ window lapses      │ ttl reached
    │                         ▼                    ▼
    │                      ABORTED              EXPIRED
    │                         │                    │
    │      reset(actor)       │                    │
    └─────────────────────────┴────────────────────┤
    │                                              │
    └──────────────── SHUTDOWN ◄────────────────────┘
                   emergency_stop (from any state)
```

| State | Response available? | Meaning |
|---|---|---|
| `NORMAL` | no | Dormant. The default. |
| `ARMED` | **no** | Emergency declared; authorizes nothing on its own. |
| `AUTHORIZED` | yes, bounded | In force, tier-capped and time-capped. |
| `EXPIRED` | no | Time limit reached; fails closed. |
| `SHUTDOWN` | no | Kill switch pulled; terminal until deliberate reset. |
| `ABORTED` | no | Declaration lapsed unauthorized. |

**Declaration is not authorization.** `declare_emergency` requires a
high/severe/critical severity, a named declarer, a reason, and a **cited
evidence digest** — you cannot declare an emergency on a hunch. It opens a
15-minute window and grants nothing.

**Two humans for anything disruptive.** At tier ≥ 2 the authorizer must differ
from the declarer. The only way to skip the live second human is an
`AutonomousPolicy`, which must name an approver and a document reference, still
expires, and cannot authorize above tier 3. It removes the live human, not the
accountability.

**Time limits are structural.** Every authorization carries a TTL capped at one
hour. Expiry is evaluated on *every* state read, so a controller cannot act
after its window even if nobody asks it to stop.

**The kill switch works from any state** and is terminal — including for drills —
until someone deliberately calls `reset` with their name attached.

---

## 3. Decision logic — least disruptive first

Measures are ordered by tier and carry a modelled blast radius:

| Measure | Tier | Disruption | Notes |
|---|---|---|---|
| `observe` | 0 | 0 | Always available; the degraded default |
| `rate_limit` | 1 | 10 | |
| `filter_source` | 1 | 15 | |
| `failover` | 2 | 35 | Disruptive: needs corroboration |
| `isolate_segment` | 2 | 40 | Disruptive: needs corroboration |
| `hard_isolate` | 3 | 80 | Strongest real measure |
| `aggressive_network_response` | 4 | 100 | **Simulation only** |

`decide()` walks the ladder for the threat class and returns the *first* measure
within the authorized ceiling — least disruptive that is effective. If the
effective measure is above the ceiling, it returns `observe` and records that a
stronger response would need higher authorization. **It degrades to watching
rather than silently acting.**

### Safeguards applied at dispatch

Each is a separate refusal with its own test:

| Risk | Guard |
|---|---|
| Target misidentification | Must resolve to *exactly one* registered asset |
| Acting on a hunch | Every action cites an evidence digest |
| Wrong target, disruptive action | Tier ≥ 2 needs ≥ 2 corroborating signals |
| Collateral impact | Modelled blast radius must be ≤ the asset's tolerance |
| Accidental escalation | Rising a tier requires a 60s cooldown; de-escalation is never blocked |
| Abuse of emergency mode | Asset ceiling is enforced *independently* of the operator's authorization — an over-broad grant still cannot exceed what the asset permits |
| Third-party targeting | Registry scopes; no wildcards |

The asset ceiling being independent of the authorization ceiling matters: it
means a mistaken or coerced grant of tier 3 still cannot hard-isolate a database
registered at tier 2. Authority and target policy must *both* permit an action.

---

## 4. Audit model

Every activation, decision, target, authorization, refusal, drill, and stop is
appended to a hash-chained log. Each entry commits to its predecessor's digest,
so editing or deleting an entry after the fact breaks `verify_audit()` at that
point rather than passing silently.

Recorded events: `init`, `declare`, `authorize`, `decide`, `dispatch`,
`dispatch_refused`, `simulate`, `simulate_refused`, `expire`, `abort`,
`emergency_stop`, `reset`.

**Refusals are audited as carefully as actions.** A record of what the system
declined to do — and why — is what distinguishes a controlled response from a
lucky one, and it is the evidence an incident review will actually want.

---

## 5. Simulation / test mode

`simulate()` is the complete rehearsal path. It runs **any** measure, including
the aggressive tier, against synthetic infrastructure only:

- The target must resolve to an asset with `is_synthetic=True`, owned by
  `synthetic-lab`. Every real asset is refused with a message naming that reason.
- It requires no declared emergency — the point is to exercise the machinery on
  a quiet afternoon rather than discover its behaviour during an incident.
- Drills are fully audited and marked `simulated: True`.
- The kill switch halts drills too.

---

## 6. Failure handling

Every failure mode resolves toward inaction:

| Failure | Behaviour |
|---|---|
| Clock skew / TTL reached | → `EXPIRED`, all response refused |
| Authorization never arrives | Arming window lapses → `ABORTED` |
| Unknown or ambiguous target | Refused, audited; no plan emitted |
| Unknown measure or threat class | Refused |
| Ceiling exceeded (auth or asset) | Refused |
| Insufficient corroboration | Refused |
| Blast radius over tolerance | Refused |
| Operator uncertainty | `emergency_stop` from any state, terminal |
| Audit tampering | `verify_audit()` reports the exact broken entry |

There is no "best effort" path and no default-allow branch. A refusal raises
`EmergencyError` after logging; **nothing is emitted on refusal.**

---

## 7. Testing strategy

55 tests, deliberately weighted toward adversarial cases — the suite tries to
break the controller rather than demonstrate it working:

| Group | What it attacks |
|---|---|
| `TheModuleCannotAct` | Asserts no I/O capability exists in the source |
| `StateMachineGatesEverything` | Acting from every non-authorized state |
| `SecondHumanIsRequired` | Self-authorization; policies exceeding ceilings |
| `ScopeCannotReachThirdParties` | Public IPs, hostnames, wildcards, ambiguity |
| `AggressiveTierIsSimulationOnly` | Five separate routes to a real asset |
| `TimeLimitsAndTheKillSwitch` | Acting after expiry; re-arming after shutdown |
| `MisidentificationAndCollateralGuards` | Uncorroborated and over-broad actions |
| `EscalationIsRateLimited` | Runaway escalation |
| `AuditIsCompleteAndTamperEvident` | Editing and deleting audit entries |

A clock is injected, so expiry and cooldown behaviour is deterministic rather
than timing-dependent.

**One test caught a real design gap during construction:** the aggressive tier
was unreachable *everywhere*, including the lab, which meant the "complete
simulation mode" requirement was not actually met. The boundary was right and
the capability was missing. That is what `simulate()` exists to provide.

---

## 8. Integration and deployment notes

- **The plan is an instruction, not an effect.** An enforcement adapter must
  translate `ResponsePlan` into a concrete change. That adapter is the component
  that needs credentials — and it should validate the plan's asset scope again
  at its own boundary. Never trust a plan more than the registry it came from.
- **Registry integrity is the trust root.** Whoever can edit the asset registry
  can widen scope. It belongs under change control with the same rigor as
  firewall rules; `Registry.digest()` exists so the active registry can be
  pinned and compared.
- **`decide()` is advisory.** A human operator can select a gentler measure than
  the recommendation; every guard still applies to whatever they dispatch.

### Deliberate non-goals

Not implemented, and not to be added: traffic generation of any kind, scanning
or probing of external hosts, any "hack back" against an attacker's
infrastructure, or autonomous action against systems not in the registry.
Excluding these is what makes the rest deployable inside an enterprise —
and hack-back is, in most jurisdictions including India, unlawful regardless of
provocation.
