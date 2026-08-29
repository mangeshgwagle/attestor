#!/usr/bin/env python3
"""Emergency Defensive Response: an authorized, auditable, last-resort controller.

What this is, and what it deliberately is not
---------------------------------------------
When a system the organization owns is under active, severe attack and ordinary
defences have failed, an operator needs to reach for stronger containment fast --
but "fast and strong" is exactly the situation in which a tool does the most
damage if it is wrong. This controller is built so that being wrong is safe.

It **decides, authorizes, and records** a defensive response and emits a scoped
*response plan*. It does not reconfigure a firewall, take a host offline, or put
a packet on a wire. Real enforcement stays with the systems the organization
already controls; this module hands them an authorized, bounded, audited
instruction and nothing more. That keeps it inside Attestor's standing invariant
-- no target execution, no network -- which is why this file imports no socket,
no HTTP client, and no subprocess (a test asserts that).

The one genuinely dangerous idea in the brief -- an "aggressive network
response" -- exists here **only as a simulation**. It is structurally impossible
to aim it at a real registered asset: the decision ladder never recommends it
against real infrastructure, and `dispatch` refuses it against any target that
is not the synthetic lab. The powerful last resort is a rehearsal, never a live
weapon pointed outward. That is the design, not a disclaimer.

The safety properties, each enforced in code and checked by a test
------------------------------------------------------------------
1. Response is available in exactly one state (`AUTHORIZED`) and nowhere else.
2. Reaching that state needs two different humans for anything disruptive,
   unless a pre-approved, documented autonomous policy is supplied.
3. Every authorization expires; an expired controller fails closed to no-response.
4. A target must resolve to an explicitly registered asset scope, or it is
   refused -- there is no way to act on arbitrary third-party infrastructure.
5. A disruptive action needs corroborating evidence, guarding misidentification.
6. An action whose modelled blast radius exceeds the asset's tolerance is refused.
7. Escalation to a higher tier needs a cooldown to elapse -- no runaway ladder.
8. The aggressive tier is simulation-only and cannot touch a real asset.
9. The emergency stop works from any state and is terminal until a deliberate reset.
10. Every activation, decision, target, authorization, and action is appended to
    a hash-chained audit log that detects any later edit or deletion.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

VERSION = "4.2"
AUDIT_SCHEMA = "attestor-emergency-audit/4.2"
PLAN_SCHEMA = "attestor-emergency-plan/4.2"

# --------------------------------------------------------------------------- #
# states of the authorization machine
# --------------------------------------------------------------------------- #
NORMAL = "NORMAL"          # dormant; no response available
ARMED = "ARMED"            # emergency declared, awaiting authorization
AUTHORIZED = "AUTHORIZED"  # authorized and in force; response permitted
EXPIRED = "EXPIRED"        # time limit reached; must re-authorize
SHUTDOWN = "SHUTDOWN"      # emergency stop pulled; terminal until reset
ABORTED = "ABORTED"        # declaration withdrawn or armed-window lapsed
STATES = (NORMAL, ARMED, AUTHORIZED, EXPIRED, SHUTDOWN, ABORTED)

# --------------------------------------------------------------------------- #
# response measures, least disruptive first. `tier` orders escalation;
# `disruption` is a modelled 0..100 blast-radius weight; `simulation_only`
# marks the measure that may never touch a real asset.
# --------------------------------------------------------------------------- #
OBSERVE = "observe"
RATE_LIMIT = "rate_limit"
FILTER_SOURCE = "filter_source"
ISOLATE_SEGMENT = "isolate_segment"
FAILOVER = "failover"
HARD_ISOLATE = "hard_isolate"
AGGRESSIVE_SIM = "aggressive_network_response"

MEASURES: dict[str, dict[str, Any]] = {
    OBSERVE:         {"tier": 0, "disruption": 0,   "simulation_only": False},
    RATE_LIMIT:      {"tier": 1, "disruption": 10,  "simulation_only": False},
    FILTER_SOURCE:   {"tier": 1, "disruption": 15,  "simulation_only": False},
    ISOLATE_SEGMENT: {"tier": 2, "disruption": 40,  "simulation_only": False},
    FAILOVER:        {"tier": 2, "disruption": 35,  "simulation_only": False},
    HARD_ISOLATE:    {"tier": 3, "disruption": 80,  "simulation_only": False},
    AGGRESSIVE_SIM:  {"tier": 4, "disruption": 100, "simulation_only": True},
}
MAX_REAL_TIER = 3  # tier 4 is simulation-only, by construction

#: Threat class -> ordered candidate measures, least disruptive first.
#: Note what is absent: no ladder for a real threat ever names the aggressive
#: tier. The strongest response the decision logic will recommend against real
#: infrastructure is a hard isolation of an asset the organization owns.
LADDER: dict[str, tuple[str, ...]] = {
    "reconnaissance":  (OBSERVE,),
    "volumetric_flood": (RATE_LIMIT, ISOLATE_SEGMENT, FAILOVER),
    "exploit_attempt": (FILTER_SOURCE, ISOLATE_SEGMENT),
    "lateral_movement": (ISOLATE_SEGMENT, HARD_ISOLATE),
    "asset_compromise": (FAILOVER, HARD_ISOLATE),
    "unknown":         (OBSERVE,),
}

DISRUPTIVE_TIER = 2          # tier at/above which corroboration is required
MIN_CORROBORATION = 2        # independent signals needed for a disruptive action
DEFAULT_ARMING_WINDOW = 15 * 60      # seconds a declaration waits for authorization
DEFAULT_MAX_ACTIVE = 60 * 60         # hard cap on an authorization's lifetime
DEFAULT_ESCALATION_COOLDOWN = 60     # seconds between rising tiers
SYNTHETIC_OWNER = "synthetic-lab"    # the only owner the aggressive tier may hit

_SCOPE_RE = re.compile(r"[A-Za-z0-9._:/\-]{3,255}")
_ID_RE = re.compile(r"[A-Za-z0-9._:\-]{1,128}")
GENESIS = "0" * 64


class EmergencyError(ValueError):
    """A request was refused. Raised instead of taking an unsafe action."""


# --------------------------------------------------------------------------- #
# canonical form + hash-chained audit
# --------------------------------------------------------------------------- #

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def digest_json(value: Any) -> str:
    return _sha(canonical_json(value))


class AuditChain:
    """Append-only, hash-chained record. Any later edit breaks `verify`."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def append(self, *, event: str, actor: str, detail: Mapping[str, Any],
               at: float) -> dict[str, Any]:
        previous = self._entries[-1]["entry_sha256"] if self._entries else GENESIS
        body = {
            "schema": AUDIT_SCHEMA,
            "index": len(self._entries),
            "event": str(event),
            "actor": str(actor),
            "detail": json.loads(canonical_json(detail)),
            "at": round(float(at), 3),
            "prev_sha256": previous,
        }
        entry = dict(body)
        entry["entry_sha256"] = _sha(canonical_json(body) + "|" + previous)
        self._entries.append(entry)
        return entry

    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        previous = GENESIS
        for position, entry in enumerate(self._entries):
            if entry.get("index") != position:
                problems.append("entry %d has wrong index" % position)
            if entry.get("prev_sha256") != previous:
                problems.append("entry %d does not chain" % position)
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            if entry.get("entry_sha256") != _sha(
                    canonical_json(body) + "|" + entry.get("prev_sha256", "")):
                problems.append("entry %d digest does not match" % position)
            previous = entry.get("entry_sha256", "")
        return (not problems), problems


# --------------------------------------------------------------------------- #
# registered, authorized infrastructure -- the only things that can be a target
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Asset:
    """One piece of infrastructure the organization has authorized us to defend.

    `scopes` are opaque prefix tokens (a hostname, a CIDR string, a segment id).
    A target matches this asset only if it begins with one of them. `max_tier`
    caps how strong a response this specific asset permits; `collateral_tolerance`
    caps the modelled blast radius. `is_synthetic` marks lab infrastructure and
    is the only thing the aggressive tier may ever touch.
    """
    asset_id: str
    owner: str
    scopes: tuple[str, ...]
    max_tier: int = 2
    collateral_tolerance: int = 40
    is_synthetic: bool = False

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.asset_id):
            raise EmergencyError("asset_id is not a valid identifier")
        if not self.owner.strip():
            raise EmergencyError("asset owner is required")
        if not self.scopes:
            raise EmergencyError("an asset must declare at least one scope")
        for scope in self.scopes:
            if scope in ("", "*") or not _SCOPE_RE.fullmatch(scope):
                raise EmergencyError("scope %r is not a bounded, explicit token" % scope)
        if not 0 <= self.max_tier <= 4:
            raise EmergencyError("max_tier out of range")
        if self.is_synthetic and self.owner != SYNTHETIC_OWNER:
            raise EmergencyError("synthetic assets must be owned by %r" % SYNTHETIC_OWNER)
        if not self.is_synthetic and self.max_tier > MAX_REAL_TIER:
            raise EmergencyError("a real asset may not authorize the simulation-only tier")

    def covers(self, target: str) -> bool:
        return any(target == s or target.startswith(s) for s in self.scopes)


class Registry:
    """The set of authorized assets. A target outside every scope is refused."""

    def __init__(self, assets: Sequence[Asset]) -> None:
        seen: dict[str, Asset] = {}
        for asset in assets:
            if asset.asset_id in seen:
                raise EmergencyError("duplicate asset_id %r" % asset.asset_id)
            seen[asset.asset_id] = asset
        self._assets = seen

    def resolve(self, target: str) -> Asset | None:
        if not isinstance(target, str) or not _SCOPE_RE.fullmatch(target or ""):
            return None
        matches = [a for a in self._assets.values() if a.covers(target)]
        # An ambiguous target (covered by two assets) is a misidentification
        # risk, so it is treated as unresolved rather than guessed.
        return matches[0] if len(matches) == 1 else None

    def digest(self) -> str:
        return digest_json([
            {"id": a.asset_id, "owner": a.owner, "scopes": list(a.scopes),
             "max_tier": a.max_tier, "synthetic": a.is_synthetic}
            for a in sorted(self._assets.values(), key=lambda x: x.asset_id)])


# --------------------------------------------------------------------------- #
# the documented, pre-approved autonomous policy (the only way to skip a
# second human) and the emitted response plan
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AutonomousPolicy:
    """A pre-approved standing authorization. Its existence is the audit trail.

    It still expires, still caps the tier, and still cannot exceed real-asset
    limits. It removes the *live* second human, not the accountability: a real
    person approved it in advance and is named in it.
    """
    policy_id: str
    approved_by: str
    approved_at: float
    doc_ref: str
    max_tier: int
    conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.policy_id):
            raise EmergencyError("policy_id is not a valid identifier")
        if not self.approved_by.strip() or not self.doc_ref.strip():
            raise EmergencyError("an autonomous policy must name an approver and a document")
        if not 0 <= self.max_tier <= MAX_REAL_TIER:
            raise EmergencyError("an autonomous policy may not authorize above tier %d" % MAX_REAL_TIER)


@dataclass(frozen=True)
class ResponsePlan:
    """An authorized instruction for an external enforcement point. Not execution."""
    plan_id: str
    measure: str
    tier: int
    target: str
    asset_id: str
    simulated: bool
    rationale: str
    created_at: float
    expires_at: float
    rollback: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA, "plan_id": self.plan_id, "measure": self.measure,
            "tier": self.tier, "target": self.target, "asset_id": self.asset_id,
            "simulated": self.simulated, "rationale": self.rationale,
            "created_at": self.created_at, "expires_at": self.expires_at,
            "rollback": self.rollback,
        }


# --------------------------------------------------------------------------- #
# the controller
# --------------------------------------------------------------------------- #

@dataclass
class _Authorization:
    declarer: str
    authorizer: str
    max_tier: int
    granted_at: float
    expires_at: float
    autonomous: str  # policy_id, or "" for a live two-human grant


class EmergencyController:
    """The authorization state machine and decision logic.

    A single controller guards a single registry. It holds no credentials and
    performs no I/O; the clock is injected so the whole machine, including
    expiry, is deterministically testable.
    """

    def __init__(self, registry: Registry, *,
                 clock: Callable[[], float],
                 arming_window: int = DEFAULT_ARMING_WINDOW,
                 max_active: int = DEFAULT_MAX_ACTIVE,
                 escalation_cooldown: int = DEFAULT_ESCALATION_COOLDOWN) -> None:
        self._registry = registry
        self._clock = clock
        self._arming_window = int(arming_window)
        self._max_active = int(max_active)
        self._cooldown = int(escalation_cooldown)
        self._state = NORMAL
        self._declared_at = 0.0
        self._declarer = ""
        self._auth: _Authorization | None = None
        self._last_tier = -1
        self._last_dispatch_at = 0.0
        self._audit = AuditChain()
        self._audit.append(event="init", actor="system",
                           detail={"registry_sha256": registry.digest()},
                           at=self._clock())

    # -- introspection ----------------------------------------------------- #

    @property
    def state(self) -> str:
        self._refresh_expiry()
        return self._state

    def audit_log(self) -> tuple[dict[str, Any], ...]:
        return self._audit.entries()

    def verify_audit(self) -> tuple[bool, list[str]]:
        return self._audit.verify()

    def status(self) -> dict[str, Any]:
        self._refresh_expiry()
        remaining = 0.0
        if self._state == AUTHORIZED and self._auth is not None:
            remaining = max(0.0, self._auth.expires_at - self._clock())
        return {
            "state": self._state,
            "max_tier": self._auth.max_tier if self._auth else None,
            "seconds_remaining": round(remaining, 1),
            "audit_intact": self._audit.verify()[0],
        }

    # -- state transitions ------------------------------------------------- #

    def _refresh_expiry(self) -> None:
        """Fail closed on time: an authorization past its limit is not in force."""
        if self._state == AUTHORIZED and self._auth is not None:
            if self._clock() >= self._auth.expires_at:
                self._state = EXPIRED
                self._audit.append(event="expire", actor="system",
                                   detail={"reason": "authorization time limit reached"},
                                   at=self._clock())
        elif self._state == ARMED:
            if self._clock() >= self._declared_at + self._arming_window:
                self._state = ABORTED
                self._audit.append(event="abort", actor="system",
                                   detail={"reason": "arming window lapsed without authorization"},
                                   at=self._clock())

    def declare_emergency(self, *, declarer: str, severity: str,
                          evidence_digest: str, reason: str) -> None:
        """NORMAL -> ARMED. Opens the window; authorizes nothing on its own."""
        self._refresh_expiry()
        if self._state != NORMAL:
            raise EmergencyError("cannot declare from state %s" % self._state)
        if severity not in ("high", "severe", "critical"):
            raise EmergencyError("emergency declaration requires a high/severe/critical severity")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_digest or ""):
            raise EmergencyError("a declaration must cite an evidence digest")
        if not declarer.strip() or not reason.strip():
            raise EmergencyError("declarer and reason are required")
        self._state = ARMED
        self._declarer = declarer.strip()
        self._declared_at = self._clock()
        self._audit.append(event="declare", actor=self._declarer,
                           detail={"severity": severity, "reason": reason[:512],
                                   "evidence_sha256": evidence_digest},
                           at=self._clock())

    def authorize(self, *, authorizer: str, max_tier: int, ttl_seconds: int,
                  autonomous_policy: AutonomousPolicy | None = None) -> None:
        """ARMED -> AUTHORIZED. Two different humans, or a documented policy.

        For anything disruptive (tier >= 2) a live grant requires an authorizer
        who is not the declarer. The only way to skip that second human is a
        pre-approved autonomous policy, which still expires and still cannot
        exceed the real-asset tier ceiling.
        """
        self._refresh_expiry()
        if self._state != ARMED:
            raise EmergencyError("authorization requires the ARMED state, not %s" % self._state)
        if not isinstance(max_tier, int) or not 0 <= max_tier <= MAX_REAL_TIER:
            raise EmergencyError("max_tier must be between 0 and %d" % MAX_REAL_TIER)
        if not authorizer.strip():
            raise EmergencyError("an authorizer is required")
        ttl = int(ttl_seconds)
        if not 1 <= ttl <= self._max_active:
            raise EmergencyError("ttl must be between 1 and %d seconds" % self._max_active)

        policy_id = ""
        if autonomous_policy is not None:
            if max_tier > autonomous_policy.max_tier:
                raise EmergencyError("requested tier exceeds the autonomous policy ceiling")
            policy_id = autonomous_policy.policy_id
        elif max_tier >= DISRUPTIVE_TIER and authorizer.strip() == self._declarer:
            raise EmergencyError(
                "a disruptive authorization needs a second human; declarer and "
                "authorizer must differ, or supply a pre-approved autonomous policy")

        now = self._clock()
        self._auth = _Authorization(
            declarer=self._declarer, authorizer=authorizer.strip(),
            max_tier=max_tier, granted_at=now, expires_at=now + ttl,
            autonomous=policy_id)
        self._state = AUTHORIZED
        self._last_tier = -1
        self._audit.append(event="authorize", actor=authorizer.strip(),
                           detail={"max_tier": max_tier, "ttl_seconds": ttl,
                                   "autonomous_policy": policy_id or None,
                                   "two_party": policy_id == "" and authorizer.strip() != self._declarer},
                           at=now)

    def emergency_stop(self, *, actor: str, reason: str = "") -> None:
        """The kill switch. Works from any state; terminal until `reset`."""
        was = self._state
        self._state = SHUTDOWN
        self._auth = None
        self._audit.append(event="emergency_stop", actor=(actor.strip() or "unknown"),
                           detail={"from_state": was, "reason": reason[:512]},
                           at=self._clock())

    def reset(self, *, actor: str) -> None:
        """Return to NORMAL from a terminal state. Deliberate and logged."""
        self._refresh_expiry()
        if self._state not in (EXPIRED, SHUTDOWN, ABORTED):
            raise EmergencyError("reset is only valid from a terminal state, not %s" % self._state)
        if not actor.strip():
            raise EmergencyError("reset requires a named actor")
        prior = self._state
        self._state = NORMAL
        self._auth = None
        self._declarer = ""
        self._last_tier = -1
        self._audit.append(event="reset", actor=actor.strip(),
                           detail={"from_state": prior}, at=self._clock())

    # -- decision + dispatch ---------------------------------------------- #

    def decide(self, *, threat_class: str) -> str:
        """The least disruptive measure that is effective and currently permitted.

        Returns a measure name -- never the aggressive tier for a real threat,
        which is not present in any ladder. If the effective measure is above
        what is authorized, it returns OBSERVE and records that a stronger
        response would need a higher authorization, rather than silently acting.
        """
        self._refresh_expiry()
        if self._state != AUTHORIZED or self._auth is None:
            raise EmergencyError("no decision outside the AUTHORIZED state")
        candidates = LADDER.get(threat_class)
        if candidates is None:
            raise EmergencyError("unknown threat class %r" % (threat_class,))
        ceiling = self._auth.max_tier
        chosen = OBSERVE
        for name in candidates:
            if MEASURES[name]["tier"] <= ceiling:
                chosen = name
                break
        self._audit.append(event="decide", actor="attestor",
                           detail={"threat_class": threat_class, "chosen": chosen,
                                   "ceiling_tier": ceiling}, at=self._clock())
        return chosen

    def dispatch(self, *, measure: str, target: str, evidence_digest: str,
                 corroborating_signals: int = 0,
                 blast_radius: int | None = None) -> ResponsePlan:
        """Validate every safeguard, then emit an authorized response plan.

        This produces an instruction for an external enforcement point (or, for
        the aggressive tier, for the synthetic simulator). It performs no
        network or system action itself. Every failure is a refusal with a
        reason, recorded in the audit log; nothing is emitted on refusal.
        """
        self._refresh_expiry()
        now = self._clock()
        if self._state != AUTHORIZED or self._auth is None:
            self._refuse("dispatch", target, "controller is not in the AUTHORIZED state")
        if measure not in MEASURES:
            self._refuse("dispatch", target, "unknown measure %r" % (measure,))
        spec = MEASURES[measure]
        tier = spec["tier"]

        if not re.fullmatch(r"[0-9a-f]{64}", evidence_digest or ""):
            self._refuse("dispatch", target, "an action must cite an evidence digest")

        asset = self._registry.resolve(target)
        if asset is None:
            # Target misidentification guard: unknown or ambiguous target.
            self._refuse("dispatch", target,
                         "target does not resolve to exactly one registered asset")

        # The categorical boundary is checked before the tunable ceilings, so an
        # operator aiming the aggressive tier at real infrastructure is told that
        # it is simulation-only rather than that a limit was set too low --
        # the second reads like something to go and raise.
        if spec["simulation_only"] and not asset.is_synthetic:
            self._refuse("dispatch", target,
                         "the aggressive tier is simulation-only and cannot target a real asset")
        if asset.is_synthetic is False and tier > MAX_REAL_TIER:
            self._refuse("dispatch", target, "tier above the real-asset ceiling")
        if tier > self._auth.max_tier:
            self._refuse("dispatch", target,
                         "measure tier %d exceeds the authorization ceiling %d"
                         % (tier, self._auth.max_tier))
        if tier > asset.max_tier:
            self._refuse("dispatch", target,
                         "measure tier %d exceeds asset ceiling %d" % (tier, asset.max_tier))

        # Corroboration guard for disruptive tiers.
        if tier >= DISRUPTIVE_TIER and corroborating_signals < MIN_CORROBORATION:
            self._refuse("dispatch", target,
                         "a disruptive action needs >= %d corroborating signals" % MIN_CORROBORATION)

        # Collateral guard.
        modelled = spec["disruption"] if blast_radius is None else int(blast_radius)
        if modelled > asset.collateral_tolerance:
            self._refuse("dispatch", target,
                         "modelled blast radius %d exceeds asset tolerance %d"
                         % (modelled, asset.collateral_tolerance))

        # Accidental-escalation guard: rising a tier needs the cooldown.
        if self._last_tier >= 0 and tier > self._last_tier:
            if now - self._last_dispatch_at < self._cooldown:
                self._refuse("dispatch", target,
                             "escalation to a higher tier is within the cooldown window")

        plan = ResponsePlan(
            plan_id=digest_json({"t": target, "m": measure, "at": now})[:24],
            measure=measure, tier=tier, target=target, asset_id=asset.asset_id,
            simulated=bool(spec["simulation_only"]),
            rationale="authorized %s against %s" % (measure, asset.asset_id),
            created_at=now, expires_at=self._auth.expires_at,
            rollback=_ROLLBACK.get(measure, "revert the change and restore prior state"))
        self._last_tier = tier
        self._last_dispatch_at = now
        self._audit.append(event="dispatch", actor=self._auth.authorizer,
                           detail={"measure": measure, "tier": tier, "target": target,
                                   "asset_id": asset.asset_id, "simulated": plan.simulated,
                                   "evidence_sha256": evidence_digest,
                                   "corroborating_signals": int(corroborating_signals)},
                           at=now)
        return plan

    def simulate(self, *, measure: str, target: str, actor: str = "drill") -> ResponsePlan:
        """Rehearse any measure -- including the aggressive tier -- on the lab only.

        This is the complete test mode. It deliberately does not require an
        emergency to be declared, because the whole point is to exercise the
        machinery on a quiet afternoon rather than discovering its behaviour
        during an incident. What it cannot do is touch anything real: the target
        must resolve to an asset registered as synthetic and owned by the lab,
        and every other path in this class refuses the aggressive tier outright.

        The emergency stop halts drills too; a pulled kill switch means the
        controller does nothing at all until somebody resets it deliberately.
        """
        now = self._clock()
        if self._state == SHUTDOWN:
            self._refuse("simulate", target, "controller is shut down; reset before drilling")
        if measure not in MEASURES:
            self._refuse("simulate", target, "unknown measure %r" % (measure,))

        asset = self._registry.resolve(target)
        if asset is None:
            self._refuse("simulate", target,
                         "target does not resolve to exactly one registered asset")
        if not asset.is_synthetic:
            self._refuse("simulate", target,
                         "simulation runs only against synthetic infrastructure")

        spec = MEASURES[measure]
        plan = ResponsePlan(
            plan_id=digest_json({"t": target, "m": measure, "at": now, "sim": True})[:24],
            measure=measure, tier=spec["tier"], target=target, asset_id=asset.asset_id,
            simulated=True,
            rationale="simulated %s against synthetic asset %s" % (measure, asset.asset_id),
            created_at=now, expires_at=now,
            rollback=_ROLLBACK.get(measure, "no real state was changed"))
        self._audit.append(event="simulate", actor=(actor.strip() or "drill"),
                           detail={"measure": measure, "tier": spec["tier"],
                                   "target": target, "asset_id": asset.asset_id,
                                   "simulated": True, "state_at_drill": self._state},
                           at=now)
        return plan

    def _refuse(self, event: str, target: str, reason: str) -> None:
        self._audit.append(event=event + "_refused", actor="attestor",
                           detail={"target": str(target)[:255], "reason": reason},
                           at=self._clock())
        raise EmergencyError(reason)


_ROLLBACK = {
    OBSERVE: "reduce telemetry to baseline",
    RATE_LIMIT: "remove the rate limit",
    FILTER_SOURCE: "remove the source from the block list",
    ISOLATE_SEGMENT: "re-attach the segment",
    FAILOVER: "fail back to the primary once healthy",
    HARD_ISOLATE: "bring the asset back online after verification",
    AGGRESSIVE_SIM: "end the simulation; no real state was changed",
}
