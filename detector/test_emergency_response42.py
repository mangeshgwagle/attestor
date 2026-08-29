#!/usr/bin/env python3
"""Emergency response: the safeguards must hold against deliberate attempts to break them.

A last-resort defensive control is only worth having if being wrong is safe, so
almost every test here is an attack on the controller rather than a happy path.
The suite tries to reach a real asset with the simulation-only tier, to skip the
second human, to act after expiry, to act on an unregistered or ambiguous
target, to escalate without a cooldown, to act on a hunch, and to quietly edit
the audit log afterwards. Each one must fail closed.

The most important test in the file is `test_no_io_capability_is_imported`: the
whole design rests on this module deciding rather than acting, so the claim that
it cannot put a packet on a wire is asserted mechanically, not promised in prose.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emergency_response42 as er  # noqa: E402


EVIDENCE = "c" * 64


class Clock:
    """An injected clock, so expiry and cooldowns are deterministic."""

    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


WEB = er.Asset(asset_id="web-tier", owner="tcs-infra",
               scopes=("10.0.1.", "web.corp.internal"),
               max_tier=3, collateral_tolerance=90)
DB = er.Asset(asset_id="db-tier", owner="tcs-infra", scopes=("10.0.2.",),
              max_tier=2, collateral_tolerance=40)
LAB = er.Asset(asset_id="lab", owner=er.SYNTHETIC_OWNER, scopes=("lab.synthetic.",),
               max_tier=4, collateral_tolerance=100, is_synthetic=True)


def controller(clock=None, assets=(WEB, DB, LAB), **kwargs):
    return er.EmergencyController(er.Registry(list(assets)),
                                  clock=clock or Clock(), **kwargs)


def armed(ctl, declarer="alice"):
    ctl.declare_emergency(declarer=declarer, severity="severe",
                          evidence_digest=EVIDENCE, reason="active flood")
    return ctl


def live(ctl, *, max_tier=2, ttl=600, declarer="alice", authorizer="bob"):
    armed(ctl, declarer=declarer)
    ctl.authorize(authorizer=authorizer, max_tier=max_tier, ttl_seconds=ttl)
    return ctl


# --------------------------------------------------------------------------- #


class TheModuleCannotAct(unittest.TestCase):
    def test_no_io_capability_is_imported(self):
        """The core claim: this module decides, it does not act."""
        source = open(er.__file__, encoding="utf-8").read()
        for forbidden in ("import socket", "import subprocess", "import requests",
                          "import urllib", "import http", "os.system", "popen"):
            self.assertNotIn(forbidden, source,
                             "the controller must not be able to perform I/O")

    def test_dispatch_returns_a_plan_not_an_effect(self):
        plan = live(controller()).dispatch(measure=er.RATE_LIMIT, target="10.0.1.5",
                                           evidence_digest=EVIDENCE)
        self.assertIsInstance(plan, er.ResponsePlan)
        self.assertIn("rollback", plan.as_dict())


class StateMachineGatesEverything(unittest.TestCase):
    def test_no_response_in_the_normal_state(self):
        ctl = controller()
        self.assertEqual(er.NORMAL, ctl.state)
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)

    def test_declaring_alone_authorizes_nothing(self):
        ctl = armed(controller())
        self.assertEqual(er.ARMED, ctl.state)
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)

    def test_a_declaration_needs_severity_and_evidence(self):
        for kwargs in ({"severity": "low"}, {"evidence_digest": "nope"}):
            base = dict(declarer="alice", severity="severe",
                        evidence_digest=EVIDENCE, reason="r")
            base.update(kwargs)
            with self.assertRaises(er.EmergencyError):
                controller().declare_emergency(**base)

    def test_authorization_requires_the_armed_state(self):
        with self.assertRaises(er.EmergencyError):
            controller().authorize(authorizer="bob", max_tier=1, ttl_seconds=60)

    def test_arming_window_lapses_to_aborted(self):
        clock = Clock()
        ctl = armed(controller(clock))
        clock.advance(er.DEFAULT_ARMING_WINDOW + 1)
        self.assertEqual(er.ABORTED, ctl.state)


class SecondHumanIsRequired(unittest.TestCase):
    def test_declarer_cannot_authorize_a_disruptive_tier_alone(self):
        ctl = armed(controller())
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.authorize(authorizer="alice", max_tier=2, ttl_seconds=60)
        self.assertIn("second human", str(caught.exception))

    def test_a_different_human_may_authorize(self):
        ctl = armed(controller())
        ctl.authorize(authorizer="bob", max_tier=2, ttl_seconds=60)
        self.assertEqual(er.AUTHORIZED, ctl.state)

    def test_self_authorization_is_allowed_only_below_the_disruptive_tier(self):
        ctl = armed(controller())
        ctl.authorize(authorizer="alice", max_tier=1, ttl_seconds=60)
        self.assertEqual(er.AUTHORIZED, ctl.state)

    def test_autonomous_policy_replaces_the_live_human_but_is_documented(self):
        policy = er.AutonomousPolicy(policy_id="p1", approved_by="ciso",
                                     approved_at=0.0, doc_ref="RUNBOOK-7", max_tier=2)
        ctl = armed(controller())
        ctl.authorize(authorizer="alice", max_tier=2, ttl_seconds=60,
                      autonomous_policy=policy)
        self.assertEqual(er.AUTHORIZED, ctl.state)
        entry = [e for e in ctl.audit_log() if e["event"] == "authorize"][0]
        self.assertEqual("p1", entry["detail"]["autonomous_policy"])

    def test_a_policy_cannot_exceed_its_own_ceiling(self):
        policy = er.AutonomousPolicy(policy_id="p1", approved_by="ciso",
                                     approved_at=0.0, doc_ref="R", max_tier=1)
        ctl = armed(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.authorize(authorizer="alice", max_tier=3, ttl_seconds=60,
                          autonomous_policy=policy)

    def test_no_policy_may_authorize_the_simulation_only_tier(self):
        with self.assertRaises(er.EmergencyError):
            er.AutonomousPolicy(policy_id="p", approved_by="c", approved_at=0.0,
                                doc_ref="R", max_tier=4)

    def test_an_undocumented_policy_is_refused(self):
        with self.assertRaises(er.EmergencyError):
            er.AutonomousPolicy(policy_id="p", approved_by="", approved_at=0.0,
                                doc_ref="", max_tier=1)


class ScopeCannotReachThirdParties(unittest.TestCase):
    def test_an_unregistered_target_is_refused(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.RATE_LIMIT, target="8.8.8.8", evidence_digest=EVIDENCE)
        self.assertIn("registered asset", str(caught.exception))

    def test_a_public_hostname_is_refused(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.FILTER_SOURCE, target="example.com",
                         evidence_digest=EVIDENCE)

    def test_an_ambiguous_target_is_refused_not_guessed(self):
        """Two assets covering one target is a misidentification risk."""
        overlap = er.Asset(asset_id="overlap", owner="tcs-infra", scopes=("10.0.1.",))
        ctl = live(controller(assets=(WEB, overlap, LAB)))
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)

    def test_a_wildcard_scope_cannot_be_registered(self):
        for bad in ("*", "", "a"):
            with self.assertRaises(er.EmergencyError):
                er.Asset(asset_id="x", owner="o", scopes=(bad,))

    def test_an_asset_needs_at_least_one_scope(self):
        with self.assertRaises(er.EmergencyError):
            er.Asset(asset_id="x", owner="o", scopes=())


class AggressiveTierIsSimulationOnly(unittest.TestCase):
    def test_no_real_threat_ladder_names_the_aggressive_tier(self):
        for threat, ladder in er.LADDER.items():
            self.assertNotIn(er.AGGRESSIVE_SIM, ladder, threat)

    def test_it_cannot_be_dispatched_at_a_real_asset(self):
        ctl = live(controller(), max_tier=er.MAX_REAL_TIER)
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.AGGRESSIVE_SIM, target="10.0.1.5",
                         evidence_digest=EVIDENCE, corroborating_signals=5)
        self.assertIn("simulation-only", str(caught.exception))

    def test_a_real_asset_cannot_register_for_the_aggressive_tier(self):
        with self.assertRaises(er.EmergencyError):
            er.Asset(asset_id="x", owner="real", scopes=("10.9.9.",), max_tier=4)

    def test_a_synthetic_asset_must_be_owned_by_the_lab(self):
        with self.assertRaises(er.EmergencyError):
            er.Asset(asset_id="x", owner="tcs-infra", scopes=("lab.",), is_synthetic=True)

    def test_authorization_cannot_reach_the_simulation_tier(self):
        ctl = armed(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.authorize(authorizer="bob", max_tier=4, ttl_seconds=60)

    def test_the_simulation_runs_against_synthetic_infrastructure(self):
        """The full rehearsal is available -- against the lab, and only there."""
        plan = controller().simulate(measure=er.AGGRESSIVE_SIM, target="lab.synthetic.1")
        self.assertTrue(plan.simulated)
        self.assertEqual(4, plan.tier)
        self.assertEqual("lab", plan.asset_id)

    def test_simulation_refuses_every_real_asset(self):
        for target in ("10.0.1.5", "10.0.2.7", "web.corp.internal"):
            with self.assertRaises(er.EmergencyError) as caught:
                controller().simulate(measure=er.AGGRESSIVE_SIM, target=target)
            self.assertIn("synthetic", str(caught.exception))

    def test_simulation_refuses_an_unregistered_target(self):
        with self.assertRaises(er.EmergencyError):
            controller().simulate(measure=er.RATE_LIMIT, target="8.8.8.8")

    def test_drills_need_no_emergency_but_are_audited(self):
        ctl = controller()
        self.assertEqual(er.NORMAL, ctl.state)
        ctl.simulate(measure=er.HARD_ISOLATE, target="lab.synthetic.2", actor="drill-bot")
        entry = [e for e in ctl.audit_log() if e["event"] == "simulate"][0]
        self.assertEqual("drill-bot", entry["actor"])
        self.assertTrue(entry["detail"]["simulated"])

    def test_the_kill_switch_halts_drills_too(self):
        ctl = controller()
        ctl.emergency_stop(actor="soc")
        with self.assertRaises(er.EmergencyError):
            ctl.simulate(measure=er.RATE_LIMIT, target="lab.synthetic.1")

class TimeLimitsAndTheKillSwitch(unittest.TestCase):
    def test_authorization_expires_and_fails_closed(self):
        clock = Clock()
        ctl = live(controller(clock), ttl=300)
        clock.advance(301)
        self.assertEqual(er.EXPIRED, ctl.state)
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)

    def test_ttl_cannot_exceed_the_hard_cap(self):
        ctl = armed(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.authorize(authorizer="bob", max_tier=1,
                          ttl_seconds=er.DEFAULT_MAX_ACTIVE + 1)

    def test_emergency_stop_works_from_authorized_and_is_terminal(self):
        ctl = live(controller())
        ctl.emergency_stop(actor="soc-lead", reason="collateral observed")
        self.assertEqual(er.SHUTDOWN, ctl.state)
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)

    def test_emergency_stop_works_from_any_state(self):
        for build in (controller, lambda: armed(controller()), lambda: live(controller())):
            ctl = build()
            ctl.emergency_stop(actor="soc")
            self.assertEqual(er.SHUTDOWN, ctl.state)

    def test_shutdown_cannot_be_re_authorized_without_a_reset(self):
        ctl = live(controller())
        ctl.emergency_stop(actor="soc")
        with self.assertRaises(er.EmergencyError):
            ctl.authorize(authorizer="bob", max_tier=2, ttl_seconds=60)

    def test_reset_is_deliberate_and_returns_to_normal(self):
        ctl = live(controller())
        ctl.emergency_stop(actor="soc")
        ctl.reset(actor="soc-lead")
        self.assertEqual(er.NORMAL, ctl.state)

    def test_reset_is_invalid_while_authorized(self):
        with self.assertRaises(er.EmergencyError):
            live(controller()).reset(actor="x")


class MisidentificationAndCollateralGuards(unittest.TestCase):
    def test_a_disruptive_action_needs_corroboration(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.ISOLATE_SEGMENT, target="10.0.2.7",
                         evidence_digest=EVIDENCE, corroborating_signals=1)
        self.assertIn("corroborating", str(caught.exception))

    def test_corroborated_disruptive_action_is_allowed(self):
        plan = live(controller()).dispatch(
            measure=er.ISOLATE_SEGMENT, target="10.0.2.7",
            evidence_digest=EVIDENCE, corroborating_signals=2)
        self.assertEqual(er.ISOLATE_SEGMENT, plan.measure)

    def test_every_action_must_cite_evidence(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest="")

    def test_blast_radius_over_tolerance_is_refused(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.ISOLATE_SEGMENT, target="10.0.2.7",
                         evidence_digest=EVIDENCE, corroborating_signals=3,
                         blast_radius=95)
        self.assertIn("blast radius", str(caught.exception))

    def test_asset_ceiling_is_enforced_independently_of_authorization(self):
        """db-tier caps at tier 2 even when the operator authorized tier 3."""
        ctl = live(controller(), max_tier=3)
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.HARD_ISOLATE, target="10.0.2.7",
                         evidence_digest=EVIDENCE, corroborating_signals=3)
        self.assertIn("asset ceiling", str(caught.exception))

    def test_measure_above_authorization_ceiling_is_refused(self):
        ctl = live(controller(), max_tier=1)
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.HARD_ISOLATE, target="10.0.1.5",
                         evidence_digest=EVIDENCE, corroborating_signals=3)


class EscalationIsRateLimited(unittest.TestCase):
    def test_rising_a_tier_inside_the_cooldown_is_refused(self):
        clock = Clock()
        ctl = live(controller(clock), max_tier=3)
        ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)
        with self.assertRaises(er.EmergencyError) as caught:
            ctl.dispatch(measure=er.ISOLATE_SEGMENT, target="10.0.1.5",
                         evidence_digest=EVIDENCE, corroborating_signals=3)
        self.assertIn("cooldown", str(caught.exception))

    def test_escalation_is_allowed_after_the_cooldown(self):
        clock = Clock()
        ctl = live(controller(clock), max_tier=3)
        ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)
        clock.advance(er.DEFAULT_ESCALATION_COOLDOWN + 1)
        plan = ctl.dispatch(measure=er.ISOLATE_SEGMENT, target="10.0.1.5",
                            evidence_digest=EVIDENCE, corroborating_signals=3)
        self.assertEqual(2, plan.tier)

    def test_de_escalation_is_never_blocked(self):
        clock = Clock()
        ctl = live(controller(clock), max_tier=3)
        ctl.dispatch(measure=er.ISOLATE_SEGMENT, target="10.0.1.5",
                     evidence_digest=EVIDENCE, corroborating_signals=3)
        plan = ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5",
                            evidence_digest=EVIDENCE)
        self.assertEqual(1, plan.tier)


class DecisionPrefersTheLeastDisruptive(unittest.TestCase):
    def test_the_gentlest_effective_measure_is_chosen(self):
        ctl = live(controller(), max_tier=3)
        self.assertEqual(er.RATE_LIMIT, ctl.decide(threat_class="volumetric_flood"))

    def test_a_low_ceiling_degrades_to_observation_rather_than_acting(self):
        ctl = live(controller(), max_tier=0)
        self.assertEqual(er.OBSERVE, ctl.decide(threat_class="lateral_movement"))

    def test_an_unknown_threat_class_is_refused(self):
        with self.assertRaises(er.EmergencyError):
            live(controller()).decide(threat_class="make_it_stop")

    def test_no_decision_outside_the_authorized_state(self):
        with self.assertRaises(er.EmergencyError):
            controller().decide(threat_class="volumetric_flood")


class AuditIsCompleteAndTamperEvident(unittest.TestCase):
    def test_every_lifecycle_event_is_recorded(self):
        clock = Clock()
        ctl = live(controller(clock), max_tier=3)
        ctl.decide(threat_class="volumetric_flood")
        ctl.dispatch(measure=er.RATE_LIMIT, target="10.0.1.5", evidence_digest=EVIDENCE)
        ctl.emergency_stop(actor="soc")
        events = [e["event"] for e in ctl.audit_log()]
        for expected in ("init", "declare", "authorize", "decide", "dispatch",
                         "emergency_stop"):
            self.assertIn(expected, events)

    def test_refusals_are_audited_too(self):
        ctl = live(controller())
        with self.assertRaises(er.EmergencyError):
            ctl.dispatch(measure=er.RATE_LIMIT, target="8.8.8.8", evidence_digest=EVIDENCE)
        self.assertIn("dispatch_refused", [e["event"] for e in ctl.audit_log()])

    def test_the_chain_verifies(self):
        ok, problems = live(controller()).verify_audit()
        self.assertTrue(ok, problems)

    def test_editing_an_entry_is_detected(self):
        ctl = live(controller())
        ctl._audit._entries[1]["detail"]["reason"] = "rewritten"
        ok, problems = ctl.verify_audit()
        self.assertFalse(ok)
        self.assertTrue(any("digest" in p for p in problems), problems)

    def test_deleting_an_entry_is_detected(self):
        ctl = live(controller())
        del ctl._audit._entries[1]
        self.assertFalse(ctl.verify_audit()[0])

    def test_status_reports_audit_integrity(self):
        ctl = live(controller())
        self.assertTrue(ctl.status()["audit_intact"])


if __name__ == "__main__":
    unittest.main()
