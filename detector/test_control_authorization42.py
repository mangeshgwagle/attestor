"""One-use capability tests for Attestor 4.2 Owner Control."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import unittest

import control_authorization42 as authorization
import control_policy42 as policy


SESSION = "1" * 32
KEY = b"owner-control-test-key-material!!"
REGISTRY = "2" * 32


class Clock:
    def __init__(self, value: float = 1_000) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def plan(session: str = SESSION, *, mutation: bool = False) -> dict:
    if not mutation:
        return policy.create_plan(
            policy.SYSTEM_INVENTORY,
            {"storage_roots": []},
            session_id=session,
        )
    return policy.create_plan(
        policy.PLAN_FUTURE_MUTATIONS,
        {
            "executor": "unavailable",
            "operations": [{
                "operation_id": "one",
                "kind": "quarantine-files",
                "root_identity_sha256": "a" * 64,
                "target_identity_sha256": "b" * 64,
                "before_sha256": "c" * 64,
                "after_sha256": "d" * 64,
                "estimated_bytes": 12,
            }],
        },
        session_id=session,
    )


def registry(clock: Clock | None = None) -> authorization.CapabilityRegistry:
    return authorization.CapabilityRegistry(
        session_id=SESSION,
        key=KEY,
        registry_id=REGISTRY,
        clock=clock or Clock(),
    )


class ControlAuthorization42Tests(unittest.TestCase):
    def test_confirmation_requires_literal_true(self) -> None:
        selected = registry()
        for value in (False, 1, "true", None):
            with self.subTest(value=value), self.assertRaises(
                    authorization.ControlAuthorizationError):
                selected.issue(plan(), confirmed=value)  # type: ignore[arg-type]

    def test_capability_is_exact_bound_consumable_and_content_free(self) -> None:
        selected_plan = plan()
        selected = registry()
        token = selected.issue(
            selected_plan,
            confirmed=True,
            nonce="3" * 48,
        )
        self.assertEqual(token["session_id"], SESSION)
        self.assertEqual(token["profile"], selected_plan["profile"])
        self.assertEqual(token["policy_sha256"], policy.POLICY_SHA256)
        self.assertEqual(token["plan_sha256"], selected_plan["plan_sha256"])
        self.assertFalse(token["mutation_authorized"])
        audit = selected.consume(token, plan=selected_plan)
        self.assertEqual(authorization.verify_consumption(audit), (True, []))
        serialized = policy.canonical_bytes(audit)
        self.assertNotIn(b"storage_roots", serialized)
        self.assertNotIn(b"333333333333333333333333333333333333333333333333", serialized)

    def test_capability_is_one_use_under_concurrent_consumption(self) -> None:
        selected_plan = plan()
        selected = registry()
        token = selected.issue(selected_plan, confirmed=True)

        def consume() -> bool:
            try:
                selected.consume(token, plan=selected_plan)
                return True
            except authorization.ControlAuthorizationError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _index: consume(), range(20)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 19)

    def test_tampered_token_and_wrong_plan_fail_even_if_shape_is_valid(self) -> None:
        selected_plan = plan()
        selected = registry()
        token = selected.issue(selected_plan, confirmed=True)
        changed = copy.deepcopy(token)
        changed["authorization_kind"] = "plan-review"
        with self.assertRaises(authorization.ControlAuthorizationError):
            selected.consume(changed, plan=selected_plan)

        other = policy.create_plan(
            policy.COMPUTER_PROJECT_SCAN,
            {"scope": "home", "max_projects": 1,
             "review_improvements": False},
            session_id=SESSION,
        )
        with self.assertRaises(authorization.ControlAuthorizationError):
            selected.consume(token, plan=other)

    def test_copied_capability_cannot_cross_live_registry(self) -> None:
        selected_plan = plan()
        first = registry()
        token = first.issue(selected_plan, confirmed=True)
        second = authorization.CapabilityRegistry(
            session_id=SESSION,
            key=KEY,
            registry_id="4" * 32,
            clock=Clock(),
        )
        with self.assertRaises(authorization.ControlAuthorizationError):
            second.consume(token, plan=selected_plan)

    def test_expiry_future_time_and_clock_rollback_fail_closed(self) -> None:
        selected_plan = plan()
        clock = Clock(100)
        selected = registry(clock)
        token = selected.issue(
            selected_plan, confirmed=True, ttl_seconds=5)
        clock.value = 105
        with self.assertRaisesRegex(
                authorization.ControlAuthorizationError, "expired"):
            selected.consume(token, plan=selected_plan)

        clock = Clock(100)
        selected = registry(clock)
        token = selected.issue(
            selected_plan, confirmed=True, ttl_seconds=5)
        clock.value = 99
        with self.assertRaisesRegex(
                authorization.ControlAuthorizationError, "not yet"):
            selected.consume(token, plan=selected_plan)

    def test_session_binding_is_exact(self) -> None:
        other_plan = plan("5" * 32)
        with self.assertRaisesRegex(
                authorization.ControlAuthorizationError, "different session"):
            registry().issue(other_plan, confirmed=True)

    def test_plan_review_capability_never_grants_mutation(self) -> None:
        selected_plan = plan(mutation=True)
        selected = registry()
        token = selected.issue(selected_plan, confirmed=True)
        self.assertEqual(token["authorization_kind"], "plan-review")
        self.assertFalse(token["mutation_authorized"])
        audit = selected.consume(token, plan=selected_plan)
        self.assertFalse(audit["mutation_authorized"])

    def test_audit_tampering_is_detected(self) -> None:
        selected_plan = plan()
        selected = registry()
        token = selected.issue(selected_plan, confirmed=True)
        audit = selected.consume(token, plan=selected_plan)
        changed = copy.deepcopy(audit)
        changed["mutation_authorized"] = True
        valid, errors = authorization.verify_consumption(changed)
        self.assertFalse(valid)
        self.assertTrue(any("safety" in error or "digest" in error
                            for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
