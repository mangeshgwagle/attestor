"""Coordinator and isolated CLI tests for Attestor 4.2 Owner Control."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

import control_policy42 as policy
import owner_control42 as owner


SESSION = "1" * 32
SCRIPT = Path(owner.__file__).resolve()


def system_plan() -> dict:
    return policy.create_plan(
        policy.SYSTEM_INVENTORY,
        {"storage_roots": []},
        session_id=SESSION,
    )


def mutation_plan() -> dict:
    return policy.create_plan(
        policy.PLAN_FUTURE_MUTATIONS,
        {
            "executor": "unavailable",
            "operations": [{
                "operation_id": "replace-one",
                "kind": "replace-existing-files",
                "root_identity_sha256": "a" * 64,
                "target_identity_sha256": "b" * 64,
                "before_sha256": "c" * 64,
                "after_sha256": "d" * 64,
                "estimated_bytes": 12,
            }],
        },
        session_id=SESSION,
    )


def safe_inventory_result() -> dict:
    return {
        "schema": "attestor-owner-control-inventory/4.2",
        "version": "4.2",
        "kind": policy.SYSTEM_INVENTORY,
        "status": "complete",
        "coverage": {"complete": True, "gaps": []},
        "execution": {
            "credential_store_accessed": False,
            "file_contents_emitted": False,
            "filesystem_mutated": False,
            "files_read_for_hashing": False,
            "mutation_executed": False,
            "network_accessed": False,
            "persistence_created": False,
            "process_executed": False,
            "shell_invoked": False,
        },
    }


class PoisonPlan:
    def __getattribute__(self, name):
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError("denied Owner Control accessed the plan")


class OwnerControl42Tests(unittest.TestCase):
    def test_denial_returns_before_plan_loading_or_computer_probe(self) -> None:
        with mock.patch.object(
                owner.policy, "require_plan",
                side_effect=AssertionError("plan loaded")), mock.patch.object(
                    owner.inventory, "execute_observation",
                    side_effect=AssertionError("computer probed")):
            report = owner.run(  # type: ignore[arg-type]
                PoisonPlan(), permission_confirmed=False)
        self.assertEqual(report["status"], "authorization-required")
        self.assertFalse(report["execution"]["plan_loaded"])
        self.assertFalse(report["execution"]["computer_probed"])
        self.assertFalse(report["execution"]["mutation_executed"])
        self.assertEqual(owner.verify_report(report), (True, []))

    def test_nonliteral_permission_never_authorizes(self) -> None:
        for value in (1, "true", None):
            with self.subTest(value=value), mock.patch.object(
                    owner.inventory, "execute_observation") as execute, self.assertRaises(
                        owner.OwnerControlError):
                owner.run(system_plan(), permission_confirmed=value)  # type: ignore[arg-type]
            execute.assert_not_called()

    def test_authorized_observation_consumes_capability_then_runs(self) -> None:
        selected_plan = system_plan()
        with mock.patch.object(
                owner.inventory, "execute_observation",
                return_value=safe_inventory_result()) as execute:
            report = owner.run(selected_plan, permission_confirmed=True)
        execute.assert_called_once()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["action"], policy.SYSTEM_INVENTORY)
        self.assertEqual(report["plan_sha256"], selected_plan["plan_sha256"])
        self.assertEqual(report["authorization"]["status"], "authorized-once")
        self.assertFalse(report["authorization"]["mutation_authorized"])
        self.assertFalse(report["execution"]["mutation_executed"])
        self.assertEqual(owner.verify_report(report), (True, []))

    def test_future_mutation_plan_is_inert_and_never_dispatches_inventory(self) -> None:
        selected_plan = mutation_plan()
        with mock.patch.object(
                owner.inventory, "execute_observation",
                side_effect=AssertionError("mutation plan dispatched")):
            report = owner.run(selected_plan, permission_confirmed=True)
        self.assertEqual(report["status"], "planned-only")
        self.assertEqual(report["result"]["executor"], "unavailable")
        self.assertFalse(report["result"]["mutation_authorized"])
        self.assertFalse(report["result"]["mutation_executed"])
        self.assertFalse(report["result"]["execution"]["filesystem_mutated"])
        self.assertFalse(report["result"]["execution"]["mutation_executed"])
        self.assertFalse(report["execution"]["computer_probed"])
        self.assertFalse(report["execution"]["mutation_executed"])
        self.assertEqual(owner.verify_report(report), (True, []))

    def test_report_tampering_is_detected_even_when_rehashed(self) -> None:
        with mock.patch.object(
                owner.inventory, "execute_observation",
                return_value=safe_inventory_result()):
            report = owner.run(system_plan(), permission_confirmed=True)
        changed = copy.deepcopy(report)
        changed["execution"]["mutation_executed"] = True
        changed["report_sha256"] = policy.digest_json({
            key: value for key, value in changed.items()
            if key != "report_sha256"
        })
        valid, errors = owner.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("side effect" in error for error in errors))

    def test_reported_nested_side_effect_fails_closed(self) -> None:
        unsafe = safe_inventory_result()
        unsafe["execution"]["network_accessed"] = True
        with mock.patch.object(
                owner.inventory, "execute_observation", return_value=unsafe), self.assertRaisesRegex(
                    owner.OwnerControlError, "forbidden side effect"):
            owner.run(system_plan(), permission_confirmed=True)

    def test_nonboolean_or_unknown_nested_effect_fails_closed(self) -> None:
        for change in (
                {"shell_invoked": 1},
                {"file_contents_emitted": True},
                {"unexpected_effect": False}):
            with self.subTest(change=change):
                unsafe = safe_inventory_result()
                unsafe["execution"].update(change)
                with mock.patch.object(
                        owner.inventory, "execute_observation",
                        return_value=unsafe), self.assertRaisesRegex(
                            owner.OwnerControlError, "forbidden side effect"):
                    owner.run(system_plan(), permission_confirmed=True)

    def test_nested_execution_tampering_is_rejected_after_rehash(self) -> None:
        with mock.patch.object(
                owner.inventory, "execute_observation",
                return_value=safe_inventory_result()):
            report = owner.run(system_plan(), permission_confirmed=True)
        changed = copy.deepcopy(report)
        changed["result"]["execution"]["unexpected_effect"] = False
        changed["report_sha256"] = policy.digest_json({
            key: value for key, value in changed.items()
            if key != "report_sha256"
        })
        valid, errors = owner.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("nested execution" in error for error in errors))

    def test_text_renderer_never_implies_mutation(self) -> None:
        text = owner.render_text(owner.denied_report())
        self.assertIn("Mutation executed: false", text)
        self.assertIn("authority: denied", text)


class OwnerControl42CliTests(unittest.TestCase):
    def invoke(self, *arguments: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8", str(SCRIPT), *arguments],
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_help_and_policy_work_from_an_untrusted_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "control_policy42.py").write_text(
                "raise RuntimeError('wrong module')\n", encoding="utf-8")
            help_result = self.invoke("--help", cwd=folder)
            policy_result = self.invoke("policy", "--format", "json", cwd=folder)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Owner Control", help_result.stdout)
        self.assertEqual(policy_result.returncode, 0, policy_result.stderr)
        document = json.loads(policy_result.stdout)
        self.assertEqual(document["policy_sha256"], policy.POLICY_SHA256)
        self.assertFalse(
            document["safety_controls"]["mutation_execution_allowed"])

    def test_unconfirmed_run_does_not_open_a_missing_plan(self) -> None:
        result = self.invoke(
            "run", "definitely-does-not-exist.json", "--format", "json")
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "authorization-required")
        self.assertFalse(report["execution"]["plan_loaded"])
        self.assertFalse(report["execution"]["computer_probed"])
        self.assertFalse(report["execution"]["mutation_executed"])

    def test_cli_builds_and_runs_exact_confirmed_plan(self) -> None:
        build = self.invoke(
            "plan", policy.SYSTEM_INVENTORY,
            "--session-id", SESSION,
            "--request-json", '{"storage_roots":[]}',
            "--format", "json",
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        selected_plan = json.loads(build.stdout)
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            plan_path = Path(folder, "plan.json")
            plan_path.write_text(
                json.dumps(selected_plan), encoding="utf-8")
            executed = self.invoke(
                "run", str(plan_path),
                "--permission",
                "--confirm-plan-sha256", selected_plan["plan_sha256"],
                "--format", "json",
            )
        self.assertEqual(executed.returncode, 0, executed.stderr)
        report = json.loads(executed.stdout)
        self.assertEqual(report["action"], policy.SYSTEM_INVENTORY)
        self.assertEqual(report["plan_sha256"], selected_plan["plan_sha256"])
        self.assertFalse(report["execution"]["mutation_executed"])

    def test_permission_requires_exact_reviewed_digest(self) -> None:
        result = self.invoke(
            "run", "missing.json", "--permission", "--format", "json")
        self.assertEqual(result.returncode, 2)
        failure = json.loads(result.stdout)
        self.assertEqual(failure["status"], "failed-closed")
        self.assertFalse(failure["mutation_executed"])
        self.assertNotIn("Traceback", result.stderr + result.stdout)

    def test_unknown_or_abbreviated_action_is_rejected(self) -> None:
        result = self.invoke(
            "plan", "system", "--session-id", SESSION,
            "--request-json", '{}')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
