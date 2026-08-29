"""Policy and strict-plan tests for Attestor 4.2 Owner Control."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

import control_policy42 as policy


SESSION = "1" * 32
DIGEST = "a" * 64


def find_request(root: str) -> dict:
    return {
        "roots": [root],
        "name_contains": "",
        "extensions": [".py"],
        "max_directories": 100,
        "max_files": 1_000,
        "max_results": 50,
        "max_depth": 6,
        "hash_files": True,
    }


def mutation_request() -> dict:
    return {
        "executor": "unavailable",
        "operations": [{
            "operation_id": "replace-one",
            "kind": "replace-existing-files",
            "root_identity_sha256": DIGEST,
            "target_identity_sha256": "b" * 64,
            "before_sha256": "c" * 64,
            "after_sha256": "d" * 64,
            "estimated_bytes": 128,
        }],
    }


class ControlPolicy42Tests(unittest.TestCase):
    def test_all_four_actions_build_exact_verified_plans(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            requests = {
                policy.SYSTEM_INVENTORY: {"storage_roots": []},
                policy.FIND_FILES: find_request(str(Path(folder).resolve())),
                policy.COMPUTER_PROJECT_SCAN: {
                    "scope": "home",
                    "max_projects": 3,
                    "review_improvements": False,
                },
                policy.PLAN_FUTURE_MUTATIONS: mutation_request(),
            }
            for action in policy.ACTION_ORDER:
                with self.subTest(action=action):
                    plan = policy.create_plan(
                        action, requests[action], session_id=SESSION)
                    self.assertEqual(policy.verify_plan(plan), (True, []))
                    self.assertEqual(plan["profile"]["slug"],
                                     "cockroach-janta-party")
                    self.assertEqual(plan["policy_sha256"],
                                     policy.POLICY_SHA256)
                    self.assertFalse(
                        plan["safety_controls"]["mutation_execution_allowed"])

    def test_future_mutation_policy_is_inert_and_immutable(self) -> None:
        row = policy.ACTION_POLICIES[policy.PLAN_FUTURE_MUTATIONS]
        self.assertEqual(row["authorization_kind"], "plan-review")
        self.assertFalse(row["executable"])
        self.assertFalse(row["mutation_authorized"])
        with self.assertRaises(TypeError):
            row["executable"] = True  # type: ignore[index]
        plan = policy.create_plan(
            policy.PLAN_FUTURE_MUTATIONS,
            mutation_request(),
            session_id=SESSION,
        )
        self.assertEqual(plan["request"]["executor"], "unavailable")

        document = policy.policy_document()
        self.assertEqual(
            document["protected_directory_names"],
            sorted(policy.frozenset()))
        self.assertEqual(
            document["sensitive_file_names"],
            sorted(policy.frozenset()))
        self.assertEqual(
            document["limits"]["max_hash_file_bytes"],
            policy.MAX_HASH_FILE_BYTES)
        self.assertFalse(
            document["actions"][policy.PLAN_FUTURE_MUTATIONS]["executable"])

    def test_plan_tampering_and_rehashed_policy_forgery_fail(self) -> None:
        plan = policy.create_plan(
            policy.SYSTEM_INVENTORY,
            {"storage_roots": []},
            session_id=SESSION,
        )
        changed = copy.deepcopy(plan)
        changed["safety_controls"]["shell_allowed"] = True
        changed["plan_sha256"] = policy.digest_json({
            key: value for key, value in changed.items()
            if key != "plan_sha256"
        })
        valid, errors = policy.verify_plan(changed)
        self.assertFalse(valid)
        self.assertTrue(any("safety" in error for error in errors))

        forged = copy.deepcopy(plan)
        forged["profile"]["slug"] = "south-park"
        forged["plan_sha256"] = policy.digest_json({
            key: value for key, value in forged.items()
            if key != "plan_sha256"
        })
        self.assertFalse(policy.verify_plan(forged)[0])

    def test_find_request_is_strict_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            request = find_request(str(Path(folder).resolve()))
            invalid = copy.deepcopy(request)
            invalid["extra"] = True
            with self.assertRaises(policy.ControlPolicyError):
                policy.create_plan(
                    policy.FIND_FILES, invalid, session_id=SESSION)
            invalid = copy.deepcopy(request)
            invalid["hash_files"] = 1
            with self.assertRaises(policy.ControlPolicyError):
                policy.create_plan(
                    policy.FIND_FILES, invalid, session_id=SESSION)
            invalid = copy.deepcopy(request)
            invalid["extensions"] = [".PY"]
            with self.assertRaises(policy.ControlPolicyError):
                policy.create_plan(
                    policy.FIND_FILES, invalid, session_id=SESSION)
            invalid = copy.deepcopy(request)
            invalid["max_results"] = policy.MAX_RESULTS + 1
            with self.assertRaises(policy.ControlPolicyError):
                policy.create_plan(
                    policy.FIND_FILES, invalid, session_id=SESSION)

    def test_protected_network_and_traversal_roots_are_refused(self) -> None:
        invalid_roots = [
            "C:/Windows/System32",
            "//server/share/project",
            "C:/Users/example/../AppData/project",
        ]
        for root in invalid_roots:
            with self.subTest(root=root), self.assertRaises(
                    policy.ControlPolicyError):
                policy.create_plan(
                    policy.FIND_FILES,
                    find_request(root),
                    session_id=SESSION,
                )

    def test_mutation_operations_are_exact_unique_and_byte_bounded(self) -> None:
        request = mutation_request()
        request["operations"].append(copy.deepcopy(request["operations"][0]))
        with self.assertRaises(policy.ControlPolicyError):
            policy.create_plan(
                policy.PLAN_FUTURE_MUTATIONS, request, session_id=SESSION)
        request = mutation_request()
        request["executor"] = "enabled"
        with self.assertRaises(policy.ControlPolicyError):
            policy.create_plan(
                policy.PLAN_FUTURE_MUTATIONS, request, session_id=SESSION)
        request = mutation_request()
        request["operations"][0]["kind"] = "delete-recursively"
        with self.assertRaises(policy.ControlPolicyError):
            policy.create_plan(
                policy.PLAN_FUTURE_MUTATIONS, request, session_id=SESSION)

    def test_canonical_json_rejects_non_json_and_hostile_depth(self) -> None:
        with self.assertRaises(policy.ControlPolicyError):
            policy.canonical_bytes({"bad": object()})
        nested: object = None
        for _ in range(policy.MAX_JSON_DEPTH + 2):
            nested = [nested]
        with self.assertRaises(policy.ControlPolicyError):
            policy.canonical_bytes(nested)

    def test_sensitive_filename_policy_excludes_credentials(self) -> None:
        for name in (".env", ".env.local", "id_rsa", "private.pem", "x.pfx"):
            with self.subTest(name=name):
                self.assertTrue(policy.is_sensitive_file_name(name))
        self.assertFalse(policy.is_sensitive_file_name(".env.example"))
        self.assertFalse(policy.is_sensitive_file_name("main.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
