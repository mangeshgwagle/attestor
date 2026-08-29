"""Read-only inventory tests for Attestor 4.2 Owner Control."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

import control_inventory42 as inventory
import control_policy42 as policy


def temporary_directory():
    return tempfile.TemporaryDirectory(dir=Path.cwd())


def request(root: Path, *, hashes: bool = True, results: int = 100) -> dict:
    return {
        "roots": [str(root.resolve())],
        "name_contains": "",
        "extensions": [],
        "max_directories": 100,
        "max_files": 1_000,
        "max_results": results,
        "max_depth": 8,
        "hash_files": hashes,
    }


class ControlInventory42Tests(unittest.TestCase):
    def test_find_files_returns_only_metadata_and_optional_hashes(self) -> None:
        with temporary_directory() as folder:
            root = Path(folder)
            (root / "src").mkdir()
            (root / "src" / "main.py").write_text(
                "print('safe')\n", encoding="utf-8")
            (root / "notes.txt").write_text("notes", encoding="utf-8")
            report = inventory.find_files(request(root))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["summary"]["results_returned"], 2)
        paths = {row["relative_path"] for row in report["files"]}
        self.assertEqual(paths, {"notes.txt", "src/main.py"})
        for row in report["files"]:
            self.assertFalse(row["content_emitted"])
            self.assertEqual(row["hash_state"], "hashed")
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("content", row)
        self.assertFalse(report["execution"]["file_contents_emitted"])
        self.assertFalse(report["execution"]["filesystem_mutated"])
        self.assertFalse(report["execution"]["mutation_executed"])
        self.assertFalse(report["execution"]["process_executed"])
        self.assertFalse(report["execution"]["network_accessed"])

    def test_sensitive_files_and_protected_directories_are_never_returned(self) -> None:
        with temporary_directory() as folder:
            root = Path(folder)
            (root / ".ssh").mkdir()
            (root / ".ssh" / "id_rsa").write_text(
                "private", encoding="utf-8")
            (root / ".env").write_text("TOKEN=secret", encoding="utf-8")
            (root / "private.pem").write_text("secret", encoding="utf-8")
            (root / ".env.example").write_text(
                "TOKEN=replace", encoding="utf-8")
            report = inventory.find_files(request(root, hashes=False))
        paths = {row["relative_path"] for row in report["files"]}
        self.assertEqual(paths, {".env.example"})
        self.assertGreaterEqual(
            report["summary"]["protected_directories_skipped"], 1)
        self.assertGreaterEqual(
            report["summary"]["sensitive_files_skipped"], 2)
        self.assertFalse(report["execution"]["files_read_for_hashing"])

    def test_links_are_not_followed_when_creation_is_available(self) -> None:
        with temporary_directory() as folder:
            root = Path(folder)
            outside = root / "outside"
            outside.mkdir()
            (outside / "hidden.py").write_text("secret", encoding="utf-8")
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlink creation is unavailable")
            report = inventory.find_files(request(root))
        paths = {row["relative_path"] for row in report["files"]}
        # The real in-scope directory is visible, but its alias is not followed.
        self.assertIn("outside/hidden.py", paths)
        self.assertNotIn("linked/hidden.py", paths)
        self.assertGreaterEqual(
            report["summary"]["linked_or_reparse_or_hardlinked_skipped"], 1)

    def test_result_boundary_is_explicit(self) -> None:
        with temporary_directory() as folder:
            root = Path(folder)
            for index in range(4):
                (root / f"f{index}.txt").write_text(str(index), encoding="utf-8")
            report = inventory.find_files(request(root, results=1))
        self.assertEqual(len(report["files"]), 1)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("result boundary" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_protected_root_fails_closed_without_returning_a_path(self) -> None:
        with self.assertRaises(inventory.ControlInventoryError) as caught:
            inventory.find_files({
                **request(Path.cwd(), hashes=False),
                "roots": ["C:/Windows/System32"],
            })
        self.assertNotIn("C:/Windows", str(caught.exception))

    def test_system_inventory_omits_identity_and_scoped_paths(self) -> None:
        with temporary_directory() as folder:
            report = inventory.system_inventory({
                "storage_roots": [str(Path(folder).resolve())],
            })
        self.assertIn(report["status"], {"complete", "partial"})
        system = report["system"]
        self.assertFalse(system["hostname_emitted"])
        self.assertFalse(system["username_emitted"])
        self.assertFalse(system["network_identifiers_emitted"])
        self.assertEqual(len(report["storage"]), 1)
        self.assertFalse(report["storage"][0]["path_emitted"])
        self.assertNotIn(str(Path(folder).resolve()), str(report))
        self.assertFalse(report["execution"]["mutation_executed"])

    def test_computer_project_scan_forces_existing_read_only_contract(self) -> None:
        fake = {
            "schema": "attestor-computer-scan/4.1",
            "version": "4.1.3",
            "status": "complete",
            "execution": {
                "target_code_executed": False,
                "network_accessed": False,
                "target_files_written": False,
                "discovered_files_written": False,
                "improvements_applied": False,
                "os_privilege_elevation_requested": False,
                "access_control_bypass_requested": False,
            },
        }
        with mock.patch.object(
                inventory.computer_scan41, "scan_computer",
                return_value=fake) as scan:
            report = inventory.computer_project_scan({
                "scope": "home",
                "max_projects": 2,
                "review_improvements": True,
            })
        scan.assert_called_once_with(
            authorized=True,
            scope="home",
            max_projects=2,
            review_improvements=True,
        )
        self.assertEqual(report["kind"], policy.COMPUTER_PROJECT_SCAN)
        self.assertFalse(report["execution"]["mutation_executed"])

    def test_project_scan_reported_side_effect_fails_closed(self) -> None:
        fake = {
            "status": "inconsistent",
            "execution": {
                "target_code_executed": False,
                "network_accessed": True,
                "target_files_written": False,
            },
        }
        with mock.patch.object(
                inventory.computer_scan41, "scan_computer",
                return_value=fake), self.assertRaises(
                    inventory.ControlInventoryError):
            inventory.computer_project_scan({
                "scope": "home",
                "max_projects": 1,
                "review_improvements": False,
            })

    def test_project_scan_requires_literal_false_effect_evidence(self) -> None:
        base = {
            "status": "complete",
            "execution": {
                "target_code_executed": False,
                "network_accessed": False,
                "target_files_written": False,
                "discovered_files_written": False,
                "improvements_applied": False,
                "os_privilege_elevation_requested": False,
                "access_control_bypass_requested": False,
            },
        }
        for field, value in (("network_accessed", 0),
                             ("target_files_written", None)):
            with self.subTest(field=field, value=value):
                fake = {**base, "execution": {**base["execution"], field: value}}
                with mock.patch.object(
                        inventory.computer_scan41, "scan_computer",
                        return_value=fake), self.assertRaises(
                            inventory.ControlInventoryError):
                    inventory.computer_project_scan({
                        "scope": "home",
                        "max_projects": 1,
                        "review_improvements": False,
                    })

    def test_inert_mutation_plan_cannot_enter_observation_dispatch(self) -> None:
        plan = policy.create_plan(
            policy.PLAN_FUTURE_MUTATIONS,
            {
                "executor": "unavailable",
                "operations": [{
                    "operation_id": "create-one",
                    "kind": "create-directory",
                    "root_identity_sha256": "a" * 64,
                    "target_identity_sha256": "b" * 64,
                    "before_sha256": "c" * 64,
                    "after_sha256": "d" * 64,
                    "estimated_bytes": 0,
                }],
            },
            session_id="1" * 32,
        )
        with self.assertRaisesRegex(
                inventory.ControlInventoryError, "not executable"):
            inventory.execute_observation(plan)


if __name__ == "__main__":
    unittest.main(verbosity=2)
