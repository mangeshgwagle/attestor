from __future__ import annotations

import copy
import hashlib
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import release_hardening


class ReleaseHardeningTests(unittest.TestCase):
    def _tree(self, root: Path):
        (root / "detector").mkdir()
        (root / "detector" / "attestor.py").write_text("print('safe')\n", encoding="utf-8")
        (root / "README.md").write_text("Attestor\n", encoding="utf-8")

    def test_reproducible_archives_are_byte_identical_and_verifiable(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir(); self._tree(root)
            one = release_hardening.deterministic_zip(root, base / "one.zip", epoch=315532800)
            two = release_hardening.deterministic_zip(root, base / "two.zip", epoch=315532800)
            self.assertEqual(one["product_version"], "4.2")
            self.assertEqual(one["prefix"], "Attestor 4.2")
            self.assertEqual(one["archive_sha256"], two["archive_sha256"])
            verified = release_hardening.verify_zip(base / "one.zip", one)
            self.assertTrue(verified["ok"], verified["errors"])

    def test_forbidden_artifacts_and_links_fail_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self._tree(root); (root / "keys.env").write_text("SECRET=x", encoding="utf-8")
            report = release_hardening.audit_tree(root)
            self.assertFalse(report["ok"])
            self.assertIn("keys.env", report["forbidden"])

    def test_environment_variants_are_forbidden_but_templates_are_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self._tree(root)
            (root / ".env.production").write_text("TOKEN=secret\n", encoding="utf-8")
            (root / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
            report = release_hardening.audit_tree(root)
        self.assertFalse(report["ok"])
        self.assertIn(".env.production", report["forbidden"])
        self.assertNotIn(".env.example", report["forbidden"])

    def test_private_keys_databases_and_bearer_caches_are_never_packaged(self):
        names = (
            "signer.pem", "private.key", "identity.p12", "identity.pfx",
            "state.db", "state.sqlite", "state.sqlite3", "state.sqlite3-wal",
            "state.db-journal", "state.sqlite-journal", "state.sqlite3-journal",
            "access.token", "offline.entitlement", "credentials.json",
            "client_secret_prod.json", "service-account-prod.json", "id_ed25519",
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self._tree(root)
            for name in names:
                (root / name).write_text("must not ship\n", encoding="utf-8")
            report = release_hardening.audit_tree(root)
        self.assertFalse(report["ok"])
        self.assertTrue(set(names).issubset(report["forbidden"]))

    def test_packaging_refuses_a_file_changed_after_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir(); self._tree(root)
            audited = release_hardening.audit_tree(root)
            (root / "README.md").write_text("changed after audit\n", encoding="utf-8")
            with mock.patch.object(release_hardening, "audit_tree", return_value=audited):
                with self.assertRaisesRegex(release_hardening.HardeningError,
                                            "changed after audit: README.md"):
                    release_hardening.deterministic_zip(root, base / "release.zip")
            self.assertFalse((base / "release.zip").exists())

    def test_ui_server_transcript_is_never_packaged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self._tree(root)
            (root / "detector" / ".ui35-server.err").write_text("trace", encoding="utf-8")
            report = release_hardening.audit_tree(root)
            self.assertFalse(report["ok"])
            self.assertIn("detector/.ui35-server.err", report["forbidden"])

    def test_audit_rejects_file_over_per_file_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "large.bin").write_bytes(b"1234")
            with mock.patch.object(release_hardening, "MAX_FILE_BYTES", 3):
                with self.assertRaisesRegex(release_hardening.HardeningError,
                                            "release file exceeds 3 bytes: large.bin"):
                    release_hardening.audit_tree(root)

    def test_audit_rejects_file_count_over_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "one.txt").write_bytes(b"1")
            (root / "two.txt").write_bytes(b"2")
            with mock.patch.object(release_hardening, "MAX_FILES", 1):
                with self.assertRaisesRegex(release_hardening.HardeningError,
                                            "release tree exceeds the packaging boundary"):
                    release_hardening.audit_tree(root)

    def test_audit_rejects_total_bytes_over_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "one.txt").write_bytes(b"12")
            (root / "two.txt").write_bytes(b"34")
            with mock.patch.object(release_hardening, "MAX_TOTAL_BYTES", 3):
                with self.assertRaisesRegex(release_hardening.HardeningError,
                                            "release tree exceeds the packaging boundary"):
                    release_hardening.audit_tree(root)

    def test_zip_verifier_rejects_traversal_and_unexpected_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir(); self._tree(root)
            manifest = release_hardening.audit_tree(root); archive = base / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape", b"x")
            report = release_hardening.verify_zip(archive, manifest)
            self.assertFalse(report["ok"])
            self.assertTrue(any("unsafe" in item for item in report["errors"]))

    def test_zip_verifier_rejects_unsafe_directories_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir()
            payload = b"safe\n"; (root / "a.txt").write_bytes(payload)
            manifest = release_hardening.audit_tree(root)
            archive = base / "unsafe-metadata.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                directory = zipfile.ZipInfo("../escape/")
                directory.create_system = 3
                directory.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                handle.writestr(directory, b"")
                linked = zipfile.ZipInfo("Attestor 4.2/a.txt")
                linked.create_system = 3
                linked.external_attr = (stat.S_IFLNK | 0o777) << 16
                handle.writestr(linked, payload)
            report = release_hardening.verify_zip(archive, manifest)
        self.assertFalse(report["ok"])
        self.assertTrue(any("unsafe" in error for error in report["errors"]))
        self.assertTrue(any("explicit regular file" in error for error in report["errors"]))

    def test_zip_verifier_requires_exact_executable_and_data_permissions(self):
        cases = (("runner.py", 0o644), ("notes.txt", 0o666))
        for name, unsafe_permissions in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                base = Path(folder); root = base / "source"; root.mkdir()
                payload = b"safe\n"; (root / name).write_bytes(payload)
                manifest = release_hardening.audit_tree(root)
                archive = base / "unsafe-permissions.zip"
                with zipfile.ZipFile(archive, "w") as handle:
                    info = zipfile.ZipInfo("Attestor 4.2/" + name)
                    info.create_system = 3
                    info.external_attr = (
                        (stat.S_IFREG | unsafe_permissions) & 0xFFFF
                    ) << 16
                    handle.writestr(info, payload)
                report = release_hardening.verify_zip(archive, manifest)
            self.assertFalse(report["ok"])
            self.assertTrue(any("invalid permissions" in error
                                for error in report["errors"]))

    def test_zip_verifier_rejects_even_expected_explicit_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir()
            (root / "nested").mkdir(); payload = b"safe\n"
            (root / "nested" / "notes.txt").write_bytes(payload)
            manifest = release_hardening.audit_tree(root)
            archive = base / "explicit-directory.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                directory = zipfile.ZipInfo("Attestor 4.2/nested/")
                directory.create_system = 3
                directory.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                handle.writestr(directory, b"")
                info = zipfile.ZipInfo("Attestor 4.2/nested/notes.txt")
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                handle.writestr(info, payload)
            report = release_hardening.verify_zip(archive, manifest)
        self.assertFalse(report["ok"])
        self.assertTrue(any("explicit directory entries" in error
                            for error in report["errors"]))

    def test_zip_verifier_rejects_duplicate_and_malformed_manifest_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); root = base / "source"; root.mkdir(); self._tree(root)
            built = release_hardening.deterministic_zip(root, base / "release.zip")
            duplicate = copy.deepcopy(built)
            duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
            duplicate["file_count"] = len(duplicate["files"])
            duplicate["bytes"] = sum(row["bytes"] for row in duplicate["files"])
            body = {key: duplicate[key] for key in
                    ("schema", "product_version", "files", "file_count", "bytes")}
            duplicate["manifest_sha256"] = hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            report = release_hardening.verify_zip(base / "release.zip", duplicate)
            self.assertFalse(report["ok"])
            self.assertTrue(any("duplicate or case-colliding" in error
                                for error in report["errors"]))

            malformed = {"files": [{"path": "../escape", "bytes": 1,
                                      "sha256": "0" * 64}]}
            report = release_hardening.verify_zip(base / "release.zip", malformed)
            self.assertFalse(report["ok"])
            self.assertTrue(any("manifest" in error for error in report["errors"]))

    def test_zip_verifier_rejects_entry_count_before_reading_members(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "many.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("Attestor 4.0/one.txt", b"1")
                handle.writestr("Attestor 4.0/two.txt", b"2")
            with mock.patch.object(release_hardening, "MAX_FILES", 1), \
                    mock.patch.object(zipfile.ZipFile, "read",
                                      side_effect=AssertionError("member read before count gate")):
                report = release_hardening.verify_zip(archive, {"files": []})
            self.assertFalse(report["ok"])
            self.assertEqual(report["files"], 0)
            self.assertIn("archive entry-count boundary exceeded", report["errors"])

    def test_archive_names_are_cross_platform_safe(self):
        unsafe = (
            "Attestor 4.0/bad:name.txt",
            "Attestor 4.0/CON.txt",
            "Attestor 4.0/nested/LPT9.log",
            "Attestor 4.0/trailing-period.",
            "Attestor 4.0/trailing-space ",
            "Attestor 4.0/repeated//separator.txt",
            "Attestor 4.0/control\x1f.txt",
        )
        self.assertTrue(release_hardening._safe_entry("Attestor 4.0/.github/workflows/ci.yml"))
        for name in unsafe:
            with self.subTest(name=name):
                self.assertFalse(release_hardening._safe_entry(name))
                with tempfile.TemporaryDirectory() as folder:
                    archive = Path(folder) / "unsafe.zip"
                    with zipfile.ZipFile(archive, "w") as handle:
                        handle.writestr(name, b"x")
                    report = release_hardening.verify_zip(archive, {"files": []})
                self.assertFalse(report["ok"])
                self.assertTrue(any("unsafe" in error for error in report["errors"]))

    def test_additional_tool_caches_and_virtual_environments_fail_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self._tree(root)
            for directory in (".mypy_cache", ".ruff_cache", ".venv"):
                target = root / directory
                target.mkdir()
                (target / "artifact.json").write_text("{}", encoding="utf-8")
            report = release_hardening.audit_tree(root)
            self.assertFalse(report["ok"])
            for directory in (".mypy_cache", ".ruff_cache", ".venv"):
                self.assertTrue(any(row.startswith(directory) for row in report["forbidden"]))

    def test_plugin_permissions_default_deny_dangerous_capabilities(self):
        decision = release_hardening.evaluate_plugin_manifest({
            "id": "acme.security", "capabilities": ["read-workspace", "network", "read-secrets"]})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.execution, "not-executed")
        self.assertEqual(decision.denied, ("network", "read-secrets"))

    def test_safe_plugin_is_only_eligible_for_external_os_sandbox(self):
        decision = release_hardening.evaluate_plugin_manifest({
            "id": "acme.linter", "capabilities": ["read-workspace", "emit-findings"]})
        self.assertTrue(decision.accepted)
        self.assertIn("separate-os-sandbox", decision.execution)

    def test_sanitized_environment_strips_credentials(self):
        result = release_hardening.sanitized_environment({"PATH": "x", "API_KEY": "secret", "HOME": "h"})
        self.assertEqual(result["PATH"], "x")
        self.assertNotIn("API_KEY", result)
        self.assertEqual(result["ATTESTOR_NETWORK"], "disabled")


if __name__ == "__main__":
    unittest.main()
