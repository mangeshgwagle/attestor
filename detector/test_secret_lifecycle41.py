#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import secret_lifecycle41 as secrets41


GITHUB_SECRET = "ghp_" + "Ab9X" * 10
AWS_SECRET = "AKIA" + "Q7W8E9R0T1Y2U3I4"
GENERIC_SECRET = "mN7!qP2@vR9#xT4$zK8%"


def serialized(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


class SecretLifecycle41Tests(unittest.TestCase):
    def assert_private(self, value) -> None:
        output = serialized(value)
        for secret in (GITHUB_SECRET, AWS_SECRET, GENERIC_SECRET):
            self.assertNotIn(secret, output)
            self.assertNotIn(secret[:12], output)

    def test_text_findings_withhold_raw_hash_prefix_and_suffix(self):
        text = (f"token = '{GITHUB_SECRET}'\n"
                f"aws = '{AWS_SECRET}'\n"
                f"password = '{GENERIC_SECRET}'\n")
        findings = secrets41.scan_text(text, source_kind="workspace", path="settings.py")
        self.assertGreaterEqual(len(findings), 3)
        self.assertTrue(all(not item.value_exposed and not item.value_hashed for item in findings))
        self.assert_private(findings)

    def test_expression_assignments_are_not_mistaken_for_literal_secrets(self):
        text = ("token = service.issue_token(user)\n"
                "password = body.get('password', '')\n"
                "const secret = crypto.randomBytes(32)\n"
                "auth: buildAuthorization(request)\n")
        self.assertEqual(
            secrets41.scan_text(text, source_kind="workspace", path="app.py"), [])
        literal = secrets41.scan_text(
            f"token={GENERIC_SECRET}\n", source_kind="workspace", path="app.env")
        self.assertTrue(any(row.rule_id == "generic-high-entropy-secret"
                            for row in literal))

    def test_token_shaped_path_and_source_label_are_redacted(self):
        findings = secrets41.scan_text(
            f"token={GITHUB_SECRET}", source_kind=GITHUB_SECRET,
            path=f"config/{GITHUB_SECRET}.env")
        self.assertEqual(findings[0].source_kind, "caller-supplied")
        self.assertIn("<redacted-secret>", findings[0].path)
        self.assert_private(findings)

    def test_staged_diff_scans_only_added_lines_with_target_line_numbers(self):
        diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
                "@@ -4,2 +4,3 @@\n"
                f"-token={AWS_SECRET}\n context = 1\n+token={GITHUB_SECRET}\n")
        findings = secrets41.scan_staged_diff(diff)
        self.assertTrue(findings)
        self.assertTrue(all(item.source_kind == "staged-diff" for item in findings))
        self.assertTrue(all(item.path == "a.py" for item in findings))
        self.assertTrue(all(item.line == 5 for item in findings))
        self.assert_private(findings)

    def test_history_export_is_supplied_data_and_git_is_never_invoked(self):
        export = ("+++ b/old.env\n@@ -0,0 +1 @@\n" + f"+token={GITHUB_SECRET}\n")
        with mock.patch("secret_lifecycle41.subprocess.run") as run:
            findings = secrets41.scan_history_export(export)
        run.assert_not_called()
        self.assertTrue(findings)
        self.assertTrue(all(item.source_kind == "git-history-export" for item in findings))

    def test_notebook_cells_and_outputs_are_inspected_without_exposure(self):
        notebook = {"cells": [{"cell_type": "code", "source": [f"token='{GITHUB_SECRET}'"],
                               "outputs": [{"output_type": "stream",
                                            "text": [f"password={GENERIC_SECRET}"]}]}]}
        findings = secrets41.scan_notebook_bytes(json.dumps(notebook).encode(), "analysis.ipynb")
        kinds = {item.source_kind for item in findings}
        self.assertIn("notebook-cell", kinds)
        self.assertIn("notebook-output", kinds)
        self.assert_private(findings)

    def test_zip_scans_safe_members_and_rejects_traversal_links_and_secret_names(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder, "bundle.zip")
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(f"safe/{GITHUB_SECRET}.env", f"token={GITHUB_SECRET}")
                handle.writestr("../escape.env", f"token={AWS_SECRET}")
                linked = zipfile.ZipInfo("linked.env")
                linked.create_system = 3
                linked.external_attr = 0o120777 << 16
                handle.writestr(linked, "target")
            findings, gaps = secrets41.scan_archive(archive)
        self.assertTrue(findings)
        self.assertTrue(any("unsafe" in gap for gap in gaps))
        self.assertTrue(any("linked" in gap for gap in gaps))
        self.assertIn("<redacted-secret>", findings[0].path)
        self.assert_private({"findings": findings, "gaps": gaps})

    def test_tar_and_oci_layer_scan_regular_members_but_never_follow_links(self):
        with tempfile.TemporaryDirectory() as folder:
            layer = Path(folder, "layer.tar")
            payload = f"token={GITHUB_SECRET}".encode()
            with tarfile.open(layer, "w") as handle:
                regular = tarfile.TarInfo("app/config.env")
                regular.size = len(payload)
                handle.addfile(regular, io.BytesIO(payload))
                linked = tarfile.TarInfo("app/link.env")
                linked.type = tarfile.SYMTYPE
                linked.linkname = "/host/secret"
                handle.addfile(linked)
            findings, gaps = secrets41.scan_oci_layer_tar(layer)
        self.assertTrue(findings)
        self.assertTrue(all(item.source_kind == "oci-layer" for item in findings))
        self.assertTrue(any("linked TAR" in gap for gap in gaps))
        self.assert_private(findings)

    def test_oci_adapter_rejects_a_zip_disguised_as_a_layer(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "layer.zip")
            with zipfile.ZipFile(target, "w") as handle:
                handle.writestr("a.env", f"token={GITHUB_SECRET}")
            with self.assertRaises(secrets41.SecretLifecycleError):
                secrets41.scan_oci_layer_tar(target)

    def test_archive_member_limit_counts_directories_and_rejected_links(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(secrets41, "MAX_ARCHIVE_MEMBERS", 2):
            archive = Path(folder, "directories.zip")
            with zipfile.ZipFile(archive, "w") as handle:
                for index in range(3):
                    handle.writestr(f"directory-{index}/", b"")
            with self.assertRaisesRegex(secrets41.SecretLifecycleError, "member/byte"):
                secrets41.scan_archive(archive)

            tar_path = Path(folder, "links.tar")
            with tarfile.open(tar_path, "w") as handle:
                for index in range(3):
                    linked = tarfile.TarInfo(f"link-{index}")
                    linked.type = tarfile.SYMTYPE
                    linked.linkname = "target"
                    handle.addfile(linked)
            with self.assertRaisesRegex(secrets41.SecretLifecycleError, "member/byte"):
                secrets41.scan_archive(tar_path)

    def test_oci_adapter_rejects_tar_zip_polyglots(self):
        with tempfile.TemporaryDirectory() as folder:
            tar_path = Path(folder, "layer.tar")
            payload = f"token={AWS_SECRET}".encode()
            with tarfile.open(tar_path, "w") as handle:
                item = tarfile.TarInfo("secret.env"); item.size = len(payload)
                handle.addfile(item, io.BytesIO(payload))
            zip_path = Path(folder, "tail.zip")
            with zipfile.ZipFile(zip_path, "w") as handle:
                handle.writestr("harmless.txt", "safe")
            polyglot = Path(folder, "polyglot.tar")
            polyglot.write_bytes(tar_path.read_bytes() + zip_path.read_bytes())
            self.assertTrue(tarfile.is_tarfile(polyglot))
            self.assertTrue(zipfile.is_zipfile(polyglot))
            with self.assertRaises(secrets41.SecretLifecycleError):
                secrets41.scan_oci_layer_tar(polyglot)

    def test_workspace_prunes_dependency_and_vcs_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".env").write_text(f"aws_access={AWS_SECRET}", encoding="utf-8")
            for directory in (root / ".git", root / "node_modules"):
                directory.mkdir()
                (directory / "hidden.env").write_text(f"token={AWS_SECRET}", encoding="utf-8")
            report = secrets41.scan_workspace(root)
        self.assertEqual(report["finding_count"], 1)
        self.assertTrue(secrets41.verify_report(report))
        self.assertEqual(report["execution"], {"target_code": False, "network": False,
                                               "git_invoked": False})
        self.assert_private(report)

    def test_report_digest_detects_tampering_and_gap_generators_are_preserved(self):
        report = secrets41._report([], (item for item in ["one gap"]), {"sources": []})
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["gaps"], ["one gap"])
        self.assertTrue(secrets41.verify_report(report))
        tampered = copy.deepcopy(report)
        tampered["gaps"].append("hidden")
        self.assertFalse(secrets41.verify_report(tampered))

    def test_report_verifier_rejects_rehashed_raw_secret_material(self):
        findings = secrets41.scan_text(
            f"token={AWS_SECRET}", source_kind="workspace", path="safe.env")
        report = secrets41._report(findings, [], {"sources": ["workspace"]})
        report["findings"][0]["path"] = AWS_SECRET
        body = {key: value for key, value in report.items() if key != "report_sha256"}
        report["report_sha256"] = hashlib.sha256(
            secrets41._canonical(body)).hexdigest()
        self.assertFalse(secrets41.verify_report(report))

    def test_lifecycle_aggregates_workspace_staged_history_archive_and_oci(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder, "workspace"); root.mkdir()
            (root / "a.env").write_text(f"token={GITHUB_SECRET}", encoding="utf-8")
            archive = Path(folder, "safe.zip")
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("b.env", f"token={AWS_SECRET}")
            layer = Path(folder, "layer.tar")
            payload = f"password={GENERIC_SECRET}".encode()
            with tarfile.open(layer, "w") as handle:
                item = tarfile.TarInfo("c.env"); item.size = len(payload)
                handle.addfile(item, io.BytesIO(payload))
            report = secrets41.scan_lifecycle(
                root=root,
                staged_diff="+++ b/d.env\n@@ -0,0 +1 @@\n+token=" + GITHUB_SECRET,
                history_export="+++ b/e.env\n@@ -0,0 +1 @@\n+token=" + AWS_SECRET,
                archives=[archive], oci_layers=[layer])
        self.assertEqual(set(report["scope"]["sources"]),
                         {"workspace", "staged-diff", "git-history-export", "archive", "oci-layer"})
        self.assertGreaterEqual(report["finding_count"], 5)
        self.assertTrue(secrets41.verify_report(report))
        self.assert_private(report)

    def test_hostile_artifact_worker_is_isolated_and_returns_verified_privacy_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "hostile.env")
            target.write_text(f"aws_access={AWS_SECRET}", encoding="utf-8")
            report = secrets41.scan_hostile_file_out_of_process(target)
        self.assertEqual(report["scope"]["out_of_process"], True)
        self.assertEqual(report["finding_count"], 1)
        self.assertTrue(secrets41.verify_report(report))
        self.assert_private(report)

    def test_export_boundaries_fail_closed(self):
        with mock.patch.object(secrets41, "MAX_EXPORT_BYTES", 8):
            with self.assertRaises(secrets41.SecretLifecycleError):
                secrets41.scan_staged_diff("+" + "x" * 20)
            with self.assertRaises(secrets41.SecretLifecycleError):
                secrets41.scan_history_export("+" + "x" * 20)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_linked_top_level_artifacts_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "real.env"; target.write_text(f"token={GITHUB_SECRET}")
            link = root / "linked.env"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symbolic-link privilege unavailable: " + str(exc))
            with self.assertRaises(secrets41.SecretLifecycleError):
                secrets41.scan_hostile_file_out_of_process(link)


if __name__ == "__main__":
    unittest.main(verbosity=2)
