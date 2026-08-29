from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

import cjp_authorization414 as authorization
import cjp_control414 as control


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_json(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8")


class CJPControl414Tests(unittest.TestCase):
    def _request(
        self,
        folder: Path,
        workspace: Path,
        *,
        action: str,
        files: list[str],
        candidate_bundle: str = "",
        backup_root: str = "",
        profile: str = control.PROFILE_SLUG,
    ) -> Path:
        path = folder / "permission-request.json"
        _write_json(path, {
            "schema": control.REQUEST_SCHEMA,
            "profile": profile,
            "action": action,
            "root": str(workspace),
            "files": files,
            "organization": "TCS",
            "issuer": "Authorized file custodian",
            "owner_statement": (
                "I am authorized to permit this exact local file operation."),
            "purpose": "Review and improve the supplied local files",
            "ttl_seconds": 300,
            "candidate_bundle": candidate_bundle,
            "backup_root": backup_root,
        })
        return path

    def _candidate(
        self,
        folder: Path,
        workspace: Path,
        changes: dict[str, bytes],
    ) -> Path:
        rows = []
        for relative, after in changes.items():
            before = (workspace / relative).read_bytes()
            rows.append({
                "path": relative,
                "before_sha256": _sha_bytes(before),
                "after_sha256": _sha_bytes(after),
                "encoding": "utf-8",
                "content": after.decode("utf-8"),
            })
        body = {"schema": control.CANDIDATE_SCHEMA, "changes": rows}
        document = {**body, "candidate_sha256": _sha_json(body)}
        path = folder / "candidate.json"
        _write_json(path, document)
        return path

    def _preview_digest(self, request: Path) -> str:
        report = control.control(
            request, permission_confirmed=True)
        self.assertEqual(report["status"], "previewed")
        return report["preview"]["preview_evidence_sha256"]

    def _transaction_change(
        self,
        target: Path,
        relative: str,
        after: bytes,
    ) -> dict[str, object]:
        before = target.read_bytes()
        return {
            "path": relative,
            "before_sha256": _sha_bytes(before),
            "after_sha256": _sha_bytes(after),
            "content": after,
            "target": target,
        }

    def test_denied_default_does_not_read_the_request_path(self) -> None:
        with mock.patch.object(
                control, "load_request",
                side_effect=AssertionError("request path was read")):
            report = control.control(
                "missing-or-sensitive.json", permission_confirmed=False)
        self.assertEqual(report["status"], "authorization-required")
        self.assertFalse(report["authorization"]["authorized"])
        self.assertEqual(
            report["response_language"]["tier"], "C3")
        self.assertFalse(
            report["response_language"]["official_cefr_claim"])

    def test_inspection_is_exact_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            target = workspace / "report.txt"
            target.write_text("private business content", encoding="utf-8")
            request = self._request(
                base, workspace, action="inspect-files",
                files=["report.txt"])
            report = control.control(
                request, permission_confirmed=True)
        self.assertEqual(report["status"], "inspected")
        row = report["result"]["files"][0]
        self.assertEqual(row["sha256"], _sha_bytes(
            b"private business content"))
        self.assertFalse(row["content_emitted"])
        self.assertNotIn("private business content", repr(report))
        self.assertEqual(
            report["authorization"]["status"], "authorized-once")

    def test_database_understanding_is_schema_only(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            target = workspace / "business.sqlite3"
            connection = sqlite3.connect(target)
            connection.execute(
                "CREATE TABLE customer(id INTEGER PRIMARY KEY, secret TEXT)")
            connection.execute(
                "INSERT INTO customer(secret) VALUES ('row-must-not-appear')")
            connection.commit()
            connection.close()
            request = self._request(
                base, workspace, action="analyze-database",
                files=["business.sqlite3"])
            report = control.control(
                request, permission_confirmed=True)
        self.assertEqual(report["status"], "understood")
        self.assertEqual(report["result"]["summary"]["sqlite"], 1)
        self.assertNotIn("row-must-not-appear", repr(report))
        database = report["result"]["databases"][0]["database"]
        self.assertFalse(database["application_row_values_queried"])

    def test_preview_never_changes_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            report = control.control(
                request, permission_confirmed=True)
            current = target.read_text(encoding="utf-8")
        self.assertEqual(report["status"], "previewed")
        self.assertTrue(report["preview"]["eligible_for_apply"])
        self.assertIn("-value = 1", report["preview"]["diffs"][0]["diff"])
        self.assertEqual(current, "value = 1\n")
        self.assertFalse(report["apply_performed"])

    def test_apply_requires_separate_literal_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            with self.assertRaises(authorization.AuthorizationError):
                control.control(
                    request, permission_confirmed=True, apply=True,
                    apply_confirmed=False,
                    preview_evidence_sha256=preview_digest)
            self.assertEqual(
                target.read_text(encoding="utf-8"), "value = 1\n")

    def test_apply_is_candidate_bound_and_persists_verified_backup(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            report = control.control(
                request, permission_confirmed=True, apply=True,
                apply_confirmed=True,
                preview_evidence_sha256=preview_digest)
            backup_file = (
                Path(report["transaction"]["backup_directory"]) / "app.py")
            applied = target.read_text(encoding="utf-8")
            backed_up = backup_file.read_text(encoding="utf-8")
        self.assertEqual(report["status"], "applied")
        self.assertTrue(report["apply_performed"])
        self.assertEqual(applied, "value = 2\n")
        self.assertEqual(backed_up, "value = 1\n")
        self.assertEqual(
            report["apply_authorization"]["authorized_actions"],
            ["apply-file-edit"])
        self.assertTrue(report["transaction"]["cleanup_complete"])
        self.assertEqual(report["transaction"]["cleanup_errors"], [])

    def test_applied_edit_reports_lock_cleanup_failure_truthfully(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            real_unlink = Path.unlink

            def fail_owned_lock(path: Path, *args, **kwargs):
                if path.name == ".attestor-cjp-control.lock":
                    raise OSError("forced owned-lock cleanup failure")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", new=fail_owned_lock):
                report = control.control(
                    request, permission_confirmed=True, apply=True,
                    apply_confirmed=True,
                    preview_evidence_sha256=preview_digest)
            applied = target.read_text(encoding="utf-8")

        self.assertEqual(report["status"], "applied")
        self.assertTrue(report["apply_performed"])
        self.assertEqual(applied, "value = 2\n")
        self.assertFalse(report["transaction"]["cleanup_complete"])
        self.assertTrue(any(
            "transaction-lock-cleanup:OSError" in error
            for error in report["transaction"]["cleanup_errors"]))
        rendered = control.render_text(report)
        self.assertIn("Cleanup complete: no", rendered)
        self.assertIn("transaction-lock-cleanup:OSError", rendered)

    def test_backup_helper_cleanup_errors_survive_transaction_report(
            self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            change = self._transaction_change(
                target, "app.py", b"value = 2\n")
            failure = control.CJPControlError(
                "forced backup failure",
                cleanup_errors=(
                    "backup-descriptor-close:OSError",
                    "partial-backup-cleanup:OSError",
                ))
            with mock.patch.object(
                    control, "_exclusive_backup_copy",
                    side_effect=failure):
                report = control._apply_transaction(
                    workspace, [change],
                    operation_sha256="8" * 64,
                    transaction_sha256="8" * 64,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["cleanup_complete"])
        self.assertEqual(
            report["cleanup_errors"][:2],
            [
                "backup-descriptor-close:OSError",
                "partial-backup-cleanup:OSError",
            ])

    def test_stage_helper_cleanup_error_survives_transaction_report(
            self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            change = self._transaction_change(
                target, "app.py", b"value = 2\n")
            failure = control.CJPControlError(
                "forced stage failure",
                cleanup_errors=("partial-stage-cleanup:OSError",))
            with mock.patch.object(
                    control, "_stage_bytes", side_effect=failure):
                report = control._apply_transaction(
                    workspace, [change],
                    operation_sha256="9" * 64,
                    transaction_sha256="9" * 64,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["cleanup_complete"])
        self.assertIn(
            "partial-stage-cleanup:OSError",
            report["cleanup_errors"])

    def test_secret_like_candidate_is_previewed_but_apply_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "settings.py"
            target.write_text("value = 1\n", encoding="utf-8")
            secret = (
                b"OPENAI_API_KEY = "
                b"'sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN123456'\n")
            candidate = self._candidate(
                base, workspace, {"settings.py": secret})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["settings.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            report = control.control(
                request, permission_confirmed=True, apply=True,
                apply_confirmed=True,
                preview_evidence_sha256=preview_digest)
            current = target.read_text(encoding="utf-8")
        self.assertEqual(report["status"], "apply-refused")
        self.assertEqual(current, "value = 1\n")
        self.assertGreater(
            report["preview"]["validations"][0][
                "credential_like_findings"], 0)
        self.assertNotIn("sk-proj-", repr(report))

    def test_profile_name_spoof_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            (workspace / "report.txt").write_text(
                "business", encoding="utf-8")
            request = self._request(
                base, workspace, action="inspect-files",
                files=["report.txt"], profile="south-park")
            with self.assertRaises(control.CJPControlError):
                control.control(
                    request, permission_confirmed=True)

    def test_sqlite_binary_replacement_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "business.sqlite3"
            connection = sqlite3.connect(target)
            connection.execute("CREATE TABLE sample(id INTEGER)")
            connection.commit()
            connection.close()
            after = bytearray(target.read_bytes())
            after[-1] ^= 1
            body = {
                "schema": control.CANDIDATE_SCHEMA,
                "changes": [{
                    "path": "business.sqlite3",
                    "before_sha256": _sha_bytes(target.read_bytes()),
                    "after_sha256": _sha_bytes(bytes(after)),
                    "encoding": "base64",
                    "content": __import__("base64").b64encode(
                        bytes(after)).decode("ascii"),
                }],
            }
            candidate = base / "candidate.json"
            _write_json(candidate, {
                **body, "candidate_sha256": _sha_json(body)})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["business.sqlite3"],
                candidate_bundle=candidate.name,
                backup_root=backup.name)
            with self.assertRaises(control.CJPControlError):
                control.control(
                    request, permission_confirmed=True)

    def test_apply_requires_a_matching_prior_preview_digest(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            with self.assertRaises(control.CJPControlError):
                control.control(
                    request, permission_confirmed=True, apply=True,
                    apply_confirmed=True,
                    preview_evidence_sha256="0" * 64)
            self.assertEqual(
                target.read_text(encoding="utf-8"), "value = 1\n")
            self.assertNotEqual(preview_digest, "0" * 64)

    def test_removed_source_secret_is_withheld_and_ineligible(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            token = (
                "sk-proj-abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMN123456")
            target = workspace / "settings.py"
            target.write_text(
                "OPENAI_API_KEY = %r\n" % token, encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"settings.py": b"value = 1\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["settings.py"], candidate_bundle=candidate.name)
            report = control.control(
                request, permission_confirmed=True)
        validation = report["preview"]["validations"][0]
        self.assertGreater(
            validation["source_credential_like_findings"], 0)
        self.assertFalse(report["preview"]["eligible_for_apply"])
        self.assertFalse(report["preview"]["diffs"][0]["content_emitted"])
        self.assertNotIn(token, repr(report))

    def test_authorized_inspection_refuses_post_consume_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            target = workspace / "report.txt"
            target.write_text("authorized", encoding="utf-8")
            request = self._request(
                base, workspace, action="inspect-files",
                files=["report.txt"])
            original_consume = authorization.AuthorizationRegistry.consume

            def consume_then_mutate(registry, *args, **kwargs):
                audit = original_consume(registry, *args, **kwargs)
                target.write_text("replacement", encoding="utf-8")
                return audit

            with mock.patch.object(
                    authorization.AuthorizationRegistry, "consume",
                    new=consume_then_mutate):
                with self.assertRaises(control.CJPControlError):
                    control.control(
                        request, permission_confirmed=True)

    def test_inspection_refuses_same_hash_root_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            moved = base / "files-original"
            workspace.mkdir()
            target = workspace / "report.txt"
            target.write_text("authorized", encoding="utf-8")
            request = self._request(
                base, workspace, action="inspect-files",
                files=["report.txt"])
            original_consume = authorization.AuthorizationRegistry.consume

            def consume_then_replace(registry, *args, **kwargs):
                audit = original_consume(registry, *args, **kwargs)
                workspace.rename(moved)
                workspace.mkdir()
                (workspace / "report.txt").write_text(
                    "authorized", encoding="utf-8")
                return audit

            with mock.patch.object(
                    authorization.AuthorizationRegistry, "consume",
                    new=consume_then_replace):
                with self.assertRaises(control.CJPControlError):
                    control.control(
                        request, permission_confirmed=True)

    def test_invalid_owner_assertion_is_rejected_before_target_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            (workspace / "app.py").write_text(
                "value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name)
            document = json.loads(request.read_text(encoding="utf-8"))
            document["owner_statement"] = "invalid\nowner statement"
            _write_json(request, document)
            with mock.patch.object(
                    control, "_sha_file",
                    side_effect=AssertionError("target was hashed early")):
                with self.assertRaises(authorization.AuthorizationError):
                    control.control(
                        request, permission_confirmed=True)

    def test_hostile_json_depth_is_a_control_error(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "deep.json"
            path.write_text(
                '{"value":' + ("[" * 1_500) + "0"
                + ("]" * 1_500) + "}",
                encoding="utf-8")
            with self.assertRaises(control.CJPControlError):
                control._load_json_file(
                    path, maximum=control.MAX_REQUEST_BYTES,
                    label="deep request")

    def test_the_depth_bound_is_enforced_at_its_stated_limit(self) -> None:
        """The refusal must be the depth, not the document.

        A guard that refused everything would satisfy the test above, so this
        pins both sides of the boundary: at the limit the document loads, one
        level past it is refused. It also fixes the limit in the tests, so a
        later change to MAX_JSON_DEPTH cannot quietly become a change to what
        this module accepts.
        """
        limit = control.MAX_JSON_DEPTH
        with tempfile.TemporaryDirectory() as folder:
            for depth, refused in ((limit, False), (limit + 1, True)):
                # The enclosing object is one level; the arrays are the rest.
                inner = depth - 1
                path = Path(folder) / ("nest%d.json" % depth)
                path.write_text(
                    '{"value":' + ("[" * inner) + "0" + ("]" * inner) + "}",
                    encoding="utf-8")
                with self.subTest(depth=depth, refused=refused):
                    if refused:
                        with self.assertRaises(control.CJPControlError):
                            control._load_json_file(
                                path, maximum=control.MAX_REQUEST_BYTES,
                                label="nested request")
                    else:
                        document, _path = control._load_json_file(
                            path, maximum=control.MAX_REQUEST_BYTES,
                            label="nested request")
                        self.assertIn("value", document)

    def test_brackets_inside_strings_are_not_structure(self) -> None:
        # Documents whose *strings* contain brackets are shallow. Counting
        # those as nesting would refuse ordinary content -- regex patterns,
        # embedded JSON, Windows paths -- so the scanner has to track strings
        # and their escapes rather than counting characters.
        self.assertEqual(control._json_depth('{"a": "[[[[[[[["}'), 1)
        self.assertEqual(control._json_depth(r'{"a": "\"[[[["}'), 1)
        self.assertEqual(control._json_depth('{"a": [1, [2, [3]]]}'), 4)
        self.assertEqual(control._json_depth("[]"), 1)
        self.assertEqual(control._json_depth('"just a string"'), 0)

    def test_a_deeply_nested_replacement_file_is_refused(self) -> None:
        # The same bound has to hold on candidate *content*, which is the side
        # an attacker actually supplies.
        with self.assertRaises(control.CJPControlError):
            control._parse_json_candidate(
                ('{"v":' + "[" * 1_000 + "0" + "]" * 1_000 + "}").encode())
        control._parse_json_candidate(b'{"v": [1, [2]]}')      # still accepted

    def test_network_spelled_request_and_backup_paths_fail_closed(self) -> None:
        with self.assertRaises(control.CJPControlError):
            control._regular_file(
                r"\\server\share\permission.json",
                maximum=control.MAX_REQUEST_BYTES,
                label="network request")
        with self.assertRaises(control.CJPControlError):
            control._safe_directory(
                r"\\server\share\backup",
                base=Path.cwd(), label="network backup")

    def test_utf8_diff_truncation_never_leaks_decode_errors(self) -> None:
        before = b"value = 'old'\n"
        after = "value = '€€€€€'\n".encode("utf-8")
        for boundary in range(1, 100):
            with self.subTest(boundary=boundary), mock.patch.object(
                    control, "MAX_DIFF_BYTES", boundary):
                report = control._bounded_diff(
                    "sample.txt", before, after)
                report["diff"].encode("utf-8", "strict")

    def test_high_line_count_diff_is_withheld_before_sequence_matching(self) -> None:
        report = control._bounded_diff(
            "large.txt",
            b"old\n" * (control.MAX_DIFF_INPUT_LINES + 1),
            b"new\n" * (control.MAX_DIFF_INPUT_LINES + 1))
        self.assertEqual(
            report["kind"], "text-diff-withheld-complexity")
        self.assertFalse(report["content_emitted"])
        self.assertTrue(report["truncated"])

    def test_terminal_controls_are_escaped_in_text_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            workspace.mkdir()
            target = workspace / "notes.txt"
            target.write_text("safe\n", encoding="utf-8")
            after = (
                b"safe\n\x1b]8;;https://evil.invalid\x07"
                b"label\x1b]8;;\x07\n")
            candidate = self._candidate(
                base, workspace, {"notes.txt": after})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["notes.txt"], candidate_bundle=candidate.name)
            report = control.control(
                request, permission_confirmed=True)
            rendered = control.render_text(report)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("\\u001b", rendered)

    def test_preexisting_transaction_lock_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            lock = workspace / ".attestor-cjp-control.lock"
            lock.write_text("owned elsewhere", encoding="utf-8")
            report = control._apply_transaction(
                workspace, [], operation_sha256="a" * 64,
                transaction_sha256="a" * 64,
                backup_root=backup,
                expected_root_identity_sha256=(
                    control._root_identity_sha256(workspace)),
                expected_backup_root_identity_sha256=(
                    control._root_identity_sha256(backup)))
            self.assertEqual(report["status"], "failed")
            self.assertEqual(
                lock.read_text(encoding="utf-8"), "owned elsewhere")

    def test_different_operations_share_one_root_transaction_lock(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            change_a = self._transaction_change(
                target, "app.py", b"value = 2\n")
            change_b = self._transaction_change(
                target, "app.py", b"value = 3\n")
            entered = threading.Event()
            release = threading.Event()
            first_lock = threading.Lock()
            first = [True]
            original_backup = control._exclusive_backup_copy

            def blocking_backup(*args, **kwargs):
                with first_lock:
                    should_block = first[0]
                    first[0] = False
                if should_block:
                    entered.set()
                    self.assertTrue(release.wait(5))
                return original_backup(*args, **kwargs)

            reports: dict[str, dict] = {}

            def run(name, change, operation):
                reports[name] = control._apply_transaction(
                    workspace, [change],
                    operation_sha256=operation,
                    transaction_sha256=operation,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))

            with mock.patch.object(
                    control, "_exclusive_backup_copy",
                    side_effect=blocking_backup):
                first_thread = threading.Thread(
                    target=run, args=("a", change_a, "a" * 64))
                first_thread.start()
                self.assertTrue(entered.wait(5))
                second_thread = threading.Thread(
                    target=run, args=("b", change_b, "b" * 64))
                second_thread.start()
                second_thread.join(5)
                self.assertFalse(second_thread.is_alive())
                release.set()
                first_thread.join(5)
                self.assertFalse(first_thread.is_alive())
            self.assertEqual(reports["a"]["status"], "applied")
            self.assertEqual(reports["b"]["status"], "failed")
            self.assertEqual(
                target.read_text(encoding="utf-8"), "value = 2\n")

    def test_exclusive_backup_refuses_existing_hardlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "source.txt"
            victim = base / "victim.txt"
            destination = base / "destination.txt"
            source.write_text("source", encoding="utf-8")
            victim.write_text("victim", encoding="utf-8")
            try:
                os_link = __import__("os").link
                os_link(victim, destination)
            except (AttributeError, OSError):
                self.skipTest("hard links are unavailable")
            with self.assertRaises(OSError):
                control._exclusive_backup_copy(
                    source, destination,
                    expected_sha256=_sha_bytes(b"source"))
            self.assertEqual(
                victim.read_text(encoding="utf-8"), "victim")

    def test_rollback_uses_bound_memory_not_mutated_backup(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            first = workspace / "a.py"
            second = workspace / "b.py"
            first.write_text("a = 1\n", encoding="utf-8")
            second.write_text("b = 1\n", encoding="utf-8")
            changes = [
                self._transaction_change(
                    first, "a.py", b"a = 2\n"),
                self._transaction_change(
                    second, "b.py", b"b = 2\n"),
            ]
            operation = "c" * 64
            original_replace = __import__("os").replace

            def fail_second(source, destination):
                if Path(destination) == second:
                    (backup / operation / "a.py").write_text(
                        "attacker-content", encoding="utf-8")
                    raise OSError("forced second apply failure")
                return original_replace(source, destination)

            with mock.patch("os.replace", side_effect=fail_second):
                report = control._apply_transaction(
                    workspace, changes,
                    operation_sha256=operation,
                    transaction_sha256=operation,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
            self.assertEqual(report["status"], "rolled-back")
            self.assertEqual(
                first.read_text(encoding="utf-8"), "a = 1\n")
            self.assertEqual(
                second.read_text(encoding="utf-8"), "b = 1\n")
            self.assertFalse(report["backup_persisted"])

    def test_failed_rollback_does_not_leave_original_stage_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            first = workspace / "a.py"
            second = workspace / "b.py"
            first.write_text("a = 1\n", encoding="utf-8")
            second.write_text("b = 1\n", encoding="utf-8")
            changes = [
                self._transaction_change(
                    first, "a.py", b"a = 2\n"),
                self._transaction_change(
                    second, "b.py", b"b = 2\n"),
            ]
            original_replace = __import__("os").replace
            first_replacements = [0]

            def fail_apply_and_rollback(source, destination):
                destination = Path(destination)
                if destination == second:
                    raise OSError("forced apply failure")
                if destination == first:
                    first_replacements[0] += 1
                    if first_replacements[0] > 1:
                        raise OSError("forced rollback failure")
                return original_replace(source, destination)

            with mock.patch(
                    "os.replace", side_effect=fail_apply_and_rollback):
                report = control._apply_transaction(
                    workspace, changes,
                    operation_sha256="d" * 64,
                    transaction_sha256="d" * 64,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
            self.assertEqual(report["status"], "failed")
            self.assertTrue(report["rollback_errors"])
            self.assertEqual(
                list(workspace.glob(".attestor-cjp-stage-*")), [])

    def test_rollback_stage_cleanup_failure_is_not_silenced(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            first = workspace / "a.py"
            second = workspace / "b.py"
            first.write_text("a = 1\n", encoding="utf-8")
            second.write_text("b = 1\n", encoding="utf-8")
            changes = [
                self._transaction_change(
                    first, "a.py", b"a = 2\n"),
                self._transaction_change(
                    second, "b.py", b"b = 2\n"),
            ]
            real_replace = __import__("os").replace
            real_unlink = Path.unlink
            first_replacements = [0]
            stage_unlinks = [0]

            def fail_apply_and_rollback(source, destination):
                destination = Path(destination)
                if destination == second:
                    raise OSError("forced apply failure")
                if destination == first:
                    first_replacements[0] += 1
                    if first_replacements[0] > 1:
                        raise OSError("forced rollback failure")
                return real_replace(source, destination)

            def fail_first_stage_unlink(path: Path, *args, **kwargs):
                if path.name.startswith(".attestor-cjp-stage-"):
                    stage_unlinks[0] += 1
                    if stage_unlinks[0] == 1:
                        raise OSError("forced rollback-stage cleanup failure")
                return real_unlink(path, *args, **kwargs)

            with mock.patch(
                    "os.replace", side_effect=fail_apply_and_rollback), \
                    mock.patch.object(
                        Path, "unlink", new=fail_first_stage_unlink):
                report = control._apply_transaction(
                    workspace, changes,
                    operation_sha256="7" * 64,
                    transaction_sha256="7" * 64,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
            cleanup_label = "a.py: rollback-stage-cleanup:OSError"
            self.assertEqual(report["status"], "failed")
            self.assertIn(cleanup_label, report["rollback_errors"])
            self.assertFalse(report["cleanup_complete"])
            self.assertIn(cleanup_label, report["cleanup_errors"])

    def test_prior_preview_digest_binds_untruncated_candidate_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "large.txt"
            target.write_bytes(b"old-value-00000\n" * 25_000)
            candidate_a = self._candidate(
                base, workspace,
                {"large.txt": b"new-value-AAAAA\n" * 25_000})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["large.txt"],
                candidate_bundle=candidate_a.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            # Replace the same bundle path with a same-size candidate whose
            # rendered diff truncates before the differing addition lines.
            self._candidate(
                base, workspace,
                {"large.txt": b"new-value-BBBBB\n" * 25_000})
            with self.assertRaises(control.CJPControlError):
                control.control(
                    request, permission_confirmed=True, apply=True,
                    apply_confirmed=True,
                    preview_evidence_sha256=preview_digest)
            self.assertEqual(
                target.read_bytes(),
                b"old-value-00000\n" * 25_000)

    def test_apply_refuses_authorized_root_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            moved_workspace = base / "files-original"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            original_consume = authorization.AuthorizationRegistry.consume

            def consume_then_replace_root(registry, *args, **kwargs):
                audit = original_consume(registry, *args, **kwargs)
                if audit["authorization_kind"] == "apply":
                    workspace.rename(moved_workspace)
                    workspace.mkdir()
                    (workspace / "app.py").write_text(
                        "value = 1\n", encoding="utf-8")
                return audit

            with mock.patch.object(
                    authorization.AuthorizationRegistry, "consume",
                    new=consume_then_replace_root):
                with self.assertRaises(control.CJPControlError):
                    control.control(
                        request, permission_confirmed=True, apply=True,
                        apply_confirmed=True,
                        preview_evidence_sha256=preview_digest)
            self.assertEqual(
                (moved_workspace / "app.py").read_text(encoding="utf-8"),
                "value = 1\n")
            self.assertEqual(
                (workspace / "app.py").read_text(encoding="utf-8"),
                "value = 1\n")

    def test_sequential_exact_candidates_get_distinct_backup_directories(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            first_digest = self._preview_digest(request)
            first = control.control(
                request, permission_confirmed=True, apply=True,
                apply_confirmed=True,
                preview_evidence_sha256=first_digest)
            self.assertEqual(first["status"], "applied")

            self._candidate(
                base, workspace, {"app.py": b"value = 3\n"})
            second_digest = self._preview_digest(request)
            second = control.control(
                request, permission_confirmed=True, apply=True,
                apply_confirmed=True,
                preview_evidence_sha256=second_digest)
            self.assertEqual(second["status"], "applied")
            self.assertNotEqual(
                first["transaction"]["backup_directory"],
                second["transaction"]["backup_directory"])
            self.assertEqual(
                target.read_text(encoding="utf-8"), "value = 3\n")

    def test_apply_refuses_backup_root_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            moved_backup = base / "backup-original"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            candidate = self._candidate(
                base, workspace, {"app.py": b"value = 2\n"})
            request = self._request(
                base, workspace, action="preview-file-edit",
                files=["app.py"], candidate_bundle=candidate.name,
                backup_root=backup.name)
            preview_digest = self._preview_digest(request)
            original_consume = authorization.AuthorizationRegistry.consume

            def consume_then_replace_backup(registry, *args, **kwargs):
                audit = original_consume(registry, *args, **kwargs)
                if audit["authorization_kind"] == "apply":
                    backup.rename(moved_backup)
                    backup.mkdir()
                return audit

            with mock.patch.object(
                    authorization.AuthorizationRegistry, "consume",
                    new=consume_then_replace_backup):
                with self.assertRaises(control.CJPControlError):
                    control.control(
                        request, permission_confirmed=True, apply=True,
                        apply_confirmed=True,
                        preview_evidence_sha256=preview_digest)
            self.assertEqual(
                target.read_text(encoding="utf-8"), "value = 1\n")
            self.assertEqual(list(backup.iterdir()), [])
            self.assertEqual(list(moved_backup.iterdir()), [])

    def test_final_target_mutation_cannot_be_reported_as_applied(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            workspace = base / "files"
            backup = base / "backup"
            workspace.mkdir()
            backup.mkdir()
            target = workspace / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            change = self._transaction_change(
                target, "app.py", b"value = 2\n")
            operation = "e" * 64
            backup_path = backup / operation / "app.py"
            original_sha_file = control._sha_file
            backup_reads = [0]

            def mutate_during_final_backup_check(path, maximum=control.MAX_FILE_BYTES):
                digest = original_sha_file(path, maximum)
                if Path(path) == backup_path:
                    backup_reads[0] += 1
                    if backup_reads[0] == 2:
                        target.write_text("attacker\n", encoding="utf-8")
                return digest

            with mock.patch.object(
                    control, "_sha_file",
                    side_effect=mutate_during_final_backup_check):
                report = control._apply_transaction(
                    workspace, [change],
                    operation_sha256=operation,
                    transaction_sha256=operation,
                    backup_root=backup,
                    expected_root_identity_sha256=(
                        control._root_identity_sha256(workspace)),
                    expected_backup_root_identity_sha256=(
                        control._root_identity_sha256(backup)))
            self.assertNotEqual(report["status"], "applied")
            self.assertEqual(
                target.read_text(encoding="utf-8"), "attacker\n")

    def test_all_dynamic_text_fields_are_terminal_safe(self) -> None:
        hostile = (
            "\x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07"
            "\nStatus: applied\tforged")
        rendered = control.render_text({
            "status": hostile,
            "action": hostile,
            "operation_sha256": hostile,
            "transaction": {
                "status": hostile,
                "backup_directory": hostile,
                "rolled_back": False,
                "cleanup_complete": False,
                "cleanup_errors": [hostile],
            },
        })
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("\\u001b", rendered)
        self.assertNotIn("\nStatus: applied", rendered)
        self.assertIn("\\u000aStatus: applied\\u0009forged", rendered)


if __name__ == "__main__":
    unittest.main()
