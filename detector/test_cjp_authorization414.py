#!/usr/bin/env python3
"""Adversarial tests for Cockroach-only local authorization manifests."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import cjp_authorization414 as authorization
import variant414


class MutableClock:
    def __init__(self, value: float = 2_000_000_000):
        self.value = value

    def __call__(self) -> float:
        return self.value


class CjpAuthorization414Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "db").mkdir()
        (self.root / "src").mkdir()
        self.database = self.root / "db" / "schema.sql"
        self.database.write_bytes(
            b"CREATE TABLE audit_events (id INTEGER PRIMARY KEY);\n")
        self.source = self.root / "src" / "service.py"
        self.source.write_bytes(
            b"def total(left, right):\n    return left + right\n")
        self.clock = MutableClock()
        self.registry = authorization.AuthorizationRegistry(clock=self.clock)
        self.preview_operation = authorization.operation_sha256({
            "action": "preview-local-enterprise-files",
            "files": ["db/schema.sql", "src/service.py"],
            "request": "Review and propose a bounded local edit.",
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue(
            self,
            *,
            actions=(authorization.INSPECT_FILES,
                     authorization.ANALYZE_DATABASE,
                     authorization.PREVIEW_FILE_EDIT),
            paths=("db/schema.sql", "src/service.py"),
            nonce="a" * 64,
            **overrides,
            ):
        arguments = {
            "organization": "Tata Consultancy Services",
            "issuer": "File owner acting with explicit permission",
            "owner_statement":
                "I authorize this exact local preview for the supplied files.",
            "purpose":
                "Inspect, understand, and preview an explicitly requested edit.",
            "allowed_actions": actions,
            "operation_sha256": self.preview_operation,
            "confirmed": True,
            "ttl_seconds": 300,
            "nonce": nonce,
        }
        arguments.update(overrides)
        return self.registry.issue_preview_authorization(
            self.root, paths, **arguments)

    def consume(
            self,
            manifest,
            *,
            actions=None,
            operation=None,
            candidate=None,
            root=None,
            ):
        if actions is None:
            actions = tuple(manifest["allowed_actions"])
        return self.registry.consume(
            manifest,
            root=self.root if root is None else root,
            requested_actions=actions,
            operation_sha256=(
                manifest["operation_sha256"]
                if operation is None else operation),
            candidate_sha256=candidate,
        )

    def preview_edit_audit(self, *, nonce="b" * 64):
        manifest = self.issue(
            actions=(authorization.PREVIEW_FILE_EDIT,),
            paths=("src/service.py",),
            nonce=nonce,
        )
        return self.consume(manifest)

    def test_default_is_denied_without_inspecting_a_path(self) -> None:
        with mock.patch.object(
                authorization, "capture_file_scope",
                side_effect=AssertionError("filesystem touched")):
            status = authorization.denied_status()
        self.assertEqual(status["status"], "authorization-required")
        self.assertFalse(status["authorized"])
        self.assertEqual(status["profile"]["slug"], "cockroach-janta-party")
        self.assertEqual(
            status["profile"]["profile_sha256"],
            variant414.profile_identity(
                variant414.COCKROACH_JANTA_PARTY))
        self.assertEqual(status["defaults"], {
            "apply": False,
            "dry_run": True,
            "network": False,
            "permission_persistence": False,
        })

    def test_manifest_is_exact_cockroach_preview_only_and_verified(self) -> None:
        manifest = self.issue()
        valid, errors = authorization.verify_manifest(manifest)
        self.assertTrue(valid, errors)
        self.assertEqual(
            manifest["profile"],
            {
                "slug": "cockroach-janta-party",
                "profile_sha256": variant414.profile_identity(
                    variant414.COCKROACH_JANTA_PARTY),
            })
        self.assertEqual(manifest["authorization_kind"], "preview")
        self.assertTrue(manifest["controls"]["dry_run"])
        self.assertFalse(manifest["controls"]["automatic_apply"])
        self.assertFalse(
            manifest["controls"]["apply_authorized_for_exact_candidate"])
        for authority in (
                "account_authority", "credential_authority",
                "network_authority", "permission_persisted",
                "target_code_execution_authority"):
            self.assertFalse(manifest["controls"][authority])
        self.assertIsNone(manifest["candidate_sha256"])
        self.assertEqual(
            [row["relative_path"] for row in manifest["file_scope"]],
            ["db/schema.sql", "src/service.py"])

    def test_organization_label_is_an_exact_two_value_allowlist(self) -> None:
        accepted = self.issue(
            organization="TCS", nonce="c" * 64)
        self.assertEqual(accepted["organization"], "TCS")
        for value in (
                "tcs", "TCS ", " Tata Consultancy Services",
                "Tata consultancy services", "Other", "", None, 7):
            with self.subTest(value=value):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(
                        organization=value,
                        nonce=authorization.hashlib.sha256(
                            repr(value).encode()).hexdigest())

    def test_confirmation_requires_exact_true(self) -> None:
        for value in (False, None, 0, 1, "true", [], object()):
            with self.subTest(value=value):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(confirmed=value, nonce=None)

    def test_preview_action_allowlist_is_tight_and_canonical(self) -> None:
        for actions in (
                (),
                (authorization.APPLY_FILE_EDIT,),
                (authorization.INSPECT_FILES, "network"),
                (authorization.INSPECT_FILES, "run-command"),
                (authorization.INSPECT_FILES,
                 authorization.INSPECT_FILES),
                authorization.INSPECT_FILES,
                {"inspect-files": True},
                (authorization.INSPECT_FILES, 3),
                (name for name in (
                    "a", "b", "c", "d", "e")),
                ):
            with self.subTest(actions=repr(actions)):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(actions=actions, nonce=None)
        manifest = self.issue(
            actions=(
                authorization.PREVIEW_FILE_EDIT,
                authorization.INSPECT_FILES,
            ),
            nonce="d" * 64,
        )
        self.assertEqual(
            manifest["allowed_actions"],
            [
                authorization.INSPECT_FILES,
                authorization.PREVIEW_FILE_EDIT,
            ])

    def test_nonce_is_exact_unique_and_never_reissued(self) -> None:
        for nonce in (
                "", "a" * 63, "a" * 65, "A" * 64, "g" * 64,
                7, b"a" * 64):
            with self.subTest(nonce=nonce):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(nonce=nonce)
        manifest = self.issue(nonce="e" * 64)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "already issued"):
            self.issue(nonce="e" * 64)
        self.consume(manifest)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "already issued"):
            self.issue(nonce="e" * 64)

    def test_manifest_is_one_use_even_under_concurrent_consumption(self) -> None:
        manifest = self.issue(nonce="f" * 64)
        outcomes: list[str] = []
        barrier = threading.Barrier(3)

        def attempt() -> None:
            barrier.wait()
            try:
                self.consume(manifest)
            except authorization.AuthorizationError:
                outcomes.append("denied")
            else:
                outcomes.append("authorized")

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(outcomes), ["authorized", "denied"])

    def test_expiry_and_clock_rollback_fail_closed(self) -> None:
        manifest = self.issue(ttl_seconds=2, nonce="1" * 64)
        self.clock.value += 2
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "current time"):
            self.consume(manifest)
        rollback = self.issue(ttl_seconds=5, nonce="2" * 64)
        self.clock.value -= 1
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "current time"):
            self.consume(rollback)
        for ttl in (True, False, 0, -1, 901, 1.5, "20"):
            with self.subTest(ttl=ttl):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(ttl_seconds=ttl, nonce=None)

    def test_scope_verification_cannot_outlive_authorization(self) -> None:
        manifest = self.issue(ttl_seconds=1, nonce="9" * 64)
        original_capture = authorization.capture_file_scope

        def capture_then_expire(*args, **kwargs):
            scope = original_capture(*args, **kwargs)
            self.clock.value += 2
            return scope

        with mock.patch.object(
                authorization, "capture_file_scope",
                side_effect=capture_then_expire):
            with self.assertRaisesRegex(
                    authorization.AuthorizationError,
                    "expired"):
                self.consume(manifest)

    def test_fresh_registry_cannot_consume_a_copied_manifest(self) -> None:
        manifest = self.issue(nonce="3" * 64)
        copied = json.loads(json.dumps(manifest))
        other = authorization.AuthorizationRegistry(clock=self.clock)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "in-memory registry"):
            other.consume(
                copied,
                root=self.root,
                requested_actions=copied["allowed_actions"],
                operation_sha256=copied["operation_sha256"],
            )

    def test_tampering_is_denied_even_when_attacker_recomputes_digest(self) -> None:
        manifest = self.issue(nonce="4" * 64)
        forged = copy.deepcopy(manifest)
        forged["owner_statement"] = (
            "A forged statement that still has a structurally valid shape.")
        forged["manifest_sha256"] = authorization._sha_json({
            key: value for key, value in forged.items()
            if key != "manifest_sha256"
        })
        self.assertTrue(authorization.verify_manifest(forged)[0])
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "in-memory registry"):
            self.consume(forged)

    def test_profile_control_and_action_escalation_forgery_fails(self) -> None:
        original = self.issue(nonce="5" * 64)
        mutations = []
        forged = copy.deepcopy(original)
        forged["profile"] = {
            "slug": "south-park",
            "profile_sha256": variant414.profile_identity(
                variant414.SOUTH_PARK),
        }
        mutations.append(forged)
        forged = copy.deepcopy(original)
        forged["controls"]["network_authority"] = True
        mutations.append(forged)
        forged = copy.deepcopy(original)
        forged["controls"]["credential_authority"] = True
        mutations.append(forged)
        forged = copy.deepcopy(original)
        forged["controls"]["permission_persisted"] = True
        mutations.append(forged)
        forged = copy.deepcopy(original)
        forged["allowed_actions"].append("run-command")
        mutations.append(forged)
        forged = copy.deepcopy(original)
        forged["organization"] = "Not TCS"
        mutations.append(forged)
        for value in mutations:
            value["manifest_sha256"] = authorization._sha_json({
                key: item for key, item in value.items()
                if key != "manifest_sha256"
            })
            with self.subTest(change=value):
                valid, errors = authorization.verify_manifest(value)
                self.assertFalse(valid)
                self.assertTrue(errors)

    def test_exact_operation_and_action_set_are_required(self) -> None:
        manifest = self.issue(nonce="6" * 64)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "exactly match"):
            self.consume(
                manifest,
                actions=(authorization.INSPECT_FILES,))
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "operation"):
            self.consume(
                manifest,
                operation="0" * 64)
        audit = self.consume(manifest)
        self.assertTrue(authorization.verify_audit(audit)[0])

    def test_changed_file_and_wrong_root_are_denied(self) -> None:
        manifest = self.issue(nonce="7" * 64)
        self.source.write_bytes(b"malicious replacement\n")
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "scope changed"):
            self.consume(manifest)

        self.source.write_bytes(
            b"def total(left, right):\n    return left + right\n")
        other_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(other_temporary.cleanup)
        other = Path(other_temporary.name)
        (other / "db").mkdir()
        (other / "src").mkdir()
        (other / "db" / "schema.sql").write_bytes(
            self.database.read_bytes())
        (other / "src" / "service.py").write_bytes(
            self.source.read_bytes())
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "scope changed"):
            self.consume(manifest, root=other)

        # Failed attempts do not grant anything and do not burn a valid nonce.
        audit = self.consume(manifest)
        self.assertEqual(audit["status"], "authorized-once")

    def test_path_traversal_absolute_network_and_device_names_are_denied(self) -> None:
        hostile = (
            "../outside.py",
            "src/../outside.py",
            "/absolute.py",
            "\\\\server\\share\\file.py",
            "src\\service.py",
            "src//service.py",
            "./src/service.py",
            "src/.",
            "src/NUL.txt",
            "src/name.",
            "src/ name.py",
            "src/name.py ",
            "src/evil\u202ename.py",
            "src/colon:name.py",
        )
        for path in hostile:
            with self.subTest(path=path):
                with self.assertRaises(authorization.AuthorizationError):
                    authorization.capture_file_scope(self.root, [path])
        with self.assertRaises(authorization.AuthorizationError):
            authorization.capture_file_scope(
                os.fspath(self.root / ".." / self.root.name),
                ["src/service.py"],
            )
        with self.assertRaises(authorization.AuthorizationError):
            authorization.capture_file_scope(
                "\\\\server\\share", ["file.py"])

    def test_duplicate_case_collision_empty_scope_and_directory_are_denied(self) -> None:
        (self.root / "Case.py").write_text("one", encoding="utf-8")
        (self.root / "case.py").write_text("two", encoding="utf-8")
        for paths in (
                (),
                "src/service.py",
                ("Case.py", "case.py"),
                ("src",),
                (item for item in ["src/service.py"] * 129),
                ):
            with self.subTest(paths=repr(paths)):
                with self.assertRaises(authorization.AuthorizationError):
                    authorization.capture_file_scope(self.root, paths)

    def test_hostile_iterators_fail_as_authorization_errors(self) -> None:
        def broken():
            yield "src/service.py"
            raise RuntimeError("hostile iterator")

        with self.assertRaisesRegex(
                authorization.AuthorizationError, "iteration failed"):
            authorization.capture_file_scope(self.root, broken())
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "iteration failed"):
            self.issue(actions=broken(), nonce=None)

    def test_file_and_total_byte_boundaries_are_enforced(self) -> None:
        with mock.patch.object(authorization, "MAX_FILE_BYTES", 3):
            with self.assertRaisesRegex(
                    authorization.AuthorizationError, "per-file"):
                authorization.capture_file_scope(
                    self.root, ["src/service.py"])
        with mock.patch.object(
                authorization, "MAX_TOTAL_BYTES", len(self.database.read_bytes())):
            with self.assertRaisesRegex(
                    authorization.AuthorizationError, "total byte"):
                authorization.capture_file_scope(
                    self.root, ["db/schema.sql", "src/service.py"])

    def test_symlink_file_and_directory_are_never_followed(self) -> None:
        outside_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(outside_temporary.cleanup)
        outside = Path(outside_temporary.name)
        outside_file = outside / "secret.py"
        outside_file.write_text("secret = 'do-not-read'\n", encoding="utf-8")
        file_link = self.root / "src" / "linked.py"
        directory_link = self.root / "linked-dir"
        try:
            os.symlink(outside_file, file_link)
            os.symlink(outside, directory_link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable for this account")
        for path in ("src/linked.py", "linked-dir/secret.py"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                        authorization.AuthorizationError,
                        "link or reparse"):
                    authorization.capture_file_scope(self.root, [path])

    def test_reparse_metadata_and_multiply_linked_files_are_denied(self) -> None:
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_file_attributes=int(
                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)),
        )
        self.assertTrue(
            authorization._is_link_or_reparse_metadata(metadata))
        hardlink = self.root / "src" / "hardlink.py"
        try:
            os.link(self.source, hardlink)
        except (OSError, NotImplementedError):
            self.skipTest("hard links are unavailable for this account")
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "multiply linked"):
            authorization.capture_file_scope(
                self.root, ["src/service.py"])
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "multiply linked"):
            authorization.capture_file_scope(
                self.root, ["src/hardlink.py"])

    def test_audit_has_no_contents_paths_or_identity_statements(self) -> None:
        marker = "UNIQUE_SECRET_MARKER_414"
        self.source.write_text(marker, encoding="utf-8")
        manifest = self.registry.issue_preview_authorization(
            self.root,
            ["src/service.py"],
            organization="TCS",
            issuer="Private issuer marker",
            owner_statement="Private owner permission marker statement",
            purpose="Private purpose marker",
            allowed_actions=[authorization.INSPECT_FILES],
            operation_sha256=authorization.operation_sha256(
                {"inspect": "src/service.py"}),
            confirmed=True,
            nonce="8" * 64,
        )
        audit = self.consume(
            manifest,
            actions=(authorization.INSPECT_FILES,))
        serialized = json.dumps(audit, sort_keys=True)
        for raw in (
                marker, "src/service.py", "Private issuer marker",
                "Private owner permission marker statement",
                "Private purpose marker", manifest["nonce"]):
            self.assertNotIn(raw, serialized)
        self.assertFalse(audit["file_contents_included"])
        self.assertFalse(audit["permission_retained"])
        self.assertEqual(
            audit["file_evidence"][0]["content_sha256"],
            authorization.hashlib.sha256(marker.encode()).hexdigest())
        self.assertTrue(authorization.verify_audit(audit)[0])

    def test_apply_requires_consumed_preview_edit_from_same_registry(self) -> None:
        unconsumed = self.issue(
            actions=(authorization.PREVIEW_FILE_EDIT,),
            paths=("src/service.py",),
            nonce="9" * 64,
        )
        fake_audit = {
            "audit_sha256": unconsumed["manifest_sha256"],
        }
        with self.assertRaises(authorization.AuthorizationError):
            self.issue_apply(fake_audit)

        other_registry = authorization.AuthorizationRegistry(clock=self.clock)
        other_manifest = other_registry.issue_preview_authorization(
            self.root,
            ["src/service.py"],
            organization="TCS",
            issuer="Authorized file owner",
            owner_statement="I authorize this exact preview operation.",
            purpose="Preview the exact bounded source edit.",
            allowed_actions=[authorization.PREVIEW_FILE_EDIT],
            operation_sha256=self.preview_operation,
            confirmed=True,
            nonce="0" * 64,
        )
        other_audit = other_registry.consume(
            other_manifest,
            root=self.root,
            requested_actions=[authorization.PREVIEW_FILE_EDIT],
            operation_sha256=self.preview_operation,
        )
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "this registry"):
            self.issue_apply(other_audit)

    def issue_apply(
            self,
            preview_audit,
            *,
            nonce="b" * 64,
            candidate=None,
            operation=None,
            organization="Tata Consultancy Services",
            apply_confirmed=True,
            paths=("src/service.py",),
            ):
        candidate = candidate or authorization.operation_sha256({
            "path": "src/service.py",
            "after": "return left + right",
        })
        if operation is None:
            operation = preview_audit.get(
                "operation_sha256", self.preview_operation)
        return self.registry.issue_apply_authorization(
            self.root,
            paths,
            organization=organization,
            issuer="File owner confirming the exact candidate",
            owner_statement=(
                "I separately authorize applying this exact reviewed "
                "candidate."),
            purpose="Apply the exact candidate reviewed in the preview.",
            operation_sha256=operation,
            candidate_sha256=candidate,
            preview_audit=preview_audit,
            preview_evidence_sha256=authorization.operation_sha256({
                "preview": "accepted",
                "candidate_sha256": candidate,
            }),
            apply_confirmed=apply_confirmed,
            ttl_seconds=120,
            nonce=nonce,
        )

    def test_apply_is_a_separate_exact_candidate_one_use_grant(self) -> None:
        preview_audit = self.preview_edit_audit(nonce="c" * 64)
        candidate = authorization.operation_sha256(
            {"candidate": "reviewed source bytes"})
        apply_manifest = self.issue_apply(
            preview_audit, candidate=candidate, nonce="d" * 64)
        self.assertEqual(apply_manifest["authorization_kind"], "apply")
        self.assertEqual(
            apply_manifest["allowed_actions"],
            [authorization.APPLY_FILE_EDIT])
        self.assertFalse(apply_manifest["controls"]["dry_run"])
        self.assertFalse(apply_manifest["controls"]["automatic_apply"])
        self.assertTrue(
            apply_manifest["controls"][
                "apply_authorized_for_exact_candidate"])
        wrong = authorization.operation_sha256({"candidate": "unreviewed"})
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "candidate"):
            self.consume(
                apply_manifest,
                actions=(authorization.APPLY_FILE_EDIT,),
                candidate=wrong,
            )
        audit = self.consume(
            apply_manifest,
            actions=(authorization.APPLY_FILE_EDIT,),
            candidate=candidate,
        )
        self.assertEqual(audit["authorization_kind"], "apply")
        self.assertEqual(audit["candidate_sha256"], candidate)
        self.assertTrue(authorization.verify_audit(audit)[0])
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "consumed"):
            self.consume(
                apply_manifest,
                actions=(authorization.APPLY_FILE_EDIT,),
                candidate=candidate,
            )

    def test_apply_operation_must_match_consumed_preview_operation(self) -> None:
        preview_audit = self.preview_edit_audit(nonce="8" * 64)
        unrelated_operation = authorization.operation_sha256({
            "action": authorization.APPLY_FILE_EDIT,
            "candidate_sha256": authorization.operation_sha256({
                "candidate": "unrelated",
            }),
        })
        with self.assertRaisesRegex(
                authorization.AuthorizationError,
                "operation does not match the preview"):
            self.issue_apply(
                preview_audit,
                operation=unrelated_operation,
                nonce="9" * 64,
            )

    def test_apply_rejects_malformed_preview_operation_evidence(self) -> None:
        preview_audit = self.preview_edit_audit(nonce="0" * 64)
        malformed = copy.deepcopy(preview_audit)
        malformed["operation_sha256"] = "not-a-sha256"
        malformed["audit_sha256"] = authorization._sha_json({
            key: value for key, value in malformed.items()
            if key != "audit_sha256"
        })
        with self.assertRaisesRegex(
                authorization.AuthorizationError,
                "preview authorization audit is invalid"):
            self.issue_apply(
                malformed,
                operation=self.preview_operation,
                nonce="1" * 64,
            )

    def test_apply_confirmation_is_exact_and_cannot_share_preview_nonce(self) -> None:
        preview_audit = self.preview_edit_audit(nonce="e" * 64)
        for value in (False, None, 0, 1, "yes"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                        authorization.AuthorizationError,
                        "separate explicit"):
                    self.issue_apply(
                        preview_audit,
                        apply_confirmed=value,
                        nonce=None,
                    )
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "already issued"):
            self.issue_apply(preview_audit, nonce="e" * 64)

    def test_apply_requires_preview_file_edit_not_inspection(self) -> None:
        manifest = self.issue(
            actions=(authorization.INSPECT_FILES,),
            paths=("src/service.py",),
            nonce="f" * 64,
        )
        audit = self.consume(manifest)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "preview-file-edit"):
            self.issue_apply(audit, nonce="1" * 64)

    def test_apply_scope_and_organization_must_match_preview(self) -> None:
        preview_audit = self.preview_edit_audit(nonce="2" * 64)
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "organization"):
            self.issue_apply(
                preview_audit, organization="TCS", nonce="3" * 64)
        self.source.write_text("changed after preview\n", encoding="utf-8")
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "scope"):
            self.issue_apply(preview_audit, nonce="4" * 64)

    def test_preview_consume_refuses_candidate_and_apply_refuses_wrong_action(self) -> None:
        preview = self.issue(
            actions=(authorization.PREVIEW_FILE_EDIT,),
            paths=("src/service.py",),
            nonce="5" * 64,
        )
        with self.assertRaisesRegex(
                authorization.AuthorizationError, "cannot carry"):
            self.consume(
                preview,
                candidate="0" * 64,
            )
        audit = self.consume(preview)
        apply_manifest = self.issue_apply(audit, nonce="6" * 64)
        with self.assertRaises(authorization.AuthorizationError):
            self.consume(
                apply_manifest,
                actions=(authorization.INSPECT_FILES,),
                candidate=apply_manifest["candidate_sha256"],
            )

    def test_owner_fields_are_bounded_and_terminal_safe(self) -> None:
        changes = (
            {"issuer": ""},
            {"issuer": " padded"},
            {"issuer": "bad\nissuer"},
            {"owner_statement": "short"},
            {"owner_statement": "statement\u202ewith bidi"},
            {"purpose": "x"},
            {"purpose": "purpose\x00hidden"},
            {"owner_statement": "x" * (authorization.MAX_TEXT_BYTES + 1)},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(authorization.AuthorizationError):
                    self.issue(nonce=None, **change)

    def test_operation_digest_is_deterministic_and_bounded(self) -> None:
        one = authorization.operation_sha256(
            {"b": [2, 3], "a": 1})
        two = authorization.operation_sha256(
            {"a": 1, "b": [2, 3]})
        self.assertEqual(one, two)
        for hostile in (
                {"float": 1.5},
                {"nan": float("nan")},
                {"bytes": b"no"},
                {"huge": "x" * (authorization.MAX_TEXT_BYTES + 1)},
                ):
            with self.subTest(hostile=repr(hostile)[:80]):
                with self.assertRaises(authorization.AuthorizationError):
                    authorization.operation_sha256(hostile)

    def test_verifiers_fail_closed_on_hostile_shapes_without_throwing(self) -> None:
        hostile: list[object] = [
            None,
            [],
            "manifest",
            {"schema": authorization.MANIFEST_SCHEMA},
            {"padding": "x" * (authorization.MAX_TEXT_BYTES + 1)},
            {"float": float("nan")},
            {1: "non-text-key"},
        ]
        cycle: dict[str, object] = {}
        cycle["cycle"] = cycle
        hostile.append(cycle)
        for value in hostile:
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(
                    authorization.verify_manifest(value)[0])
                self.assertFalse(
                    authorization.verify_audit(value)[0])

    def test_audit_tampering_and_extra_fields_are_detected(self) -> None:
        audit = self.preview_edit_audit(nonce="7" * 64)
        mutations = []
        forged = copy.deepcopy(audit)
        forged["controls"]["network_authority"] = True
        mutations.append(forged)
        forged = copy.deepcopy(audit)
        forged["permission_retained"] = True
        mutations.append(forged)
        forged = copy.deepcopy(audit)
        forged["file_contents_included"] = True
        mutations.append(forged)
        forged = copy.deepcopy(audit)
        forged["extra"] = True
        mutations.append(forged)
        forged = copy.deepcopy(audit)
        forged["file_evidence"][0]["content"] = "secret"
        mutations.append(forged)
        for value in mutations:
            value["audit_sha256"] = authorization._sha_json({
                key: item for key, item in value.items()
                if key != "audit_sha256"
            })
            with self.subTest(value=value):
                valid, errors = authorization.verify_audit(value)
                self.assertFalse(valid)
                self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
