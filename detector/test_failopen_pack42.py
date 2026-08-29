#!/usr/bin/env python3
"""Fail-open / defense-in-depth: controls that grant access when they break.

A missing check is a hole; a check that fails in the allow direction is worse,
because it looks like protection right up until the moment it errors. These
tests pair every dangerous shape with its correct twin -- fail-open against
fail-closed, default-allow against default-deny -- because the whole value of
the pack is telling those two apart. A rule that flagged both, or neither,
would be noise.
"""
from __future__ import annotations

import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect  # noqa: E402


def fired(source: str) -> set[str]:
    source = textwrap.dedent(source)
    return {row.rule for row in detect.scan_source(source, "x", "python", deep=False)}


class FailsOpen(unittest.TestCase):
    def test_a_swallowed_security_check_is_flagged(self):
        self.assertIn("py-auth-fail-open", fired("""
            def allowed(user):
                try:
                    return check_permission(user)
                except Exception:
                    pass
                return True
        """))

    def test_an_except_that_returns_allow_is_flagged(self):
        self.assertIn("py-auth-fail-open", fired("""
            def guard(request):
                try:
                    authorize(request.user)
                except Exception:
                    return True
        """))

    def test_verification_disabled_in_a_fallback_is_flagged(self):
        self.assertIn("py-verify-disabled-on-error", fired("""
            def fetch(url):
                try:
                    return client.get(url)
                except SSLError:
                    return client.get(url, verify=False)
        """))

    def test_a_default_allow_access_decision_is_flagged(self):
        self.assertIn("py-access-default-allow", fired("""
            def can_edit(user):
                is_authorized = True
                if user.is_banned:
                    is_authorized = False
                return is_authorized
        """))


class FailsClosed(unittest.TestCase):
    """The same shapes written correctly must stay silent."""

    def test_a_swallowed_non_security_error_is_not_flagged(self):
        self.assertNotIn("py-auth-fail-open", fired("""
            def load(path):
                try:
                    return open(path).read()
                except OSError:
                    return ""
        """))

    def test_denying_on_error_is_correct_and_silent(self):
        self.assertNotIn("py-auth-fail-open", fired("""
            def guard(request):
                try:
                    authorize(request.user)
                except Exception:
                    return False
        """))

    def test_a_conditional_grant_over_a_deny_default_is_silent(self):
        self.assertNotIn("py-access-default-allow", fired("""
            def can_edit(user):
                is_authorized = False
                if user.is_owner:
                    is_authorized = True
                return is_authorized
        """))

    def test_verification_on_the_normal_path_is_not_this_rule(self):
        self.assertNotIn("py-verify-disabled-on-error", fired("""
            def fetch(url):
                return client.get(url, verify=True)
        """))


class Mapping(unittest.TestCase):
    def test_the_fail_open_rules_map_to_a_weakness_class(self):
        for rid in ("py-auth-fail-open", "py-verify-disabled-on-error",
                    "py-access-default-allow"):
            with self.subTest(rule=rid):
                self.assertRegex(detect.RULE_CWE.get(rid, ""), r"^CWE-\d+$")

    def test_fail_open_is_not_tagged_as_an_attack_technique(self):
        """These are weaknesses in defenders' code, not attacker actions."""
        for rid in ("py-auth-fail-open", "py-access-default-allow"):
            self.assertEqual("", detect.attack_technique(rid))


class Precision(unittest.TestCase):
    def test_attestors_own_tree_has_no_fail_open_false_positives(self):
        """Attestor's code is fail-closed by construction; it should say so.

        The detector module itself defines these patterns as regexes and is
        excluded, as are the tests that carry deliberate bait. What remains is
        ordinary source and must not trip the pack.
        """
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        pack = {"py-auth-fail-open", "py-verify-disabled-on-error",
                "py-access-default-allow"}
        excluded = ("detect.py", "advanced_rules.py", "precision_catalog.py",
                    "multilang.py", "nativescan.py")
        offenders = []
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts or path.name.startswith("test_"):
                continue
            if path.name in excluded:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for row in detect.scan_source(source, path.as_posix(), "python", deep=False):
                if row.rule in pack:
                    offenders.append("%s:%d %s" % (path.name, row.line, row.rule))
        self.assertEqual([], offenders, "fail-open false positives: %s" % offenders[:10])


if __name__ == "__main__":
    unittest.main()
