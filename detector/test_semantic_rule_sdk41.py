from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

import analysis_snapshot41 as snapshot41
import semantic_graph41 as graph41
import semantic_rule_sdk41 as sdk


class SemanticRuleSDK41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, value: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8", newline="")
        return path

    @staticmethod
    def pack(rule: dict) -> dict:
        return sdk.seal_pack({
            "schema": sdk.SCHEMA, "version": sdk.VERSION,
            "pack_id": "fixture.rules", "rules": [rule],
        })

    @staticmethod
    def call_rule() -> dict:
        return {
            "id": "attestor41-dangerous-eval", "title": "Dynamic evaluation",
            "description": "Dynamic evaluation requires review.", "severity": "HIGH",
            "language": "python", "remediation": "Use a bounded parser.",
            "match": {"kind": "ast-call", "callee_in": ["eval", "exec"]},
            "fixtures": {
                "positive": [{"path": "bad.py", "source": "eval(value)\n"}],
                "negative": [{"path": "good.py", "source": "print(value)\n"}],
            },
        }

    def test_content_digest_hmac_authentication_and_trusted_key_id(self) -> None:
        key = b"0123456789abcdef0123456789abcdef"
        body = {"schema": sdk.SCHEMA, "version": sdk.VERSION,
                "pack_id": "signed.rules", "rules": [self.call_rule()]}
        sealed = sdk.seal_pack(body, key=key, key_id="team-security")
        validated = sdk.validate_pack(
            sealed, key=key, require_signature=True, expected_key_id="team-security")
        self.assertTrue(validated["authenticated"])
        with self.assertRaises(sdk.RulePackError):
            sdk.validate_pack(sealed, key=b"wrong-wrong-wrong!", require_signature=True)
        with self.assertRaises(sdk.RulePackError):
            sdk.validate_pack(sealed, key=key, expected_key_id="other-team")
        relabeled = copy.deepcopy(sealed)
        relabeled["signature"]["key_id"] = "attacker-label"
        with self.assertRaisesRegex(sdk.RulePackError, "signature"):
            sdk.validate_pack(relabeled, key=key)
        extra = copy.deepcopy(sealed)
        extra["signature"]["ignored"] = "unsigned metadata"
        with self.assertRaisesRegex(sdk.RulePackError, "envelope"):
            sdk.validate_pack(extra, key=key)
        malformed = copy.deepcopy(sealed)
        malformed["signature"]["value"] = "A" * 64
        with self.assertRaisesRegex(sdk.RulePackError, "envelope"):
            sdk.validate_pack(malformed, key=key)
        with self.assertRaisesRegex(sdk.RulePackError, "key_id"):
            sdk.seal_pack(body, key=key, key_id="team\u202esecurity")
        sealed["rules"][0]["title"] = "tampered"
        with self.assertRaises(sdk.RulePackError):
            sdk.validate_pack(sealed, key=key)

    def test_positive_and_negative_fixtures_gate_pack_loading(self) -> None:
        rule = self.call_rule()
        sdk.validate_pack(self.pack(rule))
        broken = self.call_rule()
        broken["fixtures"]["negative"][0]["source"] = "eval(value)\n"
        with self.assertRaisesRegex(sdk.RulePackError, "negative fixture"):
            sdk.validate_pack(self.pack(broken))
        javascript = self.call_rule()
        javascript["language"] = "typescript"
        javascript["fixtures"]["positive"][0] = {
            "path": "bad.ts", "source": "eval(value);"}
        javascript["fixtures"]["negative"][0] = {
            "path": "good.ts", "source": "safe(value);"}
        with self.assertRaisesRegex(sdk.RulePackError, "requires Python AST evidence"):
            sdk.validate_pack(self.pack(javascript))

    def test_display_text_escapes_controls_and_preserves_ordinary_unicode(self) -> None:
        rule = self.call_rule()
        rule["title"] = "Caf\N{LATIN SMALL LETTER E WITH ACUTE}\x1b[31m\u0085\u202e"
        rule["description"] = "D\N{LATIN SMALL LETTER E WITH ACUTE}tail\u202e"
        rule["remediation"] = "R\N{LATIN SMALL LETTER E WITH ACUTE}parer\x00"
        pack = self.pack(rule)
        validated = sdk.validate_pack(pack)
        self.assertEqual(
            validated["rules"][0]["description"],
            "D\N{LATIN SMALL LETTER E WITH ACUTE}tail\\u202e")

        self.write("caf\N{LATIN SMALL LETTER E WITH ACUTE}\u202e.py", "eval(value)\n")
        report = sdk.evaluate(pack, self.root)
        finding = report["findings"][0]
        self.assertEqual(
            finding["title"],
            "Caf\N{LATIN SMALL LETTER E WITH ACUTE}\\x1b[31m\\x85\\u202e")
        self.assertEqual(
            finding["remediation"],
            "R\N{LATIN SMALL LETTER E WITH ACUTE}parer\\x00")
        self.assertEqual(
            finding["path"],
            "caf\N{LATIN SMALL LETTER E WITH ACUTE}\\u202e.py")

        flood = self.call_rule()
        flood["title"] = "X" + ("\x1b" * 1_999)
        bounded = sdk.evaluate(self.pack(flood), self.root)
        bounded_title = bounded["findings"][0]["title"]
        self.assertLessEqual(len(bounded_title), 2_000)
        self.assertNotIn("\x1b", bounded_title)
        self.assertTrue(sdk.verify_report(bounded)[0], sdk.verify_report(bounded))

    def test_ast_rule_evaluation_is_bounded_and_deterministic(self) -> None:
        self.write("app.py", "eval(a)\nexec(b)\nprint(c)\n")
        pack = self.pack(self.call_rule())
        budget = sdk.RuleBudget(max_findings=1)
        first = sdk.evaluate(pack, self.root, budget=budget)
        second = sdk.evaluate(pack, self.root, budget=budget)
        self.assertEqual(first, second)
        self.assertEqual(len(first["findings"]), 1)
        self.assertIn("finding-budget-reached",
                      {row["reason"] for row in first["coverage"]["gaps"]})
        self.assertTrue(sdk.verify_report(first)[0])
        self.assertFalse(first["static_contract"]["target_code_executed"])

    def test_flow_rule_uses_same_snapshot_graph_and_nested_fixtures_do_not_cross_pollute(self) -> None:
        rule = {
            "id": "attestor41-tainted-eval", "title": "Tainted evaluation",
            "description": "Untrusted input reaches dynamic evaluation.",
            "severity": "CRITICAL", "language": "python",
            "remediation": "Remove the dynamic sink.",
            "match": {"kind": "flow-to-sink", "sink_in": ["eval"],
                      "cwe_in": ["CWE-95"]},
            "fixtures": {
                "positive": [{"path": "bad.py", "source":
                              "def f():\n    x=input()\n    eval(x)\n"}],
                "negative": [{"path": "good.py", "source":
                              "x=input()\ndef f():\n    x='safe'\n    eval(x)\n"},
                             {"path": "converted.py", "source":
                              "def f():\n    eval(int(input()))\n"}],
            },
        }
        pack = self.pack(rule)
        self.write("app.py", "def f():\n    x=input()\n    eval(x)\n")
        current = snapshot41.capture(self.root)
        graph = graph41.build(current)
        report = sdk.evaluate(pack, current, graph=graph)
        self.assertEqual(len(report["findings"]), 1)

        other_root = self.root / "other"
        other_root.mkdir()
        (other_root / "x.py").write_text("x=1\n", encoding="utf-8")
        other_graph = graph41.build(snapshot41.capture(other_root))
        refused = sdk.evaluate(pack, current, graph=other_graph)
        self.assertFalse(refused["findings"])
        self.assertIn("valid-same-snapshot-semantic-graph-required",
                      {row["reason"] for row in refused["coverage"]["gaps"]})

    def test_ast_fixture_and_target_node_budgets_fail_closed(self) -> None:
        rule = self.call_rule()
        rule["fixtures"]["positive"][0]["source"] = (
            "\n".join(f"v{i} = {i}" for i in range(80)) + "\neval(value)\n")
        sealed = self.pack(rule)
        with self.assertRaisesRegex(sdk.RulePackError, "AST node budget"):
            sdk.validate_pack(sealed, budget=sdk.RuleBudget(max_ast_nodes_per_file=100))

        self.write("huge.py", "\n".join(f"v{i}={i}" for i in range(80)))
        normal = self.pack(self.call_rule())
        report = sdk.evaluate(
            normal, self.root, budget=sdk.RuleBudget(max_ast_nodes_per_file=100))
        self.assertIn("parse-or-ast-budget-error",
                      {row["reason"] for row in report["coverage"]["gaps"]})

    def test_snapshot_coverage_gaps_propagate_and_tampering_is_detected(self) -> None:
        self.write("app.py", "print('safe')\n")
        self.write("node_modules/generated.py", "eval(x)\n")
        report = sdk.evaluate(self.pack(self.call_rule()), self.root)
        self.assertIn("snapshot-excluded-directory-policy",
                      {row["reason"] for row in report["coverage"]["gaps"]})
        report["findings"].append({"invented": True})
        self.assertFalse(sdk.verify_report(report)[0])

    def test_strict_json_and_report_verifier_reject_ambiguous_or_fake_evidence(self) -> None:
        with self.assertRaisesRegex(sdk.RulePackError, "duplicate"):
            sdk.load_pack_json(
                '{"schema":"first","schema":"second","rules":[]}')

        minimal = {"schema": sdk.REPORT_SCHEMA, "version": sdk.VERSION}
        minimal["report_sha256"] = sdk._sha(minimal)
        self.assertFalse(sdk.verify_report(minimal)[0])

        self.write("app.py", "eval(value)\n")
        malformed = sdk.evaluate(self.pack(self.call_rule()), self.root)
        malformed["findings"][0]["line"] = "1"
        malformed["report_sha256"] = sdk._sha({
            key: value for key, value in malformed.items()
            if key != "report_sha256"
        })
        valid, errors = sdk.verify_report(malformed)
        self.assertFalse(valid)
        self.assertTrue(any("finding" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
