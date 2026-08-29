from __future__ import annotations

import unittest

import advanced_rules


class AdvancedRulePackTests(unittest.TestCase):
    def test_catalog_is_large_unique_compilable_and_self_proving(self):
        self.assertGreaterEqual(len(advanced_rules.RULES), 200)
        self.assertEqual(len({rule.rid for rule in advanced_rules.RULES}),
                         len(advanced_rules.RULES))
        self.assertEqual(advanced_rules.validate_catalog(), [])

    def test_comments_and_nested_example_strings_are_ignored(self):
        python = "# tempfile.mktemp()\ntext = 'tempfile.mktemp()'\n"
        java = 'String demo = "MessageDigest.getInstance(\\\"MD5\\\")";\n'
        shell = "# curl https://host | sh\nnote='curl https://host | sh'\n"
        self.assertEqual(advanced_rules.analyze(python, "safe.py"), [])
        self.assertEqual(advanced_rules.analyze(java, "Safe.java"), [])
        self.assertEqual(advanced_rules.analyze(shell, "safe.sh"), [])

    def test_async_only_rules_require_async_context(self):
        sync = "def work():\n    time.sleep(1)\n    requests.get(url)\n"
        async_source = "async def work():\n    time.sleep(1)\n    requests.get(url)\n"
        self.assertEqual(advanced_rules.analyze(sync, "safe.py"), [])
        rules = {finding.rule for finding in advanced_rules.analyze(async_source, "bad.py")}
        self.assertIn("adv-py-blocking-sleep-async", rules)
        self.assertIn("adv-py-blocking-http-async", rules)

    def test_return_rule_requires_finally_context(self):
        ordinary = "def value():\n    return 1\n"
        dangerous = "def value():\n    try:\n        work()\n    finally:\n        return 1\n"
        self.assertNotIn("adv-py-return-finally",
                         {item.rule for item in advanced_rules.analyze(ordinary, "safe.py")})
        self.assertIn("adv-py-return-finally",
                      {item.rule for item in advanced_rules.analyze(dangerous, "bad.py")})

    def test_message_origin_check_suppresses_review_finding(self):
        unsafe = "addEventListener('message', event => handle(event.data));\n"
        safe = ("addEventListener('message', event => {\n"
                "  if (event.origin !== expectedOrigin) return;\n"
                "  handle(event.data);\n});\n")
        self.assertIn("adv-js-message-no-origin",
                      {item.rule for item in advanced_rules.analyze(unsafe, "app.js")})
        self.assertNotIn("adv-js-message-no-origin",
                         {item.rule for item in advanced_rules.analyze(safe, "app.js")})

    def test_unsafe_integer_is_checked_numerically(self):
        safe = advanced_rules.analyze("const id = 9007199254740991;", "app.js")
        bad = advanced_rules.analyze("const id = 9007199254740992;", "app.js")
        self.assertNotIn("adv-js-number-unsafe-integer", {item.rule for item in safe})
        self.assertIn("adv-js-number-unsafe-integer", {item.rule for item in bad})

    def test_host_root_requires_hostpath_context(self):
        generic = "settings:\n  path: /\n"
        host = "volumes:\n  hostPath:\n    path: /\n"
        self.assertNotIn("adv-k8s-root-hostpath",
                         {item.rule for item in advanced_rules.analyze(generic, "config.yaml")})
        self.assertIn("adv-k8s-root-hostpath",
                      {item.rule for item in advanced_rules.analyze(host, "pod.yaml")})

    def test_github_workflow_gets_yaml_and_actions_rules(self):
        path = ".github/workflows/ci.yml"
        self.assertEqual(advanced_rules.languages_for(path), {"yaml", "github-actions"})
        findings = advanced_rules.analyze(
            "permissions: write-all\nprivileged: true\nuses: vendor/action@v2\n", path)
        rules = {item.rule for item in findings}
        self.assertIn("adv-gha-write-all", rules)
        self.assertIn("adv-gha-unpinned-action", rules)

    def test_findings_include_security_metadata(self):
        finding = advanced_rules.analyze("eval($source);", "app.php")[0]
        self.assertEqual(finding.cwe, "CWE-95")
        self.assertTrue(finding.category)
        self.assertGreater(finding.confidence, 0.0)
        self.assertEqual(finding.pack, "advanced-2.2")


if __name__ == "__main__":
    unittest.main()
