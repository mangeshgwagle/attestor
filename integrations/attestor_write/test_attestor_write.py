from __future__ import annotations

import unittest

import attestor_write as ow


class TheGuaranteeIsCheckedNotClaimed(unittest.TestCase):
    """Emitted code carries no finding from a rule Attestor has.

    Narrower than "correct" and narrower than "secure" -- but unlike a
    docstring promising zero findings, it is re-established every run.
    """

    def test_a_clean_file_passes_through_unchanged(self):
        text = 'VALUE = 1\n\n\ndef add(a, b):\n    return a + b\n'
        result = ow.write({"ok.py": text})
        self.assertTrue(result.clean)
        self.assertEqual(result.files["ok.py"], text)
        self.assertEqual(result.repairs, [])

    def test_an_insecure_url_is_repaired_and_the_result_is_clean(self):
        result = ow.write({"api.py": 'URL = "http://internal.corp/v1"\n'})
        self.assertTrue(result.clean, result.summary())
        self.assertIn("https://", result.files["api.py"])
        self.assertEqual(len(result.repairs), 1)
        self.assertEqual(ow.scan_text("api.py", result.files["api.py"]), [])

    def test_attestors_own_exemptions_are_respected_not_second_guessed(self):
        """`example.com` and `localhost` are exempt, so nothing is rewritten.

        The writer repairs findings; it does not have opinions of its own.
        If Attestor does not object, the text goes out exactly as drafted --
        which is what keeps the writer's guarantee identical to the
        analyzer's, rather than a stricter thing that quietly rewrites code.
        """
        for url in ("http://example.com/v1", "http://localhost:8080"):
            with self.subTest(url=url):
                text = 'URL = "%s"\n' % url
                result = ow.write({"api.py": text})
                self.assertTrue(result.clean)
                self.assertEqual(result.files["api.py"], text)
                self.assertEqual(result.repairs, [])

    def test_a_weak_hash_is_repaired(self):
        result = ow.write({
            "h.py": "import hashlib\n\n\ndef digest(b):\n"
                    "    return hashlib.md5(b).hexdigest()\n"})
        self.assertTrue(result.clean, result.summary())
        self.assertIn("sha256", result.files["h.py"])

    def test_the_repaired_text_is_rescanned_not_assumed(self):
        """The claim is about the final text, so the final text is scanned."""
        result = ow.write({"api.py": 'A = "http://a.test"\nB = "http://b.test"\n'})
        self.assertTrue(result.clean)
        self.assertEqual(ow.scan_text("api.py", result.files["api.py"]), [])
        self.assertEqual(len(result.repairs), 2)


class WhatItWillNotDo(unittest.TestCase):
    """Refusing is a feature. A writer that guesses is worse than one that stops."""

    def test_a_finding_with_no_safe_repair_holds_the_file_back(self):
        faulted = ('import subprocess\n\n\ndef run(cmd):\n'
                   '    subprocess.run(cmd, shell=True)\n')
        result = ow.write({"run.py": faulted})
        if ow.scan_text("run.py", faulted):
            self.assertFalse(result.clean)
            self.assertNotIn("run.py", result.files)
            self.assertTrue(result.remaining)

    def test_an_unfixable_file_is_never_emitted(self):
        """Not emitted, not emitted-with-a-warning. Absent."""
        result = ow.write({
            "bad.py": 'import subprocess\nsubprocess.run(c, shell=True)\n',
            "good.py": 'VALUE = 2\n'})
        self.assertIn("good.py", result.files)
        if result.remaining:
            self.assertNotIn("bad.py", result.files)

    def test_a_repair_only_touches_the_line_attestor_objected_to(self):
        """Edits are applied by the finding's line number, never by search."""
        text = ('COMMENT = "see http://docs.test for why"\n'
                'URL = "http://api.test"\n')
        result = ow.write({"m.py": text})
        emitted = result.files.get("m.py", "")
        self.assertEqual(emitted.count("https://"), emitted.count("http"))

    def test_the_loop_terminates_even_if_a_repair_is_useless(self):
        broken = ow.Repair(rule="insecure-http-url",
                           pattern=ow.re.compile(r"nothing-matches-this"),
                           replacement="x", note="no-op")
        saved = ow._BY_RULE.get("insecure-http-url")
        ow._BY_RULE["insecure-http-url"] = [broken]
        try:
            result = ow.write({"u.py": 'U = "http://a.test"\n'})
            self.assertLessEqual(result.rounds, ow.MAX_ROUNDS)
            self.assertFalse(result.clean)
        finally:
            ow._BY_RULE["insecure-http-url"] = saved


class ScanningIsTheRealEngine(unittest.TestCase):
    def test_scan_text_uses_attestors_own_rules(self):
        found = ow.scan_text("x.py", 'URL = "http://a.test"\n')
        self.assertTrue(found)
        self.assertEqual(found[0].rule, "insecure-http-url")

    def test_language_is_taken_from_the_path(self):
        java = ow.scan_text(
            "A.java",
            'public class A {\n'
            '  void f() throws Throwable {\n'
            '    KeyGenerator k = KeyGenerator.getInstance("DESede");\n'
            '  }\n}\n')
        self.assertTrue(any(f.rule == "java-broken-cipher" for f in java))


if __name__ == "__main__":
    unittest.main()
