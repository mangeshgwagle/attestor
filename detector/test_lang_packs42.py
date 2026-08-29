#!/usr/bin/env python3
"""Go, Rust and C# rule packs: every rule fires, and clean code stays clean.

Two assertions per rule, not one. A rule that only proves it fires on a
vulnerable fixture is indistinguishable from a rule that fires on everything,
and a scanner people stop trusting is worse than one that stays quiet -- so
each pack is also run against a fixed version of the same file and must report
nothing at all.

The clean fixtures are deliberately the *same programs*, rewritten safely,
rather than unrelated snippets. An empty file would pass the negative case
without proving the rule discriminates.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect  # noqa: E402
import language_coverage42  # noqa: E402


GO_VULNERABLE = '''package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
)

func handle(db *sql.DB, name string, arg string) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	digest := md5.New()
	cmd := exec.Command("sh", "-c", "ls "+arg)
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE n='%s'", name))
	client := &http.Client{}
	sessionToken := rand.Intn(999999)
	_, _, _, _, _ = cfg, digest, cmd, client, sessionToken
}
'''

GO_CLEAN = '''package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"os/exec"
	"time"
)

func handle(db *sql.DB, name string, arg string) {
	digest := sha256.New()
	cmd := exec.Command("ls", arg)
	db.Query("SELECT * FROM t WHERE n=$1", name)
	client := &http.Client{Timeout: 10 * time.Second}
	buf := make([]byte, 32)
	rand.Read(buf)
	sessionToken := hex.EncodeToString(buf)
	_, _, _, _ = digest, cmd, client, sessionToken
}
'''

RUST_VULNERABLE = '''use std::process::Command;

fn handle(id: &str) {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
    let mut digest = Md5::new();
    let child = Command::new("sh").arg(format!("ls {}", id));
    conn.query(&format!("SELECT * FROM t WHERE id={}", id), &[]);
    let bits: u64 = unsafe { std::mem::transmute(3.0f64) };
    unsafe { raw_call(); }
}
'''

RUST_CLEAN = '''use std::process::Command;

fn handle(id: &str) {
    let client = reqwest::Client::builder().build();
    let mut digest = Sha256::new();
    let child = Command::new("ls").arg(id);
    conn.query("SELECT * FROM t WHERE id = $1", &[&id]);
}
'''

CSHARP_VULNERABLE = '''using System;

public class Handler {
    public void Run(string name, SqlConnection conn) {
        var cmd = new SqlCommand($"SELECT * FROM t WHERE n='{name}'", conn);
        Process.Start("cmd.exe", "/c dir " + name);
        var digest = MD5.Create();
        ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
        var formatter = new BinaryFormatter();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        var passwordSalt = new Random();
    }
}
'''

CSHARP_CLEAN = '''using System;

public class Handler {
    public void Run(string name, SqlConnection conn) {
        var cmd = new SqlCommand("SELECT * FROM t WHERE n=@n", conn);
        cmd.Parameters.AddWithValue("@n", name);
        var info = new ProcessStartInfo("cmd.exe");
        info.ArgumentList.Add("/c");
        info.ArgumentList.Add("dir");
        info.ArgumentList.Add(name);
        var digest = SHA256.Create();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
        var passwordSalt = RandomNumberGenerator.GetBytes(16);
    }
}
'''

# Only the rules this pack adds to `detect.RULES`. The fixtures also contain
# defects that `multilang.py` and `advanced_rules.py` report -- weak hashes,
# InsecureSkipVerify, BinaryFormatter, transmute -- and those are deliberately
# not restated here: this pack does not define them, and asserting them would
# be testing another registry through the wrong door.
EXPECTED = {
    "go": (GO_VULNERABLE, GO_CLEAN, {
        "go-command-injection", "go-http-no-timeout"}),
    "rust": (RUST_VULNERABLE, RUST_CLEAN, {
        "rust-command-injection"}),
    "csharp": (CSHARP_VULNERABLE, CSHARP_CLEAN, {
        "cs-sql-injection", "cs-command-injection", "cs-weak-hash",
        "cs-cert-validation-disabled", "cs-xxe", "cs-weak-random"}),
}


class LanguageDetection(unittest.TestCase):
    def test_the_new_extensions_are_real_languages(self):
        """They were `text` until rules existed; the rules exist now."""
        for path, expected in ((".go", "go"), (".rs", "rust"), (".cs", "csharp")):
            self.assertEqual(detect.language_for("x" + path), expected)

    def test_coverage_counts_the_new_languages(self):
        counts = language_coverage42.rule_counts()
        for language in ("go", "rust", "csharp"):
            self.assertGreater(counts.get(language, 0), 0, language)


class RulePacks(unittest.TestCase):
    def test_every_expected_rule_fires_on_the_vulnerable_fixture(self):
        for language, (vulnerable, _clean, expected) in EXPECTED.items():
            with self.subTest(language=language):
                found = {row.rule for row
                         in detect.scan_source(vulnerable, "v", language, deep=False)}
                self.assertEqual(expected - found, set(),
                                 "rules did not fire: %s" % sorted(expected - found))

    def test_the_clean_fixture_reports_nothing(self):
        """The same program written safely must be silent, not merely quieter."""
        for language, (_vulnerable, clean, _expected) in EXPECTED.items():
            with self.subTest(language=language):
                rows = detect.scan_source(clean, "c", language, deep=False)
                self.assertEqual(
                    [], rows,
                    "false positives: %s" % sorted({row.rule for row in rows}))

    def test_findings_carry_a_line_inside_the_file(self):
        for language, (vulnerable, _clean, _expected) in EXPECTED.items():
            with self.subTest(language=language):
                limit = len(vulnerable.splitlines())
                for row in detect.scan_source(vulnerable, "v", language, deep=False):
                    self.assertTrue(1 <= row.line <= limit, row)

    def test_a_comment_or_string_mention_is_not_evidence(self):
        """Masking is the point: talking about a defect is not committing one."""
        samples = {
            "go": 'package main\n// InsecureSkipVerify: true is forbidden here\n'
                  'var doc = "md5.New() must not be used"\n',
            "rust": '// danger_accept_invalid_certs(true) is banned\n'
                    'let note = "Md5::new() is forbidden";\n',
            "csharp": '// new BinaryFormatter() is banned\n'
                      'var note = "MD5.Create() is forbidden";\n',
        }
        for language, source in samples.items():
            with self.subTest(language=language):
                rows = detect.scan_source(source, "n", language, deep=False)
                self.assertEqual(
                    [], rows,
                    "matched inside a comment or literal: %s"
                    % sorted({row.rule for row in rows}))


class CweMapping(unittest.TestCase):
    def test_security_rules_declare_a_weakness_class(self):
        required = set().union(*(expected for _v, _c, expected in EXPECTED.values()))
        for rid in sorted(required):
            with self.subTest(rule=rid):
                self.assertRegex(detect.RULE_CWE.get(rid, ""), r"^CWE-\d+$")

    def test_judgement_rules_declare_no_weakness_class(self):
        """A panic on the error path has no honest single weakness class."""
        self.assertEqual("", detect.RULE_CWE.get("rust-unwrap-panic", ""))


class NoDuplicateIdentifiers(unittest.TestCase):
    def test_this_pack_does_not_restate_a_multilang_rule(self):
        """One identifier from two registries is two findings for one defect.

        `rust-unsafe-block` and `rust-transmute` were defined in both while
        this pack was being written, which is exactly the collision this
        guards against.
        """
        import multilang
        elsewhere = set()
        for rules in multilang.RULES.values():
            elsewhere.update(row[0] for row in rules)
        mine = {fn.rid for fn in detect.RULES
                if set(getattr(fn, "langs", ())) & {"go", "rust", "csharp"}}
        self.assertEqual(set(), mine & elsewhere)

    def test_detect_registers_each_identifier_once(self):
        import collections
        counts = collections.Counter(fn.rid for fn in detect.RULES)
        self.assertEqual([], [rid for rid, n in counts.items() if n > 1])


class SecretContext(unittest.TestCase):
    def test_compound_identifiers_are_split_before_matching(self):
        for name in ("sessionToken", "password_salt", "apiKey", "PrivateKey"):
            self.assertRegex(detect._split_identifiers(name),
                             detect.SECRET_CONTEXT.pattern)

    def test_an_unrelated_word_containing_a_keyword_is_not_a_match(self):
        for name in ("asphaltCount", "sessionless_flag" ):
            self.assertNotRegex(detect._split_identifiers(name).lower(),
                                r"\b(?:salt)\b")


if __name__ == "__main__":
    unittest.main()
