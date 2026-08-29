#!/usr/bin/env python3
"""
Tests for detect.py. Runs with plain `python3 test_detector.py` (no pytest
needed) and is also discoverable by pytest/unittest.

The bundled corpus under ../c, ../cpp, ../haskell is the ground truth: each file
contains exactly one planted "almost no-one can find" bug. These tests assert the
detector finds every one of them, on the right line, and -- just as importantly --
does NOT fire on the corrected versions of the same patterns.
"""
import os
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import detect

CORPUS = detect.CORPUS

# (relative path, rule id, expected 1-indexed line)
EXPECTED = [
    ("c/01_unsigned_underflow.c",      "unsigned-underflow",     26),
    ("c/02_strict_aliasing.c",         "strict-aliasing",        38),
    ("c/03_signed_overflow_ub.c",      "signed-overflow-check",  30),
    ("c/04_sizeof_pointer.c",          "sizeof-pointer-arg",     28),
    ("cpp/01_map_operator_insert.cpp", "map-operator-insert",    32),
    ("cpp/02_object_slicing.cpp",      "object-slicing",         40),
    ("cpp/03_rangefor_copy.cpp",       "rangefor-copy",          29),
    ("cpp/04_vector_bool_proxy.cpp",   "vector-bool-proxy",      32),
    ("haskell/01_int_overflow.hs",     "hs-int-overflow",        30),
    ("haskell/02_foldl_space_leak.hs", "hs-lazy-foldl",          33),
    ("haskell/03_lazy_io.hs",          "hs-lazy-io",             37),
    ("haskell/04_laziness_masks_bug.hs", "hs-lazy-error-field",  41),
    # real-world corpus
    ("realworld/payments.py",          "hardcoded-secret",        7),
    ("realworld/payments.py",          "py-mutable-default",      11),
    ("realworld/payments.py",          "py-sql-injection",        19),
    ("realworld/payments.py",          "py-eq-none",              25),
    ("realworld/payments.py",          "py-eq-bool",              28),
    ("realworld/payments.py",          "py-bare-except",          33),
    ("realworld/payments.py",          "py-except-pass",          33),
    ("realworld/payments.py",          "py-is-literal",           39),
    ("realworld/upload.c",             "scanf-unbounded",         13),
    ("realworld/upload.c",             "unsafe-libc",             17),
    ("realworld/upload.c",             "command-exec",            21),
    ("realworld/upload.c",             "float-equality",          27),
    ("realworld/config.env",           "hardcoded-secret",         7),
    # security + JavaScript corpus
    ("realworld/insecure.py",          "weak-hash",               14),
    ("realworld/insecure.py",          "tls-verify-disabled",     19),
    ("realworld/insecure.py",          "py-requests-no-timeout",  19),
    ("realworld/insecure.py",          "py-tempfile-insecure",    24),
    ("realworld/insecure.py",          "py-yaml-load",            29),
    ("realworld/insecure.py",          "py-insecure-deserialize", 34),
    ("realworld/insecure.py",          "py-subprocess-shell",     39),
    ("realworld/insecure.py",          "dangerous-eval",          44),
    ("realworld/insecure.py",          "debug-enabled",           48),
    ("realworld/app.js",               "js-loose-equality",        6),
    ("realworld/app.js",               "js-innerhtml",            11),
    ("realworld/app.js",               "dangerous-eval",          16),
    ("realworld/app.js",               "tls-verify-disabled",     21),
    ("realworld/app.js",               "js-settimeout-string",    25),
    ("realworld/log.c",                "format-string",           11),
    ("realworld/dangle.c",             "c-return-local-address",  12),
    ("realworld/dangle.c",             "c-return-local-address",  19),
    ("realworld/dangle.c",             "c-strncpy-truncation",    25),
]

CLEAN_C = """
#include <string.h>
#include <limits.h>
#include <stddef.h>
static size_t remaining(size_t cap, size_t used) {
    if (used >= cap) return 0;
    return cap - used;
}
static int adds_overflow(int x) { return x > INT_MAX - 1; }
static void copy_msg(char *dst, const char *src) {
    memcpy(dst, src, strlen(src) + 1);
}
static void resize(char **p, size_t n) {
    char *tmp = realloc(*p, n);
    if (tmp) *p = tmp;
}
static char *clone_msg(const char *src) {
    char *out = malloc(strlen(src) + 1);
    if (out) memcpy(out, src, strlen(src) + 1);
    return out;
}
"""

CLEAN_CPP = """
#include <map>
#include <vector>
#include <memory>
#include <string>
struct Shape { virtual double area() const { return 0; } virtual ~Shape() = default; };
struct Circle : Shape { double area() const override { return 3.14; } };
void f() {
    std::map<std::string,int> m{{"a",1}};
    auto it = m.find("a");
    if (it != m.end() && it->second == 0) {}
    for (auto& [k, v] : m) v *= 3;
    std::vector<std::unique_ptr<Shape>> shapes;
    std::vector<bool> bits{false};
    bool b = bits[0];
    (void)b;
    std::string name = "attestor";
    std::string moved = std::move(name);
    name = "fresh";
    int *arr = new int[3];
    delete[] arr;
    std::string stable = "ok";
    (void)moved;
}
"""

CLEAN_HS = """
import Data.List (foldl')
import System.IO (readFile')
total :: Integer
total = product [1 .. 66]
strictSum :: Int
strictSum = foldl' (+) 0 [1 .. 100]
main :: IO ()
main = do
  c <- readFile' "x.txt"
  putStrLn c
"""

CLEAN_PY = """
import os
API_KEY = os.environ["API_KEY"]
def add_item(item, cart=None):
    cart = cart if cart is not None else []
    cart.append(item)
    return cart
def find_user(db, name):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchone()
def process(user, charge, log, do):
    if user is None:
        return
    if user.active:
        charge(user)
    try:
        do()
    except ValueError as e:
        log(e)
def classify(x):
    if x == 0:
        return "zero"
    return "nonzero"
"""


CLEAN_JS = """
function isSame(a, b) {
  return a === b;
}
function render(userInput) {
  document.getElementById("out").textContent = userInput;
}
const httpsOptions = { rejectUnauthorized: true };
const counter = 0;
let total = counter + 1;
async function saveAll(items) {
  await Promise.all(items.map(async (item) => save(item)));
}
function isReallyNaN(value) {
  return Number.isNaN(value);
}
function year(d) {
  return d.getFullYear();
}
"""


def scan_text(text, suffix, tmp_path):
    p = os.path.join(tmp_path, "snippet" + suffix)
    with open(p, "w") as fh:
        fh.write(text)
    return detect.scan_file(p)


class RuleWeaknessTaggingTests(unittest.TestCase):
    """Rules carry a weakness class so coverage can be computed, not guessed."""

    def test_every_mapped_rule_id_actually_exists(self):
        # A typo here would silently drop a rule out of coverage reporting.
        declared = {fn.rid for fn in detect.RULES}
        unknown = sorted(set(detect.RULE_CWE) - declared)
        self.assertEqual(unknown, [], "RULE_CWE names rules that do not exist")

    def test_every_cwe_value_is_well_formed(self):
        for rid, cwe in detect.RULE_CWE.items():
            with self.subTest(rule=rid):
                self.assertRegex(cwe, r"^CWE-\d+$")

    def test_tagged_rules_expose_the_class_on_the_rule_object(self):
        for fn in detect.RULES:
            with self.subTest(rule=fn.rid):
                self.assertEqual(fn.cwe, detect.RULE_CWE.get(fn.rid, ""))

    def test_the_security_rules_that_matter_are_tagged(self):
        expected = {
            "py-sql-injection": "CWE-89",
            "py-os-command-injection": "CWE-78",
            "dangerous-eval": "CWE-94",
            "hardcoded-secret": "CWE-798",
            "tls-verify-disabled": "CWE-295",
            "weak-hash": "CWE-327",
            "js-innerhtml": "CWE-79",
            "py-yaml-load": "CWE-502",
            "scanf-unbounded": "CWE-120",
        }
        actual = {fn.rid: fn.cwe for fn in detect.RULES if fn.rid in expected}
        self.assertEqual(actual, expected)

    def test_untagged_rules_report_an_empty_class_not_a_wrong_one(self):
        untagged = [fn.rid for fn in detect.RULES if not fn.cwe]
        self.assertTrue(untagged, "some rules have no honest weakness class")
        for rid in untagged:
            with self.subTest(rule=rid):
                self.assertNotIn(rid, detect.RULE_CWE)


class IndirectSpellingTests(unittest.TestCase):
    """The same defect reached through a name, an alias, or a reflective call.

    Every case here was a measured survivor of the mutation gauntlet: the rule
    matched its own canonical fixture and nothing else, so renaming the value
    was enough to walk straight past it.
    """

    def rules_for(self, source):
        # Both Python engines, the way harvest.scan_content pairs them: the
        # line rules live in detect, the value-flow checks live in deepscan.
        import deepscan
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(source)
            found = detect.scan_file(path, deep=True) + deepscan.scan_path(path)
            return {finding.rule for finding in found}

    def test_weak_hash_through_alias_import_and_reflection(self):
        cases = {
            "direct": "import hashlib\nd = hashlib.md5(b'x').hexdigest()\n",
            "module alias": "import hashlib as _h\nd = _h.md5(b'x').hexdigest()\n",
            "from-import": "from hashlib import md5\nd = md5(b'x').hexdigest()\n",
            "from-import as": "from hashlib import md5 as h\nd = h(b'x').hexdigest()\n",
            "getattr": "import hashlib\nd = getattr(hashlib, 'md5')(b'x')\n",
            "new()": "import hashlib\nd = hashlib.new('md5', b'x')\n",
        }
        for label, source in cases.items():
            with self.subTest(spelling=label):
                self.assertIn("weak-hash", self.rules_for(source))

    def test_strong_hash_is_not_flagged_through_the_same_spellings(self):
        cases = [
            "import hashlib\nd = hashlib.sha256(b'x').hexdigest()\n",
            "import hashlib as _h\nd = _h.sha256(b'x').hexdigest()\n",
            "from hashlib import sha256\nd = sha256(b'x').hexdigest()\n",
            "import hashlib\nd = hashlib.new('sha256', b'x')\n",
        ]
        for source in cases:
            with self.subTest(source=source.splitlines()[0]):
                self.assertNotIn("weak-hash", self.rules_for(source))

    def test_none_comparison_in_either_operand_order(self):
        for source in ("def f(x):\n    return x == None\n",
                       "def f(x):\n    return None == x\n",
                       "def f(x):\n    return x != None\n",
                       "def f(x):\n    return None != x\n"):
            with self.subTest(source=source.strip().splitlines()[-1]):
                self.assertIn("py-eq-none", self.rules_for(source))

    def test_identity_comparison_stays_clean(self):
        for source in ("def f(x):\n    return x is None\n",
                       "def f(x):\n    return None is x\n",
                       "def f(x):\n    return x is not None\n"):
            with self.subTest(source=source.strip().splitlines()[-1]):
                self.assertNotIn("py-eq-none", self.rules_for(source))

    def test_tls_verification_disabled_through_a_module_flag(self):
        source = ("import requests\n"
                  "_TLS_VERIFY = False\n"
                  "def go(u):\n"
                  "    return requests.get(u, verify=_TLS_VERIFY, timeout=5)\n")
        self.assertIn("tls-verify-disabled", self.rules_for(source))

    def test_module_flag_set_true_does_not_trip_the_tls_rule(self):
        source = ("import requests\n"
                  "_TLS_VERIFY = True\n"
                  "def go(u):\n"
                  "    return requests.get(u, verify=_TLS_VERIFY, timeout=5)\n")
        self.assertNotIn("tls-verify-disabled", self.rules_for(source))

    def test_shell_enabled_through_a_module_flag(self):
        source = ("import subprocess\n"
                  "_USE_SHELL = True\n"
                  "def go(cmd):\n"
                  "    return subprocess.run(cmd, shell=_USE_SHELL, timeout=5)\n")
        self.assertIn("py-subprocess-shell", self.rules_for(source))

    def test_shell_disabled_through_a_module_flag_stays_clean(self):
        source = ("import subprocess\n"
                  "_USE_SHELL = False\n"
                  "def go(cmd):\n"
                  "    return subprocess.run(cmd, shell=_USE_SHELL, timeout=5)\n")
        self.assertNotIn("py-subprocess-shell", self.rules_for(source))

    def test_debug_enabled_through_a_module_flag(self):
        source = ("_DEBUG_ON = True\n"
                  "def serve(app):\n"
                  "    app.run(debug=_DEBUG_ON)\n")
        self.assertIn("debug-enabled", self.rules_for(source))

    def test_debug_flag_set_false_stays_clean(self):
        source = ("_DEBUG_ON = False\n"
                  "def serve(app):\n"
                  "    app.run(debug=_DEBUG_ON)\n")
        self.assertNotIn("debug-enabled", self.rules_for(source))

    def test_unsafe_yaml_loader_reached_reflectively(self):
        source = "import yaml\ndef load(text):\n    return getattr(yaml, 'load')(text)\n"
        self.assertIn("py-yaml-load", self.rules_for(source))

    def test_safe_yaml_loader_stays_clean(self):
        for source in ("import yaml\nd = yaml.safe_load(text)\n",
                       "import yaml\nd = getattr(yaml, 'safe_load')(text)\n",
                       "import yaml\nd = yaml.load(text, Loader=yaml.SafeLoader)\n"):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertNotIn("py-yaml-load", self.rules_for(source))

    def test_os_system_command_injection_is_detected(self):
        for source in ("import os\ndef go(name):\n    os.system('ls ' + name)\n",
                       "import os\ndef go(name):\n    os.popen(f'ls {name}').read()\n",
                       "import os\ndef go(name):\n    os.system('ls %s' % name)\n"):
            with self.subTest(source=source.strip().splitlines()[-1]):
                self.assertIn("py-os-command-injection", self.rules_for(source))

    def test_constant_os_system_command_is_not_flagged(self):
        source = "import os\ndef go():\n    os.system('ls -la')\n"
        self.assertNotIn("py-os-command-injection", self.rules_for(source))

    def test_option_dict_carrying_verify_false_is_followed_to_the_call(self):
        source = ("import requests\n"
                  "def go(u):\n"
                  "    opts = {'verify': False}\n"
                  "    return requests.get(u, timeout=5, **opts)\n")
        self.assertIn("tls-verify-disabled", self.rules_for(source))

    def test_option_dict_carrying_shell_true_is_followed_to_the_call(self):
        source = ("import subprocess\n"
                  "def go(cmd):\n"
                  "    opts = {'shell': True}\n"
                  "    return subprocess.run(cmd, timeout=5, **opts)\n")
        self.assertIn("py-subprocess-shell", self.rules_for(source))

    def test_safe_option_dicts_are_left_alone(self):
        for source in ("import requests\ndef go(u):\n"
                       "    opts = {'verify': True}\n"
                       "    return requests.get(u, timeout=5, **opts)\n",
                       "import subprocess\ndef go(c):\n"
                       "    opts = {'shell': False}\n"
                       "    return subprocess.run(c, timeout=5, **opts)\n",
                       "import requests\ndef go(u):\n"
                       "    opts = {'headers': {}}\n"
                       "    return requests.get(u, timeout=5, **opts)\n"):
            with self.subTest(source=source.splitlines()[2].strip()):
                rules = self.rules_for(source)
                self.assertNotIn("tls-verify-disabled", rules)
                self.assertNotIn("py-subprocess-shell", rules)

    def test_query_built_then_executed_is_followed_across_statements(self):
        for build in ('sql = "SELECT * FROM t WHERE n=\'" + name + "\'"',
                      'sql = f"SELECT * FROM t WHERE n={name}"',
                      'sql = "SELECT * FROM t WHERE n=%s" % name',
                      'sql = "SELECT * FROM t WHERE n={}".format(name)'):
            source = "def q(db, name):\n    %s\n    db.execute(sql)\n" % build
            with self.subTest(build=build):
                self.assertIn("py-sql-injection", self.rules_for(source))

    def test_parameterised_and_constant_queries_stay_clean(self):
        for source in ('def q(db, name):\n'
                       '    sql = "SELECT * FROM t WHERE n=?"\n'
                       '    db.execute(sql, (name,))\n',
                       'def q(db, name):\n'
                       '    msg = "hello " + name\n'
                       '    db.execute(msg)\n'):
            with self.subTest(source=source.splitlines()[1].strip()):
                self.assertNotIn("py-sql-injection", self.rules_for(source))

    def test_value_flow_does_not_cross_a_reassignment_or_a_scope(self):
        reassigned = ('def q(db, name):\n'
                      '    sql = "SELECT * FROM t WHERE n=\'" + name + "\'"\n'
                      '    sql = "SELECT 1"\n'
                      '    db.execute(sql)\n')
        other_scope = ('def build(name):\n'
                       '    sql = "SELECT * FROM t WHERE n=\'" + name + "\'"\n'
                       '    return sql\n'
                       'def run(db, sql):\n'
                       '    db.execute(sql)\n')
        for label, source in (("reassigned", reassigned),
                              ("other scope", other_scope)):
            with self.subTest(case=label):
                self.assertNotIn("py-sql-injection", self.rules_for(source))

    def test_local_boolean_reaching_a_security_kwarg(self):
        cases = {
            "verify": ("import requests\ndef go(u):\n    check = False\n"
                       "    return requests.get(u, verify=check, timeout=5)\n",
                       "tls-verify-disabled"),
            "shell": ("import subprocess\ndef go(c):\n    use = True\n"
                      "    return subprocess.run(c, shell=use, timeout=5)\n",
                      "py-subprocess-shell"),
        }
        for label, (source, rule) in cases.items():
            with self.subTest(kwarg=label):
                self.assertIn(rule, self.rules_for(source))

    def test_local_boolean_with_the_safe_value_is_not_reported(self):
        source = ("import requests\ndef go(u):\n    check = True\n"
                  "    return requests.get(u, verify=check, timeout=5)\n")
        self.assertNotIn("tls-verify-disabled", self.rules_for(source))

    def test_class_constant_reached_through_self(self):
        source = ("import requests\n"
                  "class Client:\n"
                  "    VERIFY = False\n"
                  "    def go(self, u):\n"
                  "        return requests.get(u, verify=self.VERIFY, timeout=5)\n")
        self.assertIn("tls-verify-disabled", self.rules_for(source))

    def test_class_constant_with_the_safe_value_is_not_reported(self):
        source = ("import requests\n"
                  "class Client:\n"
                  "    VERIFY = True\n"
                  "    def go(self, u):\n"
                  "        return requests.get(u, verify=self.VERIFY, timeout=5)\n")
        self.assertNotIn("tls-verify-disabled", self.rules_for(source))

    def test_command_built_then_run_through_a_shell(self):
        for sink in ("os.system(cmd)", "os.popen(cmd).read()"):
            source = ("import os\ndef go(name):\n"
                      "    cmd = 'ls ' + name\n    %s\n" % sink)
            with self.subTest(sink=sink):
                self.assertIn("py-os-command-injection", self.rules_for(source))

    def test_constant_command_is_not_reported(self):
        source = "import os\ndef go():\n    cmd = 'ls -la'\n    os.system(cmd)\n"
        self.assertNotIn("py-os-command-injection", self.rules_for(source))

    def test_algorithm_named_by_a_variable(self):
        source = ("import hashlib\ndef d(x):\n    algo = 'md5'\n"
                  "    return hashlib.new(algo, x)\n")
        self.assertIn("weak-hash", self.rules_for(source))

    def test_strong_algorithm_named_by_a_variable_is_clean(self):
        source = ("import hashlib\ndef d(x):\n    algo = 'sha256'\n"
                  "    return hashlib.new(algo, x)\n")
        self.assertNotIn("weak-hash", self.rules_for(source))

    def test_a_conditionally_rebound_name_is_not_treated_as_constant(self):
        # Found against pip's vendored distlib: `hasher` is bound by tuple
        # unpacking in one branch and by a literal in the other, so it is not
        # a constant and must not be reported as one.
        source = ("import hashlib\n"
                  "def get(digest):\n"
                  "    if isinstance(digest, tuple):\n"
                  "        hasher, digest = digest\n"
                  "    else:\n"
                  "        hasher = 'md5'\n"
                  "    return getattr(hashlib, hasher)()\n")
        self.assertNotIn("weak-hash", self.rules_for(source))

    def test_every_binding_form_defeats_constant_folding(self):
        prelude = "import requests\ndef go(u, items):\n    check = False\n"
        rebinds = ["    for check in items:\n        pass\n",
                   "    check, other = items\n",
                   "    with open('f') as check:\n        pass\n",
                   "    check += 1\n"]
        for rebind in rebinds:
            source = (prelude + rebind
                      + "    return requests.get(u, verify=check, timeout=5)\n")
            with self.subTest(rebind=rebind.strip()):
                self.assertNotIn("tls-verify-disabled", self.rules_for(source))

    def test_use_before_the_assignment_is_not_reported(self):
        source = ("import requests\n"
                  "def go(u, opts):\n"
                  "    first = requests.get(u, timeout=5, **opts)\n"
                  "    opts = {'verify': False}\n"
                  "    return first\n")
        self.assertNotIn("tls-verify-disabled", self.rules_for(source))

    def test_indirect_spellings_are_not_matched_inside_strings(self):
        source = ('DOC = "use hashlib.md5 and verify=False here"\n'
                  'NOTE = "None == x is wrong"\n'
                  'value = 1\n')
        rules = self.rules_for(source)
        self.assertNotIn("weak-hash", rules)
        self.assertNotIn("tls-verify-disabled", rules)
        self.assertNotIn("py-eq-none", rules)


class DetectorTests(unittest.TestCase):
    def test_each_planted_bug_is_found_on_the_right_line(self):
        for rel, rule, line in EXPECTED:
            path = os.path.join(CORPUS, rel)
            findings = detect.scan_file(path)
            hits = [(f.rule, f.line) for f in findings]
            self.assertIn((rule, line), hits,
                          msg=f"{rel}: expected {rule} on line {line}, got {hits}")

    def test_corpus_self_test_passes(self):
        self.assertEqual(detect.self_test(), 0)

    def test_comment_stripper_keeps_block_comments_from_eating_the_file(self):
        # Regression: a multi-line /* */ header must not blank the whole file.
        code = detect.blank("/* a\n b */\nint x = 1;\n", "c")
        self.assertIn("int x = 1;", "\n".join(code))

    def test_string_escapes_never_collapse_source_lines(self):
        samples = {
            "c": 'const char *s = "first\\\nsecond";\nint x;\n',
            "python": 's = "first\\\nsecond"\nvalue = 1\n',
            "js": 'const s = "first\\\nsecond";\nconst value = 1;\n',
            "haskell": 's = "first\\\nsecond"\nvalue = 1\n',
        }
        for lang, source in samples.items():
            with self.subTest(lang=lang):
                self.assertEqual(len(detect.blank(source, lang)), source.count("\n") + 1)
        with tempfile.TemporaryDirectory() as directory:
            findings = scan_text(
                'const char *s = "first\\\nsecond";\ngets(buffer);\n', ".c", directory)
        self.assertIn(("unsafe-libc", 3), {(f.rule, f.line) for f in findings})

    def test_no_false_positives_on_clean_c(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan_text(CLEAN_C, ".c", d), [])

    def test_no_false_positives_on_clean_cpp(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan_text(CLEAN_CPP, ".cpp", d), [])

    def test_no_false_positives_on_clean_haskell(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan_text(CLEAN_HS, ".hs", d), [])

    def test_no_false_positives_on_clean_python(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan_text(CLEAN_PY, ".py", d), [])

    def test_no_false_positives_on_clean_js(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan_text(CLEAN_JS, ".js", d), [])

    def test_sarif_output_is_wellformed(self):
        findings = detect.scan_file(os.path.join(CORPUS, "realworld", "dangle.c"))
        self.assertTrue(findings)
        sarif = detect.to_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "AttestorVonLuneberg")
        self.assertEqual(len(run["results"]), len(findings))
        r0 = run["results"][0]
        self.assertIn(r0["level"], {"error", "warning", "note"})
        self.assertEqual(
            r0["locations"][0]["physicalLocation"]["region"]["startLine"],
            findings[0].line)

    def test_detects_empty_secret_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "import os\nSECRET_KEY = os.environ.get('SECRET_KEY', '')\n",
                ".py", d)
        self.assertIn("py-empty-secret-default", {f.rule for f in findings})

    def test_detects_subprocess_without_timeout(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd)\n",
                ".py", d)
        self.assertIn("py-subprocess-no-timeout", {f.rule for f in findings})

    def test_popen_is_not_falsely_told_to_accept_unsupported_timeout_keyword(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "import subprocess\nproc = subprocess.Popen(['tool'])\n",
                ".py", d)
        self.assertNotIn("py-subprocess-no-timeout", {f.rule for f in findings})

    def test_detects_client_secret_storage(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "localStorage.setItem('token', token);\n",
                ".js", d)
        self.assertIn("js-client-secret-storage", {f.rule for f in findings})


    def test_detects_realloc_leak(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "#include <stdlib.h>\nvoid grow(char *p, int n) { p = realloc(p, n); }\n",
                ".c", d)
        self.assertIn("c-realloc-leak", {f.rule for f in findings})

    def test_detects_memcmp_padding(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "#include <string.h>\nstruct S { char c; int x; };\nint eq(struct S a, struct S b) { return memcmp(&a, &b, sizeof a) == 0; }\n",
                ".c", d)
        self.assertIn("c-memcmp-padding", {f.rule for f in findings})

    def test_detects_use_after_move(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "#include <utility>\n#include <string>\nvoid f(std::string s) { auto t = std::move(s); if (s.size()) {} }\n",
                ".cpp", d)
        self.assertIn("cpp-use-after-move", {f.rule for f in findings})

    def test_detects_dict_fromkeys_mutable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "def buckets(keys):\n    return dict.fromkeys(keys, [])\n",
                ".py", d)
        self.assertIn("py-dict-fromkeys-mutable", {f.rule for f in findings})

    def test_detects_async_foreach_and_nan_compare(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "async function f(items) { items.forEach(async item => await save(item)); }\nif (value === NaN) {}\n",
                ".js", d)
        rules = {f.rule for f in findings}
        self.assertIn("js-async-foreach", rules)
        self.assertIn("js-nan-compare", rules)


    def test_detects_free_stack_and_malloc_strlen(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "#include <stdlib.h>\n#include <string.h>\nvoid f(char *s) { int x; free(&x); char *p = malloc(strlen(s)); strcpy(p, s); }\n",
                ".c", d)
        rules = {f.rule for f in findings}
        self.assertIn("c-free-stack-address", rules)
        self.assertIn("c-malloc-strlen-no-nul", rules)

    def test_detects_cpp_lifetime_and_delete_mismatch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "#include <string>\nconst char *bad() {\n    std::string s = \"x\";\n    return s.c_str();\n}\nvoid g() {\n    int *p = new int[4];\n    delete p;\n}\n",
                ".cpp", d)
        rules = {f.rule for f in findings}
        self.assertIn("cpp-return-cstr-local", rules)
        self.assertIn("cpp-delete-array-mismatch", rules)

    def test_detects_random_security(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "import random\ntoken = random.random()\n",
                ".py", d)
        self.assertIn("py-random-security", {f.rule for f in findings})

    def test_detects_js_date_and_prototype_pollution(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "const y = d.getYear();\nobj['__proto__'] = {admin: true};\n",
                ".js", d)
        rules = {f.rule for f in findings}
        self.assertIn("js-date-getyear", rules)
        self.assertIn("js-prototype-pollution", rules)

    def test_detects_haskell_partial_function(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text(
                "first xs = head xs\n",
                ".hs", d)
        self.assertIn("hs-partial-function", {f.rule for f in findings})

    def test_literal_dependent_rules_see_values_but_not_comments(self):
        with tempfile.TemporaryDirectory() as d:
            js = scan_text(
                "// createHash('sha1') is an insecure example\n"
                "const docs = \"crypto.createHash('sha1')\";\n"
                "const digest = crypto.createHash('md5').update(data).digest();\n",
                ".js", d)
            py_path = os.path.join(d, "server.py")
            with open(py_path, "w", encoding="utf-8") as fh:
                fh.write("# app.run(host='0.0.0.0') is only documentation\n"
                         "app.run(host='0.0.0.0')\n")
            py = detect.scan_file(py_path, deep=True)
        self.assertEqual([f.line for f in js if f.rule == "weak-hash"], [3])
        self.assertEqual([f.line for f in py if f.rule == "py-bind-all-interfaces"], [2])

    def test_scanf_pattern_in_comment_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as d:
            findings = scan_text('/* never use scanf("%s", buf); */\nint ok(void){return 1;}\n',
                                 ".c", d)
        self.assertNotIn("scanf-unbounded", {f.rule for f in findings})

    def test_markdown_and_extensionless_files_are_secret_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            paths = [os.path.join(d, "notes.md"), os.path.join(d, "secrets")]
            for path in paths:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("api_key: sk-live-1234567890abcdef\n")
            for path in paths:
                self.assertIn("hardcoded-secret", {f.rule for f in detect.scan_file(path)})

    def test_extensionless_python_shebang_uses_python_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "worker")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\nimport hashlib, os\n"
                             "API_KEY = os.environ['API_KEY']\n"
                             "digest = hashlib.md5(b'data').hexdigest()\n")
            found = {finding.rule for finding in detect.scan_file(path)}
        self.assertIn("weak-hash", found)
        self.assertNotIn("hardcoded-secret", found)

    def test_binary_extensionless_file_is_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "blob")
            with open(path, "wb") as fh:
                fh.write(b"\x00api_key=sk-live-1234567890")
            self.assertEqual(detect.collect_paths([d]), [])
            err, out = io.StringIO(), io.StringIO()
            with redirect_stderr(err), redirect_stdout(out):
                rc = detect.main([path, "--no-color"])
        self.assertEqual(rc, 2)
        self.assertIn("binary", err.getvalue())


class CollectPathsTests(unittest.TestCase):
    def test_nonexistent_path_warns_instead_of_silent_clean(self):
        # found by the smoke test: a typo'd path used to yield "clean." + exit 0
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            files = detect.collect_paths(["/no/such/path.py"])
        self.assertEqual(files, [])
        self.assertIn("does not exist", buf.getvalue())

    def test_cli_missing_and_unsupported_inputs_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as d:
            unsupported = os.path.join(d, "archive.zip")
            with open(unsupported, "wb") as fh:
                fh.write(b"PK")
            for path, message in ((os.path.join(d, "missing.py"), "does not exist"),
                                  (unsupported, "unsupported input type")):
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = detect.main([path, "--no-color"])
                self.assertEqual(rc, 2)
                self.assertIn(message, err.getvalue())


class PointerLifetimeTests(unittest.TestCase):
    """Use-after-free and NULL dereference, checked in both directions.

    These rules span several lines of one function, so the risk is not that
    they stay silent -- it is that they fire on the corrected code too, which
    reads as a finding but carries no information.  Every case below therefore
    pairs the flaw with the fix Juliet ships beside it, and asserts the fix is
    clean.  The shapes are taken from the CWE-416 and CWE-476 families in the
    SARD corpus rather than invented, because a rule written against an
    invented fixture matches the fixture and nothing else.
    """

    def rules_for(self, body, lang="c"):
        source = "#include <stdlib.h>\nvoid f(void)\n{\n%s\n}\n" % body
        return {finding.rule
                for finding in detect.scan_source(source, "t." + lang, lang,
                                                  deep=True)}

    def assert_flaw_only(self, rule, flawed, fixed, lang="c"):
        self.assertIn(rule, self.rules_for(flawed, lang),
                      "%s missed the flaw" % rule)
        self.assertNotIn(rule, self.rules_for(fixed, lang),
                         "%s also fires on the corrected code" % rule)

    def test_use_after_free_reports_the_flaw_and_spares_the_fix(self):
        self.assert_flaw_only(
            "c-use-after-free",
            "    char * data = (char *)malloc(100);\n"
            "    free(data);\n"
            "    printLine(data);",
            "    char * data = (char *)malloc(100);\n"
            "    printLine(data);\n"
            "    free(data);")

    def test_use_after_delete_including_the_array_form(self):
        for release in ("delete data;", "delete [] data;"):
            with self.subTest(release=release):
                self.assert_flaw_only(
                    "c-use-after-free",
                    "    Widget * data = new Widget();\n"
                    "    %s\n    printIntLine(data->intOne);" % release,
                    "    Widget * data = new Widget();\n"
                    "    printIntLine(data->intOne);\n    %s" % release,
                    lang="cpp")

    def test_a_freed_pointer_given_a_new_value_is_live_again(self):
        self.assertNotIn("c-use-after-free", self.rules_for(
            "    char * data = (char *)malloc(100);\n"
            "    free(data);\n"
            "    data = (char *)malloc(100);\n"
            "    printLine(data);"))

    def test_a_redeclared_name_is_a_different_pointer(self):
        # Brace counting can merge two function bodies; a fresh declaration
        # must not inherit the previous pointer's state.
        self.assertNotIn("c-use-after-free", self.rules_for(
            "    char * data = (char *)malloc(100);\n"
            "    free(data);\n"
            "  }\n  void g(void) {\n"
            "    char * data = (char *)malloc(100);\n"
            "    printLine(data);"))

    def test_null_dereference_is_reported_but_a_guarded_one_is_not(self):
        self.assert_flaw_only(
            "c-null-deref",
            "    twoIntsStruct * data;\n"
            "    data = NULL;\n"
            "    printIntLine(data->intOne);",
            "    twoIntsStruct * data;\n"
            "    data = NULL;\n"
            "    if (data != NULL)\n    {\n"
            "        printIntLine(data->intOne);\n    }")

    def test_a_pointer_given_a_real_object_is_not_null(self):
        self.assertNotIn("c-null-deref", self.rules_for(
            "    twoIntsStruct * data;\n"
            "    twoIntsStruct tmp;\n"
            "    data = NULL;\n"
            "    data = &tmp;\n"
            "    printIntLine(data->intOne);"))

    def test_bitwise_null_guard_is_reported_and_the_logical_one_is_not(self):
        self.assert_flaw_only(
            "c-null-guard-bitwise",
            "    if ((data != NULL) & (data->intOne == 5))\n"
            "    {\n        printLine(\"ok\");\n    }",
            "    if ((data != NULL) && (data->intOne == 5))\n"
            "    {\n        printLine(\"ok\");\n    }")

    def test_dereference_inside_the_branch_that_proved_the_pointer_null(self):
        self.assert_flaw_only(
            "c-deref-after-null-check",
            "    int * intPointer = NULL;\n"
            "    if (intPointer == NULL)\n    {\n"
            "        printIntLine(*intPointer);\n    }",
            "    int * intPointer = NULL;\n"
            "    if (intPointer != NULL)\n    {\n"
            "        printIntLine(*intPointer);\n    }")

    def test_a_null_branch_that_assigns_first_is_not_a_flaw(self):
        self.assertNotIn("c-deref-after-null-check", self.rules_for(
            "    int * intPointer = NULL;\n"
            "    if (intPointer == NULL)\n    {\n"
            "        intPointer = (int *)malloc(sizeof(int));\n"
            "        printIntLine(*intPointer);\n    }"))

    def test_a_null_check_placed_after_the_dereference(self):
        self.assert_flaw_only(
            "c-null-check-after-deref",
            "    int * intPointer = (int *)malloc(sizeof(int));\n"
            "    printIntLine(*intPointer);\n"
            "    if (intPointer != NULL)\n    {\n"
            "        printLine(\"late\");\n    }",
            "    int * intPointer = (int *)malloc(sizeof(int));\n"
            "    if (intPointer != NULL)\n    {\n"
            "        printIntLine(*intPointer);\n    }")

    def test_a_declaration_does_not_count_as_a_dereference(self):
        # `char * data;` names a pointer, it does not read one, so a guard
        # below it is early rather than late.
        self.assertNotIn("c-null-check-after-deref", self.rules_for(
            "    char * data;\n"
            "    data = (char *)malloc(100);\n"
            "    if (data != NULL)\n    {\n"
            "        printLine(data);\n    }"))

    def test_a_reassigned_cursor_is_not_a_check_after_deref(self):
        # `p = strchr(s, x); if (p) *p = 0; p = strchr(s, y); if (p) ...` --
        # each `if (p)` guards the pointer strchr just returned, not the one
        # written through earlier.  The reassignment makes it a fresh value, so
        # the later test is a real guard, not a check after a dereference.
        # This fired on 28 of Juliet's corrected CWE-761 variants before the fix.
        self.assertNotIn("c-null-check-after-deref", self.rules_for(
            "    char * replace;\n"
            "    replace = strchr(data, 13);\n"
            "    if (replace) { *replace = 0; }\n"
            "    replace = strchr(data, 10);\n"
            "    if (replace) { *replace = 0; }"))

    def test_a_genuine_check_after_deref_still_fires_after_the_cursor_fix(self):
        # The reassignment reset must not blind the rule to the real defect.
        self.assertIn("c-null-check-after-deref", self.rules_for(
            "    int * p = (int *)malloc(4);\n"
            "    printIntLine(*p);\n"
            "    if (p != NULL)\n    {\n"
            "        printLine(\"late\");\n    }"))

    def test_every_lifetime_rule_carries_its_cwe(self):
        for name in ("c-use-after-free", "c-null-deref", "c-null-guard-bitwise",
                     "c-deref-after-null-check", "c-null-check-after-deref",
                     "c-stack-buffer-overflow", "c-struct-member-overrun"):
            with self.subTest(rule=name):
                self.assertIn(name, detect.RULE_CWE)
                self.assertRegex(detect.RULE_CWE[name], r"^CWE-\d+$")


class OutputShapeTests(unittest.TestCase):
    """The report has to read like someone chose what to say.

    The shape this replaced printed every finding as an identical five-line
    block, sorted by path, with the same confidence/exploitability/autofix
    trailer on all of them. Uniform emphasis is the same as none.
    """

    def findings_for(self, path):
        return detect.scan_file(os.path.join(CORPUS, path), deep=True)

    def test_severity_bands_are_worst_first(self):
        text = detect.fmt_human(self.findings_for("realworld/insecure.py"),
                                use_color=False)
        positions = [text.find(level) for level in ("HIGH", "MEDIUM")]
        self.assertNotIn(-1, positions)
        self.assertLess(positions[0], positions[1])

    def test_a_band_states_how_many_it_holds(self):
        findings = self.findings_for("realworld/insecure.py")
        high = sum(1 for f in findings if f.severity == "HIGH")
        self.assertIn("HIGH  (%d)" % high,
                      detect.fmt_human(findings, use_color=False))

    def test_the_trailer_appears_only_when_it_says_something(self):
        text = detect.fmt_human(self.findings_for("realworld/insecure.py"),
                                use_color=False)
        # Never repeated on every finding the way the old trailer was.
        self.assertLess(text.count("- autofixable"), text.count("fix:"))
        self.assertNotIn("safe-autofix: no", text)

    def test_the_output_is_ascii_so_every_terminal_can_show_it(self):
        # A middle dot rendered as a replacement character on this console,
        # and Attestor ships to Raspberry Pi terminals too.
        text = detect.fmt_human(self.findings_for("realworld/insecure.py"),
                                use_color=False)
        text += detect.fmt_summary(self.findings_for("realworld/insecure.py"),
                                   1, "LOW")
        text.encode("ascii")

    def test_long_messages_are_wrapped_not_run_off_the_edge(self):
        text = detect.fmt_human(self.findings_for("realworld/insecure.py"),
                                use_color=False)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 90, line)

    def test_the_summary_gives_the_shape_and_the_next_command(self):
        findings = self.findings_for("realworld/insecure.py")
        summary = detect.fmt_summary(findings, 1, "LOW")
        self.assertIn("finding", summary)
        self.assertIn("high", summary)
        self.assertIn("planner41.py", summary)

    def test_a_clean_scan_says_so_plainly(self):
        summary = detect.fmt_summary([], 3, "LOW")
        self.assertIn("nothing found", summary)
        self.assertIn("3 files", summary)

    def test_a_raised_floor_is_disclosed(self):
        findings = self.findings_for("realworld/insecure.py")
        self.assertIn("severity floor HIGH",
                      detect.fmt_summary(findings, 1, "HIGH"))
        self.assertNotIn("severity floor", detect.fmt_summary(findings, 1, "LOW"))


class RouteAccessControlTests(unittest.TestCase):
    """Routes with no access control -- CWE-862 and CWE-306.

    These two are ranks 4 and 21 of the Top 25 and Juliet has no case for
    either, so the shapes came from pairs generated to a specification by a
    local model.  The model wrote code; it was never asked to judge anything,
    and its "fixed" bodies were unreliable enough that only the shape was
    used.  The numbers that matter are therefore the negatives below: a rule
    built on the *absence* of a check has to stay quiet on every legitimate
    reason a route might not have one.
    """

    def rules_for(self, source):
        return {finding.rule
                for finding in detect.scan_source(source, "app.py", "python",
                                                  deep=True)}

    FLASK_LOOKUP = ("from flask import Flask, jsonify\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/order/<int:order_id>')\n"
                    "def get_order(order_id):\n"
                    "    order = db.orders.get(order_id)\n"
                    "    return jsonify(order)\n")

    ADMIN_ROUTE = ("from flask import Flask, jsonify\n"
                   "app = Flask(__name__)\n"
                   "@app.route('/admin/delete_user', methods=['POST'])\n"
                   "def delete_user():\n"
                   "    db.remove_user(1)\n"
                   "    return jsonify({'status': 'deleted'})\n")

    def test_a_record_fetched_by_caller_supplied_id_is_reported(self):
        self.assertIn("py-route-missing-authorization",
                      self.rules_for(self.FLASK_LOOKUP))

    def test_a_suffixed_lookup_call_counts_too(self):
        # `db.get_note(note_id)` is as much a lookup as `db.get(note_id)`;
        # an exact-name list missed half the generated shapes.
        source = self.FLASK_LOOKUP.replace("db.orders.get(order_id)",
                                           "db.get_order_record(order_id)")
        self.assertIn("py-route-missing-authorization", self.rules_for(source))

    def test_a_privileged_route_without_authentication_is_reported(self):
        self.assertIn("py-route-missing-authentication",
                      self.rules_for(self.ADMIN_ROUTE))

    def test_an_ownership_check_silences_it(self):
        guarded = self.FLASK_LOOKUP.replace(
            "    return jsonify(order)",
            "    if order.owner != session.get('user'):\n"
            "        return jsonify({}), 403\n"
            "    return jsonify(order)")
        self.assertNotIn("py-route-missing-authorization",
                         self.rules_for(guarded))

    def test_a_login_required_decorator_silences_it(self):
        guarded = self.ADMIN_ROUTE.replace(
            "def delete_user():", "@login_required\ndef delete_user():")
        self.assertNotIn("py-route-missing-authentication",
                         self.rules_for(guarded))

    def test_a_fastapi_dependency_silences_it(self):
        source = ("from fastapi import FastAPI, Depends\n"
                  "app = FastAPI()\n"
                  "@app.get('/admin/export')\n"
                  "def export(user=Depends(current_user)):\n"
                  "    return db.dump()\n")
        self.assertNotIn("py-route-missing-authentication",
                         self.rules_for(source))

    def test_an_unprivileged_public_route_is_left_alone(self):
        # Health checks and landing pages have no check because they need
        # none; reporting them would make the rule unusable.
        for path, name in (("/health", "health"), ("/", "index"),
                           ("/about", "about")):
            with self.subTest(path=path):
                source = ("from flask import Flask\napp = Flask(__name__)\n"
                          "@app.route('%s')\ndef %s():\n    return 'ok'\n"
                          % (path, name))
                self.assertEqual(self.rules_for(source) & {
                    "py-route-missing-authentication",
                    "py-route-missing-authorization"}, set())

    def test_the_login_route_itself_is_not_flagged(self):
        source = ("from flask import Flask, request\napp = Flask(__name__)\n"
                  "@app.route('/login', methods=['POST'])\n"
                  "def login():\n    return check(request.form)\n")
        self.assertEqual(self.rules_for(source) & {
            "py-route-missing-authentication",
            "py-route-missing-authorization"}, set())

    def test_a_route_that_already_returns_403_is_left_alone(self):
        guarded = self.ADMIN_ROUTE.replace(
            "    db.remove_user(1)",
            "    if not ok():\n        return jsonify({}), 403\n"
            "    db.remove_user(1)")
        self.assertNotIn("py-route-missing-authentication",
                         self.rules_for(guarded))

    UPLOAD = ("from flask import Flask, request\n"
              "app = Flask(__name__)\n"
              "@app.route('/upload', methods=['POST'])\n"
              "def upload():\n"
              "    f = request.files['file']\n"
              "    f.save('uploads/' + f.filename)\n"
              "    return 'ok'\n")

    BODY_READ = ("from flask import Flask, request\n"
                 "app = Flask(__name__)\n"
                 "@app.route('/data', methods=['POST'])\n"
                 "def data():\n"
                 "    return request.get_data().decode('utf-8')\n")

    def test_an_upload_named_by_the_caller_is_reported(self):
        self.assertIn("py-upload-unrestricted", self.rules_for(self.UPLOAD))

    def test_secure_filename_silences_it(self):
        guarded = self.UPLOAD.replace("'uploads/' + f.filename",
                                      "'uploads/' + secure_filename(f.filename)")
        self.assertNotIn("py-upload-unrestricted", self.rules_for(guarded))

    def test_an_extension_allow_list_silences_it(self):
        guarded = self.UPLOAD.replace(
            "    f.save(",
            "    if not f.filename.endswith(('.txt', '.pdf')):\n"
            "        return 'no', 400\n    f.save(")
        self.assertNotIn("py-upload-unrestricted", self.rules_for(guarded))

    def test_reading_the_whole_body_is_reported(self):
        self.assertIn("py-unbounded-read", self.rules_for(self.BODY_READ))

    def test_a_size_ceiling_silences_it(self):
        capped = self.BODY_READ.replace(
            "    return request.get_data()",
            "    if request.content_length > MAX_SIZE:\n"
            "        return '', 413\n    return request.get_data()")
        self.assertNotIn("py-unbounded-read", self.rules_for(capped))

    def test_a_bare_read_of_a_local_file_is_not_a_request_read(self):
        # `open("VERSION").read()` in a route is a config file. The first
        # version of this rule reported it, which would have made the rule
        # unusable on any real service.
        source = ("from flask import Flask\napp = Flask(__name__)\n"
                  "@app.route('/version')\ndef version():\n"
                  "    return open('VERSION').read()\n")
        self.assertNotIn("py-unbounded-read", self.rules_for(source))

    def test_both_rules_carry_their_top_25_class(self):
        self.assertEqual(detect.RULE_CWE["py-route-missing-authorization"],
                         "CWE-862")
        self.assertEqual(detect.RULE_CWE["py-route-missing-authentication"],
                         "CWE-306")

    def test_attestor_s_own_python_is_not_flagged(self):
        # A rule keyed on absence must not fire on code that has no routes.
        with open(os.path.join(CORPUS, "detector", "harvest.py"),
                  encoding="utf-8", errors="replace") as handle:
            source = handle.read()
        self.assertEqual(self.rules_for(source) & {
            "py-route-missing-authentication",
            "py-route-missing-authorization"}, set())


class AllocatorPairingTests(unittest.TestCase):
    """What allocated a pointer decides what may release it.

    CWE-762 and CWE-590, ~5,000 Juliet cases that no rule fired on even once.
    The ordering test below is the one that matters: the first version built
    the allocation map for a whole span before looking for releases, so the
    last allocation in the file decided how an earlier release was judged, and
    it reported 160 false positives out of 172.
    """

    def rules_for(self, body, lang="cpp"):
        source = "#include <stdlib.h>\nvoid f(void)\n{\n%s\n}\n" % body
        return {finding.rule
                for finding in detect.scan_source(source, "t." + lang, lang,
                                                  deep=True)}

    def test_malloc_released_with_delete_is_reported(self):
        self.assertIn("c-mismatched-free", self.rules_for(
            "    char * p = (char *)malloc(100);\n    delete [] p;"))

    def test_new_array_released_with_free_is_reported(self):
        self.assertIn("c-mismatched-free", self.rules_for(
            "    char * p = new char[100];\n    free(p);"))

    def test_new_released_with_delete_array_is_reported(self):
        self.assertIn("c-mismatched-free", self.rules_for(
            "    Widget * p = new Widget;\n    delete [] p;"))

    def test_matching_pairs_are_left_alone(self):
        for body in ("    char * p = (char *)malloc(100);\n    free(p);",
                     "    char * p = new char[100];\n    delete [] p;",
                     "    Widget * p = new Widget;\n    delete p;"):
            with self.subTest(body=body.split(chr(10))[0].strip()):
                self.assertNotIn("c-mismatched-free", self.rules_for(body))

    def test_a_later_allocation_does_not_judge_an_earlier_release(self):
        # Two functions that brace counting merges into one span: the first
        # pairs new[]/delete[] correctly, the second uses malloc/free. Neither
        # is a defect, and reading the map as a whole made both look like one.
        source = ("    char * p = new char[100];\n    delete [] p;\n"
                  "  }\n  void g(void) {\n"
                  "    char * p = (char *)malloc(100);\n    free(p);")
        self.assertNotIn("c-mismatched-free", self.rules_for(source))

    def test_freeing_a_stack_array_is_reported(self):
        self.assertIn("c-free-not-on-heap", self.rules_for(
            "    char buf[100];\n    free(buf);", lang="c"))

    def test_freeing_alloca_memory_is_reported(self):
        self.assertIn("c-free-not-on-heap", self.rules_for(
            "    char * p = (char *)ALLOCA(100);\n    free(p);", lang="c"))

    def test_freeing_real_heap_memory_is_not_reported(self):
        self.assertNotIn("c-free-not-on-heap", self.rules_for(
            "    char * p = (char *)malloc(100);\n    free(p);", lang="c"))

    def test_an_unknown_pointer_is_left_alone(self):
        # A pointer whose origin is not visible could be anything; guessing
        # would report every free of a parameter.
        self.assertEqual(self.rules_for("    free(incoming);", lang="c") & {
            "c-mismatched-free", "c-free-not-on-heap"}, set())

    def test_both_rules_carry_their_cwe(self):
        self.assertEqual(detect.RULE_CWE["c-mismatched-free"], "CWE-762")
        self.assertEqual(detect.RULE_CWE["c-free-not-on-heap"], "CWE-590")


class BufferOverflowTests(unittest.TestCase):
    """Copies that exceed the destination, and the ones that only look like it.

    The hard half is the negatives.  Comparing the two buffers' *capacities*
    catches Juliet's flawed cases and also reports the corrected ones, because
    `strcpy` copies to the terminator and the fix works by shortening the
    contents rather than the buffer.  Every case below therefore pins a
    capacity/content distinction that a plausible version of this rule gets
    wrong.
    """

    def rules_for(self, body, lang="c"):
        source = "#include <string.h>\nvoid f(void)\n{\n%s\n}\n" % body
        return {finding.rule
                for finding in detect.scan_source(source, "t." + lang, lang,
                                                  deep=True)}

    def test_memcpy_longer_than_the_destination_is_reported(self):
        self.assertIn("c-heap-buffer-overflow", self.rules_for(
            "    char * data = (char *)malloc(50*sizeof(char));\n"
            "    char source[100];\n"
            "    memcpy(data, source, 100*sizeof(char));"))

    def test_a_memcpy_that_fits_is_not_reported(self):
        self.assertNotIn("c-heap-buffer-overflow", self.rules_for(
            "    char * data = (char *)malloc(100*sizeof(char));\n"
            "    char source[100];\n"
            "    memcpy(data, source, 100*sizeof(char));"))

    def test_strcpy_of_contents_too_long_for_the_destination(self):
        self.assertIn("c-stack-buffer-overflow", self.rules_for(
            "    char data[50];\n"
            "    char source[100];\n"
            "    memset(source, 'C', 99);\n"
            "    strcpy(data, source);"))

    def test_a_big_source_holding_a_short_string_is_not_an_overflow(self):
        # 100-byte buffer, 49 characters in it, 50-byte destination: this is
        # how Juliet writes the *fix*, and a capacity comparison calls it a bug.
        self.assertNotIn("c-stack-buffer-overflow", self.rules_for(
            "    char data[50];\n"
            "    char source[100];\n"
            "    memset(source, 'C', 49);\n"
            "    strcpy(data, source);"))

    def test_strcat_counts_what_the_destination_already_holds(self):
        self.assertIn("c-stack-buffer-overflow", self.rules_for(
            "    char dest[50] = \"\";\n"
            "    char source[100];\n"
            "    memset(source, 'C', 99);\n"
            "    strcat(dest, source);"))

    def test_an_alias_carries_the_buffer_it_points_at(self):
        self.assertIn("c-heap-buffer-overflow", self.rules_for(
            "    char * data;\n"
            "    char * small = (char *)malloc(10*sizeof(char));\n"
            "    data = small;\n"
            "    char source[100];\n"
            "    memcpy(data, source, 100*sizeof(char));"))

    def test_an_unknown_size_is_not_treated_as_a_small_one(self):
        for size in ("n", "len*sizeof(char)", "strlen(source)"):
            with self.subTest(size=size):
                self.assertNotIn("c-heap-buffer-overflow", self.rules_for(
                    "    char * data = (char *)malloc(%s);\n"
                    "    char source[100];\n"
                    "    memcpy(data, source, 100*sizeof(char));" % size))

    def test_sizeof_the_whole_struct_used_to_fill_one_member(self):
        self.assertIn("c-struct-member-overrun", self.rules_for(
            "    charVoid structCharVoid;\n"
            "    memcpy(structCharVoid.charFirst, SRC_STR, "
            "sizeof(structCharVoid));"))

    def test_sizeof_the_member_itself_is_correct(self):
        self.assertNotIn("c-struct-member-overrun", self.rules_for(
            "    charVoid structCharVoid;\n"
            "    memcpy(structCharVoid.charFirst, SRC_STR, "
            "sizeof(structCharVoid.charFirst));"))

    def scan_unit(self, source, lang="c"):
        return {finding.rule
                for finding in detect.scan_source(source, "t." + lang, lang,
                                                  deep=True)}

    # -- capacity crossing a call, which is how half of Juliet is shaped ---- #
    CROSS_FILE = """#define SRC_STRING "AAAAAAAAAA"
void sink(char * data);
void caller(void)
{
    char * data;
    char * small = (char *)ALLOCA((10)*sizeof(char));
    data = small;
    sink(data);
}
void sink(char * data)
{
    char source[10+1] = SRC_STRING;
    strcpy(data, source);
}
"""

    def test_a_buffer_size_reaches_the_function_it_is_passed_to(self):
        # Neither function contains the defect: `caller` picks a ten-byte
        # buffer, `sink` copies ten characters plus a terminator into it.
        self.assertIn("c-stack-buffer-overflow", self.scan_unit(self.CROSS_FILE))

    # Juliet's 52/53/54 families hand the buffer along a chain of three, four
    # and five files, every link but the first a function forwarding a
    # parameter it was given. One hop of propagation caught none of them.
    CHAINED = """#define SRC_STRING "AAAAAAAAAA"
void hop_one(char * data);
void hop_two(char * data);
void sink(char * data);
void caller(void)
{
    char * data;
    char * small = (char *)ALLOCA((10)*sizeof(char));
    data = small;
    hop_one(data);
}
void hop_one(char * data)
{
    hop_two(data);
}
void hop_two(char * data)
{
    sink(data);
}
void sink(char * data)
{
    char source[10+1] = SRC_STRING;
    strcpy(data, source);
}
"""

    def test_a_buffer_size_survives_a_chain_of_calls(self):
        self.assertIn("c-stack-buffer-overflow", self.scan_unit(self.CHAINED))

    def test_the_same_chain_with_room_to_spare_stays_silent(self):
        roomy = self.CHAINED.replace("ALLOCA((10)*", "ALLOCA((40)*")
        self.assertNotIn("c-stack-buffer-overflow", self.scan_unit(roomy))

    def test_a_chain_whose_callers_disagree_is_left_unknown(self):
        # Two entry points hand `hop_one` different buffers, so nothing about
        # its parameter is known and guessing the smaller one would invent an
        # overflow in the caller that is fine.
        ambiguous = self.CHAINED.replace(
            "void hop_one(char * data)\n{",
            "void other(void)\n{\n"
            "    char * big = (char *)ALLOCA((99)*sizeof(char));\n"
            "    hop_one(big);\n}\n"
            "void hop_one(char * data)\n{")
        self.assertNotIn("c-stack-buffer-overflow", self.scan_unit(ambiguous))

    def test_propagation_is_bounded(self):
        self.assertLessEqual(detect.MAX_PROPAGATION_ROUNDS, 16)
        self.assertGreaterEqual(detect.MAX_PROPAGATION_ROUNDS, 5)

    def test_the_same_shape_with_room_to_spare_is_not_reported(self):
        roomy = self.CROSS_FILE.replace("ALLOCA((10)*", "ALLOCA((20)*")
        self.assertNotIn("c-stack-buffer-overflow", self.scan_unit(roomy))

    def test_a_string_macro_is_resolved_not_assumed(self):
        # Assuming a macro fills its array would invent an overflow here: the
        # buffer is 11 and holds 10, which fits exactly.
        fits = self.CROSS_FILE.replace("ALLOCA((10)*", "ALLOCA((11)*")
        self.assertNotIn("c-stack-buffer-overflow", self.scan_unit(fits))

    def test_a_parameter_reached_with_two_sizes_is_left_unknown(self):
        # Two callers disagree, so nothing is known about the parameter and
        # guessing the smaller one would report a defect that may not exist.
        ambiguous = self.CROSS_FILE.replace(
            "void sink(char * data)\n{",
            "void other(void)\n{\n"
            "    char * big = (char *)ALLOCA((99)*sizeof(char));\n"
            "    sink(big);\n}\n"
            "void sink(char * data)\n{")
        self.assertNotIn("c-stack-buffer-overflow", self.scan_unit(ambiguous))

    def test_function_headers_and_parameters_are_recovered(self):
        defs = detect._c_function_defs(self.CROSS_FILE.splitlines())
        found = {name: params for name, params, _, _ in defs}
        self.assertIn("caller", found)
        self.assertEqual(found.get("sink"), ["data"])

    def test_string_macros_are_collected_with_their_lengths(self):
        macros = detect._string_macros(self.CROSS_FILE.splitlines())
        self.assertEqual(macros.get("SRC_STRING"), 10)

    def test_the_arithmetic_evaluator_refuses_what_it_cannot_prove(self):
        self.assertEqual(detect._const_value("10+1"), 11)
        self.assertEqual(detect._const_value("(10)*2"), 20)
        self.assertEqual(detect._const_value("100-1"), 99)
        for unknown in ("n", "len+1", "sizeof(x)", "10/2", "", "0x10"):
            with self.subTest(text=unknown):
                self.assertIsNone(detect._const_value(unknown))


class ReturnInsideFinally(unittest.TestCase):
    """The replacement for a rule that could not have worked.

    `advanced_rules`' `adv-py-return-finally` used the pattern `^\\s*return\\b`
    with the message "return inside finally can suppress exceptions". The
    message names a real defect; the pattern matches every return statement in
    Python and never mentions `finally`. It produced 1,211 findings on Attestor's
    own source, all of them wrong, and nothing in this suite noticed -- which
    is why the negative cases below matter more than the positive one.
    """

    def hits(self, source):
        return [f for f in detect.scan_source(source, "t.py", "python",
                                              deep=True)
                if f.rule == "py-return-in-finally"]

    def test_a_return_inside_finally_is_reported(self):
        self.assertEqual(len(self.hits(
            "def f():\n"
            "    try:\n"
            "        risky()\n"
            "    finally:\n"
            "        return 1\n")), 1)

    def test_break_and_continue_count_too(self):
        # Same defect: the in-flight exception is discarded either way.
        for word in ("break", "continue"):
            with self.subTest(statement=word):
                self.assertEqual(len(self.hits(
                    "def f():\n"
                    "    for i in x:\n"
                    "        try:\n"
                    "            risky()\n"
                    "        finally:\n"
                    "            %s\n" % word)), 1)

    def test_a_return_after_the_finally_block_is_not(self):
        self.assertEqual(self.hits(
            "def f():\n"
            "    try:\n"
            "        risky()\n"
            "    finally:\n"
            "        cleanup()\n"
            "    return 1\n"), [])

    def test_ordinary_returns_are_not_reported(self):
        """The 1,211-finding case, reduced to one test.

        If this ever fails, the rule has regressed to matching any return and
        the tier carrying it is producing volume, not evidence.
        """
        self.assertEqual(self.hits(
            "def g():\n"
            "    return 1\n"
            "\n"
            "def h():\n"
            "    for i in x:\n"
            "        if i:\n"
            "            continue\n"
            "    return 2\n"), [])

    def test_a_later_function_does_not_inherit_the_block(self):
        self.assertEqual(self.hits(
            "def f():\n"
            "    try:\n"
            "        risky()\n"
            "    finally:\n"
            "        cleanup()\n"
            "\n"
            "def other():\n"
            "    return 3\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
