#!/usr/bin/env python3
"""Tests for migrate42.py — Code migration engine."""
import os
import tempfile
import unittest

from migrate42 import (
    Language, MigrationCategory, Confidence, MigrationEngine,
    MigrationMatch, MigrationReport, MigrationRule,
    list_rules, rules_for_language, get_rule, scan,
    LANG_EXT_MAP, VERSION, _REGISTRY,
)


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "4.2")

    def test_registry_populated(self):
        self.assertGreater(len(_REGISTRY), 20)

    def test_lang_ext_map(self):
        self.assertEqual(LANG_EXT_MAP[".py"], Language.PYTHON)
        self.assertEqual(LANG_EXT_MAP[".js"], Language.JAVASCRIPT)
        self.assertEqual(LANG_EXT_MAP[".java"], Language.JAVA)


class TestRegistry(unittest.TestCase):
    def test_list_rules(self):
        rules = list_rules()
        self.assertGreater(len(rules), 20)

    def test_get_rule(self):
        r = get_rule("py-print-func")
        self.assertIsNotNone(r)
        self.assertEqual(r.language, Language.PYTHON)

    def test_get_rule_missing(self):
        self.assertIsNone(get_rule("nonexistent-rule"))

    def test_rules_for_python(self):
        rules = rules_for_language(Language.PYTHON)
        self.assertGreater(len(rules), 8)
        for r in rules:
            self.assertIn(r.language, (Language.PYTHON, Language.GENERAL))

    def test_rules_for_javascript(self):
        rules = rules_for_language(Language.JAVASCRIPT)
        self.assertGreater(len(rules), 5)

    def test_rules_for_java(self):
        rules = rules_for_language(Language.JAVA)
        self.assertGreater(len(rules), 3)

    def test_all_rules_have_required_fields(self):
        for rule in list_rules():
            self.assertTrue(rule.rule_id)
            self.assertTrue(rule.name)
            self.assertIsInstance(rule.language, Language)
            self.assertIsInstance(rule.category, MigrationCategory)
            self.assertTrue(rule.description)
            self.assertIsNotNone(rule.detector)


# =========================================================================== #
#  PYTHON MIGRATION TESTS                                                      #
# =========================================================================== #

class TestPyPrintFunc(unittest.TestCase):
    def test_simple_print(self):
        engine = MigrationEngine()
        matches = engine.scan_line('print "hello"', Language.PYTHON)
        self.assertEqual(len(matches), 1)
        self.assertIn("print(", matches[0].replacement)

    def test_print_with_args(self):
        engine = MigrationEngine()
        matches = engine.scan_line('print "x =", x', Language.PYTHON)
        self.assertEqual(len(matches), 1)
        self.assertIn("print(", matches[0].replacement)

    def test_print_function_ignored(self):
        engine = MigrationEngine()
        matches = engine.scan_line('print("hello")', Language.PYTHON)
        print_matches = [m for m in matches if m.rule.rule_id == "py-print-func"]
        self.assertEqual(len(print_matches), 0)

    def test_generates_test_code(self):
        engine = MigrationEngine()
        matches = engine.scan_line('print "test"', Language.PYTHON)
        self.assertGreater(len(matches[0].test_code), 0)
        self.assertIn("unittest", matches[0].test_code)


class TestPyFstring(unittest.TestCase):
    def test_simple_format(self):
        engine = MigrationEngine()
        matches = engine.scan_line('x = "hello %s" % name', Language.PYTHON)
        fstr = [m for m in matches if m.rule.rule_id == "py-fstring"]
        self.assertEqual(len(fstr), 1)
        self.assertIn("f\"", fstr[0].replacement)

    def test_multiple_args(self):
        engine = MigrationEngine()
        matches = engine.scan_line('x = "%s is %d" % (name, age)', Language.PYTHON)
        fstr = [m for m in matches if m.rule.rule_id == "py-fstring"]
        self.assertEqual(len(fstr), 1)


class TestPyPathlib(unittest.TestCase):
    def test_os_path_join(self):
        engine = MigrationEngine()
        matches = engine.scan_line('p = os.path.join(a, b)', Language.PYTHON)
        pathlib = [m for m in matches if m.rule.rule_id == "py-pathlib"]
        self.assertEqual(len(pathlib), 1)
        self.assertIn("Path", pathlib[0].replacement)

    def test_os_path_exists(self):
        engine = MigrationEngine()
        matches = engine.scan_line('if os.path.exists(f):', Language.PYTHON)
        pathlib = [m for m in matches if m.rule.rule_id == "py-pathlib"]
        self.assertEqual(len(pathlib), 1)


class TestPyDictIn(unittest.TestCase):
    def test_has_key(self):
        engine = MigrationEngine()
        matches = engine.scan_line('if d.has_key("x"):', Language.PYTHON)
        dk = [m for m in matches if m.rule.rule_id == "py-dict-in"]
        self.assertEqual(len(dk), 1)
        self.assertIn('"x" in d', dk[0].replacement)


class TestPySuper(unittest.TestCase):
    def test_old_super(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '        super(MyClass, self).__init__()', Language.PYTHON)
        s = [m for m in matches if m.rule.rule_id == "py-super"]
        self.assertEqual(len(s), 1)
        self.assertIn("super().__init__", s[0].replacement)


class TestPyExceptAs(unittest.TestCase):
    def test_old_except(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    except ValueError, e:', Language.PYTHON)
        ea = [m for m in matches if m.rule.rule_id == "py-except-as"]
        self.assertEqual(len(ea), 1)
        self.assertIn("except ValueError as e:", ea[0].replacement)


class TestPyRaise(unittest.TestCase):
    def test_old_raise(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    raise ValueError, "bad value"', Language.PYTHON)
        r = [m for m in matches if m.rule.rule_id == "py-raise"]
        self.assertEqual(len(r), 1)
        self.assertIn('raise ValueError("bad value")', r[0].replacement)


class TestPyUnionPipe(unittest.TestCase):
    def test_optional(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'def f(x: Optional[str]) -> None:', Language.PYTHON)
        u = [m for m in matches if m.rule.rule_id == "py-union-pipe"]
        self.assertEqual(len(u), 1)
        self.assertIn("str | None", u[0].replacement)


class TestPyTypeAnnot(unittest.TestCase):
    def test_type_comment(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    items = []  # type: List[int]', Language.PYTHON)
        ta = [m for m in matches if m.rule.rule_id == "py-type-annot"]
        self.assertEqual(len(ta), 1)
        self.assertIn("items: List[int] = []", ta[0].replacement)


class TestPyEnumerate(unittest.TestCase):
    def test_range_len(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    for i in range(len(items)):', Language.PYTHON)
        en = [m for m in matches if m.rule.rule_id == "py-enumerate"]
        self.assertEqual(len(en), 1)
        self.assertIn("enumerate(items)", en[0].replacement)
        self.assertIn("item", en[0].replacement)


class TestPyWithOpen(unittest.TestCase):
    def test_bare_open(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    f = open("data.txt")', Language.PYTHON)
        wo = [m for m in matches if m.rule.rule_id == "py-with-open"]
        self.assertEqual(len(wo), 1)
        self.assertIn("with open(", wo[0].replacement)


# =========================================================================== #
#  JAVASCRIPT MIGRATION TESTS                                                  #
# =========================================================================== #

class TestJsLetConst(unittest.TestCase):
    def test_var_to_const(self):
        engine = MigrationEngine()
        matches = engine.scan_line('var x = 5;', Language.JAVASCRIPT)
        lc = [m for m in matches if m.rule.rule_id == "js-let-const"]
        self.assertEqual(len(lc), 1)
        self.assertIn("const x", lc[0].replacement)


class TestJsEsmImport(unittest.TestCase):
    def test_require_to_import(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'const fs = require("fs");', Language.JAVASCRIPT)
        esm = [m for m in matches if m.rule.rule_id == "js-esm-import"]
        self.assertEqual(len(esm), 1)
        self.assertIn('import fs from "fs"', esm[0].replacement)

    def test_destructured_require(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'const { readFile } = require("fs");', Language.JAVASCRIPT)
        esm = [m for m in matches if m.rule.rule_id == "js-esm-named"]
        self.assertEqual(len(esm), 1)
        self.assertIn('import { readFile }', esm[0].replacement)


class TestJsEsmExport(unittest.TestCase):
    def test_module_exports(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'module.exports = MyClass;', Language.JAVASCRIPT)
        ex = [m for m in matches if m.rule.rule_id == "js-esm-export"]
        self.assertEqual(len(ex), 1)
        self.assertIn("export default MyClass", ex[0].replacement)


class TestJsArrow(unittest.TestCase):
    def test_anon_function(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'arr.map(function(x) { return x * 2; })', Language.JAVASCRIPT)
        ar = [m for m in matches if m.rule.rule_id == "js-arrow"]
        self.assertEqual(len(ar), 1)
        self.assertIn("(x) =>", ar[0].replacement)

    def test_named_function_ignored(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'function doStuff(x) {', Language.JAVASCRIPT)
        ar = [m for m in matches if m.rule.rule_id == "js-arrow"]
        self.assertEqual(len(ar), 0)


class TestJsTemplateLit(unittest.TestCase):
    def test_string_concat(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'var msg = "Hello " + name + "!";', Language.JAVASCRIPT)
        tl = [m for m in matches if m.rule.rule_id == "js-template-lit"]
        self.assertEqual(len(tl), 1)
        self.assertIn("${name}", tl[0].replacement)


class TestJsStrictEq(unittest.TestCase):
    def test_loose_equality(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'if (x == 5) {', Language.JAVASCRIPT)
        se = [m for m in matches if m.rule.rule_id == "js-strict-eq"]
        self.assertEqual(len(se), 1)
        self.assertIn("===", se[0].replacement)

    def test_null_check_ignored(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'if (x == null) {', Language.JAVASCRIPT)
        se = [m for m in matches if m.rule.rule_id == "js-strict-eq"]
        self.assertEqual(len(se), 0)


class TestJsAsyncAwait(unittest.TestCase):
    def test_then_chain(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            'fetch(url).then(function(res) {', Language.JAVASCRIPT)
        aa = [m for m in matches if m.rule.rule_id == "js-async-await"]
        self.assertEqual(len(aa), 1)
        self.assertIn("await", aa[0].replacement)


# =========================================================================== #
#  JAVA MIGRATION TESTS                                                        #
# =========================================================================== #

class TestJavaDiamond(unittest.TestCase):
    def test_raw_arraylist(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    List<String> list = new ArrayList();', Language.JAVA)
        d = [m for m in matches if m.rule.rule_id == "java-diamond"]
        self.assertEqual(len(d), 1)
        self.assertIn("ArrayList<>()", d[0].replacement)

    def test_already_parameterized(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    List<String> list = new ArrayList<String>();', Language.JAVA)
        d = [m for m in matches if m.rule.rule_id == "java-diamond"]
        self.assertEqual(len(d), 0)


class TestJavaLambda(unittest.TestCase):
    def test_anon_runnable(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    Runnable r = new Runnable() {', Language.JAVA)
        lm = [m for m in matches if m.rule.rule_id == "java-lambda"]
        self.assertEqual(len(lm), 1)
        self.assertIn("lambda", lm[0].replacement)


class TestJavaOptional(unittest.TestCase):
    def test_null_check(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    if (value != null) {', Language.JAVA)
        op = [m for m in matches if m.rule.rule_id == "java-optional"]
        self.assertEqual(len(op), 1)
        self.assertIn("Optional", op[0].replacement)


# =========================================================================== #
#  CSS MIGRATION TESTS                                                         #
# =========================================================================== #

class TestCssVendorPrefix(unittest.TestCase):
    def test_webkit_transform(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    -webkit-transform: rotate(45deg);', Language.CSS)
        vp = [m for m in matches if m.rule.rule_id == "css-vendor-prefix"]
        self.assertEqual(len(vp), 1)
        self.assertNotIn("-webkit-", vp[0].replacement)
        self.assertIn("transform:", vp[0].replacement)

    def test_unknown_prop_ignored(self):
        engine = MigrationEngine()
        matches = engine.scan_line(
            '    -webkit-custom-thing: yes;', Language.CSS)
        vp = [m for m in matches if m.rule.rule_id == "css-vendor-prefix"]
        self.assertEqual(len(vp), 0)


# =========================================================================== #
#  ENGINE TESTS                                                                #
# =========================================================================== #

class TestMigrationEngine(unittest.TestCase):
    def test_scan_source_python(self):
        source = (
            'import os\n'
            'print "hello"\n'
            'p = os.path.join(a, b)\n'
            'x = "val %s" % name\n'
        )
        engine = MigrationEngine()
        matches = engine.scan_source(source, Language.PYTHON)
        self.assertGreater(len(matches), 0)
        rules_hit = {m.rule.rule_id for m in matches}
        self.assertIn("py-print-func", rules_hit)

    def test_scan_source_javascript(self):
        source = (
            'var x = 5;\n'
            'const fs = require("fs");\n'
            'module.exports = App;\n'
        )
        engine = MigrationEngine()
        matches = engine.scan_source(source, Language.JAVASCRIPT)
        rules_hit = {m.rule.rule_id for m in matches}
        self.assertIn("js-let-const", rules_hit)
        self.assertIn("js-esm-import", rules_hit)
        self.assertIn("js-esm-export", rules_hit)

    def test_confidence_filter(self):
        engine_high = MigrationEngine(min_confidence=Confidence.HIGH)
        engine_all = MigrationEngine(min_confidence=Confidence.LOW)
        source = 'if os.path.exists(f):\n'
        high = engine_high.scan_source(source, Language.PYTHON)
        low = engine_all.scan_source(source, Language.PYTHON)
        self.assertLessEqual(len(high), len(low))

    def test_breaking_filter(self):
        engine_no = MigrationEngine(include_breaking=False)
        engine_yes = MigrationEngine(include_breaking=True)
        source = '"line1\\n" + "line2\\n"\n'
        no_break = engine_no.scan_source(source, Language.JAVA)
        yes_break = engine_yes.scan_source(source, Language.JAVA)
        self.assertLessEqual(len(no_break), len(yes_break))

    def test_apply(self):
        source = 'print "hello"\nprint "world"\n'
        engine = MigrationEngine()
        result = engine.apply(source, Language.PYTHON)
        self.assertIn('print("hello")', result)
        self.assertIn('print("world")', result)

    def test_summary(self):
        reports = {
            "a.py": MigrationReport(file_path="a.py", matches=[
                MigrationMatch(
                    rule=get_rule("py-print-func"),
                    file_path="a.py", line=1,
                    original='print "x"',
                    replacement='print("x")'),
            ]),
        }
        engine = MigrationEngine()
        s = engine.summary(reports)
        self.assertIn("Migration Analysis", s)
        self.assertIn("Files with migrations: 1", s)


class TestScanFileAndProject(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_scan_file(self):
        path = self._write("app.py", 'print "hello"\n')
        engine = MigrationEngine()
        matches = engine.scan_file(path)
        self.assertGreater(len(matches), 0)

    def test_scan_file_unsupported_ext(self):
        path = self._write("data.txt", 'print "hello"\n')
        engine = MigrationEngine()
        matches = engine.scan_file(path)
        self.assertEqual(len(matches), 0)

    def test_scan_project(self):
        self._write("app.py", 'print "hello"\n')
        self._write("util.js", 'var x = 5;\n')
        engine = MigrationEngine()
        reports = engine.scan_project(self.tmpdir)
        self.assertGreater(len(reports), 0)

    def test_scan_project_skips_node_modules(self):
        self._write("node_modules/pkg/index.js", 'var x = 5;\n')
        self._write("app.js", 'const y = 10;\n')
        engine = MigrationEngine()
        reports = engine.scan_project(self.tmpdir)
        for path in reports:
            self.assertNotIn("node_modules", path)

    def test_scan_function(self):
        path = self._write("old.py", 'print "hello"\n')
        matches = scan(path)
        self.assertGreater(len(matches), 0)


class TestMigrationMatch(unittest.TestCase):
    def test_match_id_deterministic(self):
        r = get_rule("py-print-func")
        m1 = MigrationMatch(rule=r, file_path="a.py", line=1,
                            original="x", replacement="y")
        m2 = MigrationMatch(rule=r, file_path="a.py", line=1,
                            original="x", replacement="y")
        self.assertEqual(m1.match_id, m2.match_id)

    def test_match_id_unique(self):
        r = get_rule("py-print-func")
        m1 = MigrationMatch(rule=r, file_path="a.py", line=1,
                            original="x", replacement="y")
        m2 = MigrationMatch(rule=r, file_path="b.py", line=2,
                            original="x", replacement="y")
        self.assertNotEqual(m1.match_id, m2.match_id)


class TestMigrationReport(unittest.TestCase):
    def test_by_category(self):
        r = get_rule("py-print-func")
        m = MigrationMatch(rule=r, file_path="a.py", line=1,
                           original="x", replacement="y")
        report = MigrationReport(file_path="a.py", matches=[m])
        cats = report.by_category()
        self.assertIn("SYNTAX_MODERNIZATION", cats)

    def test_total_migrations(self):
        r = get_rule("py-print-func")
        matches = [
            MigrationMatch(rule=r, file_path="a.py", line=i,
                           original="x", replacement="y")
            for i in range(5)
        ]
        report = MigrationReport(file_path="a.py", matches=matches)
        self.assertEqual(report.total_migrations, 5)


if __name__ == "__main__":
    unittest.main()
