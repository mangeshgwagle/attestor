#!/usr/bin/env python3
"""Tests for attack_surface42.py — Attack surface mapper."""
import os
import tempfile
import unittest

from attack_surface42 import (
    EntryType, Severity, EntryPoint, AttackSurface, ScanPattern,
    AttackSurfaceMapper, PYTHON_PATTERNS, JS_PATTERNS, JAVA_PATTERNS,
    C_PATTERNS, GENERAL_PATTERNS, LANG_EXT_MAP, SKIP_DIRS,
    FRAMEWORK_INDICATORS, VERSION,
)


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "4.2")

    def test_python_patterns(self):
        self.assertGreater(len(PYTHON_PATTERNS), 20)

    def test_js_patterns(self):
        self.assertGreater(len(JS_PATTERNS), 10)

    def test_java_patterns(self):
        self.assertGreater(len(JAVA_PATTERNS), 8)

    def test_c_patterns(self):
        self.assertGreater(len(C_PATTERNS), 3)

    def test_general_patterns(self):
        self.assertGreater(len(GENERAL_PATTERNS), 2)

    def test_lang_ext_map(self):
        self.assertEqual(LANG_EXT_MAP[".py"], "python")
        self.assertEqual(LANG_EXT_MAP[".js"], "javascript")

    def test_skip_dirs(self):
        self.assertIn("node_modules", SKIP_DIRS)
        self.assertIn(".git", SKIP_DIRS)

    def test_framework_indicators(self):
        self.assertIn("flask", FRAMEWORK_INDICATORS)
        self.assertIn("express", FRAMEWORK_INDICATORS)


class TestEntryType(unittest.TestCase):
    def test_all_types(self):
        self.assertEqual(len(EntryType), 20)


class TestEntryPoint(unittest.TestCase):
    def test_risk_score_unauthenticated(self):
        ep = EntryPoint(
            entry_type=EntryType.COMMAND_EXEC,
            file_path="app.py", line=10,
            code_snippet="os.system(cmd)", language="python",
            severity=Severity.CRITICAL, requires_auth=False,
        )
        self.assertEqual(ep.risk_score, 10)

    def test_risk_score_authenticated(self):
        ep = EntryPoint(
            entry_type=EntryType.HTTP_ENDPOINT,
            file_path="app.py", line=10,
            code_snippet="@app.route('/')", language="python",
            severity=Severity.MEDIUM, requires_auth=True,
        )
        self.assertEqual(ep.risk_score, 5)

    def test_risk_score_capped(self):
        ep = EntryPoint(
            entry_type=EntryType.COMMAND_EXEC,
            file_path="app.py", line=10,
            code_snippet="system(cmd)", language="c",
            severity=Severity.CRITICAL, requires_auth=False,
        )
        self.assertLessEqual(ep.risk_score, 10)


class TestAttackSurface(unittest.TestCase):
    def _make_surface(self):
        entries = [
            EntryPoint(EntryType.HTTP_ENDPOINT, "app.py", 10,
                       "@app.route('/')", "python", Severity.MEDIUM),
            EntryPoint(EntryType.COMMAND_EXEC, "util.py", 20,
                       "os.system(cmd)", "python", Severity.CRITICAL,
                       cwe=78),
            EntryPoint(EntryType.SQL_SINK, "db.py", 30,
                       "cursor.execute(q)", "python", Severity.HIGH,
                       requires_auth=True, cwe=89),
        ]
        return AttackSurface(
            project_path="/test", entries=entries,
            files_scanned=3, languages={"python"},
        )

    def test_by_type(self):
        s = self._make_surface()
        endpoints = s.by_type(EntryType.HTTP_ENDPOINT)
        self.assertEqual(len(endpoints), 1)

    def test_by_severity(self):
        s = self._make_surface()
        critical = s.by_severity(Severity.CRITICAL)
        self.assertEqual(len(critical), 1)

    def test_unauthenticated(self):
        s = self._make_surface()
        unauth = s.unauthenticated()
        self.assertEqual(len(unauth), 2)

    def test_endpoints(self):
        s = self._make_surface()
        self.assertEqual(len(s.endpoints()), 1)

    def test_high_value_targets(self):
        s = self._make_surface()
        hvt = s.high_value_targets()
        self.assertGreater(len(hvt), 0)

    def test_summary(self):
        s = self._make_surface()
        summary = s.summary()
        self.assertIn("Attack Surface Map", summary)
        self.assertIn("Files scanned: 3", summary)
        self.assertIn("COMMAND_EXEC", summary)

    def test_to_dict(self):
        s = self._make_surface()
        d = s.to_dict()
        self.assertEqual(d["files_scanned"], 3)
        self.assertEqual(d["total_entries"], 3)
        self.assertEqual(len(d["entries"]), 3)

    def test_empty_surface(self):
        s = AttackSurface(project_path="/empty")
        self.assertEqual(len(s.entries), 0)
        summary = s.summary()
        self.assertIn("Total entry points: 0", summary)


class TestAttackSurfaceMapperScan(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_file(self, name, content):
        path = os.path.join(self.tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_scan_flask_routes(self):
        self._write_file("app.py", (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/api/users')\n"
            "def users():\n"
            "    return 'ok'\n"
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        endpoints = surface.by_type(EntryType.HTTP_ENDPOINT)
        self.assertGreater(len(endpoints), 0)
        self.assertIn("flask", surface.frameworks)

    def test_scan_command_injection(self):
        self._write_file("run.py", (
            "import os\n"
            "os.system('echo hello')\n"
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        cmd_entries = surface.by_type(EntryType.COMMAND_EXEC)
        self.assertGreater(len(cmd_entries), 0)
        self.assertEqual(cmd_entries[0].cwe, 78)

    def test_scan_eval(self):
        self._write_file("danger.py", "result = eval(user_input)\n")
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        evals = surface.by_type(EntryType.EVAL_EXEC)
        self.assertGreater(len(evals), 0)

    def test_scan_pickle(self):
        self._write_file("data.py", (
            "import pickle\n"
            "obj = pickle.loads(data)\n"
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        deser = surface.by_type(EntryType.DESERIALIZATION)
        self.assertGreater(len(deser), 0)
        self.assertEqual(deser[0].cwe, 502)

    def test_scan_js_express(self):
        self._write_file("server.js", (
            'const express = require("express");\n'
            'const app = express();\n'
            'app.get("/api/data", (req, res) => {\n'
            '    res.json({ok: true});\n'
            '});\n'
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        endpoints = surface.by_type(EntryType.HTTP_ENDPOINT)
        self.assertGreater(len(endpoints), 0)
        self.assertIn("express", surface.frameworks)

    def test_scan_hardcoded_password(self):
        self._write_file("config.py", (
            'password = "super_secret_123"\n'
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        creds = [e for e in surface.entries if e.cwe == 798]
        self.assertGreater(len(creds), 0)

    def test_skip_node_modules(self):
        self._write_file("node_modules/pkg/index.js", 'eval("hello")\n')
        self._write_file("app.js", 'console.log("clean")\n')
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        for e in surface.entries:
            self.assertNotIn("node_modules", e.file_path)

    def test_scan_sql_python(self):
        self._write_file("db.py", (
            "cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        sql = surface.by_type(EntryType.SQL_SINK)
        self.assertGreater(len(sql), 0)

    def test_scan_auth_context_detection(self):
        self._write_file("views.py", (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "@login_required\n"
            "@app.route('/admin')\n"
            "def admin():\n"
            "    return 'admin panel'\n"
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        endpoints = surface.by_type(EntryType.HTTP_ENDPOINT)
        auth_eps = [e for e in endpoints if e.requires_auth]
        self.assertGreater(len(auth_eps), 0)

    def test_scan_empty_project(self):
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        self.assertEqual(len(surface.entries), 0)
        self.assertEqual(surface.files_scanned, 0)

    def test_scan_file_method(self):
        path = self._write_file("util.py", "os.system('ls')\n")
        mapper = AttackSurfaceMapper()
        entries = mapper.scan_file(path)
        self.assertGreater(len(entries), 0)

    def test_scan_c_buffer(self):
        self._write_file("vuln.c", (
            '#include <string.h>\n'
            'void f() { strcpy(dst, src); }\n'
        ))
        mapper = AttackSurfaceMapper()
        surface = mapper.scan(self.tmpdir)
        bufs = [e for e in surface.entries if e.cwe == 120]
        self.assertGreater(len(bufs), 0)


class TestScanPattern(unittest.TestCase):
    def test_all_patterns_have_entry_type(self):
        all_p = PYTHON_PATTERNS + JS_PATTERNS + JAVA_PATTERNS + C_PATTERNS + GENERAL_PATTERNS
        for p in all_p:
            self.assertIsInstance(p.entry_type, EntryType)
            self.assertIsInstance(p.severity, Severity)

    def test_all_patterns_compile(self):
        all_p = PYTHON_PATTERNS + JS_PATTERNS + JAVA_PATTERNS + C_PATTERNS + GENERAL_PATTERNS
        for p in all_p:
            import re
            re.compile(p.regex)


if __name__ == "__main__":
    unittest.main()
