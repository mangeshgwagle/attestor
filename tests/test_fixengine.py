"""Tests for fix engine -- AST-aware security repair."""
import textwrap

import fixengine


def test_plan_sqli_format():
    code = textwrap.dedent("""\
        import sqlite3
        def get_user(db, user_id):
            db.execute("SELECT * FROM users WHERE id = %s" % user_id)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-89", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "parameterized_query"
    assert plan.confidence >= 0.80
    assert any("?" in s.new_text for s in plan.steps)


def test_plan_sqli_fstring():
    code = textwrap.dedent("""\
        def query(db, name):
            db.execute(f"SELECT * FROM users WHERE name = {name}")
    """)
    finding = {"sink_line": 2, "cwe": "CWE-89", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "?" in plan.steps[0].new_text
    assert "name" in plan.steps[0].new_text


def test_plan_sqli_concat():
    code = textwrap.dedent("""\
        def query(db, user):
            db.execute("SELECT * FROM t WHERE x = " + user)
    """)
    finding = {"sink_line": 2, "cwe": "CWE-89", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "?" in plan.steps[0].new_text


def test_plan_cmdi_os_system():
    code = textwrap.dedent("""\
        import os
        def run(cmd):
            os.system("ls " + cmd)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-78", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "safe_subprocess"
    assert "subprocess.run" in plan.steps[0].new_text
    assert "shlex" in plan.imports_needed


def test_plan_cmdi_subprocess_shell():
    code = textwrap.dedent("""\
        import subprocess
        def run(cmd):
            subprocess.call(cmd, shell=True)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-78", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "shell=False" in plan.steps[0].new_text


def test_plan_eval():
    code = textwrap.dedent("""\
        def process(data):
            return eval(data)
    """)
    finding = {"sink_line": 2, "cwe": "CWE-95", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "literal_eval"
    assert "ast.literal_eval" in plan.steps[0].new_text
    assert "ast" in plan.imports_needed


def test_plan_hardcoded_secret():
    code = textwrap.dedent("""\
        API_KEY = "sk-proj-abc123def456"
    """)
    finding = {"sink_line": 1, "cwe": "CWE-798", "file": "config.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "env_var"
    assert 'os.environ["API_KEY"]' in plan.steps[0].new_text


def test_plan_hardcoded_ignores_short_values():
    code = 'name = "hello"\n'
    finding = {"sink_line": 1, "cwe": "CWE-798", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is None


def test_plan_path_traversal():
    code = textwrap.dedent("""\
        import os
        def read_file(base, filename):
            path = os.path.join(base, filename)
            return open(path).read()
    """)
    finding = {"sink_line": 3, "cwe": "CWE-22", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "path_guard"
    assert any("realpath" in s.new_text for s in plan.steps)


def test_plan_yaml_load():
    code = textwrap.dedent("""\
        import yaml
        def load_config(path):
            with open(path) as f:
                return yaml.load(f)
    """)
    finding = {"sink_line": 4, "cwe": "CWE-502", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "safe_load" in plan.steps[0].new_text
    assert plan.confidence >= 0.85


def test_plan_yaml_safe_load_skipped():
    code = textwrap.dedent("""\
        import yaml
        def load_config(path):
            with open(path) as f:
                return yaml.safe_load(f)
    """)
    finding = {"sink_line": 4, "cwe": "CWE-502", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is None


def test_plan_pickle():
    code = textwrap.dedent("""\
        import pickle
        def load_data(path):
            with open(path, "rb") as f:
                return pickle.load(f)
    """)
    finding = {"sink_line": 4, "cwe": "CWE-502", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "json.load" in plan.steps[0].new_text
    assert plan.risk == "HIGH"


def test_plan_weak_hash():
    code = textwrap.dedent("""\
        import hashlib
        def hash_password(pw):
            return hashlib.md5(pw.encode()).hexdigest()
    """)
    finding = {"sink_line": 3, "cwe": "CWE-327", "file": "auth.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "sha256" in plan.steps[0].new_text


def test_plan_weak_random():
    code = textwrap.dedent("""\
        import random
        def make_token():
            return random.random()
    """)
    finding = {"sink_line": 3, "cwe": "CWE-327", "file": "auth.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "secrets" in plan.steps[0].new_text or "secrets" in plan.imports_needed


def test_plan_tls_verify():
    code = textwrap.dedent("""\
        import requests
        def fetch(url):
            return requests.get(url, verify=False)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-295", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert "verify=True" in plan.steps[0].new_text


def test_plan_ssrf():
    code = textwrap.dedent("""\
        import requests
        def proxy(url):
            return requests.get(url)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-918", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.strategy == "url_allowlist"
    assert any("127.0.0.1" in s.new_text for s in plan.steps)


def test_apply_fix_sqli():
    code = textwrap.dedent("""\
        import sqlite3
        def get_user(db, user_id):
            db.execute("SELECT * FROM users WHERE id = %s" % user_id)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-89", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    result = fixengine.apply_fix(plan, code)
    assert result.applied
    assert "?" in result.fixed
    assert "%" not in result.fixed.split("execute")[1]


def test_apply_fix_adds_import():
    code = textwrap.dedent("""\
        def process(data):
            return eval(data)
    """)
    finding = {"sink_line": 2, "cwe": "CWE-95", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    result = fixengine.apply_fix(plan, code)
    assert result.applied
    assert "import ast" in result.fixed
    assert "ast.literal_eval" in result.fixed


def test_apply_fix_no_duplicate_import():
    code = textwrap.dedent("""\
        import ast
        def process(data):
            return eval(data)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-95", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    result = fixengine.apply_fix(plan, code)
    assert result.applied
    assert result.fixed.count("import ast") == 1


def test_apply_fixes_multiple():
    code = textwrap.dedent("""\
        import hashlib
        def bad():
            h = hashlib.md5(b"test")
            return eval("1+2")
    """)
    findings = [
        {"sink_line": 3, "cwe": "CWE-327", "file": "app.py"},
        {"sink_line": 4, "cwe": "CWE-95", "file": "app.py"},
    ]
    plans = fixengine.plan_fixes(findings, code, "app.py")
    assert len(plans) >= 2
    fixed, results = fixengine.apply_fixes(plans, code)
    applied = sum(1 for r in results if r.applied)
    assert applied >= 2
    assert "sha256" in fixed
    assert "literal_eval" in fixed


def test_plan_via_sink_type():
    code = textwrap.dedent("""\
        import os
        def run(cmd):
            os.system(cmd)
    """)
    finding = {"sink_line": 3, "sink_type": "command_injection", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert plan.cwe == "CWE-78"


def test_render_plans():
    code = textwrap.dedent("""\
        import hashlib
        def hash(pw):
            return hashlib.md5(pw.encode()).hexdigest()
    """)
    finding = {"sink_line": 3, "cwe": "CWE-327", "file": "auth.py"}
    plan = fixengine.plan_fix(finding, code)
    output = fixengine.render([plan])
    assert "Fix Engine" in output
    assert "sha256" in output
    assert "confidence" in output


def test_render_empty():
    output = fixengine.render([])
    assert "nothing fixable" in output


def test_to_dict():
    code = textwrap.dedent("""\
        import yaml
        def load(path):
            return yaml.load(open(path))
    """)
    finding = {"sink_line": 3, "cwe": "CWE-502", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    dicts = fixengine.to_dict([plan])
    assert len(dicts) == 1
    assert dicts[0]["strategy"] == "safe_deserialize"
    assert dicts[0]["confidence"] >= 0.85
    assert len(dicts[0]["reasoning"]) > 0


def test_diff_lines_generated():
    code = textwrap.dedent("""\
        import requests
        def fetch(url):
            return requests.get(url, verify=False)
    """)
    finding = {"sink_line": 3, "cwe": "CWE-295", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    result = fixengine.apply_fix(plan, code)
    assert len(result.diff_lines) > 0
    has_minus = any(l.startswith("-") for l in result.diff_lines)
    has_plus = any(l.startswith("+") for l in result.diff_lines)
    assert has_minus and has_plus


def test_unknown_cwe_returns_none():
    code = "x = 1\n"
    finding = {"sink_line": 1, "cwe": "CWE-999999", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is None


def test_plan_xss_format_html():
    code = textwrap.dedent("""\
        def render(name):
            return "<h1>Hello {name}</h1>".format(name=name)
    """)
    finding = {"sink_line": 2, "cwe": "CWE-79", "file": "app.py"}
    plan = fixengine.plan_fix(finding, code)
    assert plan is not None
    assert any("html.escape" in s.new_text for s in plan.steps)
