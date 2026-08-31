"""Tests for taint policy DSL."""
import textwrap
import taint_dsl


POLICY_TEXT = textwrap.dedent("""\
    sources:
      - pattern: 'request\\.args\\.get\\('
        label: user_input
      - pattern: 'os\\.environ\\['
        label: env_var

    sinks:
      - pattern: 'os\\.system\\('
        severity: CRITICAL
        cwe: CWE-78
        category: command_injection
      - pattern: 'eval\\('
        severity: CRITICAL
        cwe: CWE-95
        category: eval_injection

    sanitizers:
      - pattern: 'shlex\\.quote\\('
        neutralizes: [command_injection]
      - pattern: 'html\\.escape\\('
        neutralizes: [xss]
""")


def test_load_policy():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    assert len(policy.sources) == 2
    assert len(policy.sinks) == 2
    assert len(policy.sanitizers) == 2
    assert policy.sources[0].label == "user_input"
    assert policy.sinks[0].category == "command_injection"


def test_basic_taint_flow():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        cmd = request.args.get('cmd')
        os.system(cmd)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    assert len(findings) >= 1
    assert findings[0].sink_category == "command_injection"
    assert not findings[0].sanitized


def test_sanitized_flow():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        cmd = request.args.get('cmd')
        safe = shlex.quote(cmd)
        os.system(safe)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    cmd_findings = [f for f in findings if f.sink_category == "command_injection"]
    assert all(f.sanitized for f in cmd_findings)


def test_no_source_no_finding():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        cmd = "ls -la"
        os.system(cmd)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    assert len(findings) == 0


def test_multiple_sources():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        user_cmd = request.args.get('cmd')
        env_cmd = os.environ['CMD']
        os.system(user_cmd)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    sources = {f.source_label for f in findings}
    assert "user_input" in sources
    assert "env_var" in sources


def test_eval_sink():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        expr = request.args.get('expr')
        eval(expr)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    assert any(f.sink_category == "eval_injection" for f in findings)


def test_wrong_sanitizer_doesnt_neutralize():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = textwrap.dedent("""\
        cmd = request.args.get('cmd')
        safe = html.escape(cmd)
        os.system(safe)
    """)
    findings = taint_dsl.apply_policy(code, policy)
    cmd_findings = [f for f in findings if f.sink_category == "command_injection"]
    assert any(not f.sanitized for f in cmd_findings)


def test_scan_with_policy(tmp_path):
    policy = taint_dsl.load_policy(POLICY_TEXT)
    f = tmp_path / "app.py"
    f.write_text(textwrap.dedent("""\
        cmd = request.args.get('cmd')
        os.system(cmd)
    """), encoding="utf-8")
    findings = taint_dsl.scan_with_policy([str(tmp_path)], policy)
    assert len(findings) >= 1


def test_to_dict():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = "cmd = request.args.get('cmd')\nos.system(cmd)\n"
    findings = taint_dsl.apply_policy(code, policy, "test.py")
    dicts = taint_dsl.to_dict(findings)
    assert len(dicts) >= 1
    assert "sink_file" in dicts[0]
    assert "source_label" in dicts[0]


def test_render():
    policy = taint_dsl.load_policy(POLICY_TEXT)
    code = "cmd = request.args.get('cmd')\nos.system(cmd)\n"
    findings = taint_dsl.apply_policy(code, policy, "test.py")
    output = taint_dsl.render(findings)
    assert "Taint Policy DSL" in output
    assert "command_injection" in output


def test_load_policy_file(tmp_path):
    pf = tmp_path / "policy.yaml"
    pf.write_text(POLICY_TEXT, encoding="utf-8")
    policy = taint_dsl.load_policy_file(str(pf))
    assert len(policy.sources) == 2


def test_propagators():
    policy_text = textwrap.dedent("""\
        sources:
          - pattern: 'input\\('
            label: stdin

        sinks:
          - pattern: 'exec\\('
            severity: HIGH
            cwe: CWE-78
            category: code_exec

        propagators:
          - pattern: 'str\\('
            from: arg0
            to: return
    """)
    policy = taint_dsl.load_policy(policy_text)
    assert len(policy.propagators) == 1
    assert policy.propagators[0].to == "return"
