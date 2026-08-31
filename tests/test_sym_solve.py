"""Tests for symbolic path feasibility engine."""
import textwrap
import sym_solve


def test_feasible_no_guards():
    code = textwrap.dedent("""\
        def handler(request):
            cmd = request.args.get('cmd')
            os.system(cmd)
    """)
    finding = {"sink_line": 3, "sink_type": "command_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.FEASIBLE
    assert len(r.constraints) == 0


def test_feasible_with_satisfiable_guard():
    code = textwrap.dedent("""\
        def handler(request):
            cmd = request.args.get('cmd')
            if cmd.startswith('/bin'):
                os.system(cmd)
    """)
    finding = {"sink_line": 4, "sink_type": "command_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.FEASIBLE
    assert len(r.constraints) >= 1


def test_infeasible_contradiction():
    code = textwrap.dedent("""\
        def handler(request):
            val = request.args.get('x')
            if val != val:
                eval(val)
    """)
    finding = {"sink_line": 4, "sink_type": "eval_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.INFEASIBLE


def test_infeasible_eq_neq_same_value():
    code = textwrap.dedent("""\
        def handler(request):
            x = request.args.get('x')
            if x == 'admin':
                if x != 'admin':
                    eval(x)
    """)
    finding = {"sink_line": 5, "sink_type": "eval_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.INFEASIBLE


def test_else_branch_negation():
    code = textwrap.dedent("""\
        def handler(request):
            val = request.args.get('x')
            if val == val:
                pass
            else:
                eval(val)
    """)
    finding = {"sink_line": 6, "sink_type": "eval_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.INFEASIBLE


def test_not_operator():
    code = textwrap.dedent("""\
        def handler(request):
            val = request.args.get('x')
            if not is_safe(val):
                eval(val)
    """)
    finding = {"sink_line": 4, "sink_type": "eval_injection"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.FEASIBLE
    assert any(c.negated for c in r.constraints)


def test_unknown_no_sink_line():
    finding = {"sink_type": "test"}
    r = sym_solve.analyze_finding(finding, "x = 1")
    assert r.feasibility == sym_solve.Feasibility.UNKNOWN


def test_unknown_syntax_error():
    finding = {"sink_line": 1, "sink_type": "test"}
    r = sym_solve.analyze_finding(finding, "def @@@ broken")
    assert r.feasibility == sym_solve.Feasibility.UNKNOWN


def test_analyze_findings_with_files(tmp_path):
    code = textwrap.dedent("""\
        def handler(request):
            x = request.args.get('x')
            if x != x:
                eval(x)
    """)
    f = tmp_path / "vuln.py"
    f.write_text(code, encoding="utf-8")
    findings = [{"sink_file": str(f), "sink_line": 4, "sink_type": "eval"}]
    results = sym_solve.analyze_findings(findings, [str(tmp_path)])
    assert len(results) == 1
    assert results[0].feasibility == sym_solve.Feasibility.INFEASIBLE


def test_analyze_findings_file_not_found():
    findings = [{"sink_file": "/no/such/file.py", "sink_line": 1}]
    results = sym_solve.analyze_findings(findings, [])
    assert results[0].feasibility == sym_solve.Feasibility.UNKNOWN


def test_to_dict():
    code = textwrap.dedent("""\
        def handler(request):
            cmd = request.args.get('cmd')
            if cmd.startswith('/bin'):
                os.system(cmd)
    """)
    finding = {"sink_line": 4, "sink_type": "command_injection"}
    r = sym_solve.analyze_finding(finding, code)
    dicts = sym_solve.to_dict([r])
    assert len(dicts) == 1
    assert dicts[0]["feasibility"] == "feasible"
    assert "path_constraints" in dicts[0]


def test_render():
    code_infeasible = textwrap.dedent("""\
        def handler(request):
            val = request.args.get('x')
            if val != val:
                eval(val)
    """)
    code_feasible = textwrap.dedent("""\
        def handler(request):
            cmd = request.args.get('cmd')
            os.system(cmd)
    """)
    r1 = sym_solve.analyze_finding(
        {"sink_line": 4, "sink_type": "eval", "sink_file": "a.py"}, code_infeasible)
    r2 = sym_solve.analyze_finding(
        {"sink_line": 3, "sink_type": "cmd_inject", "sink_file": "b.py"}, code_feasible)
    output = sym_solve.render([r1, r2])
    assert "PRUNED" in output
    assert "EXPLOITABLE" in output
    assert "1 exploitable" in output
    assert "1 dead" in output


def test_is_none_and_compare():
    code = textwrap.dedent("""\
        def handler(request):
            x = request.args.get('x')
            if x is None:
                if x > 5:
                    eval(x)
    """)
    finding = {"sink_line": 5, "sink_type": "eval"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.INFEASIBLE


def test_range_contradiction():
    code = textwrap.dedent("""\
        def handler(request):
            x = int(request.args.get('x'))
            if x < 5:
                if x > 10:
                    eval(str(x))
    """)
    finding = {"sink_line": 5, "sink_type": "eval"}
    r = sym_solve.analyze_finding(finding, code)
    assert r.feasibility == sym_solve.Feasibility.INFEASIBLE
