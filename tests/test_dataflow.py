"""Tests for the interprocedural dataflow engine -- the SOTA core.

These lock in the behaviour that separates real dataflow analysis from pattern
matching: cross-function taint, sanitizer awareness, and evidence traces."""
import textwrap

import dataflow


def _scan(tmp_path, code):
    f = tmp_path / "t.py"
    f.write_text(textwrap.dedent(code), encoding="utf-8")
    return dataflow.scan_paths([str(f)])


def test_intraprocedural_command_injection(tmp_path):
    findings = _scan(tmp_path, """
        import subprocess
        from flask import request
        def h():
            x = request.form.get('q')
            subprocess.run('grep ' + x, shell=True)
    """)
    assert any(f.cwe == "CWE-78" for f in findings)


def test_interprocedural_command_injection(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def src():
            return request.args.get('c')
        def sink(d):
            os.system('echo ' + d)
        def h():
            v = src()
            sink(v)
    """)
    inter = [f for f in findings if f.cwe == "CWE-78" and f.interprocedural]
    assert inter, "cross-function command injection must be detected"


def test_multi_hop_interprocedural(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def a():
            return request.args.get('x')
        def b():
            return a()
        def c(v):
            os.system(v)
        def h():
            c(b())
    """)
    assert any(f.cwe == "CWE-78" for f in findings), "a->b->c chain must be detected"


def test_sanitizer_suppresses_finding(tmp_path):
    findings = _scan(tmp_path, """
        import subprocess, shlex
        from flask import request
        def h():
            x = request.args.get('q')
            subprocess.run(['echo', shlex.quote(x)])
    """)
    assert not findings, "shlex.quote must neutralise the taint (no finding)"


def test_int_cast_suppresses_finding(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def h():
            n = int(request.args.get('n'))
            os.system('sleep %d' % n)
    """)
    assert not findings, "int() cast must neutralise the taint"


def test_constant_argument_not_flagged(tmp_path):
    findings = _scan(tmp_path, """
        import os
        def h():
            os.system('ls -la /tmp')
    """)
    assert not findings, "a constant sink argument is not a vulnerability"


def test_finding_carries_evidence_trace(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def src():
            return request.args.get('c')
        def sink(d):
            os.system('echo ' + d)
        def h():
            sink(src())
    """)
    assert findings
    f = findings[0]
    assert len(f.trace) >= 2, "a finding must carry a source->sink trace"
    notes = " ".join(s.note for s in f.trace)
    assert "source" in notes and "sink" in notes
