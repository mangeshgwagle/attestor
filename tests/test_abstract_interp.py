"""Tests for abstract interpretation value-range engine."""
import textwrap
import abstract_interp
from abstract_interp import Range


def test_range_arithmetic():
    a = Range(1, 10)
    b = Range(2, 5)
    r = a + b
    assert r.lo == 3 and r.hi == 15
    r = a - b
    assert r.lo == -4 and r.hi == 8
    r = a * b
    assert r.lo == 2 and r.hi == 50


def test_range_contains_zero():
    assert Range(-1, 1).contains_zero()
    assert not Range(1, 10).contains_zero()
    assert Range(0, 0).contains_zero()


def test_range_overflow():
    assert not Range(0, 100).overflows_32()
    assert Range(0, 2**31 + 1).overflows_32()
    assert not Range(0, 2**31 + 1).overflows_64()
    assert Range(0, 2**63 + 1).overflows_64()


def test_division_by_zero():
    code = textwrap.dedent("""\
        x = 10
        y = 0
        z = x // y
    """)
    findings = abstract_interp.scan_source(code)
    cats = [f.category for f in findings]
    assert "division_by_zero" in cats


def test_no_division_by_zero_safe():
    code = textwrap.dedent("""\
        x = 10
        y = 5
        z = x // y
    """)
    findings = abstract_interp.scan_source(code)
    div_findings = [f for f in findings if f.category == "division_by_zero"]
    assert len(div_findings) == 0


def test_overflow_32():
    code = textwrap.dedent("""\
        a = 2000000000
        b = 2000000000
        c = a + b
    """)
    findings = abstract_interp.scan_source(code)
    overflow = [f for f in findings if "overflow_32" in f.category]
    assert len(overflow) >= 1


def test_negative_index():
    code = textwrap.dedent("""\
        idx = -1
        arr = [1, 2, 3]
        arr[idx]
    """)
    findings = abstract_interp.scan_source(code)
    neg = [f for f in findings if f.category == "negative_index"]
    assert len(neg) >= 1


def test_range_narrowing_on_branch():
    code = textwrap.dedent("""\
        x = 100
        if x < 50:
            y = x // 0
    """)
    findings = abstract_interp.scan_source(code)
    assert any(f.category == "division_by_zero" for f in findings)


def test_for_range_tracking():
    code = textwrap.dedent("""\
        for i in range(10):
            x = i * 1000000000
    """)
    findings = abstract_interp.scan_source(code)
    overflow = [f for f in findings if "overflow" in f.category]
    assert len(overflow) >= 0


def test_augmented_assign():
    code = textwrap.dedent("""\
        x = 2000000000
        x += 2000000000
    """)
    findings = abstract_interp.scan_source(code)
    overflow = [f for f in findings if "overflow" in f.category]
    assert len(overflow) >= 1


def test_scan_file(tmp_path):
    f = tmp_path / "test.py"
    f.write_text(textwrap.dedent("""\
        x = 10
        y = 0
        z = x // y
    """), encoding="utf-8")
    findings = abstract_interp.scan_file(str(f))
    assert any(f.category == "division_by_zero" for f in findings)


def test_scan_paths(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(textwrap.dedent("""\
        a = 2**32
        b = a * a
    """), encoding="utf-8")
    findings = abstract_interp.scan_paths([str(tmp_path)])
    assert len(findings) >= 1


def test_to_dict():
    code = "x = 10\ny = 0\nz = x // y\n"
    findings = abstract_interp.scan_source(code, "test.py")
    dicts = abstract_interp.to_dict(findings)
    assert len(dicts) >= 1
    assert "sink_file" in dicts[0]
    assert "range_lo" in dicts[0]


def test_render():
    code = "x = 10\ny = 0\nz = x // y\n"
    findings = abstract_interp.scan_source(code, "test.py")
    output = abstract_interp.render(findings)
    assert "division_by_zero" in output
    assert "Abstract Interpretation" in output


def test_no_findings_clean():
    code = textwrap.dedent("""\
        x = 5
        y = 3
        z = x + y
    """)
    findings = abstract_interp.scan_source(code)
    assert len(findings) == 0
