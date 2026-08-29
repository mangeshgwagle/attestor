"""Tests for verified autofix -- dry-run safety, apply+verify, and the fixers."""
import textwrap

import autofix


def _write(tmp_path, code):
    f = tmp_path / "m.py"
    f.write_text(textwrap.dedent(code), encoding="utf-8")
    return f


def test_dry_run_does_not_write(tmp_path):
    f = _write(tmp_path, """
        import hashlib
        def d(x):
            return hashlib.md5(x).hexdigest()
    """)
    before = f.read_text(encoding="utf-8")
    results = autofix.fix_paths([str(f)], apply=False)
    assert results and results[0].edits, "should propose a fix"
    assert f.read_text(encoding="utf-8") == before, "dry-run must not modify the file"


def test_apply_and_verify_weak_hash(tmp_path):
    f = _write(tmp_path, """
        import hashlib
        def d(x):
            return hashlib.md5(x).hexdigest()
    """)
    results = autofix.fix_paths([str(f)], apply=True)
    assert results[0].applied
    assert all(e.verified for e in results[0].edits)
    assert "sha256(" in f.read_text(encoding="utf-8")
    assert "md5(" not in f.read_text(encoding="utf-8")


def test_multiple_fixers(tmp_path):
    f = _write(tmp_path, """
        import requests
        def g(x, url):
            if x == None:
                return requests.get(url, verify=False)
    """)
    results = autofix.fix_paths([str(f)], apply=True)
    text = f.read_text(encoding="utf-8")
    assert "is None" in text
    assert "verify=True" in text


def test_compare_url_https_and_ssh():
    https = autofix._compare_url("https://github.com/o/r.git", "main", "b")
    ssh = autofix._compare_url("git@github.com:o/r.git", "main", "b")
    assert https == "https://github.com/o/r/compare/main...b?expand=1"
    assert ssh == https
