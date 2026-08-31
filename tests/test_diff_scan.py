"""Tests for diff-only scanning."""
import os
import textwrap
from unittest.mock import patch, MagicMock

import diff_scan


def test_near_changed_exact():
    assert diff_scan._near_changed(10, {10}, 5)


def test_near_changed_within_context():
    assert diff_scan._near_changed(12, {10}, 5)
    assert diff_scan._near_changed(8, {10}, 5)


def test_near_changed_outside_context():
    assert not diff_scan._near_changed(20, {10}, 5)


def test_near_changed_empty_set_allows_all():
    assert diff_scan._near_changed(999, set(), 5)


def test_render_no_findings():
    text = diff_scan.render([], [diff_scan.DiffFile("a.py", "M")])
    assert "no new findings" in text
    assert "1 file(s)" in text


def test_render_with_findings():
    findings = [
        {"sink_type": "xss", "cwe": "CWE-79", "severity": "HIGH",
         "sink_file": "app.js", "sink_line": 15, "language": "javascript"},
    ]
    text = diff_scan.render(findings)
    assert "Diff Scan" in text
    assert "xss" in text
    assert "CWE-79" in text


def test_get_changed_files_parses_output():
    fake_output = "M\tapp.py\nA\tsrc/util.js\nD\told.py\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_output)
        with patch("diff_scan._get_changed_lines", return_value=set()):
            files = diff_scan.get_changed_files("/repo")
    paths = [os.path.basename(f.path) for f in files]
    assert "app.py" in paths
    assert "util.js" in paths
    assert "old.py" not in paths  # deleted files excluded


def test_get_changed_files_skips_non_code():
    fake_output = "M\tREADME.md\nM\tapp.py\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=fake_output)
        with patch("diff_scan._get_changed_lines", return_value=set()):
            files = diff_scan.get_changed_files("/repo")
    assert len(files) == 1
    assert files[0].path.endswith("app.py")


def test_get_changed_lines_parses_hunk_headers():
    diff_output = "@@ -10,3 +15,5 @@\n+new code\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=diff_output)
        lines = diff_scan._get_changed_lines("/repo", "app.py", "main", False)
    assert lines == {15, 16, 17, 18, 19}


def test_scan_diff_filters_by_proximity(tmp_path):
    vuln_code = textwrap.dedent("""\
        import os
        from flask import request
        def h():
            x = request.form.get('q')
            os.system('grep ' + x)
    """)
    f = tmp_path / "app.py"
    f.write_text(vuln_code, encoding="utf-8")

    with patch("diff_scan.get_changed_files") as mock_gcf:
        mock_gcf.return_value = [
            diff_scan.DiffFile(path=str(f), status="M", changed_lines={4, 5}),
        ]
        findings = diff_scan.scan_diff(str(tmp_path))
    assert findings, "finding near changed lines should be included"


def test_scan_diff_excludes_distant_findings(tmp_path):
    vuln_code = textwrap.dedent("""\
        import os
        from flask import request
        def h():
            x = request.form.get('q')
            os.system('grep ' + x)
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        # padding
        def other():
            pass
    """)
    f = tmp_path / "app.py"
    f.write_text(vuln_code, encoding="utf-8")

    with patch("diff_scan.get_changed_files") as mock_gcf:
        mock_gcf.return_value = [
            diff_scan.DiffFile(path=str(f), status="M", changed_lines={20}),
        ]
        findings = diff_scan.scan_diff(str(tmp_path), context_lines=3)
    assert not findings, "finding far from changed lines should be excluded"


def test_main_json(tmp_path, capsys):
    with patch("diff_scan.get_changed_files", return_value=[]):
        with patch("diff_scan.scan_diff", return_value=[]):
            diff_scan.main(["--json", str(tmp_path)])
    out = capsys.readouterr().out
    assert "[]" in out
