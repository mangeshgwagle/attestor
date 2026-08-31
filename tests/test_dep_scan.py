"""Tests for dependency vulnerability scanner."""
import json
import os
import textwrap

import dep_scan


def test_parse_requirements_txt(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==2.3.0\nrequests>=2.28.0\njinja2~=3.1.2\n", encoding="utf-8")
    deps = dep_scan.parse_requirements_txt(str(f))
    assert deps["flask"] == "2.3.0"
    assert deps["requests"] == "2.28.0"
    assert deps["jinja2"] == "3.1.2"


def test_parse_requirements_ignores_comments(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("# comment\nflask==2.3.0\n-r other.txt\n", encoding="utf-8")
    deps = dep_scan.parse_requirements_txt(str(f))
    assert "flask" in deps
    assert len(deps) == 1


def test_parse_package_json(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "dependencies": {"express": "^4.18.0", "axios": "~1.6.0"},
        "devDependencies": {"jest": "29.0.0"},
    }), encoding="utf-8")
    deps = dep_scan.parse_package_json(str(f))
    assert deps["express"] == "4.18.0"
    assert deps["axios"] == "1.6.0"
    assert deps["jest"] == "29.0.0"


def test_parse_pipfile_lock(tmp_path):
    f = tmp_path / "Pipfile.lock"
    f.write_text(json.dumps({
        "default": {"flask": {"version": "==2.3.0"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }), encoding="utf-8")
    deps = dep_scan.parse_pipfile_lock(str(f))
    assert deps["flask"] == "2.3.0"
    assert deps["pytest"] == "7.4.0"


def test_parse_package_lock(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps({
        "packages": {
            "node_modules/express": {"version": "4.18.0"},
            "node_modules/lodash": {"version": "4.17.20"},
        }
    }), encoding="utf-8")
    deps = dep_scan.parse_package_lock(str(f))
    assert deps["express"] == "4.18.0"
    assert deps["lodash"] == "4.17.20"


def test_version_comparison():
    assert dep_scan._version_below("2.3.0", "2.3.2")
    assert not dep_scan._version_below("2.3.2", "2.3.2")
    assert not dep_scan._version_below("3.0.0", "2.3.2")
    assert dep_scan._version_below("4.17.20", "4.17.21")


def test_scan_finds_vulnerable_flask(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==2.3.0\n", encoding="utf-8")
    findings = dep_scan.scan_lockfile(str(f))
    assert len(findings) >= 1
    assert any(f.cve == "CVE-2023-30861" for f in findings)
    assert all(f.package == "flask" for f in findings)


def test_scan_safe_version_no_finding(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==3.0.0\n", encoding="utf-8")
    findings = dep_scan.scan_lockfile(str(f))
    flask_findings = [f for f in findings if f.package == "flask"]
    assert flask_findings == []


def test_scan_npm_vulnerable_lodash(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "dependencies": {"lodash": "4.17.20"},
    }), encoding="utf-8")
    findings = dep_scan.scan_lockfile(str(f))
    assert any(f.cve == "CVE-2021-23337" for f in findings)


def test_scan_paths_walks_directory(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\n", encoding="utf-8")
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package.json").write_text(json.dumps({
        "dependencies": {"lodash": "4.17.20"},
    }), encoding="utf-8")
    findings = dep_scan.scan_paths([str(tmp_path)])
    packages = {f.package for f in findings}
    assert "flask" in packages
    assert "lodash" in packages


def test_to_dict():
    f = dep_scan.DepFinding(
        package="flask", installed_version="2.3.0",
        vulnerable_range="< 2.3.2", fixed_version="2.3.2",
        cve="CVE-2023-30861", severity="HIGH",
        description="test", ecosystem="pip", lockfile="requirements.txt",
    )
    d = dep_scan.to_dict([f])
    assert d[0]["sink_type"] == "vulnerable_dependency"
    assert d[0]["cve"] == "CVE-2023-30861"


def test_render_no_findings():
    assert "No known-vulnerable" in dep_scan.render([])


def test_render_with_findings():
    f = dep_scan.DepFinding(
        package="flask", installed_version="2.3.0",
        vulnerable_range="< 2.3.2", fixed_version="2.3.2",
        cve="CVE-2023-30861", severity="HIGH",
        description="Session cookie issue", ecosystem="pip",
        lockfile="requirements.txt",
    )
    text = dep_scan.render([f])
    assert "flask" in text
    assert "CVE-2023-30861" in text
    assert "2.3.2" in text


def test_cross_reference():
    dep_findings = [dep_scan.DepFinding(
        package="flask", installed_version="2.3.0",
        vulnerable_range="< 2.3.2", fixed_version="2.3.2",
        cve="CVE-2023-30861", severity="HIGH",
        description="test", ecosystem="pip", lockfile="requirements.txt",
    )]
    code_findings = [
        {"sink_code": "app = flask.Flask(__name__)", "sink_file": "app.py",
         "sink_line": 5, "trace": []},
    ]
    result = dep_scan.cross_reference(dep_findings, code_findings)
    assert result[0].reachable
    assert result[0].reachable_file == "app.py"
