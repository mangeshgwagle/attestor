"""Tests for GitHub Actions CI pipeline scanner."""
import os
import textwrap

import ci_scan


def _write_workflow(tmp_path, content):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    f = d / "ci.yml"
    f.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(f)


def test_expression_injection(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: issue_comment
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.event.comment.body }}
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-001" for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_expression_injection_multiline_run(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "PR title: ${{ github.event.pull_request.title }}"
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-001" for f in findings)


def test_no_injection_safe_context(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.sha }}
    """)
    findings = ci_scan.scan_file(path)
    injection_findings = [f for f in findings if f.rule_id == "GHA-001"]
    assert injection_findings == []


def test_write_all_permissions(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        permissions: write-all
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-002" for f in findings)


def test_contents_write(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        permissions:
          contents: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-003" for f in findings)


def test_unpinned_action(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: some-org/some-action@main
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-004" for f in findings)


def test_pinned_action_no_finding(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
    """)
    findings = ci_scan.scan_file(path)
    pinned_findings = [f for f in findings if f.rule_id == "GHA-004"]
    assert pinned_findings == []


def test_trusted_owner_no_finding(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
    """)
    findings = ci_scan.scan_file(path)
    pinned_findings = [f for f in findings if f.rule_id == "GHA-004"]
    assert pinned_findings == []


def test_secret_in_echo(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ secrets.API_KEY }}
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-006" for f in findings)


def test_self_hosted_runner(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: self-hosted
            steps:
              - run: echo ok
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-007" for f in findings)


def test_unsecure_commands(tmp_path):
    path = _write_workflow(tmp_path, """\
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              ACTIONS_ALLOW_UNSECURE_COMMANDS: true
            steps:
              - run: echo ok
    """)
    findings = ci_scan.scan_file(path)
    assert any(f.rule_id == "GHA-008" for f in findings)


def test_scan_paths_finds_workflows(tmp_path):
    _write_workflow(tmp_path, """\
        name: CI
        on: push
        permissions: write-all
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
    """)
    findings = ci_scan.scan_paths([str(tmp_path)])
    assert any(f.rule_id == "GHA-002" for f in findings)


def test_non_workflow_file_skipped(tmp_path):
    f = tmp_path / "ci.yml"
    f.write_text("permissions: write-all\n", encoding="utf-8")
    assert ci_scan.scan_file(str(f)) == []


def test_to_dict():
    f = ci_scan.CIFinding(
        rule_id="GHA-001", severity="CRITICAL",
        file=".github/workflows/ci.yml", line=7,
        code="run: echo ${{ github.event.comment.body }}",
        description="Expression injection", category="injection", cwe="CWE-78",
    )
    d = ci_scan.to_dict([f])
    assert d[0]["language"] == "github-actions"
    assert d[0]["cwe"] == "CWE-78"


def test_render_no_findings():
    assert "No GitHub Actions" in ci_scan.render([])


def test_render_with_findings():
    f = ci_scan.CIFinding(
        rule_id="GHA-001", severity="CRITICAL",
        file=".github/workflows/ci.yml", line=7,
        code="run: echo injection",
        description="Expression injection", category="injection",
    )
    text = ci_scan.render([f])
    assert "GHA-001" in text
    assert "CRITICAL" in text
