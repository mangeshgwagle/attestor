"""Tests for IaC security scanner."""
import os
import textwrap

import iac_scan


def test_dockerfile_root_user(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12\nUSER root\nRUN pip install flask\n", encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "DOCKER-001" for f in findings)


def test_dockerfile_no_user(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12\nRUN pip install flask\n", encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "DOCKER-007" for f in findings)


def test_dockerfile_add_instead_of_copy(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12\nADD app.py /app/\nUSER nonroot\n", encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "DOCKER-002" for f in findings)


def test_dockerfile_latest_tag(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:latest\nUSER app\n", encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "DOCKER-003" for f in findings)


def test_dockerfile_clean(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nCOPY app.py /app/\nUSER appuser\n", encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert findings == []


def test_terraform_public_s3(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n', encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "TF-001" for f in findings)


def test_terraform_open_sg(tmp_path):
    f = tmp_path / "sg.tf"
    f.write_text(textwrap.dedent("""\
        resource "aws_security_group_rule" "r" {
          cidr_blocks = ["0.0.0.0/0"]
          type = "ingress"
        }
    """), encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "TF-002" for f in findings)


def test_terraform_unencrypted(tmp_path):
    f = tmp_path / "db.tf"
    f.write_text('resource "aws_rds_instance" "db" {\n  encrypted = false\n}\n', encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "TF-003" for f in findings)


def test_k8s_privileged(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(textwrap.dedent("""\
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: app
            securityContext:
              privileged: true
    """), encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "K8S-001" for f in findings)


def test_k8s_host_network(tmp_path):
    f = tmp_path / "deploy.yaml"
    f.write_text(textwrap.dedent("""\
        apiVersion: v1
        kind: Pod
        spec:
          hostNetwork: true
          containers:
          - name: app
            resources:
              limits:
                memory: "128Mi"
    """), encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "K8S-002" for f in findings)


def test_k8s_no_resource_limits(tmp_path):
    f = tmp_path / "app.yaml"
    f.write_text(textwrap.dedent("""\
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: app
            image: nginx
    """), encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "K8S-008" for f in findings)


def test_cfn_public_bucket(tmp_path):
    f = tmp_path / "stack.yaml"
    f.write_text(textwrap.dedent("""\
        AWSTemplateFormatVersion: '2010-09-09'
        Resources:
          Bucket:
            Type: AWS::S3::Bucket
            Properties:
              AccessControl: PublicRead
    """), encoding="utf-8")
    findings = iac_scan.scan_file(str(f))
    assert any(f.rule_id == "CFN-001" for f in findings)


def test_scan_paths_walks(tmp_path):
    d = tmp_path / "infra"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM python:latest\nUSER app\n", encoding="utf-8")
    (d / "main.tf").write_text('acl = "public-read"\n', encoding="utf-8")
    findings = iac_scan.scan_paths([str(tmp_path)])
    rules = {f.rule_id for f in findings}
    assert "DOCKER-003" in rules
    assert "TF-001" in rules


def test_to_dict():
    f = iac_scan.IaCFinding(
        rule_id="TF-001", severity="CRITICAL",
        file="main.tf", line=2, code='acl = "public-read"',
        description="S3 public", category="access_control", cwe="CWE-284",
    )
    d = iac_scan.to_dict([f])
    assert d[0]["rule_id"] == "TF-001"
    assert d[0]["language"] == "iac"


def test_render_no_findings():
    assert "No IaC" in iac_scan.render([])


def test_render_with_findings():
    f = iac_scan.IaCFinding(
        rule_id="K8S-001", severity="CRITICAL",
        file="pod.yaml", line=7, code="privileged: true",
        description="Privileged container", category="privilege", cwe="CWE-250",
    )
    text = iac_scan.render([f])
    assert "K8S-001" in text
    assert "CRITICAL" in text


def test_non_iac_file_skipped(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("print('hello')\n", encoding="utf-8")
    assert iac_scan.scan_file(str(f)) == []
