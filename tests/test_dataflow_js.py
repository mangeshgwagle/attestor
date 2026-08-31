"""Tests for the JS/TS interprocedural dataflow engine."""
import textwrap

import dataflow_js


def _scan(tmp_path, code, ext=".js"):
    f = tmp_path / f"t{ext}"
    f.write_text(textwrap.dedent(code), encoding="utf-8")
    return dataflow_js.scan_paths([str(f)])


def test_direct_xss_innerhtml(tmp_path):
    findings = _scan(tmp_path, """
        function render() {
            const input = document.location.search;
            document.getElementById('out').innerHTML = input;
        }
    """)
    assert any(f.cwe == "CWE-79" for f in findings)


def test_express_sqli(tmp_path):
    findings = _scan(tmp_path, """
        const express = require('express');
        function handleQuery(req, res) {
            const id = req.query.id;
            db.query("SELECT * FROM users WHERE id = " + id);
        }
    """)
    assert any(f.cwe == "CWE-89" for f in findings)


def test_command_injection_child_process(tmp_path):
    findings = _scan(tmp_path, """
        const { exec } = require('child_process');
        function run(req, res) {
            const cmd = req.body.command;
            exec("ls " + cmd);
        }
    """)
    assert any(f.cwe == "CWE-78" for f in findings)


def test_interprocedural_xss(tmp_path):
    findings = _scan(tmp_path, """
        function getInput() {
            return document.location.hash;
        }
        function display(html) {
            document.getElementById('x').innerHTML = html;
        }
        function main() {
            const data = getInput();
            display(data);
        }
    """)
    inter = [f for f in findings if f.cwe == "CWE-79" and f.interprocedural]
    assert inter, "cross-function XSS must be detected"


def test_sanitizer_kills_taint(tmp_path):
    findings = _scan(tmp_path, """
        function safe(req, res) {
            const name = req.query.name;
            const clean = DOMPurify.sanitize(name);
            document.getElementById('out').innerHTML = clean;
        }
    """)
    assert not findings, "DOMPurify.sanitize must neutralise the taint"


def test_parseInt_sanitizes(tmp_path):
    findings = _scan(tmp_path, """
        function handler(req, res) {
            const id = parseInt(req.query.id);
            db.query("SELECT * FROM users WHERE id = " + id);
        }
    """)
    assert not findings, "parseInt must neutralise the taint"


def test_constant_not_flagged(tmp_path):
    findings = _scan(tmp_path, """
        function safe() {
            document.getElementById('x').innerHTML = "<b>hello</b>";
        }
    """)
    assert not findings, "a constant sink is not a vulnerability"


def test_finding_has_evidence_trace(tmp_path):
    findings = _scan(tmp_path, """
        function handler(req, res) {
            const name = req.query.name;
            document.getElementById('out').innerHTML = name;
        }
    """)
    assert findings
    f = findings[0]
    assert len(f.trace) >= 2, "finding must carry source->sink trace"
    notes = " ".join(s.note for s in f.trace)
    assert "source" in notes


def test_typescript_support(tmp_path):
    findings = _scan(tmp_path, """
        function handler(req: Request, res: Response): void {
            const input: string = req.body.data;
            eval(input);
        }
    """, ext=".ts")
    assert any(f.cwe == "CWE-95" for f in findings)


def test_path_traversal_fs(tmp_path):
    findings = _scan(tmp_path, """
        const fs = require('fs');
        function download(req, res) {
            const file = req.params.filename;
            fs.readFileSync("/uploads/" + file);
        }
    """)
    assert any(f.cwe == "CWE-22" for f in findings)


def test_ssrf_fetch(tmp_path):
    findings = _scan(tmp_path, """
        async function proxy(req, res) {
            const url = req.query.url;
            fetch(url);
        }
    """)
    assert any(f.cwe == "CWE-918" for f in findings)


def test_to_dict_format(tmp_path):
    findings = _scan(tmp_path, """
        function handler(req, res) {
            const x = req.body.input;
            eval(x);
        }
    """)
    dicts = dataflow_js.to_dict(findings)
    assert dicts
    d = dicts[0]
    assert "cwe" in d and "trace" in d and "language" in d
    assert d["language"] == "javascript"


def test_render_output(tmp_path):
    findings = _scan(tmp_path, """
        function handler(req, res) {
            const x = req.body.input;
            eval(x);
        }
    """)
    text = dataflow_js.render(findings)
    assert "JS/TS Dataflow" in text
    assert "CWE-95" in text
