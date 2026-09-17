"""Tests for novel code pattern detector."""
import os
import sys
import tempfile
import shutil
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import novel_detector


def _write_file(root, name, content):
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content))
    return path


def test_shannon_entropy_empty():
    assert novel_detector._shannon_entropy("") == 0.0


def test_shannon_entropy_uniform():
    e = novel_detector._shannon_entropy("aaaa")
    assert e == 0.0


def test_shannon_entropy_random():
    e = novel_detector._shannon_entropy("abcdefghij")
    assert e > 3.0


def test_cyclomatic_simple():
    tree = __import__("ast").parse("x = 1")
    func = __import__("ast").parse("def f():\n  x = 1").body[0]
    assert novel_detector._cyclomatic_complexity(func) == 1


def test_cyclomatic_branching():
    code = "def f(x):\n  if x: pass\n  if y: pass\n  for i in r: pass"
    func = __import__("ast").parse(code).body[0]
    assert novel_detector._cyclomatic_complexity(func) >= 4


def test_max_nesting():
    code = "def f():\n  if True:\n    for x in y:\n      if z:\n        pass"
    func = __import__("ast").parse(code).body[0]
    assert novel_detector._max_nesting(func) >= 3


def test_extract_imports():
    code = "import os\nimport json\nfrom pathlib import Path"
    tree = __import__("ast").parse(code)
    imports = novel_detector._extract_imports(tree)
    assert "os" in imports
    assert "json" in imports
    assert "pathlib" in imports


def test_classify_imports_network():
    imports = {"socket", "json", "os"}
    cats = novel_detector._classify_imports(imports)
    assert "network" in cats
    assert "execution" in cats


def test_classify_imports_empty():
    cats = novel_detector._classify_imports({"collections", "itertools"})
    assert len(cats) == 0


def test_suspicious_combo_detection():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "suspicious.py", """
            import socket
            import subprocess
            import base64

            def download_and_exec():
                data = socket.socket().recv(4096)
                decoded = base64.b64decode(data)
                subprocess.run(decoded, shell=True)
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_directory(root)
        combo_findings = [f for f in findings
                          if f.category == "suspicious-import-combo"]
        assert len(combo_findings) >= 1
        has_high = any(f.severity == "HIGH" for f in combo_findings)
        assert has_high
    finally:
        shutil.rmtree(root)


def test_entropy_detection():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "encoded.py", """
            secret = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc="
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "encoded.py"))
        entropy_findings = [f for f in findings
                            if f.category == "high-entropy-string"]
        assert len(entropy_findings) >= 1
    finally:
        shutil.rmtree(root)


def test_obfuscation_detection():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "obfuscated.py", r"""
            x = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21"
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "obfuscated.py"))
        obf_findings = [f for f in findings
                        if f.category == "obfuscation-pattern"]
        assert len(obf_findings) >= 1
        assert obf_findings[0].severity == "HIGH"
    finally:
        shutil.rmtree(root)


def test_anti_pattern_cluster():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "dangerous.py", """
            def evil():
                x = eval("1+1")
                y = exec("pass")
                z = getattr(__builtins__, "open")
                w = __import__("os")
                return x
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "dangerous.py"))
        cluster = [f for f in findings
                   if f.category == "anti-pattern-cluster"]
        assert len(cluster) >= 1
        assert cluster[0].function_name == "evil"
    finally:
        shutil.rmtree(root)


def test_structural_outlier():
    root = tempfile.mkdtemp()
    try:
        normals = ""
        for i in range(30):
            normals += f"def f{i}():\n    return {i}\n\n"

        big_lines = []
        big_lines.append("def monster():")
        for d in range(6):
            indent = "    " * (d + 1)
            big_lines.append(f"{indent}if True:")
        deep_indent = "    " * 7
        for i in range(100):
            big_lines.append(f"{deep_indent}x{i} = {i}")
        big_func = "\n".join(big_lines) + "\n"

        _write_file(root, "codebase.py", normals + big_func)

        nd = novel_detector.NovelDetector(z_threshold=1.5)
        findings = nd.scan_directory(root)
        outliers = [f for f in findings if f.category == "structural-outlier"]
        assert len(outliers) >= 1
        assert outliers[0].function_name == "monster"
    finally:
        shutil.rmtree(root)


def test_scan_non_python():
    root = tempfile.mkdtemp()
    try:
        path = os.path.join(root, "readme.md")
        with open(path, "w") as f:
            f.write("# Hello\nThis is not python.")
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(path)
        assert findings == []
    finally:
        shutil.rmtree(root)


def test_scan_syntax_error():
    root = tempfile.mkdtemp()
    try:
        path = _write_file(root, "broken.py", "def (:")
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(path)
        assert findings == []
    finally:
        shutil.rmtree(root)


def test_scan_empty_dir():
    root = tempfile.mkdtemp()
    try:
        nd = novel_detector.NovelDetector()
        findings = nd.scan_directory(root)
        assert findings == []
    finally:
        shutil.rmtree(root)


def test_to_dict():
    f = novel_detector.NovelFinding(
        path="test.py", line=10, end_line=20,
        category="test", severity="HIGH",
        description="test finding", evidence="x = 1",
        score=3.5, function_name="foo",
        metrics={"complexity": 15})
    d = novel_detector.to_dict([f])
    assert len(d) == 1
    assert d[0]["path"] == "test.py"
    assert d[0]["score"] == 3.5
    assert d[0]["metrics"]["complexity"] == 15


def test_render():
    f = novel_detector.NovelFinding(
        path="test.py", line=10, end_line=20,
        category="structural-outlier", severity="HIGH",
        description="outlier function", evidence="def monster()",
        score=4.2, function_name="monster")
    text = novel_detector.render([f])
    assert "structural-outlier" in text
    assert "HIGH" in text
    assert "outlier function" in text


def test_render_empty():
    text = novel_detector.render([])
    assert "No novel" in text


def test_name_entropy():
    e1 = novel_detector._name_entropy("process_data")
    e2 = novel_detector._name_entropy("xqzwvbjklm")
    assert e2 > e1


def test_dynamic_import_detection():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "dyn.py", """
            mod = __import__("os")
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "dyn.py"))
        obf = [f for f in findings if f.category == "obfuscation-pattern"]
        assert len(obf) >= 1
    finally:
        shutil.rmtree(root)


def test_js_obfuscation_eval_atob():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "mal.js", """
            eval(atob("YWxlcnQoMSk="));
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "mal.js"))
        obf = [f for f in findings if f.category == "obfuscation-pattern"]
        assert len(obf) >= 1
        assert obf[0].severity == "HIGH"
    finally:
        shutil.rmtree(root)


def test_js_function_constructor():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "inject.js", """
            var fn = new Function("return document.cookie");
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "inject.js"))
        obf = [f for f in findings if f.category == "obfuscation-pattern"]
        assert len(obf) >= 1
    finally:
        shutil.rmtree(root)


def test_js_fromcharcode_chain():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "charcode.js", """
            var s = String.fromCharCode(72, 101, 108, 108, 111, 32, 87);
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "charcode.js"))
        obf = [f for f in findings if f.category == "obfuscation-pattern"]
        assert len(obf) >= 1
    finally:
        shutil.rmtree(root)


def test_js_suspicious_imports():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "c2.js", """
            const http = require("http");
            const cp = require("child_process");
            const crypto = require("crypto");
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "c2.js"))
        combo = [f for f in findings if f.category == "suspicious-import-combo"]
        assert len(combo) >= 1
    finally:
        shutil.rmtree(root)


def test_js_entropy_string():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "key.js", """
            const key = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=";
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "key.js"))
        ent = [f for f in findings if f.category == "high-entropy-string"]
        assert len(ent) >= 1
    finally:
        shutil.rmtree(root)


def test_js_clean_file():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "clean.js", """
            function add(a, b) {
                return a + b;
            }
            module.exports = { add };
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "clean.js"))
        assert len(findings) == 0
    finally:
        shutil.rmtree(root)


def test_ts_file_supported():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "app.ts", """
            eval(atob("dGVzdA=="));
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_file(os.path.join(root, "app.ts"))
        assert len(findings) >= 1
    finally:
        shutil.rmtree(root)


def test_scan_directory_includes_js():
    root = tempfile.mkdtemp()
    try:
        _write_file(root, "ok.py", """
            def hello():
                return 42
        """)
        _write_file(root, "bad.js", """
            eval(atob("payload"));
        """)
        nd = novel_detector.NovelDetector()
        findings = nd.scan_directory(root)
        js_findings = [f for f in findings if f.path.endswith(".js")]
        assert len(js_findings) >= 1
    finally:
        shutil.rmtree(root)
