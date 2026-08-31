"""Tests for cross-service dataflow engine."""
import os
import textwrap

import dataflow_cross


def test_extract_fetch_tainted():
    lines = [
        "const name = document.location.hash;",
        "fetch('/api/search', {method: 'POST', body: JSON.stringify({q: name})})",
    ]
    calls = dataflow_cross.extract_http_calls("app.js", lines)
    assert len(calls) == 1
    assert calls[0].url == "/api/search"
    assert calls[0].method == "POST"
    assert "name" in calls[0].tainted_fields


def test_extract_fetch_untainted():
    lines = [
        "const x = 42;",
        "fetch('/api/health')",
    ]
    calls = dataflow_cross.extract_http_calls("app.js", lines)
    assert calls == []


def test_extract_axios_tainted():
    lines = [
        "const input = document.getElementById('q').value;",
        "axios.post('/api/query', {data: input})",
    ]
    calls = dataflow_cross.extract_http_calls("app.js", lines)
    assert len(calls) == 1
    assert calls[0].method == "POST"
    assert calls[0].url == "/api/query"


def test_extract_xhr_tainted():
    lines = [
        "const val = window.location.search;",
        "xhr.open('GET', '/api/data');",
        "xhr.send(val);",
    ]
    calls = dataflow_cross.extract_http_calls("app.js", lines)
    assert len(calls) == 1
    assert calls[0].method == "GET"


def test_extract_flask_route():
    lines = [
        "@app.route('/api/search', methods=['POST'])",
        "def search():",
        "    q = request.json['q']",
    ]
    routes = dataflow_cross.extract_routes("app.py", lines)
    assert len(routes) == 1
    assert routes[0].path == "/api/search"
    assert routes[0].method == "POST"
    assert routes[0].func_name == "search"
    assert routes[0].framework == "flask"


def test_extract_fastapi_route():
    lines = [
        "@router.post('/api/items')",
        "async def create_item(item: Item):",
        "    pass",
    ]
    routes = dataflow_cross.extract_routes("main.py", lines)
    assert len(routes) == 1
    assert routes[0].method == "POST"
    assert routes[0].path == "/api/items"
    assert routes[0].framework == "fastapi"


def test_extract_express_route():
    lines = [
        "app.post('/api/search', function handler(req, res) {",
        "  res.send('ok');",
        "});",
    ]
    routes = dataflow_cross.extract_routes("server.js", lines)
    assert len(routes) == 1
    assert routes[0].method == "POST"
    assert routes[0].path == "/api/search"
    assert routes[0].framework == "express"


def test_paths_match_exact():
    assert dataflow_cross._paths_match("/api/search", "/api/search")


def test_paths_match_param():
    assert dataflow_cross._paths_match("/api/users/123", "/api/users/<id>")
    assert dataflow_cross._paths_match("/api/users/123", "/api/users/:id")
    assert dataflow_cross._paths_match("/api/users/123", "/api/users/{id}")


def test_paths_no_match():
    assert not dataflow_cross._paths_match("/api/search", "/api/users")
    assert not dataflow_cross._paths_match("/api/a/b", "/api/a")


def test_methods_match():
    assert dataflow_cross._methods_match("POST", "POST")
    assert dataflow_cross._methods_match("GET", "ALL")
    assert not dataflow_cross._methods_match("GET", "POST")


def test_chain_produces_finding():
    call = dataflow_cross.HTTPCallSite(
        file="app.js", line=10, code="fetch('/api/search'...)",
        method="POST", url="/api/search",
        tainted_fields=["name"], source_type="dom_url",
        source_trace=[dataflow_cross.Step("app.js", 5, "const name = location.hash", "source")],
    )
    route = dataflow_cross.RouteHandler(
        file="app.py", line=20, code="@app.route('/api/search'...)",
        method="POST", path="/api/search",
        func_name="search", framework="flask",
    )
    py_finding = {
        "cwe": "CWE-89", "sink_type": "sql_injection",
        "sink_file": "app.py", "sink_line": 25,
        "sink_code": "cursor.execute(q)", "severity": "CRITICAL",
        "trace": [
            {"file": "app.py", "line": 22, "code": "q = request.json['q']", "note": "source"},
            {"file": "app.py", "line": 25, "code": "cursor.execute(q)", "note": "sink"},
        ],
    }
    findings = dataflow_cross.chain([call], [route], [py_finding])
    assert len(findings) == 1
    f = findings[0]
    assert f.sink_type == "sql_injection"
    assert f.cwe == "CWE-89"
    assert f.source_type == "dom_url"
    assert f.client_file == "app.js"
    assert f.server_file == "app.py"
    assert f.endpoint == "POST /api/search"
    assert len(f.trace) >= 3


def test_chain_no_match_different_path():
    call = dataflow_cross.HTTPCallSite(
        file="a.js", line=1, code="", method="POST", url="/api/foo",
        tainted_fields=["x"], source_type="dom",
    )
    route = dataflow_cross.RouteHandler(
        file="b.py", line=1, code="", method="POST", path="/api/bar",
        func_name="bar", framework="flask",
    )
    findings = dataflow_cross.chain([call], [route], [{"sink_file": "b.py"}])
    assert findings == []


def test_to_dict():
    f = dataflow_cross.Finding(
        cwe="CWE-79", sink_type="xss", sink_file="s.py", sink_line=10,
        sink_code="render(x)", source_type="dom_input", severity="HIGH",
        trace=[dataflow_cross.Step("a.js", 1, "code", "note")],
        client_file="a.js", server_file="s.py", endpoint="POST /api/x",
    )
    d = dataflow_cross.to_dict([f])
    assert len(d) == 1
    assert d[0]["language"] == "cross-service"
    assert d[0]["client_file"] == "a.js"
    assert d[0]["endpoint"] == "POST /api/x"


def test_render_no_findings():
    text = dataflow_cross.render([])
    assert "No cross-service" in text


def test_render_with_findings():
    f = dataflow_cross.Finding(
        cwe="CWE-78", sink_type="command_injection", sink_file="app.py",
        sink_line=42, sink_code="os.system(x)", source_type="dom_url",
        severity="CRITICAL", trace=[], client_file="front.js",
        server_file="app.py", endpoint="POST /api/run",
    )
    text = dataflow_cross.render([f])
    assert "Cross-Service" in text
    assert "command_injection" in text
    assert "CRITICAL" in text


def test_scan_paths_end_to_end(tmp_path):
    js = tmp_path / "client.js"
    js.write_text(textwrap.dedent("""\
        const input = document.getElementById('q').value;
        fetch('/api/search', {method: 'POST', body: JSON.stringify({q: input})})
    """), encoding="utf-8")

    py = tmp_path / "app.py"
    py.write_text(textwrap.dedent("""\
        from flask import Flask, request
        import os
        app = Flask(__name__)
        @app.route('/api/search', methods=['POST'])
        def search():
            q = request.form.get('q')
            os.system('grep ' + q)
    """), encoding="utf-8")

    findings = dataflow_cross.scan_paths([str(tmp_path)])
    assert len(findings) >= 1
    f = findings[0]
    assert f.endpoint == "POST /api/search"
    assert f.language == "cross-service"
