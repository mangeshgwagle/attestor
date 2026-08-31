"""Tests for reachability JS extension."""
import textwrap
import reachability


def test_js_function_extraction(tmp_path):
    f = tmp_path / "app.js"
    f.write_text(textwrap.dedent("""\
        function helper() {
            return process(data);
        }
        app.get('/api/data', function handler(req, res) {
            const result = helper();
            res.send(result);
        });
    """), encoding="utf-8")
    graph = reachability.build([str(tmp_path)])
    names = {f.name for lst in graph.values() for f in lst}
    assert "helper" in names
    assert "handler" in names


def test_js_entry_point_detection(tmp_path):
    f = tmp_path / "server.js"
    f.write_text(textwrap.dedent("""\
        app.post('/api/search', function search(req, res) {
            const q = req.body.q;
            res.send(lookup(q));
        });
        function lookup(query) {
            return db.find(query);
        }
    """), encoding="utf-8")
    graph = reachability.build([str(tmp_path)])
    entries = [f for lst in graph.values() for f in lst if f.is_entry]
    assert any(e.name == "search" for e in entries)


def test_js_reachable_function(tmp_path):
    f = tmp_path / "app.js"
    f.write_text(textwrap.dedent("""\
        export default function main() {
            doWork();
        }
        function doWork() {
            dangerous();
        }
        function dangerous() {
            eval(input);
        }
        function unused() {
            eval(x);
        }
    """), encoding="utf-8")
    graph = reachability.build([str(tmp_path)])
    reachable, _ = reachability._reachable_set(graph)
    names = {f.name for fid, f in [(id(f), f) for lst in graph.values()
             for f in lst] if id(f) in reachable}
    assert "dangerous" in names
    assert "doWork" in names


def test_mixed_py_js(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent("""\
        from flask import request
        import os
        @app.route('/api/run')
        def run():
            os.system(request.args['cmd'])
    """), encoding="utf-8")
    (tmp_path / "client.js").write_text(textwrap.dedent("""\
        app.get('/health', function health(req, res) {
            res.send('ok');
        });
    """), encoding="utf-8")
    graph = reachability.build([str(tmp_path)])
    names = {f.name for lst in graph.values() for f in lst}
    assert "run" in names
    assert "health" in names


def test_annotate_with_js_finding(tmp_path):
    f = tmp_path / "server.js"
    f.write_text(textwrap.dedent("""\
        app.get('/api', function handler(req, res) {
            runQuery(req.query.q);
        });
        function runQuery(q) {
            eval(q);
        }
    """), encoding="utf-8")
    findings = [
        {"sink_file": str(f), "sink_line": 5, "sink_type": "eval_injection"},
    ]
    results = reachability.annotate(findings, [str(tmp_path)])
    assert len(results) == 1
    assert results[0][1].reachable
