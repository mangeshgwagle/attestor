"""Tests for inter-procedural dataflow analysis."""
import os
import textwrap

import interprocedural


def _write_file(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(f)


def test_index_single_file(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def greet(name):
            return "hello " + name
    """)
    index = interprocedural.build_index([str(tmp_path)])
    assert len(index.functions) >= 1
    assert any("greet" in k for k in index.functions)


def test_index_entry_point(tmp_path):
    _write_file(tmp_path, "app.py", """\
        from flask import Flask
        app = Flask(__name__)

        @app.route("/")
        def index():
            return "hello"
    """)
    index = interprocedural.build_index([str(tmp_path)])
    func = [f for f in index.functions.values() if f.name == "index"]
    assert len(func) == 1
    assert func[0].is_entry_point


def test_call_graph_basic(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def process(data):
            return clean(data)

        def clean(text):
            return text.strip()
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    assert len(graph.edges) >= 1
    callee_names = [e.callee for e in graph.edges]
    assert any("clean" in c for c in callee_names)


def test_local_sink_detection(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import os
        def run_cmd(cmd):
            os.system(cmd)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    func = [f for f in index.functions.values() if f.name == "run_cmd"][0]
    assert 0 in func.sink_params
    assert any(s[1] == "command_injection" for s in func.sink_params[0])


def test_cross_function_taint(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import os
        def get_input():
            return input()

        def run_cmd(cmd):
            os.system(cmd)

        def handler(user_cmd):
            run_cmd(user_cmd)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    assert len(findings) >= 1
    cmd_findings = [f for f in findings if f.category == "command_injection"]
    assert len(cmd_findings) >= 1


def test_cross_function_chain_length(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import os
        def step3(cmd):
            os.system(cmd)

        def step2(data):
            step3(data)

        def step1(user_input):
            step2(user_input)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    chains = [f for f in findings if f.chain_length >= 3]
    assert len(chains) >= 1


def test_sql_injection_cross_func(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def query_user(db, username):
            db.execute("SELECT * FROM users WHERE name = '" + username + "'")

        def handle_request(db, user_input):
            query_user(db, user_input)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    sql = [f for f in findings if f.category == "sql_injection"]
    assert len(sql) >= 1


def test_multi_file_cross_function(tmp_path):
    _write_file(tmp_path, "utils.py", """\
        import os
        def execute(cmd):
            os.system(cmd)
    """)
    _write_file(tmp_path, "handler.py", """\
        from utils import execute
        def handle(user_cmd):
            execute(user_cmd)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    cross = [f for f in findings if f.chain_length > 1]
    assert len(cross) >= 1


def test_no_false_positive_safe_code(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def add(a, b):
            return a + b

        def compute(x, y):
            return add(x, y)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    assert len(findings) == 0


def test_entry_point_with_sink(tmp_path):
    _write_file(tmp_path, "app.py", """\
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/run")
        def run_endpoint():
            cmd = request.args.get("cmd")
            import os
            os.system(cmd)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    entry_funcs = [f for f in index.functions.values() if f.is_entry_point]
    assert len(entry_funcs) >= 1


def test_render_empty():
    output = interprocedural.render([])
    assert "nothing indexed" in output


def test_render_with_findings(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import os
        def dangerous(cmd):
            os.system(cmd)

        def handler(user_input):
            dangerous(user_input)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    output = interprocedural.render(findings, index)
    assert "Inter-procedural" in output
    assert "command_injection" in output


def test_render_no_findings_with_index(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def safe(x):
            return x + 1
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    output = interprocedural.render(findings, index)
    assert "no cross-function" in output


def test_to_dict(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import os
        def run(cmd):
            os.system(cmd)
    """)
    index = interprocedural.build_index([str(tmp_path)])
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph)
    dicts = interprocedural.to_dict(findings)
    assert len(dicts) >= 1
    assert dicts[0]["category"] == "command_injection"
    assert dicts[0]["cwe"] == "CWE-78"


def test_scan_paths_convenience(tmp_path):
    _write_file(tmp_path, "app.py", """\
        def danger(x):
            eval(x)
    """)
    findings = interprocedural.scan_paths([str(tmp_path)])
    assert len(findings) >= 1
    assert any(f.category == "code_injection" for f in findings)


def test_deserialization_detection(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import pickle
        def load_data(data):
            return pickle.loads(data)
    """)
    findings = interprocedural.scan_paths([str(tmp_path)])
    deser = [f for f in findings if f.category == "deserialization"]
    assert len(deser) >= 1


def test_ssrf_detection(tmp_path):
    _write_file(tmp_path, "app.py", """\
        import requests
        def fetch(url):
            return requests.get(url)
    """)
    findings = interprocedural.scan_paths([str(tmp_path)])
    ssrf = [f for f in findings if f.category == "ssrf"]
    assert len(ssrf) >= 1
