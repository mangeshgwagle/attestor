"""Tests for semantic clone detection."""
import textwrap
import clone_detect


def test_extract_functions():
    code = textwrap.dedent("""\
        def foo(x, y):
            z = x + y
            return z * 2

        def bar(a, b):
            c = a + b
            return c * 2
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    assert len(sigs) == 2
    assert sigs[0].param_count == 2


def test_exact_clones():
    code = textwrap.dedent("""\
        def process_a(x, y):
            z = x + y
            result = z * 2
            return result

        def process_b(a, b):
            c = a + b
            result = c * 2
            return result
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    clones = clone_detect.find_clones(sigs)
    assert len(clones) >= 1
    assert clones[0].size == 2


def test_no_clones_different_structure():
    code = textwrap.dedent("""\
        def adder(x, y):
            return x + y + 1 + 2 + 3

        def multiplier(x, y, z):
            for i in range(z):
                x = x * y
                if x > 100:
                    break
            return x
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    clones = clone_detect.find_clones(sigs)
    assert len(clones) == 0


def test_near_clones():
    code = textwrap.dedent("""\
        def process_data(items):
            result = []
            for item in items:
                val = item * 2
                result.append(val)
            return result

        def transform_data(entries):
            output = []
            for entry in entries:
                val = entry * 3
                output.append(val)
                print(val)
            return output
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    nears = clone_detect.find_near_clones(sigs, threshold=0.6)
    assert len(nears) >= 1
    assert nears[0].similarity >= 0.6


def test_min_nodes_filter():
    code = textwrap.dedent("""\
        def tiny(x):
            return x
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    assert len(sigs) == 0


def test_scan_paths(tmp_path):
    (tmp_path / "a.py").write_text(textwrap.dedent("""\
        def handler_a(request):
            data = request.get_json()
            result = process(data)
            return jsonify(result)

        def handler_b(req):
            payload = req.get_json()
            output = process(payload)
            return jsonify(output)
    """), encoding="utf-8")
    clones, nears = clone_detect.scan_paths([str(tmp_path)])
    assert len(clones) >= 1


def test_to_dict():
    code = textwrap.dedent("""\
        def fa(x, y):
            z = x + y
            result = z * 2
            return result

        def fb(a, b):
            c = a + b
            result = c * 2
            return result
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    clones = clone_detect.find_clones(sigs)
    dicts = clone_detect.to_dict(clones, [])
    assert len(dicts) >= 2
    assert all("sink_file" in d for d in dicts)
    assert all("fingerprint" in d for d in dicts)


def test_render():
    code = textwrap.dedent("""\
        def fa(x, y):
            z = x + y
            result = z * 2
            return result

        def fb(a, b):
            c = a + b
            result = c * 2
            return result
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    clones = clone_detect.find_clones(sigs)
    nears = clone_detect.find_near_clones(sigs)
    output = clone_detect.render(clones, nears)
    assert "EXACT CLONE" in output
    assert "fa()" in output and "fb()" in output


def test_cross_file_clones(tmp_path):
    code_a = textwrap.dedent("""\
        def validate_input(data):
            if not data:
                raise ValueError("empty")
            cleaned = data.strip()
            return cleaned.lower()
    """)
    code_b = textwrap.dedent("""\
        def sanitize_input(text):
            if not text:
                raise ValueError("empty")
            cleaned = text.strip()
            return cleaned.lower()
    """)
    (tmp_path / "mod_a.py").write_text(code_a, encoding="utf-8")
    (tmp_path / "mod_b.py").write_text(code_b, encoding="utf-8")
    clones, _ = clone_detect.scan_paths([str(tmp_path)])
    assert len(clones) >= 1
    files = {m.file for g in clones for m in g.members}
    assert len(files) == 2


def test_docstring_stripped():
    code = textwrap.dedent("""\
        def with_doc(x, y):
            '''This function adds two numbers.'''
            z = x + y
            result = z * 2
            return result

        def no_doc(a, b):
            c = a + b
            result = c * 2
            return result
    """)
    sigs = clone_detect.extract_functions(code, "test.py")
    clones = clone_detect.find_clones(sigs)
    assert len(clones) >= 1
