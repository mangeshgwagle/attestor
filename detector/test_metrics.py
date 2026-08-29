#!/usr/bin/env python3
"""
Tests for metrics.py -- the maintainability engine (complexity/nesting/len/args).

Deterministic and offline. Each measurement has explicit expected numbers so the
counting rules are pinned down, and the flagging/exit-code path is covered.
"""
import io
import unittest
from contextlib import redirect_stdout

import metrics


def by_name(src):
    return {m.qualname: m for m in metrics.analyze_source(src, "<t>")}


class ComplexityTests(unittest.TestCase):
    def test_straight_line_is_one(self):
        m = by_name("def f(a, b):\n    x = a + b\n    return x\n")["f"]
        self.assertEqual(m.complexity, 1)

    def test_each_branch_adds_one(self):
        src = ("def f(x):\n"
               "    if x > 0:\n"
               "        return 1\n"
               "    elif x < 0:\n"
               "        return -1\n"
               "    return 0\n")
        # base 1 + if + elif = 3
        self.assertEqual(by_name(src)["f"].complexity, 3)

    def test_loops_and_except_count(self):
        src = ("def f(xs):\n"
               "    for x in xs:\n"
               "        while x:\n"
               "            x -= 1\n"
               "    try:\n"
               "        g()\n"
               "    except ValueError:\n"
               "        pass\n")
        # base 1 + for + while + except = 4
        self.assertEqual(by_name(src)["f"].complexity, 4)

    def test_boolean_operators_count_each_extra_operand(self):
        src = "def f(a, b, c):\n    return a and b and c or a\n"
        # base 1 + (and: 3 values -> 2) + (or: 2 values -> 1) = 4
        self.assertEqual(by_name(src)["f"].complexity, 4)

    def test_ternary_and_comprehension_if_count(self):
        src = ("def f(xs):\n"
               "    y = 1 if xs else 0\n"
               "    return [x for x in xs if x if x > 1]\n")
        # base 1 + ternary + two comprehension ifs = 4
        self.assertEqual(by_name(src)["f"].complexity, 4)

    def test_match_cases_count(self):
        src = ("def f(x):\n"
               "    match x:\n"
               "        case 1:\n"
               "            return 'a'\n"
               "        case 2:\n"
               "            return 'b'\n"
               "        case _:\n"
               "            return 'z'\n")
        # base 1 + three cases = 4
        self.assertEqual(by_name(src)["f"].complexity, 4)

    def test_assert_and_plain_else_do_not_count(self):
        src = ("def f(x):\n"
               "    assert x\n"
               "    if x:\n"
               "        return 1\n"
               "    else:\n"
               "        return 2\n")
        # base 1 + if = 2 (assert and else add no path)
        self.assertEqual(by_name(src)["f"].complexity, 2)


class ScopeTests(unittest.TestCase):
    def test_nested_function_is_measured_separately(self):
        src = ("def outer(a):\n"
               "    def inner(b):\n"
               "        if b:\n"
               "            return 1\n"
               "        return 0\n"
               "    return inner(a)\n")
        got = by_name(src)
        self.assertIn("outer", got)
        self.assertIn("outer.inner", got)
        # inner's branch must NOT inflate outer
        self.assertEqual(got["outer"].complexity, 1)
        self.assertEqual(got["outer.inner"].complexity, 2)

    def test_methods_get_qualified_names(self):
        src = ("class C:\n"
               "    def m(self, x):\n"
               "        return x\n")
        got = by_name(src)
        self.assertIn("C.m", got)
        self.assertEqual(got["C.m"].args, 2)   # self + x

    def test_async_functions_are_measured(self):
        src = "async def go(x):\n    if x:\n        return await x\n    return None\n"
        self.assertEqual(by_name(src)["go"].complexity, 2)


class ShapeTests(unittest.TestCase):
    def test_length_spans_the_def(self):
        src = "def f(a):\n    x = 1\n    y = 2\n    return x + y\n"
        self.assertEqual(by_name(src)["f"].length, 4)

    def test_nesting_depth_flat_is_zero(self):
        self.assertEqual(by_name("def f():\n    return 1\n")["f"].nesting, 0)

    def test_nesting_depth_counts_deepest_block(self):
        src = ("def f(xs):\n"
               "    for x in xs:\n"
               "        if x:\n"
               "            while x:\n"
               "                x -= 1\n")
        # for(1) -> if(2) -> while(3)
        self.assertEqual(by_name(src)["f"].nesting, 3)

    def test_elif_chain_is_not_extra_nesting(self):
        src = ("def f(x):\n"
               "    if x == 1:\n"
               "        return 1\n"
               "    elif x == 2:\n"
               "        return 2\n"
               "    elif x == 3:\n"
               "        return 3\n")
        # all arms share one level despite AST nesting elif in orelse
        self.assertEqual(by_name(src)["f"].nesting, 1)

    def test_arg_count_includes_varargs_and_kwargs(self):
        src = "def f(a, b, *args, c, **kw):\n    return a\n"
        self.assertEqual(by_name(src)["f"].args, 5)   # a, b, *args, c, **kw


class ReportingTests(unittest.TestCase):
    def test_syntax_error_yields_no_metrics(self):
        self.assertEqual(metrics.analyze_source("def f(:\n"), [])

    def test_exceeded_lists_the_blown_limits(self):
        src = "def f(a, b, c, d, e, f, g):\n    return 1\n"   # 7 args
        m = by_name(src)["f"]
        self.assertIn("args", m.exceeded(metrics.DEFAULT_LIMITS))
        self.assertNotIn("complexity", m.exceeded(metrics.DEFAULT_LIMITS))

    def test_exit_code_is_number_of_flagged_functions(self):
        # one clean function, one over the complexity limit
        gnarly = "def bad(x):\n" + "".join(
            "    if x == %d:\n        return %d\n" % (i, i) for i in range(12))
        src = "def ok():\n    return 1\n" + gnarly
        path = _tmpfile(src)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = metrics.main([path])
        self.assertEqual(rc, 1)                      # exactly one flagged
        self.assertIn("bad", buf.getvalue())

    def test_top_flag_ignores_thresholds(self):
        src = "def a():\n    return 1\n\ndef b():\n    return 2\n"
        path = _tmpfile(src)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = metrics.main([path, "--top", "2"])
        self.assertEqual(rc, 0)                       # --top never flags
        self.assertIn("top 2 by cognitive complexity", buf.getvalue())

    def test_json_output_is_valid(self):
        import json
        path = _tmpfile("def f(x):\n    return x\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            metrics.main([path, "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["qualname"], "f")
        self.assertIn("over", data[0])


class CognitiveTests(unittest.TestCase):
    def test_straight_line_is_zero(self):
        self.assertEqual(by_name("def f(x):\n    y = x + 1\n    return y\n")["f"].cognitive, 0)

    def test_single_if_is_one(self):
        self.assertEqual(by_name("def f(x):\n    if x:\n        return 1\n")["f"].cognitive, 1)

    def test_canonical_sonar_example_is_nine(self):
        # SonarSource's documented worked example scores 9.
        src = ("def m(c1, c2, c3):\n"
               "    try:\n"
               "        if c1:\n"
               "            for i in range(10):\n"
               "                while c2:\n"
               "                    pass\n"
               "    except Exception:\n"
               "        if c3:\n"
               "            pass\n")
        self.assertEqual(by_name(src)["m"].cognitive, 9)

    def test_boolean_sequence_counts_each_switch(self):
        # `and` chain = +1, switching to `or` = +1; the if itself = +1 -> 3
        src = "def f(a, b, c):\n    if a and b and c or a:\n        return 1\n"
        self.assertEqual(by_name(src)["f"].cognitive, 3)

    def test_elif_chain_is_flat(self):
        src = ("def f(x):\n"
               "    if x == 1:\n        return 1\n"
               "    elif x == 2:\n        return 2\n"
               "    elif x == 3:\n        return 3\n")
        self.assertEqual(by_name(src)["f"].cognitive, 3)   # 1 + 1 + 1, no nesting

    def test_nesting_costs_more_than_flat_at_equal_cyclomatic(self):
        flat = by_name("def f(a, b):\n    if a:\n        pass\n    if b:\n        pass\n")["f"]
        nested = by_name("def f(a, b):\n    if a:\n        if b:\n            pass\n")["f"]
        self.assertEqual(flat.complexity, nested.complexity)   # cyclomatic: both 3
        self.assertLess(flat.cognitive, nested.cognitive)      # cognitive: 2 < 3
        self.assertEqual(flat.cognitive, 2)
        self.assertEqual(nested.cognitive, 3)

    def test_nested_function_measured_separately(self):
        src = ("def outer(x):\n"
               "    def inner(y):\n"
               "        if y:\n            return 1\n"
               "        return 0\n"
               "    return inner(x)\n")
        got = by_name(src)
        self.assertEqual(got["outer"].cognitive, 0)     # inner's branch stays out
        self.assertEqual(got["outer.inner"].cognitive, 1)


def _tmpfile(src):
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".py")
    import os
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
