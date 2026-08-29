#!/usr/bin/env python3
"""
Tests for deepscan.py -- the AST-based "deep understanding" analyzer.

Deterministic and offline. Every check has a positive case (the bug is found)
and the suite asserts clean code stays clean (no false positives), because a
noisy analyzer is a useless one.
"""
import ast
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import deepscan


def rules(src):
    return {f.rule for f in deepscan.analyze(src, "<t>")}


def findings_on(src, rule):
    return [f for f in deepscan.analyze(src, "<t>") if f.rule == rule]


class RareBugTests(unittest.TestCase):
    """The tiny, rarely-caught ones -- deepscan's headline act."""

    def test_assert_tuple_always_true(self):
        src = "def f(x):\n    assert (x > 0, 'must be positive')\n"
        self.assertIn("assert-tuple", rules(src))

    def test_assert_plain_is_fine(self):
        src = "def f(x):\n    assert x > 0, 'must be positive'\n"
        self.assertNotIn("assert-tuple", rules(src))

    def test_empty_assert_tuple_not_flagged(self):
        # assert () is falsy -> not the "always true" trap
        self.assertNotIn("assert-tuple", rules("assert ()\n"))

    def test_return_in_finally(self):
        src = ("def f():\n"
               "    try:\n        return 1\n"
               "    finally:\n        return 2\n")
        self.assertIn("return-in-finally", rules(src))

    def test_break_in_finally(self):
        src = ("for i in range(3):\n"
               "    try:\n        pass\n"
               "    finally:\n        break\n")
        self.assertIn("return-in-finally", rules(src))

    def test_return_in_finally_nested_func_is_ok(self):
        # a return inside a def *inside* finally is legitimate
        src = ("def outer():\n"
               "    try:\n        pass\n"
               "    finally:\n"
               "        def inner():\n            return 1\n"
               "        inner()\n")
        self.assertNotIn("return-in-finally", rules(src))

    def test_dict_duplicate_key(self):
        self.assertIn("dict-duplicate-key", rules("d = {'a': 1, 'a': 2}\n"))

    def test_dict_distinct_keys_ok(self):
        self.assertNotIn("dict-duplicate-key", rules("d = {'a': 1, 'b': 2}\n"))

    def test_redefined_function(self):
        src = "def f():\n    pass\n\ndef f():\n    pass\n"
        self.assertIn("redefined-function", rules(src))

    def test_property_setter_not_redefinition(self):
        # decorated same-name methods (property/setter) are legitimate
        src = ("class C:\n"
               "    @property\n    def x(self):\n        return 1\n"
               "    @x.setter\n    def x(self, v):\n        self._x = v\n")
        self.assertNotIn("redefined-function", rules(src))

    def test_self_comparison(self):
        self.assertIn("self-comparison", rules("def f(a):\n    return a == a\n"))

    def test_not_equal_self_is_nan_idiom(self):
        # x != x is the classic NaN check -- must NOT be flagged
        self.assertNotIn("self-comparison", rules("def f(a):\n    return a != a\n"))


    def test_list_multiply_alias(self):
        self.assertIn("list-multiply-alias", rules("matrix = [[0] * 3] * 4\n"))

    def test_dataclass_mutable_default(self):
        src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    items: list = []\n"
        self.assertIn("dataclass-mutable-default", rules(src))

    def test_mutable_class_attribute(self):
        src = "class C:\n    cache = {}\n"
        self.assertIn("mutable-class-attribute", rules(src))

    def test_late_binding_closure(self):
        src = "funcs = []\nfor i in range(3):\n    funcs.append(lambda: i)\n"
        self.assertIn("late-binding-closure", rules(src))

    def test_late_binding_bound_default_is_ok(self):
        src = "funcs = []\nfor i in range(3):\n    funcs.append(lambda i=i: i)\n"
        self.assertNotIn("late-binding-closure", rules(src))


    def test_call_default(self):
        src = "import time\ndef stamp(now=time.time()):\n    return now\n"
        self.assertIn("call-default", rules(src))

    def test_exception_var_leak(self):
        src = "try:\n    1 / 0\nexcept ZeroDivisionError as e:\n    pass\nprint(e)\n"
        self.assertIn("exception-var-leak", rules(src))

    def test_return_value_in_init(self):
        src = "class C:\n    def __init__(self):\n        return 3\n"
        self.assertIn("return-value-in-init", rules(src))

    def test_return_in_nested_function_inside_init_is_ok(self):
        src = ("class C:\n"
               "    def __init__(self):\n"
               "        def build():\n            return 3\n"
               "        self.value = build()\n")
        self.assertNotIn("return-value-in-init", rules(src))

    def test_async_runtime_traps(self):
        src = "import asyncio, time\nasync def child():\n    return 1\nasync def parent():\n    child()\n    asyncio.run(child())\n    time.sleep(1)\n"
        got = rules(src)
        self.assertIn("unawaited-coroutine", got)
        self.assertIn("asyncio-run-in-async", got)
        self.assertIn("blocking-sleep-in-async", got)

    def test_async_await_is_ok(self):
        src = "async def child():\n    return 1\nasync def parent():\n    return await child()\n"
        self.assertNotIn("unawaited-coroutine", rules(src))

    def test_sync_nested_function_is_not_treated_as_async_body(self):
        src = ("import time\nasync def outer():\n"
               "    def blocking_helper():\n        time.sleep(1)\n"
               "    blocking_helper()\n")
        self.assertNotIn("blocking-sleep-in-async", rules(src))


class CommonBugTests(unittest.TestCase):
    """The everyday ones regex can miss once scope matters."""

    def test_undefined_name(self):
        src = "def f():\n    return total\n"
        self.assertIn("undefined-name", rules(src))

    def test_defined_name_ok(self):
        src = "def f():\n    total = 1\n    return total\n"
        self.assertNotIn("undefined-name", rules(src))

    def test_local_in_another_function_does_not_define_this_scope(self):
        src = ("def producer():\n    total = 1\n    return total\n\n"
               "def consumer():\n    return total\n")
        found = findings_on(src, "undefined-name")
        self.assertEqual([(f.line, "total" in f.message) for f in found], [(6, True)])

    def test_nested_function_can_close_over_enclosing_local(self):
        src = ("def outer():\n    total = 1\n"
               "    def inner():\n        return total\n"
               "    return inner\n")
        self.assertNotIn("undefined-name", rules(src))

    def test_global_assignment_is_a_binding_for_that_function(self):
        src = "def initialize():\n    global total\n    total = 1\n    return total\n"
        self.assertNotIn("undefined-name", rules(src))

    def test_explicit_global_assignment_is_visible_to_other_functions(self):
        src = ("def initialize():\n    global total\n    total = 1\n\n"
               "def read():\n    return total\n")
        self.assertNotIn("undefined-name", rules(src))

    def test_method_does_not_treat_class_attribute_as_bare_local(self):
        src = "class Counter:\n    value = 1\n    def read(self):\n        return value\n"
        self.assertIn("undefined-name", rules(src))

    def test_comprehension_target_does_not_leak(self):
        src = "items = [item for item in ()]\nprint(item)\n"
        self.assertIn("undefined-name", rules(src))

    def test_except_as_binding_is_defined(self):
        # 'except X as e' binds e -- must not be reported undefined
        src = ("def f():\n    try:\n        pass\n"
               "    except ValueError as e:\n        return str(e)\n")
        self.assertNotIn("undefined-name", rules(src))

    def test_annotations_dont_trip_undefined(self):
        src = "def f(x: int) -> bool:\n    return x > 0\n"
        self.assertNotIn("undefined-name", rules(src))

    def test_annotated_assignment_forward_reference_is_accepted(self):
        self.assertNotIn("undefined-name", rules("value: FutureType = 1\n"))

    def test_exec_disables_undefined_check(self):
        # dynamic name injection -> we bail rather than false-positive
        src = "def f():\n    exec('y = 1')\n    return y\n"
        self.assertNotIn("undefined-name", rules(src))

    def test_unreachable_after_return(self):
        src = "def f():\n    return 1\n    x = 2\n"
        self.assertIn("unreachable-code", rules(src))

    def test_mutable_default(self):
        self.assertIn("mutable-default", rules("def f(x=[]):\n    return x\n"))

    def test_none_default_ok(self):
        self.assertNotIn("mutable-default", rules("def f(x=None):\n    return x\n"))

    def test_bare_except(self):
        src = "try:\n    pass\nexcept:\n    pass\n"
        self.assertIn("bare-except", rules(src))

    def test_unordered_except(self):
        src = ("try:\n    pass\n"
               "except Exception:\n    pass\n"
               "except ValueError:\n    pass\n")
        self.assertIn("except-unordered", rules(src))

    def test_ordered_except_ok(self):
        src = ("try:\n    pass\n"
               "except ValueError:\n    pass\n"
               "except Exception:\n    pass\n")
        self.assertNotIn("except-unordered", rules(src))

    def test_exception_tuple_members_do_not_shadow_each_other(self):
        src = ("try:\n    pass\n"
               "except (OSError, PermissionError, ValueError):\n    pass\n")
        self.assertNotIn("except-unordered", rules(src))

    def test_full_builtin_exception_hierarchy_is_understood(self):
        src = ("try:\n    b'x'.decode('utf-8')\n"
               "except UnicodeError:\n    pass\n"
               "except UnicodeDecodeError:\n    pass\n")
        self.assertIn("except-unordered", rules(src))

    def test_is_literal(self):
        self.assertIn("is-literal", rules("def f(x):\n    return x is 3\n"))

    def test_float_equality(self):
        self.assertIn("float-equality", rules("def f(x):\n    return x == 0.5\n"))

    def test_unused_import(self):
        self.assertIn("unused-import", rules("import os\nx = 1\n"))

    def test_used_import_ok(self):
        self.assertNotIn("unused-import", rules("import os\nos.getcwd()\n"))

    def test_star_import_suppresses_unused(self):
        # can't reason about names a star-import may provide
        self.assertNotIn("unused-import", rules("from os import *\nimport sys\n"))

    def test_shadow_builtin(self):
        self.assertIn("shadow-builtin", rules("list = [1, 2, 3]\n"))


class SyntaxAndStructureTests(unittest.TestCase):
    def test_syntax_error_reported_once(self):
        fs = deepscan.analyze("def f(:\n    pass\n", "<t>")
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].rule, "syntax-error")

    def test_complexity_counts_branches(self):
        tree = ast.parse("def f(x):\n    if x:\n        return 1\n    return 2\n")
        fn = tree.body[0]
        self.assertEqual(deepscan.complexity(fn), 2)   # base 1 + one if

    def test_explain_describes_structure(self):
        src = ('"""Module doc."""\n'
               "import os\n\n"
               "def helper():\n    return os.getcwd()\n\n"
               "def main():\n    return helper()\n")
        text = deepscan.explain(src, "sample.py")
        self.assertIn("how sample.py works", text)
        self.assertIn("Module doc.", text)
        self.assertIn("def helper", text)
        self.assertIn("main -> helper", text)   # call graph edge

    def test_explain_handles_syntax_error(self):
        text = deepscan.explain("def (:\n", "broken.py")
        self.assertIn("cannot parse", text)

    def test_cli_missing_and_unsupported_inputs_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing.py")
            unsupported = os.path.join(directory, "notes.txt")
            with open(unsupported, "w", encoding="utf-8") as handle:
                handle.write("plain text")
            for path, expected in ((missing, "does not exist"),
                                   (unsupported, "unsupported input type")):
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = deepscan.main([path])
                self.assertEqual(rc, 2)
                self.assertIn(expected, err.getvalue())


class NoFalsePositiveTests(unittest.TestCase):
    CLEAN = '''\
"""A correct module: deepscan must stay silent."""
import math


def area(radius):
    """Circle area."""
    return math.pi * radius * radius


def totals(items, acc=None):
    if acc is None:
        acc = []
    for it in items:
        acc.append(it * 2)
    return acc


class Counter:
    def __init__(self, start=0):
        self.value = start

    def bump(self, by=1):
        self.value += by
        return self.value
'''

    def test_clean_code_has_zero_findings(self):
        self.assertEqual(deepscan.analyze(self.CLEAN, "clean.py"), [])

    def test_detector_modules_have_no_high_findings(self):
        # deepscan must not cry wolf on the real codebase it ships with
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        for mod in ("detect.py", "online.py", "personalities.py", "attestor.py",
                    "codegen.py", "harvest.py", "deepscan.py"):
            with open(os.path.join(here, mod), encoding="utf-8") as fh:
                src = fh.read()
            highs = [f for f in deepscan.analyze(src, mod) if f.severity == "HIGH"]
            self.assertEqual(highs, [], f"{mod} produced HIGH false positives: {highs}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
