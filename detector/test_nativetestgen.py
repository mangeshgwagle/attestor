#!/usr/bin/env python3
"""Tests for nativetestgen.py -- C/C++ test-harness scaffolding. Offline."""
import os
import shutil
import subprocess
import tempfile
import unittest

import nativetestgen as tg


class ExtractTests(unittest.TestCase):
    def test_finds_functions_and_signatures(self):
        src = "int add(int a, int b) {\n    return a + b;\n}\nvoid go(char *p) {\n    (void)p;\n}\n"
        funcs = {name: (ret, params) for ret, name, params in tg.functions(src, "c")}
        self.assertIn("add", funcs)
        self.assertIn("go", funcs)
        self.assertEqual(funcs["add"][0], "int")
        self.assertEqual(funcs["add"][1], [("int", "a", ""), ("int", "b", "")])

    def test_skips_control_keywords_and_main(self):
        src = "int main(void) {\n    if (1) {\n        return 0;\n    }\n    return 0;\n}\n"
        names = {name for _r, name, _p in tg.functions(src, "c")}
        self.assertNotIn("main", names)
        self.assertNotIn("if", names)

    def test_ignores_signatures_inside_strings(self):
        src = 'void real(void) {\n    const char *s = "int fake(int x) {";\n}\n'
        names = {name for _r, name, _p in tg.functions(src, "c")}
        self.assertEqual(names, {"real"})


class InitTests(unittest.TestCase):
    def test_c_initialisers(self):
        self.assertEqual(tg._init_for("int", "c"), "0")
        self.assertEqual(tg._init_for("double", "c"), "0.0")
        self.assertEqual(tg._init_for("char *", "c"), "NULL")
        self.assertEqual(tg._init_for("struct Point", "c"), "{0}")

    def test_cpp_pointer_is_nullptr(self):
        self.assertEqual(tg._init_for("Widget *", "cpp"), "nullptr")


class GenerateTests(unittest.TestCase):
    def test_harness_has_a_stub_and_call_per_function(self):
        src = "int add(int a, int b) {\n    return a + b;\n}\n"
        out = tg.generate(src, "math.c", "c")
        self.assertIn("static void test_add(void)", out)
        self.assertIn("int result = add(a, b);", out)
        self.assertIn("test_add();", out)
        self.assertIn("int main(void)", out)

    def test_char_pointer_parameters_get_storage(self):
        src = "void copy(char *dst, const char *src) {\n}\n"
        out = tg.generate(src, "copy.c", "c")
        self.assertIn("char dst_storage[256] = {0};", out)
        self.assertIn("char * dst = dst_storage;", out)
        self.assertIn("const char src_storage[256] = {0};", out)
        self.assertIn("const char * src = src_storage;", out)

    def test_void_function_has_no_result(self):
        src = "void go(int a) {\n    (void)a;\n}\n"
        out = tg.generate(src, "x.c", "c")
        self.assertIn("go(a);", out)
        self.assertNotIn("result = go", out)

    def test_empty_file_is_handled(self):
        out = tg.generate("/* nothing */\n", "x.c", "c")
        self.assertIn("no function definitions found", out)

    def test_include_lines_do_not_corrupt_static_void_signature(self):
        src = "#include <string.h>\nstatic void copy_message(char *dst, const char src[]) {\n}\n"
        funcs = tg.functions(src, "c")
        self.assertEqual(funcs[0][0], "static void")
        out = tg.generate(src, "copy.c", "c")
        self.assertIn("char dst_storage[256] = {0};", out)
        self.assertIn("char * dst = dst_storage;", out)
        self.assertIn("const char src[1] = {0};", out)
        self.assertIn("copy_message(dst, src);", out)
        self.assertNotIn("result = copy_message", out)

    def test_array_parameter_gets_array_storage(self):
        out = tg.generate("void fill(int xs[4]) { xs[0] = 1; }\n", "x.c", "c")
        self.assertIn("int xs[4] = {0};", out)
        self.assertIn("fill(xs);", out)

    def test_unnamed_parameter_gets_a_valid_generated_name(self):
        out = tg.generate("int value(int) { return 1; }\n", "x.cpp", "cpp")
        self.assertIn("int arg0 = 0;", out)
        self.assertIn("value(arg0)", out)
        self.assertNotIn("int int", out)

    def test_overloads_get_unique_stub_names_and_clean_result_types(self):
        src = ("inline int convert(int value) { return value; }\n"
               "inline double convert(double value) { return value; }\n")
        out = tg.generate(src, "x.cpp", "cpp")
        self.assertIn("static void test_convert(void)", out)
        self.assertIn("static void test_convert_2(void)", out)
        self.assertEqual(out.count("test_convert();"), 1)
        self.assertEqual(out.count("test_convert_2();"), 1)
        self.assertNotIn("inline int result", out)

    @unittest.skipUnless(shutil.which("g++") or shutil.which("clang++"),
                         "C++ compiler required for generated-harness regression")
    def test_overloaded_cpp_harness_is_syntax_compilable(self):
        source = ("inline int convert(int value) { return value; }\n"
                  "inline double convert(double value) { return value; }\n")
        harness = tg.generate(source, "x.cpp", "cpp")
        compiler = shutil.which("g++") or shutil.which("clang++")
        with tempfile.TemporaryDirectory() as directory:
            header = os.path.join(directory, "x.h")
            test_file = os.path.join(directory, "test_x.cpp")
            with open(header, "w", encoding="utf-8") as handle:
                handle.write(source)
            with open(test_file, "w", encoding="utf-8") as handle:
                handle.write(harness)
            result = subprocess.run([compiler, "-fsyntax-only", test_file],
                                    capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
