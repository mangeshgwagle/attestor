#!/usr/bin/env python3
"""Tests for nativescan.py -- the expanded C/C++/Assembly bug net. Offline."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import nativescan as ns


def rules(src, lang="c", path="t.c"):
    return {f.rule for f in ns.scan_text(src, path, lang)}


class CTests(unittest.TestCase):
    def test_gets_is_critical(self):
        found = ns.scan_text("void f(char *b){ gets(b); }\n", "t.c", "c")
        self.assertEqual(found[0].rule, "native-gets")
        self.assertEqual(found[0].severity, "CRITICAL")

    def test_unsafe_string_functions(self):
        got = rules("void f(char*a,char*b){ strcpy(a,b); strcat(a,b); sprintf(a,\"%d\",1); }\n")
        self.assertIn("native-strcpy", got)
        self.assertIn("native-strcat", got)
        self.assertIn("native-sprintf", got)

    def test_format_string_on_variable(self):
        self.assertIn("native-format-string", rules("void f(char*u){ printf(u); }\n"))

    def test_assignment_in_condition(self):
        self.assertIn("native-assign-in-if", rules("void f(int a,int b){ if (a = b) {} }\n"))

    def test_eq_bool(self):
        self.assertIn("native-eq-bool", rules("void f(int x){ if (x == true) {} }\n"))

    def test_unsigned_underflow_check(self):
        src = ("size_t remaining(size_t capacity, size_t used) {\n"
               "  size_t left = capacity - used;\n"
               "  if (left < 0) return 0;\n"
               "  return left;\n"
               "}\n")
        self.assertIn("native-unsigned-underflow-check", rules(src))

    def test_signed_overflow_check(self):
        self.assertIn("native-signed-overflow-check",
                      rules("int f(int x){ return x + 1 < x; }\n"))

    def test_strict_aliasing_cast(self):
        self.assertIn("native-strict-aliasing-cast",
                      rules("int f(void){ int x=0; return *(float *)&x; }\n"))

    def test_keywords_in_string_are_ignored(self):
        # gets/strcpy live in a string literal -> blanked, not flagged
        got = rules('const char *s = "gets strcpy sprintf system";\n')
        self.assertEqual(got, set())

    def test_scanf_literal_width_is_understood(self):
        unsafe = rules('void f(char *b){ scanf("%s", b); }\n')
        safe = rules('void f(char *b){ scanf("%31s", b); }\n')
        comment = rules('// scanf("%s", b);\nint ok(void){ return 1; }\n')
        self.assertIn("native-scanf-unbounded", unsafe)
        self.assertNotIn("native-scanf-unbounded", safe)
        self.assertNotIn("native-scanf-unbounded", comment)

    def test_multiline_fscanf_is_detected(self):
        src = 'void f(FILE *in, char *b){\n  fscanf(\n    in,\n    "%s",\n    b);\n}\n'
        self.assertIn("native-scanf-unbounded", rules(src))

    def test_sizeof_pointer_rule_distinguishes_arrays(self):
        pointer = rules("void clear(char *p){ memset(p, 0, sizeof(p)); }\n")
        array = rules("void clear(void){ char a[32]; memset(a, 0, sizeof(a)); }\n")
        array_param = rules("void clear(char a[32]){ memset(a, 0, sizeof(a)); }\n")
        multiplication = rules(
            "void clear(char a[32], int p){ int x = 2; int y = x * p; "
            "memset(a, 0, sizeof(p)); (void)y; }\n")
        self.assertIn("native-memset-sizeof-ptr", pointer)
        self.assertNotIn("native-memset-sizeof-ptr", array)
        self.assertIn("native-memset-sizeof-ptr", array_param)
        self.assertNotIn("native-memset-sizeof-ptr", multiplication)

    def test_clean_c_is_silent(self):
        src = "int add(int a, int b) {\n    return a + b;\n}\n"
        self.assertEqual(rules(src), set())

    def test_min_severity_filters(self):
        src = "void f(char*a,char*b){ strcpy(a,b); if(a==true){} }\n"  # HIGH + LOW
        high_only = ns.scan(_tmp(src), min_severity="HIGH")
        self.assertTrue(all(f.severity in ("CRITICAL", "HIGH") for f in high_only))
        self.assertTrue(any(f.rule == "native-strcpy" for f in high_only))


class CppTests(unittest.TestCase):
    def test_using_namespace(self):
        self.assertIn("native-using-namespace-header",
                      rules("using namespace std;\n", "cpp", "t.cpp"))

    def test_delete_this(self):
        self.assertIn("native-delete-this",
                      rules("void C::f(){ delete this; }\n", "cpp", "t.cpp"))

    def test_map_operator_lookup_inserts(self):
        src = ("#include <map>\n"
               "void f(){ std::map<int, int> counts; if (counts[3] == 0) {} }\n")
        self.assertIn("native-cpp-map-operator-insert", rules(src, "cpp", "t.cpp"))

    def test_vector_value_push_slices_derived(self):
        src = ("#include <vector>\n"
               "struct Shape { virtual int area() const { return 0; } };\n"
               "struct Circle : Shape { int area() const override { return 1; } };\n"
               "void f(){ std::vector<Shape> shapes; shapes.push_back(Circle{}); }\n")
        self.assertIn("native-cpp-object-slicing", rules(src, "cpp", "t.cpp"))

    def test_c_only_rule_does_not_fire_for_cpp_extras(self):
        # a C++-only rule must not fire on plain C
        self.assertNotIn("native-using-namespace-header",
                         rules("int x = 1;\n", "c", "t.c"))


class AsmTests(unittest.TestCase):
    # Well-formed otherwise, so each test isolates the one thing it is about.
    NOTE = '.section .note.GNU-stack,"",@progbits\n'

    def rules(self, src):
        return sorted({f.rule for f in ns.scan_text(src, "t.s", "asm")})

    def test_duplicate_label(self):
        src = ("start:\n    nop\nloop:\n    jmp loop\n    pop %rbp\nloop:\n"
               "    ret\n" + self.NOTE)
        self.assertIn("native-asm-duplicate-label", self.rules(src))

    def test_unique_labels_are_clean(self):
        src = "start:\n    nop\ndone:\n    ret\n" + self.NOTE
        self.assertEqual(self.rules(src), [])

    # -- executable stack ------------------------------------------------- #
    def test_missing_gnu_stack_note_is_reported(self):
        # Omitting it makes the linker mark the stack executable for the whole
        # program, not just this object.
        src = "start:\n    call helper\n    ret\n"
        self.assertIn("native-asm-exec-stack", self.rules(src))

    def test_the_note_silences_it(self):
        src = "start:\n    call helper\n    ret\n" + self.NOTE
        self.assertNotIn("native-asm-exec-stack", self.rules(src))

    def test_a_data_only_object_is_left_alone(self):
        # No instructions means no stack to mark.
        src = ".data\nmsg:\n    .asciz \"hello\"\n"
        self.assertEqual(self.rules(src), [])

    # -- prologue that is never unwound ----------------------------------- #
    def test_pushes_never_popped_before_ret_are_reported(self):
        src = ("f:\n    push %rbp\n    mov %rsp, %rbp\n    call helper\n"
               "    ret\n" + self.NOTE)
        self.assertIn("native-asm-stack-imbalance", self.rules(src))

    def test_a_matching_pop_is_clean(self):
        src = ("f:\n    push %rbp\n    mov %rsp, %rbp\n    call helper\n"
               "    pop %rbp\n    ret\n" + self.NOTE)
        self.assertNotIn("native-asm-stack-imbalance", self.rules(src))

    def test_leave_counts_as_restoring_the_frame(self):
        src = ("f:\n    push %rbp\n    mov %rsp, %rbp\n    sub $32, %rsp\n"
               "    leave\n    ret\n" + self.NOTE)
        self.assertNotIn("native-asm-stack-imbalance", self.rules(src))

    def test_an_explicit_stack_pointer_restore_is_clean(self):
        src = ("f:\n    push %rbp\n    sub $16, %rsp\n    add $16, %rsp\n"
               "    ret\n" + self.NOTE)
        self.assertNotIn("native-asm-stack-imbalance", self.rules(src))

    def test_a_label_resets_the_prologue_tracking(self):
        # Pushes before an unrelated label do not belong to this body.
        src = ("f:\n    push %rbp\n    pop %rbp\n    ret\ng:\n    nop\n"
               "    ret\n" + self.NOTE)
        self.assertNotIn("native-asm-stack-imbalance", self.rules(src))

    def test_comments_do_not_create_findings(self):
        src = ("f:\n    push %rbp   # save frame\n    pop %rbp  ; restore\n"
               "    ret\n" + self.NOTE)
        self.assertEqual(self.rules(src), [])


class CliTests(unittest.TestCase):
    def test_missing_and_unsupported_inputs_fail(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "missing.c")
            text = os.path.join(d, "notes.txt")
            with open(text, "w", encoding="utf-8") as handle:
                handle.write("not native source")
            for path, expected in ((missing, "does not exist"),
                                   (text, "unsupported native input")):
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = ns.main([path])
                self.assertEqual(rc, 2)
                self.assertIn(expected, err.getvalue())


def _tmp(src):
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".c")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return [path]


if __name__ == "__main__":
    unittest.main(verbosity=2)
