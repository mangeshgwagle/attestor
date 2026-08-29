#!/usr/bin/env python3
"""The blanking rewrite must equal the implementation it replaced, exactly.

Why this test exists
--------------------
`blank_python` and `_comments_python` are not rules. They are what every
Python rule sees instead of the file: strings and comments are replaced by
spaces so that a pattern cannot match inside a docstring. If they change
behaviour by one character, every rule downstream is reading a different file
and the change is invisible until some rule quietly stops firing.

That makes ordinary testing insufficient. A handful of cases would pass while
a rewrite mangled some construct nobody thought of. So the pre-rewrite
implementations are kept here verbatim as the reference, and the live ones are
required to agree with them on every Python file in the tree plus a set of
constructs chosen to be awkward.

The reference is deliberately not imported from `detect`. If it were, this
would compare the new code against itself and pass no matter what.
"""
from __future__ import annotations

import pathlib
import unittest

import detect

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


# ---- the implementations as they stood before the rewrite ----------------- #

def reference_blank_python(text: str) -> list[str]:
    i, n = 0, len(text)
    cur = []
    in_line = False
    triple = None
    single = None
    while i < n:
        c = text[i]
        three = text[i:i + 3]
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1; continue
        if triple:
            if three == triple:
                cur.append("   "); i += 3; triple = None; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if single:
            if c == "\\":
                masked, width = detect._masked_escape(text, i)
                cur.append(masked); i += width; continue
            if c == single:
                cur.append(single); single = None; i += 1; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if c == "#":
            in_line = True; cur.append(" "); i += 1; continue
        if three == '"""' or three == "'''":
            triple = three; cur.append("   "); i += 3; continue
        if c == "'" or c == '"':
            single = c; cur.append(c); i += 1; continue
        cur.append(c); i += 1
    return "".join(cur).split("\n")


def reference_comments_python(text: str) -> list[str]:
    cur, i, n = [], 0, len(text)
    in_line = False
    triple = single = None
    while i < n:
        c = text[i]
        three = text[i:i + 3]
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1; continue
        if triple:
            if three == triple:
                cur.append(three); i += 3; triple = None; continue
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            i += 1; continue
        if single:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            if c == single:
                single = None
            i += 1; continue
        if c == "#":
            cur.append(" "); i += 1; in_line = True; continue
        if three in ('"""', "'''"):
            triple = three; cur.append(three); i += 3; continue
        if c in ("'", '"'):
            single = c
        cur.append(c); i += 1
    return "".join(cur).split("\n")


# Constructs chosen because each one is a plausible way to get this wrong.
AWKWARD = [
    "",
    "\n",
    "x = 1\n",
    "# just a comment\n",
    "# comment with 'quote and \"double\n",
    "s = 'hash # inside a string'\n",
    's = "triple \'\'\' inside a normal string"\n',
    "d = '''a docstring\nover lines\n'''\n",
    'd = """with a # hash and \'single\' quotes"""\n',
    "e = 'escaped \\' quote'\n",
    'e = "escaped \\" quote"\n',
    "t = '''unterminated triple\n",
    "u = 'unterminated single\n",
    "b = 'ends with backslash\\\\'\n",
    "trailing_backslash_at_eof = 'x\\",          # escape runs off the end
    "'''",                                       # a bare triple, nothing else
    '"""',
    "''",
    '""',
    "f = f'{x!r} # not a comment'\n",
    "r = r'\\n raw backslash'\n",
    "nested = '''outer \"\"\" inner still outer'''\n",
    "adjacent = '' '' ''\n",
    "quote_then_eof = '",
    "hash_then_eof = #",
    "crlf = 'x'\r\ny = 2\r\n",
    "tabs\tand\tspaces = '\t'\n",
    "unicode = 'café — dash'\n",
    "empty_triple = ''''''\n",                   # six quotes
    "seven = '''''''\n",
]


def tree_sources() -> list[tuple[str, str]]:
    """Every Python file in the distribution, as (label, text)."""
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        try:
            out.append((str(path.relative_to(ROOT)),
                        path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


class BlankingIsUnchanged(unittest.TestCase):
    def test_awkward_constructs(self):
        for index, text in enumerate(AWKWARD):
            with self.subTest(case=index, text=text[:40]):
                self.assertEqual(detect.blank_python(text),
                                 reference_blank_python(text))
                self.assertEqual(detect._comments_python(text),
                                 reference_comments_python(text))

    def test_every_python_file_in_the_tree(self):
        sources = tree_sources()
        # If this ever collects nothing the test would pass vacuously, which
        # is the failure mode a corpus test is most prone to.
        self.assertGreater(len(sources), 100)
        for label, text in sources:
            with self.subTest(file=label):
                self.assertEqual(detect.blank_python(text),
                                 reference_blank_python(text))
                self.assertEqual(detect._comments_python(text),
                                 reference_comments_python(text))

    def test_prefixes_of_a_hard_file(self):
        """Every prefix, so a rewrite cannot depend on seeing a whole token."""
        text = (HERE / "detect.py").read_text(encoding="utf-8",
                                              errors="replace")[:6000]
        for cut in range(0, len(text), 97):
            chunk = text[:cut]
            with self.subTest(length=cut):
                self.assertEqual(detect.blank_python(chunk),
                                 reference_blank_python(chunk))
                self.assertEqual(detect._comments_python(chunk),
                                 reference_comments_python(chunk))


if __name__ == "__main__":
    unittest.main(verbosity=2)
