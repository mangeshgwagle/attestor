#!/usr/bin/env python3
"""Deterministic code migration / modernization engine for Owen.

Detects outdated code patterns and transforms them into modern equivalents.
Same registry architecture as poc_gen42 / patch_gen42 — each migration is
a registered transform with a detector, a rewriter, and a regression test.

Usage:
    engine = MigrationEngine()
    results = engine.scan_file("app.py")
    for r in results:
        print(r.original, "->", r.replacement)
        print(r.test_code)
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

VERSION = "4.2"

# =========================================================================== #
#  DATA TYPES                                                                  #
# =========================================================================== #

class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    TYPESCRIPT = "typescript"
    CSS = "css"
    GENERAL = "general"


class MigrationCategory(Enum):
    SYNTAX_MODERNIZATION = auto()
    API_UPGRADE = auto()
    IDIOM_UPDATE = auto()
    PERFORMANCE = auto()
    STYLE = auto()
    FRAMEWORK_MIGRATION = auto()


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MigrationRule:
    rule_id: str
    name: str
    language: Language
    category: MigrationCategory
    description: str
    source_pattern: str
    detector: Callable
    transformer: Callable
    confidence: Confidence = Confidence.HIGH
    breaking: bool = False
    references: list[str] = field(default_factory=list)


@dataclass
class MigrationMatch:
    rule: MigrationRule
    file_path: str
    line: int
    original: str
    replacement: str
    test_code: str = ""
    confidence: Confidence = Confidence.HIGH

    @property
    def match_id(self) -> str:
        raw = "%s:%s:%d" % (self.rule.rule_id, self.file_path, self.line)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class MigrationReport:
    file_path: str
    matches: list[MigrationMatch] = field(default_factory=list)
    lines_before: int = 0
    lines_after: int = 0

    @property
    def total_migrations(self) -> int:
        return len(self.matches)

    def by_category(self) -> dict[str, list[MigrationMatch]]:
        groups: dict[str, list[MigrationMatch]] = {}
        for m in self.matches:
            name = m.rule.category.name
            groups.setdefault(name, []).append(m)
        return groups


# =========================================================================== #
#  REGISTRY                                                                    #
# =========================================================================== #

_REGISTRY: dict[str, MigrationRule] = {}


def migration(rule_id: str, name: str, language: Language,
              category: MigrationCategory, description: str,
              source_pattern: str = "",
              confidence: Confidence = Confidence.HIGH,
              breaking: bool = False):
    def decorator(func):
        parts = func.__name__.split("__", 1)
        detector_fn = func
        transformer_fn = getattr(func, '_transformer', None)

        rule = MigrationRule(
            rule_id=rule_id, name=name, language=language,
            category=category, description=description,
            source_pattern=source_pattern,
            detector=detector_fn,
            transformer=transformer_fn or detector_fn,
            confidence=confidence, breaking=breaking,
        )
        _REGISTRY[rule_id] = rule
        func._rule = rule
        return func
    return decorator


def get_rule(rule_id: str) -> MigrationRule | None:
    return _REGISTRY.get(rule_id)


def list_rules() -> list[MigrationRule]:
    return list(_REGISTRY.values())


def rules_for_language(lang: Language) -> list[MigrationRule]:
    return [r for r in _REGISTRY.values()
            if r.language == lang or r.language == Language.GENERAL]


# =========================================================================== #
#  PYTHON MIGRATIONS                                                           #
# =========================================================================== #

_PY_PRINT_STMT = re.compile(
    r'^(\s*)print\s+(?![\s(])(.+)$')

@migration("py-print-func", "Print statement to function",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert Python 2 print statements to print() function calls",
           source_pattern=r'print "hello"')
def py_print_func(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_PRINT_STMT.match(line)
    if not m:
        return None
    indent, args = m.group(1), m.group(2).rstrip()
    if args.startswith(">>"):
        parts = args.split(",", 1)
        if len(parts) == 2:
            dest = parts[0].replace(">>", "").strip()
            msg = parts[1].strip()
            replacement = "%sprint(%s, file=%s)" % (indent, msg, dest)
        else:
            return None
    else:
        replacement = "%sprint(%s)" % (indent, args)

    test = (
        'import unittest\n'
        'class TestPrintMigration(unittest.TestCase):\n'
        '    def test_print_is_function(self):\n'
        '        """Verify print() works as function call."""\n'
        '        import io, sys\n'
        '        buf = io.StringIO()\n'
        '        sys.stdout = buf\n'
        '        %s\n'
        '        sys.stdout = sys.__stdout__\n'
        '        self.assertGreater(len(buf.getvalue()), 0)\n'
    ) % replacement.strip()

    return MigrationMatch(
        rule=_REGISTRY["py-print-func"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
        test_code=test,
    )


_PY_PCT_FORMAT = re.compile(
    r"""(['"])((?:[^'"]|(?!\1).)*?%(?:s|d|f|r|x|o|e|g|i|c|(?:\d+(?:\.\d+)?[sdfxoe]))(?:[^'"]|(?!\1).)*?)\1\s*%\s*(.+)$""")

@migration("py-fstring", "%-format to f-string",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert %-style string formatting to f-strings",
           source_pattern=r'"hello %s" % name')
def py_fstring(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_PCT_FORMAT.search(line)
    if not m:
        return None
    quote = m.group(1)
    fmt_str = m.group(2)
    args_str = m.group(3).rstrip()

    if args_str.startswith("(") and args_str.endswith(")"):
        inner = args_str[1:-1]
        args = [a.strip() for a in _split_args(inner)]
    else:
        args = [args_str]

    specs = re.findall(r'%(?:\d+(?:\.\d+)?)?([sdrfxoeigc])', fmt_str)
    if len(specs) != len(args):
        return None

    new_str = fmt_str
    for arg in args:
        new_str = re.sub(r'%(?:\d+(?:\.\d+)?)?[sdrfxoeigc]',
                         '{%s}' % arg, new_str, count=1)

    full_match = m.group(0)
    replacement = line.replace(full_match, 'f%s%s%s' % (quote, new_str, quote))

    test = (
        'import unittest\n'
        'class TestFStringMigration(unittest.TestCase):\n'
        '    def test_fstring_equivalent(self):\n'
        '        """Verify f-string produces same output as %%-format."""\n'
        '        name = "test"\n'
        '        val = 42\n'
        '        old = %s\n'
        '        new = %s\n'
        '        self.assertEqual(old, new)\n'
    ) % (full_match, 'f%s%s%s' % (quote, new_str, quote))

    return MigrationMatch(
        rule=_REGISTRY["py-fstring"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
        test_code=test,
    )


def _split_args(s: str) -> list[str]:
    depth = 0
    parts = []
    current = []
    for ch in s:
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


_PY_OSPATH = re.compile(
    r'os\.path\.(join|exists|isfile|isdir|basename|dirname|abspath|splitext|'
    r'getsize|expanduser|realpath)\s*\(')

@migration("py-pathlib", "os.path to pathlib",
           Language.PYTHON, MigrationCategory.API_UPGRADE,
           "Convert os.path calls to pathlib.Path equivalents",
           source_pattern=r'os.path.join(a, b)',
           confidence=Confidence.MEDIUM)
def py_pathlib(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_OSPATH.search(line)
    if not m:
        return None

    func = m.group(1)
    conversions = {
        "join": "Path(%s)",
        "exists": "Path(%s).exists()",
        "isfile": "Path(%s).is_file()",
        "isdir": "Path(%s).is_dir()",
        "basename": "Path(%s).name",
        "dirname": "Path(%s).parent",
        "abspath": "Path(%s).resolve()",
        "splitext": "Path(%s).stem, Path(%s).suffix",
        "getsize": "Path(%s).stat().st_size",
        "expanduser": "Path(%s).expanduser()",
        "realpath": "Path(%s).resolve()",
    }
    suggestion = conversions.get(func, "")
    if not suggestion:
        return None

    return MigrationMatch(
        rule=_REGISTRY["py-pathlib"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="# Use: from pathlib import Path; %s" % suggestion,
        confidence=Confidence.MEDIUM,
    )


_PY_HASKEY = re.compile(r'(\w+)\.has_key\s*\(\s*(.+?)\s*\)')

@migration("py-dict-in", "dict.has_key() to 'in'",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Replace dict.has_key(k) with k in dict",
           source_pattern=r'd.has_key("x")')
def py_dict_in(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_HASKEY.search(line)
    if not m:
        return None
    dict_name, key = m.group(1), m.group(2)
    old = m.group(0)
    new = "%s in %s" % (key, dict_name)
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["py-dict-in"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_OLDSUPER = re.compile(
    r'super\s*\(\s*(\w+)\s*,\s*self\s*\)')

@migration("py-super", "Old-style super() to super()",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert super(ClassName, self) to super()",
           source_pattern=r'super(MyClass, self).__init__()')
def py_super(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_OLDSUPER.search(line)
    if not m:
        return None
    replacement = line.replace(m.group(0), "super()")

    return MigrationMatch(
        rule=_REGISTRY["py-super"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_OLDEXCEPT = re.compile(
    r'except\s+(\w+(?:\.\w+)*)\s*,\s*(\w+)\s*:')

@migration("py-except-as", "except X, e to except X as e",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert Python 2 except syntax to Python 3 'as' syntax",
           source_pattern=r'except ValueError, e:')
def py_except_as(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_OLDEXCEPT.search(line)
    if not m:
        return None
    exc_type, var = m.group(1), m.group(2)
    old = m.group(0)
    new = "except %s as %s:" % (exc_type, var)
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["py-except-as"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_OLDRAISE = re.compile(
    r'raise\s+(\w+(?:\.\w+)*)\s*,\s*(.+)')

@migration("py-raise", "raise X, msg to raise X(msg)",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert Python 2 raise syntax to Python 3",
           source_pattern=r'raise ValueError, "bad"')
def py_raise(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_OLDRAISE.search(line)
    if not m:
        return None
    exc_type, args = m.group(1), m.group(2).rstrip()
    old = m.group(0)
    new = "raise %s(%s)" % (exc_type, args)
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["py-raise"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_TYPING_OPTIONAL = re.compile(
    r'Optional\[(\w[\w\[\], ]*)\]')

@migration("py-union-pipe", "Optional[X] to X | None",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert typing.Optional[X] to X | None (Python 3.10+)",
           source_pattern=r'Optional[str]',
           confidence=Confidence.MEDIUM)
def py_union_pipe(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_TYPING_OPTIONAL.search(line)
    if not m:
        return None
    inner = m.group(1)
    old = m.group(0)
    new = "%s | None" % inner
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["py-union-pipe"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
        confidence=Confidence.MEDIUM,
    )


_PY_TYPE_COMMENT = re.compile(
    r'^(\s*)(\w+)\s*=\s*(.+?)\s*#\s*type:\s*(\w[\w\[\], |]*)\s*$')

@migration("py-type-annot", "Type comment to annotation",
           Language.PYTHON, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert # type: X comments to proper type annotations",
           source_pattern=r'x = []  # type: List[int]')
def py_type_annot(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_TYPE_COMMENT.match(line)
    if not m:
        return None
    indent, var, value, type_str = m.group(1), m.group(2), m.group(3), m.group(4)
    replacement = "%s%s: %s = %s" % (indent, var, type_str, value)

    return MigrationMatch(
        rule=_REGISTRY["py-type-annot"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_ENUMERATE = re.compile(
    r'for\s+(\w+)\s+in\s+range\s*\(\s*len\s*\(\s*(\w+)\s*\)\s*\)\s*:')

@migration("py-enumerate", "range(len()) to enumerate()",
           Language.PYTHON, MigrationCategory.IDIOM_UPDATE,
           "Convert for i in range(len(x)) to for i, val in enumerate(x)",
           source_pattern=r'for i in range(len(items)):')
def py_enumerate(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_ENUMERATE.search(line)
    if not m:
        return None
    idx_var, collection = m.group(1), m.group(2)
    item_var = "item"
    if collection.endswith("s") and len(collection) > 1:
        item_var = collection[:-1]
    old = m.group(0)
    new = "for %s, %s in enumerate(%s):" % (idx_var, item_var, collection)
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["py-enumerate"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_PY_DICT_COMP = re.compile(
    r'dict\s*\(\s*\[\s*\(\s*(\w+)\s*,\s*(\w+(?:\[.*?\])?)\s*\)\s+for\s+')

@migration("py-dict-comp", "dict([]) to dict comprehension",
           Language.PYTHON, MigrationCategory.IDIOM_UPDATE,
           "Convert dict([(k,v) for ...]) to {k: v for ...}",
           source_pattern=r'dict([(k, v) for k, v in items])')
def py_dict_comp(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_DICT_COMP.search(line)
    if not m:
        return None

    return MigrationMatch(
        rule=_REGISTRY["py-dict-comp"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="# Rewrite as: {k: v for ...} dict comprehension",
        confidence=Confidence.MEDIUM,
    )


_PY_CTX_OPEN = re.compile(
    r'^(\s*)(\w+)\s*=\s*open\s*\((.+)\)\s*$')

@migration("py-with-open", "open() to with-open",
           Language.PYTHON, MigrationCategory.IDIOM_UPDATE,
           "Convert bare open() to with-statement context manager",
           source_pattern=r'f = open("x.txt")')
def py_with_open(line: str, **ctx) -> MigrationMatch | None:
    m = _PY_CTX_OPEN.match(line)
    if not m:
        return None
    indent, var, args = m.group(1), m.group(2), m.group(3)
    replacement = "%swith open(%s) as %s:" % (indent, args, var)

    return MigrationMatch(
        rule=_REGISTRY["py-with-open"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


# =========================================================================== #
#  JAVASCRIPT MIGRATIONS                                                       #
# =========================================================================== #

_JS_VAR = re.compile(r'^(\s*)var\s+(\w+)\s*=\s*(.+)$')

@migration("js-let-const", "var to let/const",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert var declarations to let or const",
           source_pattern=r'var x = 5')
def js_let_const(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_VAR.match(line)
    if not m:
        return None
    indent, name, value = m.group(1), m.group(2), m.group(3)
    keyword = "const"
    replacement = "%s%s %s = %s" % (indent, keyword, name, value)

    return MigrationMatch(
        rule=_REGISTRY["js-let-const"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JS_REQUIRE = re.compile(
    r"""^(\s*)(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$""")

@migration("js-esm-import", "require() to import",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert CommonJS require() to ES module import",
           source_pattern=r'const fs = require("fs")')
def js_esm_import(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_REQUIRE.match(line)
    if not m:
        return None
    indent, name, module = m.group(1), m.group(2), m.group(3)
    replacement = '%simport %s from "%s";' % (indent, name, module)

    return MigrationMatch(
        rule=_REGISTRY["js-esm-import"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JS_REQUIRE_DESTRUCTURE = re.compile(
    r"""^(\s*)(?:const|let|var)\s+\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$""")

@migration("js-esm-named", "Destructured require to named import",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert const { a, b } = require('x') to import { a, b } from 'x'",
           source_pattern=r'const { readFile } = require("fs")')
def js_esm_named(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_REQUIRE_DESTRUCTURE.match(line)
    if not m:
        return None
    indent, names, module = m.group(1), m.group(2).strip(), m.group(3)
    replacement = '%simport { %s } from "%s";' % (indent, names, module)

    return MigrationMatch(
        rule=_REGISTRY["js-esm-named"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JS_MODULE_EXPORTS = re.compile(
    r'^(\s*)module\.exports\s*=\s*(.+)$')

@migration("js-esm-export", "module.exports to export default",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert module.exports to export default",
           source_pattern=r'module.exports = MyClass')
def js_esm_export(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_MODULE_EXPORTS.match(line)
    if not m:
        return None
    indent, value = m.group(1), m.group(2).rstrip().rstrip(";")
    replacement = "%sexport default %s;" % (indent, value)

    return MigrationMatch(
        rule=_REGISTRY["js-esm-export"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JS_CALLBACK = re.compile(
    r'function\s*\(\s*(\w*)\s*\)\s*\{')

@migration("js-arrow", "function() to arrow function",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert anonymous function expressions to arrow functions",
           source_pattern=r'function(x) { return x; }',
           confidence=Confidence.MEDIUM)
def js_arrow(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_CALLBACK.search(line)
    if not m:
        return None
    if re.match(r'^\s*function\s+\w+', line):
        return None
    param = m.group(1)
    old = m.group(0)
    if param:
        new = "(%s) => {" % param
    else:
        new = "() => {"
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["js-arrow"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
        confidence=Confidence.MEDIUM,
    )


_JS_TEMPLATE = re.compile(
    r"""(['"])([^'"]*?)\1\s*\+\s*(\w+)(?:\s*\+\s*(['"])([^'"]*?)\4)?""")

@migration("js-template-lit", "String concat to template literal",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert string concatenation to template literals",
           source_pattern=r'"Hello " + name + "!"')
def js_template_lit(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_TEMPLATE.search(line)
    if not m:
        return None
    pre = m.group(2)
    var_name = m.group(3)
    post = m.group(5) or ""
    old = m.group(0)
    new = "`%s${%s}%s`" % (pre, var_name, post)
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["js-template-lit"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JS_PROMISE_THEN = re.compile(
    r'\.then\s*\(\s*(?:function\s*\(\s*(\w+)\s*\)|(\w+)\s*=>)')

@migration("js-async-await", ".then() to async/await",
           Language.JAVASCRIPT, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert .then() promise chains to async/await",
           source_pattern=r'fetch(url).then(res => res.json())',
           confidence=Confidence.MEDIUM)
def js_async_await(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_PROMISE_THEN.search(line)
    if not m:
        return None
    param = m.group(1) or m.group(2)

    return MigrationMatch(
        rule=_REGISTRY["js-async-await"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="// Rewrite as: const %s = await <expression>;" % (param or "result"),
        confidence=Confidence.MEDIUM,
    )


_JS_EQUALITY = re.compile(r'(?<!=)(==|!=)(?!=)')

@migration("js-strict-eq", "== to ===",
           Language.JAVASCRIPT, MigrationCategory.IDIOM_UPDATE,
           "Convert loose equality to strict equality",
           source_pattern=r'if (x == null)')
def js_strict_eq(line: str, **ctx) -> MigrationMatch | None:
    m = _JS_EQUALITY.search(line)
    if not m:
        return None
    if "null" in line or "undefined" in line:
        return None
    op = m.group(1)
    new_op = "===" if op == "==" else "!=="
    replacement = line[:m.start(1)] + new_op + line[m.end(1):]

    return MigrationMatch(
        rule=_REGISTRY["js-strict-eq"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


# =========================================================================== #
#  JAVA MIGRATIONS                                                             #
# =========================================================================== #

_JAVA_RAW_TYPE = re.compile(
    r'(new\s+(?:ArrayList|HashMap|HashSet|LinkedList|TreeMap|TreeSet|Vector))\s*\(\s*\)')

@migration("java-diamond", "Raw type to diamond operator",
           Language.JAVA, MigrationCategory.SYNTAX_MODERNIZATION,
           "Add diamond operator <> to raw generic type instantiations",
           source_pattern=r'new ArrayList()')
def java_diamond(line: str, **ctx) -> MigrationMatch | None:
    m = _JAVA_RAW_TYPE.search(line)
    if not m:
        return None
    if re.search(r'<[^>]*>\s*\(', line):
        return None
    old = m.group(0)
    new = m.group(1) + "<>()"
    replacement = line.replace(old, new)

    return MigrationMatch(
        rule=_REGISTRY["java-diamond"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


_JAVA_STRCONCAT_LOOP = re.compile(
    r'(\w+)\s*\+=\s*(".*?"|\w+)')

@migration("java-stringbuilder", "String += in loop to StringBuilder",
           Language.JAVA, MigrationCategory.PERFORMANCE,
           "Flag string concatenation with += (use StringBuilder in loops)",
           source_pattern=r'result += item',
           confidence=Confidence.MEDIUM)
def java_stringbuilder(line: str, **ctx) -> MigrationMatch | None:
    m = _JAVA_STRCONCAT_LOOP.search(line)
    if not m:
        return None
    if "String" not in ctx.get("context_above", ""):
        return None
    var = m.group(1)

    return MigrationMatch(
        rule=_REGISTRY["java-stringbuilder"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="// Use StringBuilder: sb.append(%s)" % m.group(2),
        confidence=Confidence.MEDIUM,
    )


_JAVA_ANON_CLASS = re.compile(
    r'new\s+(Runnable|Callable|Comparator|ActionListener|Predicate|Function|Consumer|Supplier)\s*\(\s*\)\s*\{')

@migration("java-lambda", "Anonymous class to lambda",
           Language.JAVA, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert single-method anonymous classes to lambda expressions",
           source_pattern=r'new Runnable() { public void run() { ... } }')
def java_lambda(line: str, **ctx) -> MigrationMatch | None:
    m = _JAVA_ANON_CLASS.search(line)
    if not m:
        return None

    return MigrationMatch(
        rule=_REGISTRY["java-lambda"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="// Convert to lambda: () -> { ... }",
    )


_JAVA_TRY_FINALLY = re.compile(
    r'^\s*finally\s*\{')
_JAVA_CLOSE = re.compile(r'(\w+)\.close\s*\(\s*\)')

@migration("java-try-resources", "try-finally to try-with-resources",
           Language.JAVA, MigrationCategory.IDIOM_UPDATE,
           "Convert try-finally with .close() to try-with-resources",
           source_pattern=r'finally { stream.close(); }',
           confidence=Confidence.MEDIUM)
def java_try_resources(line: str, **ctx) -> MigrationMatch | None:
    if not _JAVA_TRY_FINALLY.match(line):
        return None
    context_below = ctx.get("context_below", "")
    m = _JAVA_CLOSE.search(context_below)
    if not m:
        return None

    return MigrationMatch(
        rule=_REGISTRY["java-try-resources"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="// Convert to try-with-resources: try (%s = ...) { }" % m.group(1),
        confidence=Confidence.MEDIUM,
    )


_JAVA_OPTIONAL = re.compile(
    r'if\s*\(\s*(\w+)\s*!=\s*null\s*\)')

@migration("java-optional", "Null check to Optional",
           Language.JAVA, MigrationCategory.IDIOM_UPDATE,
           "Convert null checks to Optional.ofNullable()",
           source_pattern=r'if (value != null)',
           confidence=Confidence.LOW)
def java_optional(line: str, **ctx) -> MigrationMatch | None:
    m = _JAVA_OPTIONAL.search(line)
    if not m:
        return None
    var = m.group(1)

    return MigrationMatch(
        rule=_REGISTRY["java-optional"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement="// Consider: Optional.ofNullable(%s).ifPresent(v -> { ... })" % var,
        confidence=Confidence.LOW,
    )


_JAVA_TEXTBLOCK = re.compile(
    r'("(?:[^"\\]|\\.)*?")\s*\+\s*\n?\s*("(?:[^"\\]|\\.)*?")')

@migration("java-textblock", "Concatenated strings to text block",
           Language.JAVA, MigrationCategory.SYNTAX_MODERNIZATION,
           "Convert multi-line string concatenation to text blocks (Java 15+)",
           source_pattern=r'"line1\\n" + "line2\\n"',
           confidence=Confidence.MEDIUM, breaking=True)
def java_textblock(line: str, **ctx) -> MigrationMatch | None:
    if "\\n" not in line or "+" not in line:
        return None
    m = _JAVA_TEXTBLOCK.search(line)
    if not m:
        return None

    return MigrationMatch(
        rule=_REGISTRY["java-textblock"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement='// Convert to text block: ""\"\\n...\\n""\"',
        confidence=Confidence.MEDIUM,
    )


# =========================================================================== #
#  CSS MIGRATIONS                                                              #
# =========================================================================== #

_CSS_VENDOR = re.compile(
    r'^\s*(-webkit-|-moz-|-ms-|-o-)([\w-]+)')

@migration("css-vendor-prefix", "Remove unnecessary vendor prefixes",
           Language.CSS, MigrationCategory.STYLE,
           "Flag vendor-prefixed properties that are now standard",
           source_pattern=r'-webkit-transform: rotate(45deg)')
def css_vendor_prefix(line: str, **ctx) -> MigrationMatch | None:
    m = _CSS_VENDOR.match(line)
    if not m:
        return None
    standard_props = {
        "transform", "transition", "animation", "flex", "grid",
        "border-radius", "box-shadow", "opacity", "filter",
        "column-count", "column-gap", "user-select", "appearance",
        "backdrop-filter", "text-decoration", "box-sizing",
    }
    prop = m.group(2)
    if prop not in standard_props:
        return None
    replacement = line.replace(m.group(1), "")

    return MigrationMatch(
        rule=_REGISTRY["css-vendor-prefix"],
        file_path=ctx.get("file_path", ""),
        line=ctx.get("line_num", 0),
        original=line.rstrip(),
        replacement=replacement,
    )


# =========================================================================== #
#  ENGINE                                                                      #
# =========================================================================== #

LANG_EXT_MAP = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT, ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".css": Language.CSS, ".scss": Language.CSS,
}


class MigrationEngine:
    """Scans files and applies migration rules."""

    def __init__(self, languages: list[Language] | None = None,
                 min_confidence: Confidence = Confidence.LOW,
                 include_breaking: bool = False):
        self._languages = languages
        self._min_confidence = min_confidence
        self._include_breaking = include_breaking

    def scan_line(self, line: str, language: Language,
                  file_path: str = "", line_num: int = 0,
                  context_above: str = "",
                  context_below: str = "") -> list[MigrationMatch]:
        matches = []
        rules = rules_for_language(language)

        conf_order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        min_ord = conf_order.get(self._min_confidence, 2)

        for rule in rules:
            if not self._include_breaking and rule.breaking:
                continue
            if conf_order.get(rule.confidence, 2) > min_ord:
                continue

            result = rule.detector(
                line,
                file_path=file_path,
                line_num=line_num,
                context_above=context_above,
                context_below=context_below,
            )
            if result:
                matches.append(result)

        return matches

    def scan_source(self, source: str, language: Language,
                    file_path: str = "") -> list[MigrationMatch]:
        lines = source.splitlines()
        all_matches = []

        for i, line in enumerate(lines):
            above = "\n".join(lines[max(0, i - 5):i])
            below = "\n".join(lines[i + 1:min(len(lines), i + 5)])
            matches = self.scan_line(
                line, language, file_path=file_path,
                line_num=i + 1, context_above=above,
                context_below=below)
            all_matches.extend(matches)

        return all_matches

    def scan_file(self, path: str) -> list[MigrationMatch]:
        ext = os.path.splitext(path)[1].lower()
        language = LANG_EXT_MAP.get(ext)
        if not language:
            return []

        if self._languages and language not in self._languages:
            return []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except OSError:
            return []

        return self.scan_source(source, language, file_path=path)

    def scan_project(self, root: str) -> dict[str, MigrationReport]:
        reports: dict[str, MigrationReport] = {}
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".tox",
            "venv", ".venv", "dist", "build", "vendor",
        }

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext not in LANG_EXT_MAP:
                    continue

                matches = self.scan_file(fpath)
                if matches:
                    rel = os.path.relpath(fpath, root)
                    reports[rel] = MigrationReport(
                        file_path=rel, matches=matches)

        return reports

    def apply(self, source: str, language: Language) -> str:
        matches = self.scan_source(source, language)
        lines = source.splitlines()

        replacements: dict[int, str] = {}
        for m in matches:
            if m.confidence == Confidence.HIGH and m.line > 0:
                replacements[m.line - 1] = m.replacement

        result = []
        for i, line in enumerate(lines):
            if i in replacements:
                result.append(replacements[i])
            else:
                result.append(line)

        return "\n".join(result)

    def summary(self, reports: dict[str, MigrationReport]) -> str:
        total_files = len(reports)
        total_matches = sum(r.total_migrations for r in reports.values())

        lines = [
            "=== Migration Analysis ===",
            "Files with migrations: %d" % total_files,
            "Total opportunities: %d" % total_matches,
        ]

        by_rule: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for r in reports.values():
            for m in r.matches:
                by_rule[m.rule.name] = by_rule.get(m.rule.name, 0) + 1
                by_cat[m.rule.category.name] = by_cat.get(m.rule.category.name, 0) + 1

        if by_cat:
            lines.append("")
            lines.append("By category:")
            for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
                lines.append("  %s: %d" % (cat, count))

        if by_rule:
            lines.append("")
            lines.append("By rule:")
            for name, count in sorted(by_rule.items(), key=lambda x: -x[1]):
                lines.append("  %s: %d" % (name, count))

        return "\n".join(lines)


def scan(path: str) -> list[MigrationMatch]:
    engine = MigrationEngine()
    if os.path.isfile(path):
        return engine.scan_file(path)
    return [m for r in engine.scan_project(path).values() for m in r.matches]
