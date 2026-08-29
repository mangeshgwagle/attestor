#!/usr/bin/env python3
"""
detect.py -- a static detector for subtle, "almost no-one can find" bugs in
C, C++ and Haskell source.

It does not try to be a compiler. It strips comments and string literals (so it
never trips over the bug *described in a comment*, only real code), does a little
lightweight declaration tracking, and then applies a curated set of rules -- each
one targeting a class of defect that reads as correct code, passes small tests,
and ships before it bites.

Usage:
    detect.py [PATH ...]          scan files/dirs (default: the bundled corpus)
    detect.py --json              machine-readable output
    detect.py --severity HIGH     only show findings at/above a level
    detect.py --list-rules        describe every rule
    detect.py --self-test         scan the bundled corpus, assert every planted
                                  bug is found (exit 0 = all found)

Exit code: number of findings (capped at 250), or 0 if none. --self-test exits
0 on success, 1 on failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable


HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.normpath(os.path.join(HERE, ".."))   # the c/ cpp/ haskell/ demos

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

LANG_BY_EXT = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".hs": "haskell", ".lhs": "haskell",
    ".py": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",
    # config / plain-text files: only the language-agnostic rules (secrets) run.
    ".java": "java",
    ".env": "text", ".ini": "text", ".cfg": "text", ".conf": "text",
    ".toml": "text", ".yaml": "text", ".yml": "text", ".json": "text",
    ".properties": "text", ".txt": "text", ".md": "text", ".markdown": "text",
    ".rst": "text", ".sh": "text", ".bash": "text", ".zsh": "text",
    ".ps1": "text", ".xml": "text", ".rb": "text", ".php": "text",
    ".kt": "text", ".kts": "text", ".swift": "text", ".sol": "text",
    ".vue": "text", ".svelte": "text", ".nginx": "text",
    # `.java` is above, as a real language. Go, Rust and C# were text until
    # rules existed for them; the rule packs below now do, so they are real
    # languages here and `language_coverage42` counts them. All three are
    # C-family in the only respect `blank()` cares about -- `//` line
    # comments, `/* */` blocks and double-quoted strings -- so the default
    # `blank_c_like` masking is correct for them without a new masker.
    ".rs": "rust", ".go": "go", ".cs": "csharp",
    # Assembly, in two dialects that share nothing but the word.
    # `asm` is free-form x86-64 (NASM/MASM/GAS). `hlasm` is IBM High Level
    # Assembler for System/360 and its z/Architecture descendants, which is
    # column-sensitive and needs its own masker -- see `blank_hlasm`.
    ".asm": "asm", ".s": "asm", ".nasm": "asm",
    ".mlc": "hlasm", ".hlasm": "hlasm",
    ".sql": "text", ".tf": "text", ".tfvars": "text", ".gradle": "text",
    ".html": "text", ".htm": "text", ".css": "text", ".scss": "text",
    ".less": "text", ".lock": "text", ".csv": "text", ".tsv": "text",
    ".proto": "text", ".graphql": "text", ".gql": "text", ".bat": "text",
    ".cmd": "text", ".example": "text", ".sample": "text", ".template": "text",
}

TEXT_BASENAMES = {
    ".dockerignore", ".env", ".gitignore", ".npmrc", ".pypirc", ".netrc",
    "dockerfile", "jenkinsfile", "makefile", "procfile", "vagrantfile",
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "build", "dist", "target", ".stack-work",
}
MAX_BYTES = 2 * 1024 * 1024


class ScanError(OSError):
    """An input could not be scanned completely and must not count as clean."""


def language_for(path: str) -> str | None:
    """Return the scanner language, including common extensionless config files."""
    base = os.path.basename(path).lower()
    ext = os.path.splitext(base)[1].lower()
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if base in TEXT_BASENAMES or not ext:
        return "text"
    return None


def _shebang_language(path: str, text: str, fallback: str) -> str:
    """Refine extensionless scripts without guessing from arbitrary contents."""
    if os.path.splitext(os.path.basename(path))[1] or not text.startswith("#!"):
        return fallback
    first = text.split("\n", 1)[0].lower()
    if re.search(r"\bpython(?:\d+(?:\.\d+)*)?\b", first):
        return "python"
    if re.search(r"\b(?:node|deno|bun)\b", first):
        return "js"
    if re.search(r"\b(?:runghc|runhaskell)\b", first):
        return "haskell"
    return fallback


def _binary_sample(data: bytes) -> bool:
    """Conservative binary sniff: NUL or a large share of non-text controls."""
    if b"\x00" in data:
        return True
    if not data:
        return False
    controls = sum(byte < 32 and byte not in (8, 9, 10, 12, 13) for byte in data)
    return controls / len(data) > 0.10


def _input_problem(path: str) -> str | None:
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            return "file is too large (%d bytes; limit is %d)" % (size, MAX_BYTES)
        with open(path, "rb") as fh:
            if _binary_sample(fh.read(8192)):
                return "file appears to be binary"
    except OSError as exc:
        return "cannot read: %s" % exc
    return None


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    path: str
    line: int          # 1-indexed
    rule: str
    severity: str
    message: str
    fix: str
    snippet: str = ""
    confidence: float = 0.0
    exploitability: str = ""
    safe_to_autofix: bool = False

    def __post_init__(self):
        import confidence as _confidence
        _confidence.enrich(self)

    def sort_key(self):
        return (self.path, self.line, -SEVERITY_ORDER[self.severity], self.rule)


# --------------------------------------------------------------------------- #
# Comment / string blanking -- keeps line numbers and columns intact by
# replacing the *contents* of comments and string/char literals with spaces.
# --------------------------------------------------------------------------- #
def _masked_escape(text: str, index: int) -> tuple[str, int]:
    """Blank a backslash escape without ever swallowing an escaped newline."""
    if index + 1 >= len(text):
        return " ", 1
    following = text[index + 1]
    if following == "\r" and index + 2 < len(text) and text[index + 2] == "\n":
        return " \r\n", 3
    return " " + ("\n" if following == "\n" else " "), 2


def blank_c_like(text: str) -> list[str]:
    out, i, n = [], 0, len(text)
    in_block = in_line = in_str = in_chr = False
    cur = []
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                cur.append(c)
            else:
                cur.append(" ")
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False; cur.append("  "); i += 2; continue
            cur.append("\n" if c == "\n" else " ")
        elif in_str:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append("\n" if c == "\n" else (" " if c != '"' else '"'))
            if c == '"':
                in_str = False
        elif in_chr:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append("\n" if c == "\n" else (" " if c != "'" else "'"))
            if c == "'":
                in_chr = False
        else:
            if c == "/" and nxt == "/":
                in_line = True; cur.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                in_block = True; cur.append("  "); i += 2; continue
            if c == '"':
                in_str = True; cur.append('"')
            elif c == "'":
                in_chr = True; cur.append("'")
            else:
                cur.append(c)
        i += 1
    return "".join(cur).split("\n")


def blank_haskell(text: str) -> list[str]:
    out, i, n = [], 0, len(text)
    block_depth = 0
    in_line = in_str = False
    cur = []
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            cur.append(c if c == "\n" else " ")
            if c == "\n":
                in_line = False
        elif block_depth > 0:
            if c == "{" and nxt == "-":
                block_depth += 1; cur.append("  "); i += 2; continue
            if c == "-" and nxt == "}":
                block_depth -= 1; cur.append("  "); i += 2; continue
            cur.append("\n" if c == "\n" else " ")
        elif in_str:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append("\n" if c == "\n" else (" " if c != '"' else '"'))
            if c == '"':
                in_str = False
        else:
            if c == "{" and nxt == "-":
                block_depth += 1; cur.append("  "); i += 2; continue
            if c == "-" and nxt == "-":
                # `--` starts a line comment unless it is part of an operator
                # (e.g. `-->`); for our purposes a following space/EOL is enough.
                follow = text[i + 2] if i + 2 < n else "\n"
                if not follow.isalnum() and follow not in "!#$%&*+./<=>?@\\^|~:-":
                    in_line = True; cur.append("  "); i += 2; continue
                cur.append(c)
            elif c == '"':
                in_str = True; cur.append('"')
            else:
                cur.append(c)
        i += 1
    return "".join(cur).split("\n")


def blank_python(text: str) -> list[str]:
    """Strings and comments replaced by spaces; newlines and quotes kept.

    The three-character lookahead is taken only where it can matter -- when
    the current character is a quote. Slicing it unconditionally allocated one
    string per character of every file scanned, roughly 180,000 for a 180 KB
    source, to answer a question that only arises at the few thousand
    positions actually holding a `'` or a `"`.

    `test_blank_equivalence42` keeps the pre-rewrite implementation and
    requires this to match it byte for byte on every Python file in the tree.
    That test is not optional politeness: this function is what every Python
    rule reads instead of the file, so a one-character difference changes what
    every rule sees and shows up only as some rule quietly not firing.
    """
    i, n = 0, len(text)
    cur = []
    in_line = False
    triple = None   # the active triple-quote delimiter, if any
    single = None   # ' or " while inside a single-line string
    while i < n:
        c = text[i]
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1; continue
        if triple:
            # `triple[0]` is the quote it was built from, so any other
            # character cannot close it and never needs the slice.
            if c == triple[0] and text[i:i + 3] == triple:
                cur.append("   "); i += 3; triple = None; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if single:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            if c == single:
                cur.append(single); single = None; i += 1; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if c == "#":
            in_line = True; cur.append(" "); i += 1; continue
        if c == "'" or c == '"':
            three = text[i:i + 3]
            if three == '"""' or three == "'''":
                triple = three; cur.append("   "); i += 3; continue
            single = c; cur.append(c); i += 1; continue
        cur.append(c); i += 1
    return "".join(cur).split("\n")


def blank_js(text: str) -> list[str]:
    """Like blank_c_like, but also blanks template literals (backtick strings)."""
    out, i, n = [], 0, len(text)
    in_block = in_line = in_s = in_d = in_t = False
    cur = []
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            cur.append(c if c == "\n" else " ")
            if c == "\n":
                in_line = False
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False; cur.append("  "); i += 2; continue
            cur.append("\n" if c == "\n" else " ")
        elif in_s:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append("'" if c == "'" else ("\n" if c == "\n" else " "))
            if c == "'":
                in_s = False
        elif in_d:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append('"' if c == '"' else ("\n" if c == "\n" else " "))
            if c == '"':
                in_d = False
        elif in_t:
            if c == "\\":
                masked, width = _masked_escape(text, i)
                cur.append(masked); i += width; continue
            cur.append("`" if c == "`" else ("\n" if c == "\n" else " "))
            if c == "`":
                in_t = False
        else:
            if c == "/" and nxt == "/":
                in_line = True; cur.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                in_block = True; cur.append("  "); i += 2; continue
            if c == "'":
                in_s = True; cur.append("'")
            elif c == '"':
                in_d = True; cur.append('"')
            elif c == "`":
                in_t = True; cur.append("`")
            else:
                cur.append(c)
        i += 1
    return "".join(cur).split("\n")


def blank_asm(text: str) -> list[str]:
    """Blank comments and string contents in free-form assembly.

    Covers the three comment conventions that coexist in x86-64 sources: `;`
    (NASM/MASM), `#` (GAS), and `//` plus `/* */` (GAS run through the C
    preprocessor). Character positions are preserved so a rule can report a
    column, and quoted data is blanked so a mnemonic named inside a string
    constant is not mistaken for an instruction.
    """
    out: list[str] = []
    in_block = False
    for line in text.split("\n"):
        chars = list(line)
        index, quote = 0, None
        while index < len(chars):
            char = chars[index]
            nxt = chars[index + 1] if index + 1 < len(chars) else ""
            if in_block:
                if char == "*" and nxt == "/":
                    chars[index] = chars[index + 1] = " "
                    in_block = False
                    index += 2
                    continue
                chars[index] = " "
            elif quote:
                if char == "\\":
                    chars[index] = " "
                    if index + 1 < len(chars):
                        chars[index + 1] = " "
                    index += 2
                    continue
                if char == quote:
                    quote = None
                else:
                    chars[index] = " "
            elif char in "\"'":
                quote = char
            elif char == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                in_block = True
                index += 2
                continue
            elif char in ";#" or (char == "/" and nxt == "/"):
                for blank_at in range(index, len(chars)):
                    chars[blank_at] = " "
                break
            index += 1
        out.append("".join(chars))
    return out


def blank_hlasm(text: str) -> list[str]:
    """Blank comments in IBM High Level Assembler, which is column-sensitive.

    HLASM is not free-form and cannot be masked like x86 assembly:

    * `*` in column 1 makes the whole line a comment, and `.*` opens a macro
      comment. Neither has a terminator.
    * There is no comment *character* on a statement line. The comment is
      whatever follows the operand field after a blank, so the mask has to find
      the end of the operands rather than scan for a delimiter.
    * Column 72 is the continuation indicator, not code, and columns 73-80 are
      the sequence-number field -- historically card columns. Anything out
      there is never an instruction and is blanked.

    Getting this wrong in the obvious way (treating `*` anywhere as a comment)
    would erase every multiplication and every location-counter reference,
    since `*` is also the current-address symbol.
    """
    out: list[str] = []
    for line in text.split("\n"):
        if line[:1] == "*" or line[:2] == ".*":
            out.append(" " * len(line))
            continue
        # Sequence-number field and the continuation column are not code.
        body = line[:71]
        tail = " " * (len(line) - len(body))
        chars = list(body)
        index, quote, field = 0, None, 0
        while index < len(chars):
            char = chars[index]
            if quote:
                if char == "'":
                    quote = None
                else:
                    chars[index] = " "
            elif char == "'":
                quote = char
            elif char == " ":
                # Blank outside a quote ends a field: label, operation,
                # operands, then comment. Everything past the third is prose.
                while index < len(chars) and chars[index] == " ":
                    index += 1
                field += 1
                if field >= 3:
                    for blank_at in range(index, len(chars)):
                        chars[blank_at] = " "
                    break
                continue
            index += 1
        out.append("".join(chars) + tail)
    return out


def _comments_asm_like(text: str, hlasm: bool = False) -> list[str]:
    """Blank only the comments in assembly, keeping quoted operands intact.

    `blank_asm`/`blank_hlasm` blank literals too, which is right for matching
    instructions but wrong for this view. A rule reading `ctx.literal` wants the
    operand text: section flags (`.section .data,"awx"`) are directive syntax
    and a payload path (`/bin/sh`) is data the rule is specifically looking for.
    Both survive here; only the trailing comment is removed.
    """
    out: list[str] = []
    in_block = False
    for line in text.split("\n"):
        if hlasm:
            if line[:1] == "*" or line[:2] == ".*":
                out.append(" " * len(line))
                continue
            body, tail = line[:71], " " * max(0, len(line) - 71)
            chars = list(body)
            index, quote, field = 0, None, 0
            while index < len(chars):
                char = chars[index]
                if quote:
                    if char == "'":
                        quote = None
                elif char == "'":
                    quote = char
                elif char == " ":
                    while index < len(chars) and chars[index] == " ":
                        index += 1
                    field += 1
                    if field >= 3:
                        for blank_at in range(index, len(chars)):
                            chars[blank_at] = " "
                        break
                    continue
                index += 1
            out.append("".join(chars) + tail)
            continue
        chars = list(line)
        index, quote = 0, None
        while index < len(chars):
            char = chars[index]
            nxt = chars[index + 1] if index + 1 < len(chars) else ""
            if in_block:
                if char == "*" and nxt == "/":
                    chars[index] = chars[index + 1] = " "
                    in_block = False
                    index += 2
                    continue
                chars[index] = " "
            elif quote:
                if char == "\\":
                    index += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                in_block = True
                index += 2
                continue
            elif char in ";#" or (char == "/" and nxt == "/"):
                for blank_at in range(index, len(chars)):
                    chars[blank_at] = " "
                break
            index += 1
        out.append("".join(chars))
    return out


def blank(text: str, lang: str) -> list[str]:
    if lang == "haskell":
        return blank_haskell(text)
    if lang == "python":
        return blank_python(text)
    if lang == "js":
        return blank_js(text)
    if lang == "asm":
        return blank_asm(text)
    if lang == "hlasm":
        return blank_hlasm(text)
    if lang == "text":
        return text.split("\n")          # no code structure; raw rules only
    return blank_c_like(text)


def _comments_c_like(text: str, javascript: bool = False) -> list[str]:
    """Blank comments while preserving literals for rules that inspect values."""
    cur, i, n = [], 0, len(text)
    in_block = in_line = False
    quote = None
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
            continue
        if in_block:
            if c == "*" and nxt == "/":
                cur.append("  "); i += 2; in_block = False; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "/" and nxt == "/":
            cur.append("  "); i += 2; in_line = True; continue
        if c == "/" and nxt == "*":
            cur.append("  "); i += 2; in_block = True; continue
        if c in ("'", '"') or javascript and c == "`":
            quote = c
        cur.append(c); i += 1
    return "".join(cur).split("\n")


def _comments_python(text: str) -> list[str]:
    """Comments replaced by spaces; string contents kept as they are.

    The three-character slice is taken only at a quote, for the reason given
    in `blank_python`, and guarded by the same equivalence test.
    """
    cur, i, n = [], 0, len(text)
    in_line = False
    triple = single = None
    while i < n:
        c = text[i]
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1; continue
        if triple:
            if c == triple[0] and text[i:i + 3] == triple:
                cur.append(triple); i += 3; triple = None; continue
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
        if c == "'" or c == '"':
            three = text[i:i + 3]
            if three == '"""' or three == "'''":
                triple = three; cur.append(three); i += 3; continue
            single = c
        cur.append(c); i += 1
    return "".join(cur).split("\n")


def _comments_haskell(text: str) -> list[str]:
    cur, i, n = [], 0, len(text)
    block_depth = 0
    in_line = False
    quote = None
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            cur.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1; continue
        if block_depth:
            if c == "{" and nxt == "-":
                block_depth += 1; cur.append("  "); i += 2; continue
            if c == "-" and nxt == "}":
                block_depth -= 1; cur.append("  "); i += 2; continue
            cur.append("\n" if c == "\n" else " "); i += 1; continue
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1; continue
        if c == "{" and nxt == "-":
            block_depth = 1; cur.append("  "); i += 2; continue
        if c == "-" and nxt == "-":
            in_line = True; cur.append("  "); i += 2; continue
        if c in ("'", '"'):
            quote = c
        cur.append(c); i += 1
    return "".join(cur).split("\n")


def blank_comments(text: str, lang: str) -> list[str]:
    """Preserve code and literals but erase comments, retaining exact line mapping."""
    if lang == "asm" or lang == "hlasm":
        return _comments_asm_like(text, hlasm=(lang == "hlasm"))
    if lang == "python":
        return _comments_python(text)
    if lang == "js":
        return _comments_c_like(text, javascript=True)
    if lang == "haskell":
        return _comments_haskell(text)
    if lang in ("c", "cpp", "java", "go", "rust", "csharp"):
        return _comments_c_like(text)
    if lang in ("asm", "hlasm"):
        return _comments_asm_like(text, hlasm=(lang == "hlasm"))
    return text.split("\n")


# --------------------------------------------------------------------------- #
# Lightweight context: cheap declaration tracking per file.
# --------------------------------------------------------------------------- #
UNSIGNED_DECL = re.compile(
    r"\b(?:size_t|unsigned(?:\s+(?:int|long|long\s+long|char|short))?"
    r"|uint(?:8|16|32|64)_t|uintptr_t|uintmax_t|size_type)\b\s*\**\s*([A-Za-z_]\w*)"
)
# Only needed to notice that a name is *not* unsigned in the scope using it,
# so a local declaration can override a same-named unsigned one elsewhere.
#
# Deliberately NOT called SIGNED_DECL: that name is already taken further down
# the file by a `\A`-anchored pattern for matching a single declaration line.
# Reusing it here silently bound this lookup to that one instead -- which, run
# against a joined function body, can only ever match at offset zero and so
# found nothing at all. Every scope came back empty and the fix appeared to do
# nothing, with no error anywhere to say why.
SIGNED_DECL_ANYWHERE = re.compile(
    r"\b(?:signed|int|long(?:\s+long)?|short|char|ptrdiff_t|ssize_t"
    r"|int(?:8|16|32|64)_t|intptr_t|intmax_t)\b\s*\**\s*([A-Za-z_]\w*)"
)
MAP_DECL = re.compile(
    r"\b(?:std::)?(?:unordered_|flat_)?(?:multi)?map\s*<[^;{}]*?>\s+([A-Za-z_]\w*)"
)
CONTAINER_OF = re.compile(
    r"\b(?:std::)?(?:vector|list|deque|set|multiset|stack|queue)\s*<\s*([A-Za-z_]\w*)\s*>"
)
CLASS_HEAD = re.compile(r"\b(?:class|struct)\s+([A-Za-z_]\w*)")
FUNC_HEAD = re.compile(r"\b[A-Za-z_][\w:<>,&\s\*]*?\b([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*\{")
HS_SIG = re.compile(r"^\s*([A-Za-z_]\w*)\s*::\s*(.+?)\s*$")


@dataclass
class Ctx:
    lang: str
    raw: list[str]
    code: list[str]
    literal: list[str] = field(default_factory=list)
    unsigned_vars: set = field(default_factory=set)
    # (start, end, unsigned names, signed names) per function body.
    unsigned_scopes: list = field(default_factory=list)
    map_vars: set = field(default_factory=set)
    pointer_params: set = field(default_factory=set)
    virtual_classes: set = field(default_factory=set)
    has_vector_bool: bool = False
    int_return_funcs: set = field(default_factory=set)
    # Python: names that reach hashlib, and module-level literal boolean flags.
    # A defect reached through a name is the same defect as the literal form; a
    # rule that only matches the literal is walked past by renaming the value.
    hash_module_aliases: set = field(default_factory=set)
    weak_hash_names: set = field(default_factory=set)
    false_flags: set = field(default_factory=set)
    true_flags: set = field(default_factory=set)
    # One buffer-size walk shared by the stack and heap overflow rules, which
    # ask the same question and differ only in which answers they keep.
    overflow_reports: list | None = None
    # Java: what other files in the same program learned about taint crossing
    # a file boundary. Empty for a single-file scan, which is why every rule
    # behaves exactly as before unless scan_project supplied one.
    cross_file_taint: object = None


PY_HASHLIB_IMPORT = re.compile(
    r"(?m)^[ \t]*import[ \t]+hashlib(?:[ \t]+as[ \t]+([A-Za-z_]\w*))?[ \t]*$")
PY_HASHLIB_FROM = re.compile(
    r"(?m)^[ \t]*from[ \t]+hashlib[ \t]+import[ \t]+(.+)$")
PY_MODULE_FLAG = re.compile(
    r"(?m)^([A-Za-z_]\w*)[ \t]*(?::[^=\n]+)?=[ \t]*(True|False)[ \t]*$")
WEAK_HASH_NAMES = ("md5", "sha1")


def _python_symbols(ctx: Ctx, joined: str) -> None:
    """Names through which a Python file can reach hashlib or a boolean flag."""
    for match in PY_HASHLIB_IMPORT.finditer(joined):
        ctx.hash_module_aliases.add(match.group(1) or "hashlib")
    for match in PY_HASHLIB_FROM.finditer(joined):
        for piece in match.group(1).split(","):
            parts = piece.replace("(", " ").replace(")", " ").split()
            if not parts:
                continue
            imported = parts[0]
            bound = parts[2] if len(parts) >= 3 and parts[1] == "as" else imported
            if imported in WEAK_HASH_NAMES:
                ctx.weak_hash_names.add(bound)
            elif imported == "new":
                ctx.hash_module_aliases.add("")   # bare new(...) is ambiguous
    # Only column-zero assignments count: a module constant, not a local whose
    # value we would have to scope-track to know.
    for match in PY_MODULE_FLAG.finditer(joined):
        target = ctx.true_flags if match.group(2) == "True" else ctx.false_flags
        target.add(match.group(1))


def build_ctx(lang: str, raw: list[str], code: list[str], literal: list[str] | None = None) -> Ctx:
    ctx = Ctx(lang=lang, raw=raw, code=code, literal=literal or raw)
    joined = "\n".join(code)

    if lang in ("c", "cpp"):
        for m in UNSIGNED_DECL.finditer(joined):
            ctx.unsigned_vars.add(m.group(1))
        # ...and again per function, because the set above is file-wide and
        # that is not good enough. A file holding `dlimb s` in one function
        # and `int64_t s` in another marks `s` unsigned everywhere, so the
        # necessary `s < 0` guard in the *signed* function is reported as
        # dead code. Measured on real C: six such reports, all wrong.
        for start, end in _c_function_spans(code):
            body = "\n".join(code[start:end + 1])
            ctx.unsigned_scopes.append((
                start, end,
                {m.group(1) for m in UNSIGNED_DECL.finditer(body)},
                {m.group(1) for m in SIGNED_DECL_ANYWHERE.finditer(body)},
            ))
        for m in MAP_DECL.finditer(joined):
            ctx.map_vars.add(m.group(1))
        ctx.has_vector_bool = re.search(r"\bvector\s*<\s*bool\s*>", joined) is not None
        # pointer / array function parameters (used by the sizeof rule)
        for m in FUNC_HEAD.finditer(joined):
            for param in m.group(2).split(","):
                p = param.strip()
                if not p or p == "void":
                    continue
                am = re.search(r"\*\s*(?:const\s+)?([A-Za-z_]\w*)\s*$", p) or \
                    re.search(r"([A-Za-z_]\w*)\s*\[[^\]]*\]\s*$", p)
                if am:
                    ctx.pointer_params.add(am.group(1))
        # classes that declare virtual / override -> polymorphic bases
        ctx.virtual_classes = _polymorphic_classes(code)

    elif lang == "python":
        _python_symbols(ctx, joined)

    elif lang == "haskell":
        for line in code:
            m = HS_SIG.match(line)
            if m:
                ret = m.group(2).split("->")[-1].strip()
                if ret == "Int":
                    ctx.int_return_funcs.add(m.group(1))
    return ctx


def _polymorphic_classes(code: list[str]) -> set:
    """Names of class/struct types whose body mentions virtual/override."""
    result, current, depth_at_open = set(), None, None
    depth = 0
    for line in code:
        if current is None:
            m = CLASS_HEAD.search(line)
            if m and "{" in line.split(m.group(0), 1)[-1] or (m and "{" in line):
                current = m.group(1)
                depth = line.count("{") - line.count("}")
                if re.search(r"\b(virtual|override)\b", line):
                    result.add(current)
                if depth <= 0:
                    current = None
            elif m:
                current = m.group(1)   # body opens on a later line
                depth = 0
        else:
            depth += line.count("{") - line.count("}")
            if re.search(r"\b(virtual|override)\b", line):
                result.add(current)
            if depth <= 0:
                current = None
    return result


def _block_lines(code: list[str], start_idx: int) -> Iterable[tuple[int, str]]:
    """Yield (idx, line) for the brace-delimited block starting at/after start_idx."""
    depth, started = 0, False
    for idx in range(start_idx, len(code)):
        line = code[idx]
        depth += line.count("{") - line.count("}")
        if "{" in line:
            started = True
        if started:
            yield idx, line
        if started and depth <= 0:
            return


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
RULES: list = []


# Weakness class per rule, kept as one auditable table rather than scattered
# through 65 decorator calls.  Only rules with an unambiguous mapping are
# listed: a wrong CWE is worse than none, because coverage reporting and
# prioritisation both read this.  Rules absent here are correctness or
# maintainability checks with no honest weakness class, and they report "".
RULE_CWE = {
    # C / C++ memory, arithmetic and undefined behaviour
    "unsigned-underflow": "CWE-191",
    "signed-overflow-check": "CWE-190",
    "strict-aliasing": "CWE-758",
    "sizeof-pointer-arg": "CWE-467",
    "assign-in-condition": "CWE-481",
    "unsafe-libc": "CWE-120",
    "scanf-unbounded": "CWE-120",
    "c-malloc-strlen-no-nul": "CWE-787",
    "c-strncpy-truncation": "CWE-170",
    "c-realloc-leak": "CWE-401",
    "c-free-stack-address": "CWE-590",
    "c-return-local-address": "CWE-562",
    "cpp-return-cstr-local": "CWE-562",
    "cpp-delete-array-mismatch": "CWE-762",
    "cpp-use-after-move": "CWE-672",
    "c-memcmp-padding": "CWE-188",
    "c-use-after-free": "CWE-416",
    "c-null-deref": "CWE-476",
    "c-null-guard-bitwise": "CWE-476",
    "c-deref-after-null-check": "CWE-476",
    "c-null-check-after-deref": "CWE-476",
    "py-route-missing-authorization": "CWE-862",
    "py-upload-unrestricted": "CWE-434",
    "py-unbounded-read": "CWE-770",
    "py-route-missing-authentication": "CWE-306",
    "c-mismatched-free": "CWE-762",
    "c-free-not-on-heap": "CWE-590",
    "c-stack-buffer-overflow": "CWE-121",
    "c-heap-buffer-overflow": "CWE-122",
    "c-struct-member-overrun": "CWE-787",
    "format-string": "CWE-134",
    "c-partial-init": "CWE-457",
    "c-signed-size": "CWE-194",
    "c-numeric-truncation": "CWE-197",
    "java-command-injection": "CWE-78",
    "java-sql-injection": "CWE-89",
    "java-weak-hash": "CWE-327",
    "java-insecure-deserialize": "CWE-502",
    "java-weak-random": "CWE-338",
    "java-fixed-seed": "CWE-336",
    "java-ldap-injection": "CWE-90",
    "java-xpath-injection": "CWE-643",
    "java-xss-reflected": "CWE-80",
    "java-response-splitting": "CWE-113",
    "java-array-index-unchecked": "CWE-129",
    # CWE-190 and CWE-191 are the same rule: overflow and underflow are one
    # analysis, and Juliet splits them only by which direction the value ran.
    "java-integer-overflow": "CWE-190",
    "java-divide-by-zero": "CWE-369",
    "java-unbounded-allocation": "CWE-789",
    "java-unbounded-loop": "CWE-400",
    "java-numeric-truncation": "CWE-197",
    "java-format-string": "CWE-134",
    # CWE-23 and CWE-36 are one analysis: relative and absolute traversal
    # differ only in whether a base directory is concatenated first.
    "java-path-traversal": "CWE-23",
    "java-unsafe-reflection": "CWE-470",
    "java-external-config": "CWE-15",
    "java-string-identity-compare": "CWE-597",
    "java-weak-prng": "CWE-338",
    "java-broken-cipher": "CWE-327",
    # CWE-546 and CWE-615 are the same rule: a comment that should not have
    # shipped, differing only in whether it names unfinished work or leaks
    # something about the system.
    "java-suspicious-comment": "CWE-546",
    "java-system-exit": "CWE-382",
    "java-overbroad-catch": "CWE-396",
    "java-generic-throw": "CWE-397",
    "java-explicit-finalize": "CWE-586",
    "java-obsolete-api": "CWE-477",
    "java-insecure-cookie": "CWE-614",
    "java-xxe": "CWE-611",
    "command-exec": "CWE-78",
    "c-command-injection": "CWE-78",
    "c-integer-overflow": "CWE-190",
    "c-path-traversal": "CWE-23",
    "c-buffer-underwrite": "CWE-124",
    "c-double-free": "CWE-415",
    "c-memory-leak": "CWE-401",
    "c-divide-by-zero": "CWE-369",
    "c-unchecked-return": "CWE-252",
    "c-wrong-return-check": "CWE-253",
    "c-uninitialised-read": "CWE-457",
    "weak-rng": "CWE-338",
    "float-equality": "CWE-1077",
    "empty-catch": "CWE-390",
    # Haskell
    "hs-int-overflow": "CWE-190",
    # Python
    "py-sql-injection": "CWE-89",
    "py-os-command-injection": "CWE-78",
    "py-subprocess-shell": "CWE-78",
    "py-yaml-load": "CWE-502",
    "py-insecure-deserialize": "CWE-502",
    "py-random-security": "CWE-338",
    "py-assert-validation": "CWE-617",
    "py-tempfile-insecure": "CWE-377",
    "py-bind-all-interfaces": "CWE-1327",
    "py-empty-secret-default": "CWE-1188",
    "py-requests-no-timeout": "CWE-400",
    "py-subprocess-no-timeout": "CWE-400",
    "py-bare-except": "CWE-396",
    "py-except-pass": "CWE-390",
    # Cross-language
    "hardcoded-secret": "CWE-798",
    "tls-verify-disabled": "CWE-295",
    "weak-hash": "CWE-327",
    "dangerous-eval": "CWE-94",
    "debug-enabled": "CWE-489",
    "insecure-http-url": "CWE-319",
    # JavaScript
    "js-innerhtml": "CWE-79",
    "js-settimeout-string": "CWE-94",
    "js-prototype-pollution": "CWE-1321",
    "js-client-secret-storage": "CWE-922",
    # Go / Rust / C#. Only the rules this file adds; `multilang.py` and
    # `advanced_rules.py` carry their own identifiers and are not listed here.
    "go-command-injection": "CWE-78",
    "go-http-no-timeout": "CWE-1088",
    "rust-command-injection": "CWE-78",
    "cs-sql-injection": "CWE-89",
    "cs-command-injection": "CWE-78",
    "cs-weak-hash": "CWE-327",
    "cs-cert-validation-disabled": "CWE-295",
    "cs-xxe": "CWE-611",
    "cs-weak-random": "CWE-338",
    # `rust-unwrap-panic` is deliberately absent: a panic on the error path has
    # no honest single weakness class, and a wrong CWE is worse than none
    # because coverage and prioritisation both read this table.
    # Fail-open / defense-in-depth
    "py-auth-fail-open": "CWE-636",             # Not Failing Securely ('Failing Open')
    "py-verify-disabled-on-error": "CWE-295",   # Improper Certificate Validation
    "py-access-default-allow": "CWE-636",
    # Assembly. Only the classes with an unambiguous mapping are listed: a
    # stack pivot and a NOP sled are attacker *techniques* rather than weakness
    # classes, so they carry an ATT&CK id in RULE_ATTACK instead and are absent
    # here rather than forced into an approximate CWE.
    "asm-writable-executable-section": "CWE-2119",
    "asm-legacy-int80": "CWE-197",              # numeric truncation of arguments
    "hlasm-authorized-mode": "CWE-250",         # execution with unnecessary privilege
    "hlasm-storage-key-change": "CWE-250",
    "hlasm-execute-variable-length": "CWE-120",  # classic buffer copy without size check
}

# Additional weakness classes a rule genuinely covers, beyond its primary one.
#
# `RULE_CWE` holds exactly one CWE per rule because that is what a finding
# reports, and consumers validate it as a single identifier. But CWE is a
# hierarchy, and several rules detect a shape that spans sibling classes. A rule
# credited with only its primary class then reads as having *no* coverage of the
# sibling, which understates real detection.
#
# Measured on NIST Juliet Java, every entry below already fires on the class it
# claims: path traversal on 8/8 CWE-36 cases, reflected XSS on 9/9 of CWE-81 and
# 9/9 of CWE-83, weak hash on 10/10 CWE-328, unbounded loop on 6/6 CWE-606.
# These are taxonomy corrections for detections that already happen, not credit
# claimed for analysis that does not exist -- which is the line that separates
# fixing a measurement from gaming one. A class where nothing fires (CWE-259,
# hard-coded password) is deliberately absent and stays a real gap.
RULE_CWE_ALSO = {
    # CWE-22 parent: relative (23) and absolute (36) traversal are siblings, and
    # the same sink analysis covers both.
    "java-path-traversal": ("CWE-36",),
    "c-path-traversal": ("CWE-36",),
    # CWE-79 parent: basic (80), error-message (81) and attribute (83) XSS differ
    # in the injection context, not in the tainted-value-reaching-output shape.
    "java-xss-reflected": ("CWE-81", "CWE-83"),
    # CWE-328 is the reversible-one-way-hash case; detecting MD5/SHA-1 is that
    # weakness as directly as it is the broader broken-crypto class.
    "java-weak-hash": ("CWE-328",),
    # CWE-606 (unchecked input for loop condition) is a specific cause of the
    # uncontrolled resource consumption this rule reports.
    "java-unbounded-loop": ("CWE-606",),
}


def covered_cwes(rule_id: str) -> tuple[str, ...]:
    """Every weakness class a rule legitimately detects, primary first."""
    primary = RULE_CWE.get(rule_id, "")
    extra = RULE_CWE_ALSO.get(rule_id, ())
    return ((primary,) if primary else ()) + tuple(extra)


def rule(rid, langs, severity, title, fix, deep=False):
    def deco(fn: Callable):
        fn.rid, fn.langs, fn.severity, fn.title, fn.fix = rid, langs, severity, title, fix
        fn.cwe = RULE_CWE.get(rid, "")
        fn.deep = deep      # deep rules only run with --deep (higher recall, more noise)
        RULES.append(fn)
        return fn
    return deco


def _f(ctx, idx, rid, severity, message, fix):
    return Finding(path="", line=idx + 1, rule=rid, severity=severity,
                   message=message, fix=fix, snippet=ctx.raw[idx].strip())


# ---- C / C++ -------------------------------------------------------------- #
CMP_ZERO = re.compile(r"\b([A-Za-z_]\w*)\s*(<|>=)\s*0\b")


def _unsigned_here(ctx, index, name):
    """Is `name` unsigned in the scope that line `index` belongs to?

    A local declaration decides it, either way -- that is what makes this
    different from the file-wide set, and it is the whole point.
    """
    for start, end, unsigned, signed in ctx.unsigned_scopes:
        if start <= index <= end:
            if name in signed:
                return False              # declared signed right here
            if name in unsigned:
                return True
            break                        # in a function, not declared here
    return name in ctx.unsigned_vars


@rule("unsigned-underflow", ("c", "cpp"), "HIGH",
      "comparison of an unsigned value against 0 is always true/false (dead guard)",
      "compare before subtracting; never let a size_t/unsigned subtraction underflow.")
def r_unsigned(ctx):
    for idx, line in enumerate(ctx.code):
        for m in CMP_ZERO.finditer(line):
            var, op = m.group(1), m.group(2)
            if _unsigned_here(ctx, idx, var):
                always = "false" if op == "<" else "true"
                yield _f(ctx, idx, "unsigned-underflow", "HIGH",
                         f"'{var}' is unsigned, so '{var} {op} 0' is always {always} "
                         f"-- the guard is dead code and a subtraction likely underflowed.",
                         r_unsigned.fix)


ALIAS_CAST = re.compile(
    r"\(\s*(?:const\s+|unsigned\s+|signed\s+)*"
    r"(float|double|int|long|short|char|int8_t|int16_t|int32_t|int64_t)"
    r"\s*\*\s*\)\s*&\s*([A-Za-z_]\w*)"
)


@rule("strict-aliasing", ("c", "cpp"), "HIGH",
      "type-punning via a pointer cast violates strict aliasing (output changes under -O2)",
      "copy bytes with memcpy / std::bit_cast, or build with -fno-strict-aliasing.")
def r_alias(ctx):
    for idx, line in enumerate(ctx.code):
        for m in ALIAS_CAST.finditer(line):
            yield _f(ctx, idx, "strict-aliasing", "HIGH",
                     f"casting '&{m.group(2)}' to a '{m.group(1)} *' aliases memory through "
                     f"an incompatible type; the optimizer may assume it never happens.",
                     r_alias.fix)


# x + k < x   (or  x > x + k) -- self-comparison overflow check
OVF1 = re.compile(r"\b([A-Za-z_]\w*)\s*\+\s*\w+\s*<\s*\1\b")
OVF2 = re.compile(r"\b([A-Za-z_]\w*)\s*>\s*\1\s*\+\s*\w+")


@rule("signed-overflow-check", ("c", "cpp"), "HIGH",
      "overflow check 'x + k < x' is undefined behavior and gets optimized away",
      "check before overflowing, e.g. 'if (x > INT_MAX - k)'.")
def r_overflow(ctx):
    for idx, line in enumerate(ctx.code):
        if OVF1.search(line) or OVF2.search(line):
            yield _f(ctx, idx, "signed-overflow-check", "HIGH",
                     "signed overflow is UB, so the compiler may fold this comparison "
                     "to a constant and delete the check.", r_overflow.fix)


SIZEOF_OPERAND = re.compile(r"\bsizeof\s*\(?\s*([A-Za-z_]\w*)")


@rule("sizeof-pointer-arg", ("c", "cpp"), "HIGH",
      "sizeof on a pointer/array parameter measures the pointer, not the buffer",
      "pass the length explicitly; sizeof a decayed array parameter is the pointer size.")
def r_sizeof(ctx):
    for idx, line in enumerate(ctx.code):
        for m in SIZEOF_OPERAND.finditer(line):
            if m.group(1) in ctx.pointer_params:
                yield _f(ctx, idx, "sizeof-pointer-arg", "HIGH",
                         f"'{m.group(1)}' is a pointer/array parameter; sizeof yields the "
                         f"pointer width, silently truncating any copy that uses it.",
                         r_sizeof.fix)


MAP_INDEX = re.compile(r"\b([A-Za-z_]\w*)\s*\[")


@rule("map-operator-insert", ("cpp",), "MEDIUM",
      "operator[] on a std::map inserts a default element on read",
      "use .at(), .find() or .contains() for lookups; reserve [] for insert-or-assign.")
def r_map(ctx):
    for idx, line in enumerate(ctx.code):
        for m in MAP_INDEX.finditer(line):
            if m.group(1) not in ctx.map_vars:
                continue
            # find the matching ']' and look at what follows
            j = line.find("[", m.end() - 1)
            depth, k = 0, j
            while k < len(line):
                if line[k] == "[":
                    depth += 1
                elif line[k] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            after = line[k + 1:].lstrip()
            is_write = after.startswith("=") and not after.startswith("==")
            if not is_write:
                yield _f(ctx, idx, "map-operator-insert", "MEDIUM",
                         f"reading '{m.group(1)}[...]' default-constructs and inserts the key; "
                         f"a lookup silently grows the map.", r_map.fix)


@rule("object-slicing", ("cpp",), "HIGH",
      "a standard container holding a polymorphic base by value slices derived objects",
      "store std::unique_ptr<Base>/std::shared_ptr<Base>; polymorphism needs a pointer/ref.")
def r_slice(ctx):
    for idx, line in enumerate(ctx.code):
        for m in CONTAINER_OF.finditer(line):
            if m.group(1) in ctx.virtual_classes:
                yield _f(ctx, idx, "object-slicing", "HIGH",
                         f"'{m.group(1)}' is polymorphic (has virtual/override); storing it "
                         f"by value slices the derived part and loses virtual dispatch.",
                         r_slice.fix)


RANGEFOR_BIND = re.compile(r"\bfor\s*\(\s*auto\s+\[([^\]]*)\]\s*:")


@rule("rangefor-copy", ("cpp",), "MEDIUM",
      "range-for with 'auto [..]' (no &) iterates copies; writes don't reach the container",
      "bind by reference: 'for (auto& [k, v] : container)'.")
def r_rangefor(ctx):
    for idx, line in enumerate(ctx.code):
        m = RANGEFOR_BIND.search(line)
        if not m:
            continue
        names = [n.strip() for n in m.group(1).split(",") if n.strip()]
        mutates = False
        for _, bline in _block_lines(ctx.code, idx):
            for nm in names:
                if re.search(rf"\b{re.escape(nm)}\s*[-+*/%&|^]?=\s*[^=]", bline):
                    mutates = True
        sev = "HIGH" if mutates else "MEDIUM"
        extra = " and the loop assigns to a bound copy, so the writes are lost" if mutates else ""
        yield _f(ctx, idx, "rangefor-copy", sev,
                 f"'auto [{m.group(1)}]' binds by value{extra}; add '&' to mutate in place.",
                 r_rangefor.fix)


AUTO_INDEX = re.compile(r"\bauto\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\[")


@rule("vector-bool-proxy", ("cpp",), "MEDIUM",
      "'auto x = v[i]' on std::vector<bool> captures a proxy that aliases the bit",
      "write 'bool x = v[i]' to force a real copy, or avoid std::vector<bool>.")
def r_vbool(ctx):
    if not ctx.has_vector_bool:
        return
    for idx, line in enumerate(ctx.code):
        m = AUTO_INDEX.search(line)
        if m:
            yield _f(ctx, idx, "vector-bool-proxy", "MEDIUM",
                     f"with a std::vector<bool> in scope, 'auto {m.group(1)} = {m.group(2)}[...]' "
                     f"may deduce a proxy reference, not a bool; assigning to it mutates the vector.",
                     r_vbool.fix)


ASSIGN_IN_COND = re.compile(r"\b(?:if|while)\s*\(\s*[A-Za-z_][\w.\->\[\]]*\s*=\s*[^=]")


@rule("assign-in-condition", ("c", "cpp"), "MEDIUM",
      "assignment (=) inside an if/while condition; did you mean '=='?",
      "use '==' to compare, or wrap an intentional assignment in extra parentheses.")
def r_assign_cond(ctx):
    for idx, line in enumerate(ctx.code):
        if ASSIGN_IN_COND.search(line):
            yield _f(ctx, idx, "assign-in-condition", "MEDIUM",
                     "a single '=' in a condition assigns instead of comparing.",
                     r_assign_cond.fix)


UNSAFE_LIBC = re.compile(r"\b(gets|strcpy|strcat|sprintf)\s*\(")


@rule("unsafe-libc", ("c", "cpp"), "HIGH",
      "unbounded C string function with no length limit (buffer overflow risk)",
      "use the bounded variant: fgets / snprintf / strncpy / strncat (or std::string).")
def r_unsafe_libc(ctx):
    for idx, line in enumerate(ctx.code):
        m = UNSAFE_LIBC.search(line)
        if m:
            yield _f(ctx, idx, "unsafe-libc", "HIGH",
                     f"'{m.group(1)}' writes without a length bound and can overflow the destination.",
                     r_unsafe_libc.fix)


# ---- Haskell -------------------------------------------------------------- #
@rule("hs-int-overflow", ("haskell",), "MEDIUM",
      "fixed-width Int arithmetic can silently overflow (use Integer for unbounded results)",
      "give the function an Integer result type; Int wraps in two's complement with no error.")
def r_hs_int(ctx):
    bodies: dict[str, list[int]] = {}
    for idx, line in enumerate(ctx.code):
        bm = re.match(r"^\s*([A-Za-z_]\w*)\b.*=", line)
        if bm:
            bodies.setdefault(bm.group(1), []).append(idx)
    for name in ctx.int_return_funcs:
        for idx in bodies.get(name, []):
            # search the binding's line and the next few for risky arithmetic
            window = "\n".join(ctx.code[idx:idx + 4])
            if re.search(r"\b(product|factorial)\b|\^|\bsum\b", window):
                yield _f(ctx, idx, "hs-int-overflow", "MEDIUM",
                         f"'{name}' returns Int but does unbounded arithmetic "
                         f"(product/sum/^); large inputs wrap silently. Use Integer.",
                         r_hs_int.fix)
                break


@rule("hs-lazy-foldl", ("haskell",), "MEDIUM",
      "lazy foldl builds an O(n) thunk chain (space leak / stack overflow)",
      "use Data.List.foldl' (strict) or sum; they run in constant space.")
def r_hs_foldl(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bfoldl\b(?!')", line):
            yield _f(ctx, idx, "hs-lazy-foldl", "MEDIUM",
                     "lazy 'foldl' accumulates thunks; on a large input it leaks space or "
                     "overflows the stack. Prefer foldl'.", r_hs_foldl.fix)


@rule("hs-lazy-io", ("haskell",), "MEDIUM",
      "lazy readFile/hGetContents not forced before reuse can corrupt or lock the file",
      "force the contents (length/evaluate) or use readFile' / Data.Text.IO (strict).")
def r_hs_lazyio(ctx):
    joined = "\n".join(ctx.code)
    has_write = re.search(r"\bwriteFile\b", joined) is not None
    for idx, line in enumerate(ctx.code):
        if re.search(r"\breadFile\b(?!')", line) or re.search(r"\bhGetContents\b", line):
            sev = "MEDIUM"
            note = ("a later writeFile to the same handle/path can lock it or truncate it "
                    "mid-read") if has_write else "the file is read lazily and on demand"
            yield _f(ctx, idx, "hs-lazy-io", sev,
                     f"lazy I/O: {note}. Force the read or use the strict variant.",
                     r_hs_lazyio.fix)


@rule("hs-lazy-error-field", ("haskell",), "MEDIUM",
      "a value seeded with error/undefined stays a dormant landmine under lazy evaluation",
      "make the field strict (!field / StrictData) so the error fires at construction.")
def r_hs_landmine(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"=\s*(error\b|undefined\b)", line):
            yield _f(ctx, idx, "hs-lazy-error-field", "MEDIUM",
                     "this field/binding is set to error/undefined; laziness keeps it dormant "
                     "until something forces it, hiding the bug far from its cause.",
                     r_hs_landmine.fix)


@rule("hs-partial-function", ("haskell",), "MEDIUM",
      "partial functions like head/tail/read/fromJust crash on valid edge-case inputs",
      "pattern-match, use Maybe/Either, or total alternatives such as listToMaybe/readMaybe.")
def r_hs_partial(ctx):
    for idx, line in enumerate(ctx.code):
        if re.match(r"\s*import\b", line):
            continue
        m = re.search(r"\b(head|tail|read|fromJust)\b", line)
        if m:
            yield _f(ctx, idx, "hs-partial-function", "MEDIUM",
                     f"'{m.group(1)}' is partial: an empty list, malformed string, or Nothing crashes at runtime.",
                     r_hs_partial.fix)


# ---- Universal (any file) ------------------------------------------------- #
SECRET_ASSIGN = re.compile(
    r"(?i)\b(pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"token|client[_-]?secret|private[_-]?key|db[_-]?pass\w*)\b\s*[:=]\s*"
    r"['\"]([^'\"]{6,})['\"]"
)
AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIV_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
# obvious non-secrets we should not nag about
SECRET_PLACEHOLDER = re.compile(
    r"(?i)(\{\{?.*\}?\}|\$\{?\w|<[\w .-]+>|^env[:.]|os\.environ|getenv|process\.env|"
    r"example|changeme|placeholder|your[_-]?\w+|xxx+|\*{4,}|redacted|dummy|sample)"
)


SECRET_NAME = (r"pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
               r"token|client[_-]?secret|private[_-]?key|db[_-]?pass\w*")
# unquoted form (config/.env/.ini) -- only trusted on plain-text files, where a
# bare `KEY=value` is the norm and won't collide with code like `pw = get_pw()`.
SECRET_UNQUOTED = re.compile(
    rf"(?i)\b({SECRET_NAME})\b\s*[:=]\s*([^\s'\"#;]{{8,}})")
EMPTY_SECRET_ENV_DEFAULT = re.compile(
    r"\bos\.environ\.get\s*\(\s*['\"](?:SECRET_KEY|JWT_SECRET|TOKEN_SECRET|"
    r"SESSION_SECRET|SIGNING_KEY)['\"]\s*,\s*['\"]\s*['\"]\s*\)")


@rule("hardcoded-secret", ("*",), "HIGH",
      "a credential (password / API key / token / private key) is hardcoded in source",
      "load secrets from the environment or a secrets manager; never commit them, and rotate any that leaked.")
def r_secret(ctx):
    for idx, line in enumerate(ctx.raw):                 # secrets live in literals -> use raw
        hit = None
        m = SECRET_ASSIGN.search(line)
        if m and not SECRET_PLACEHOLDER.search(m.group(2)):
            hit = f"hardcoded value assigned to '{m.group(1)}'"
        elif ctx.lang == "text" and SECRET_UNQUOTED.search(line):
            um = SECRET_UNQUOTED.search(line)
            if not SECRET_PLACEHOLDER.search(um.group(2)):
                hit = f"hardcoded value assigned to '{um.group(1)}'"
        if hit is None and AWS_KEY.search(line):
            hit = "an AWS access key id (AKIA...) is committed in plaintext"
        elif hit is None and PRIV_KEY.search(line):
            hit = "a private key block is committed in plaintext"
        if hit:
            yield _f(ctx, idx, "hardcoded-secret", "HIGH",
                     f"{hit}; anyone with repo access (or git history) has the credential.",
                     r_secret.fix)


@rule("py-empty-secret-default", ("python",), "HIGH",
      "a signing/session secret falls back to the empty string",
      "require the secret to be set, or generate an explicit dev-only random value.")
def r_empty_secret_default(ctx):
    for idx, line in enumerate(ctx.literal):
        if EMPTY_SECRET_ENV_DEFAULT.search(line) and \
                re.search(r"\bos\.environ\.get\s*\(", ctx.code[idx]):
            yield _f(ctx, idx, "py-empty-secret-default", "HIGH",
                     "this environment lookup silently uses an empty signing secret when "
                     "configuration is missing; tokens/cookies become forgeable.",
                     r_empty_secret_default.fix)

# ---- more C / C++ --------------------------------------------------------- #
FLOAT_EQ = re.compile(r"(?:[!=]=\s*-?\d+\.\d+f?|-?\d+\.\d+f?\s*[!=]=)")


@rule("float-equality", ("c", "cpp"), "MEDIUM",
      "comparing floating-point values with == / != (rounding makes this unreliable)",
      "compare within a tolerance: fabs(a - b) < epsilon.")
def r_floateq(ctx):
    for idx, line in enumerate(ctx.code):
        if FLOAT_EQ.search(line):
            yield _f(ctx, idx, "float-equality", "MEDIUM",
                     "floating-point results rarely land on an exact value; == / != will "
                     "fail in ways that depend on rounding and optimization.", r_floateq.fix)


SCANF_CALL = re.compile(r"\bscanf\s*\(\s*\"((?:\\.|[^\"\\])*)\"", re.S)
SCANF_STRING = re.compile(r"%(?P<suppress>\*)?(?P<width>\d*)(?:l)?s")


@rule("scanf-unbounded", ("c", "cpp"), "HIGH",
      "scanf(\"%s\") has no length limit and overflows the destination buffer",
      "give %s a field width (e.g. %63s) or use fgets; never read unbounded input into a fixed buffer.")
def r_scanf(ctx):
    joined = "\n".join(ctx.literal)
    blanked = "\n".join(ctx.code)
    for match in SCANF_CALL.finditer(joined):
        if not re.match(r"scanf\s*\(", blanked[match.start():]):
            continue
        fmt = match.group(1).replace("%%", "")
        unsafe = any(not spec.group("suppress") and not spec.group("width")
                     for spec in SCANF_STRING.finditer(fmt))
        if unsafe:
            idx = joined.count("\n", 0, match.start())
            yield _f(ctx, idx, "scanf-unbounded", "HIGH",
                     "an unbounded %s lets input run past the buffer -- a classic stack smash.",
                     r_scanf.fix)


SYSTEM_CALL = re.compile(r"\b(system|popen|execlp|execvp)\s*\(")


@rule("command-exec", ("c", "cpp"), "MEDIUM",
      "spawning a shell/command (system/popen/exec*) is a command-injection risk",
      "avoid the shell; use exec with an explicit argv and validated inputs.")
def r_system(ctx):
    for idx, line in enumerate(ctx.code):
        m = SYSTEM_CALL.search(line)
        if m:
            yield _f(ctx, idx, "command-exec", "MEDIUM",
                     f"'{m.group(1)}' runs an external command; if any part comes from input "
                     f"it is a command-injection hole.", r_system.fix)


# The sinks `command-exec` above does not name. That rule is a hygiene check --
# "you are spawning a shell" -- and it is right to fire on every one of these.
# This list is wider because it has to cover what the ground truth actually
# uses: the wide-character forms, the whole exec family rather than the two -p
# spellings, and the Windows spawn/CreateProcess calls.
COMMAND_SINK = re.compile(
    r"\b(_?wsystem|system|_popen|popen|execlp|execle|execl|execvp|execve|execv|"
    r"_execlp|_execl|_execvp|_execv|_spawnlp|_spawnl|_spawnvp|_spawnv|"
    r"CreateProcess[AW]?|ShellExecute[AW]?|EXECL|EXECLP)\s*\(")

# Reading from any of these is reading something the caller did not choose.
COMMAND_TAINT_SOURCE = re.compile(
    r"\b(getenv|_wgetenv|GetEnvironmentVariable[AW]?|fgets|fgetws|gets|_getws|"
    r"getline|recv|recvfrom|read|fread|scanf|fscanf|wscanf|fwscanf|"
    r"accept)\s*\(")

# A literal assignment is how the corrected variant differs from the flaw:
# same sink, same shape, but the command stops coming from outside.
COMMAND_LITERAL = re.compile(
    r"=\s*L?\"|\b(?:strcpy|strcat|wcscpy|wcscat|sprintf|swprintf|_tcscpy)\s*\("
    r"\s*(\w+)\s*,\s*L?\"")


# Identifiers that appear in argument lists and are never a tainted buffer.
_NOT_A_BUFFER = frozenset({
    "char", "wchar_t", "int", "unsigned", "long", "short", "size_t", "void",
    "const", "sizeof", "strlen", "wcslen", "NULL", "stdin", "stdout", "stderr",
    "sizeof", "static", "signed", "FILE", "SOCKET", "true", "false",
})

_DEFINE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(.+?)\s*$")

# The assigned-to name, tolerating a declaration prefix and an array suffix so
# that `char *args[] = {...}` yields `args` rather than nothing.
_ASSIGN_TARGET = re.compile(
    r"\s*(?:[\w \t*]*?\b)?(\w+)\s*(?:\[[^\]]*\])?\s*=(?!=)")


def _object_macros(code):
    """Object-like `#define NAME value` pairs declared in this file.

    The ground truth routes its tainted buffer through one -- the sink reads
    `EXECLP(..., COMMAND_ARG3, NULL)` while `#define COMMAND_ARG3 data` sits
    a hundred lines up -- so a rule matching variable names at the sink sees
    nothing.  Real C does the same thing for real reasons, so resolving these
    is not a concession to the corpus.

    Function-like macros are skipped: expanding them needs argument
    substitution, and guessing at that would put names into sinks that the
    preprocessor never puts there.
    """
    macros = {}
    for line in code:
        match = _DEFINE.match(line)
        if match and "(" not in match.group(1):
            macros[match.group(1)] = match.group(2)
    return macros


def _expand(text, macros, rounds=3):
    """Substitute object-like macros, bounded so a cycle cannot hang a scan."""
    for _ in range(rounds):
        grown = re.sub(r"\b(\w+)\b",
                       lambda m: macros.get(m.group(1), m.group(0)), text)
        if grown == text:
            break
        text = grown
    return text


def _buffer_names(text):
    """Identifiers in an argument list that could name a buffer.

    Deliberately liberal about position: the tainted buffer arrives as
    `(char *)(data + dataLen)` as often as it arrives as `data`, so anything
    that only matches a bare comma-delimited name misses the common case.
    Type keywords and library helpers are filtered instead.
    """
    return {name for name in re.findall(r"\b([A-Za-z_]\w*)\b", text)
            if name not in _NOT_A_BUFFER}


def _command_taint(code, start, end, macros=None):
    """Per-line: which local names hold text that came from outside.

    Walked in order rather than gathered first, for the reason
    ``_allocation_walk`` is: a name can be tainted at one line and overwritten
    with a constant at the next, and a whole-span set would judge the sink by
    whichever assignment happened to be last in the file.

    Conservative in one direction on purpose. Taint is cleared on assignment
    from a literal, because that is a real correction; it is *not* cleared by
    a length check or a comparison, because neither of those makes an
    attacker-supplied string safe to hand to a shell.
    """
    tainted: set[str] = set()
    for index in range(start, end + 1):
        line = code[index]
        yield index, line, frozenset(tainted)

        literal = COMMAND_LITERAL.search(line)
        if literal:
            # `strcat(data, "ls ")` and `data = "ls "` both re-establish a
            # known command; the first names its target, the second does not.
            target = literal.group(1)
            if target:
                tainted.discard(target)
            else:
                assigned = re.match(r"\s*(?:\w[\w \t*]*?\b)?(\w+)\s*=", line)
                if assigned:
                    tainted.discard(assigned.group(1))
            continue

        source = COMMAND_TAINT_SOURCE.search(line)
        if source:
            # Everything the call could be filling: `x = getenv(...)` taints
            # the left side, `recv(s, (char *)(data + n), ...)` taints `data`.
            target = _ASSIGN_TARGET.match(line)
            if target and target.group(1) not in _NOT_A_BUFFER:
                tainted.add(target.group(1))
            tainted |= _buffer_names(line[source.end() - 1:])
            continue

        # Ordinary propagation: a name assigned from an expression that
        # mentions tainted data is itself tainted. This is what carries the
        # buffer into the argument vector -- `char *args[] = {path, arg, data,
        # NULL};` then `execv(path, args)` -- where the sink never names the
        # buffer at all.
        target = _ASSIGN_TARGET.match(line)
        if not target or target.group(1) in _NOT_A_BUFFER:
            continue
        name = target.group(1)
        if name in tainted:
            continue
        # Expanded for the same reason the sink is: the vector is built from
        # `COMMAND_ARG3`, not from `data`, and only the preprocessor knows
        # those are the same thing.
        right = line[target.end(1):]
        if macros:
            right = _expand(right, macros)
        if any(re.search(r"\b%s\b" % re.escape(held), right)
               for held in tainted):
            tainted.add(name)


@rule("c-command-injection", ("c", "cpp"), "HIGH",
      "a command built from external input is handed to a shell or exec",
      "pass a fixed program with an explicit argv, and never place caller "
      "input in the command string; validate against an allow-list if the "
      "program itself must vary.")
def r_command_injection(ctx):
    """Fires only when the command carries something from outside.

    Separate from ``command-exec`` on purpose. That rule reports the presence
    of a shell, which is worth knowing and is true of correct code as well.
    This one reports the vulnerability, and the difference between the two is
    the whole point: a rule that cannot tell a fixed program from an
    attacker-supplied one reports every ``system()`` in the tree and says
    nothing about which of them is a hole.
    """
    macros = _object_macros(ctx.code)
    for start, end in _c_function_spans(ctx.code):
        for index, line, tainted in _command_taint(ctx.code, start, end,
                                                   macros):
            if not tainted:
                continue
            # Expanded before the sink is matched, not after: the call is
            # written `SYSTEM(data)` behind `#define SYSTEM system` as often
            # as it is written `system(data)`, and the buffer reaches it under
            # a macro name too. Portability shims in real C look the same.
            expanded = _expand(line, macros)
            sink = COMMAND_SINK.search(expanded)
            if not sink:
                continue
            arguments = expanded[sink.end() - 1:]
            carried = [name for name in tainted
                       if re.search(r"\b%s\b" % re.escape(name), arguments)]
            if carried:
                yield _f(ctx, index, "c-command-injection", "HIGH",
                         "'%s' runs a command holding '%s', which came from "
                         "outside the program; anything that adds a ';' or a "
                         "'|' to it runs next."
                         % (sink.group(1), sorted(carried)[0]),
                         r_command_injection.fix)


# Functions whose return value carries the only report of failure. Curated,
# not inferred: plenty of calls have returns worth ignoring -- `printf` is the
# obvious one -- and a rule that demanded every return be inspected would bury
# the cases that matter under the ones that do not.
MUST_CHECK_RETURN = frozenset({
    # Security context. Ignoring these leaves the process running with
    # privileges it believes it dropped.
    "ImpersonateSelf", "ImpersonateNamedPipeClient", "RpcImpersonateClient",
    "SetThreadToken", "setuid", "setgid", "seteuid", "setegid", "setreuid",
    "setregid", "AdjustTokenPrivileges", "InitializeSecurityDescriptor",
    "SetSecurityDescriptorDacl", "CreateProcessAsUser",
    # Filesystem and process state.
    "chdir", "chroot", "chmod", "chown", "fchmod", "fchown", "mkdir", "rmdir",
    "unlink", "rename", "truncate", "ftruncate", "fflush", "fclose", "fseek",
    "SetFilePointer", "DeleteFile", "MoveFile", "CreateDirectory",
    # Allocation and IO whose failure is silent otherwise.
    # The output side matters as much as the input side: a `fputs` that ran
    # out of disk reports it here and nowhere else, and the held-out families
    # of this class are almost entirely these.
    "fgets", "fgetws", "fread", "fwrite", "read", "write", "recv", "send",
    "realloc", "strtok_s", "wcstombs_s", "mbstowcs_s",
    "fputs", "fputws", "fputc", "fputwc", "putc", "putwc", "putchar",
    "putwchar", "puts", "fprintf", "fwprintf", "fscanf", "fwscanf", "scanf",
    "wscanf", "sscanf", "swscanf", "snprintf", "swprintf", "system", "remove",
    "_wremove", "_wrename", "setvbuf", "fsetpos", "fgetpos",
})

# Functions returning an unsigned count. Comparing one `< 0` is a branch the
# compiler can prove is never taken -- the check is present, reads like error
# handling, and does nothing. That is a different mistake from the pointer
# case below, and it is what the held-out families of CWE-253 actually use.
UNSIGNED_RETURNING = frozenset({
    "fread", "fwrite", "strlen", "wcslen", "strnlen", "strspn", "strcspn",
    "sizeof", "strftime", "wcsftime", "mbstowcs", "wcstombs",
})

_COUNTED = "|".join(sorted(map(re.escape, UNSIGNED_RETURNING)))

UNSIGNED_MISCHECK = re.compile(
    r"\b(%s)\s*\(.*\)\s*<\s*0(?![\w.])" % _COUNTED)

# `fread(...) == 0` is the incomplete check the corpus actually ships: it
# catches total failure and misses a short read, which returns a positive
# count smaller than the one requested. The corrected variant compares against
# the requested count instead -- `!= 100-1` -- so testing against zero is the
# discriminator, not the presence of a test.
SHORT_COUNT_MISCHECK = re.compile(
    r"\b(%s)\s*\(.*\)\s*[=!]=\s*0(?![\w.])" % _COUNTED)

# The call is the whole statement: no assignment, no condition, no return.
BARE_CALL_STATEMENT = re.compile(r"^\s*([A-Za-z_]\w*)\s*\([^;]*\)\s*;\s*$")


@rule("c-unchecked-return", ("c", "cpp"), "MEDIUM",
      "a call whose return value is its only failure report is ignored",
      "test the result and handle the failure; a privilege change or file "
      "operation that quietly did nothing is worse than one that errored.")
def r_unchecked_return(ctx):
    """Called as a bare statement, with the result dropped.

    Both variants call the same function at the same place. The corrected one
    wraps it -- `if (!ImpersonateSelf(...))` -- so what separates them is
    whether the value goes anywhere, not whether the call happens.
    """
    for index, line in enumerate(ctx.code):
        match = BARE_CALL_STATEMENT.match(line)
        if match and match.group(1) in MUST_CHECK_RETURN:
            yield _f(ctx, index, "c-unchecked-return", "MEDIUM",
                     "'%s' reports failure only through its return value, and "
                     "this call discards it." % match.group(1),
                     r_unchecked_return.fix)


# Functions returning a pointer, where NULL is the failure. Comparing one with
# a relational operator, or against a number, tests something the standard
# never promised.
POINTER_RETURNING = frozenset({
    "fgets", "fgetws", "fopen", "_wfopen", "freopen", "tmpfile", "malloc",
    "calloc", "realloc", "strdup", "_strdup", "wcsdup", "strchr", "strrchr",
    "strstr", "wcschr", "wcsstr", "memchr", "getenv", "_wgetenv", "gets",
    "opendir", "readdir", "setlocale", "localtime", "gmtime",
})

POINTER_MISCHECK = re.compile(
    r"\b([A-Za-z_]\w*)\s*\([^;]*\)\s*(<=|>=|<|>)\s*[-(]?\s*\d")


@rule("c-wrong-return-check", ("c", "cpp"), "HIGH",
      "a pointer-returning call is compared as if it returned a number",
      "compare the result against NULL; an ordering test on a pointer is "
      "undefined and the failure path never runs.")
def r_wrong_return_check(ctx):
    """`if (fgets(...) < 0)` and its relatives.

    The check is present, which is what makes this its own class rather than
    an unchecked return: it simply tests a condition that cannot become true.
    A reader skims it and sees error handling; the compiler emits a branch
    that is never taken.
    """
    for index, line in enumerate(ctx.code):
        match = POINTER_MISCHECK.search(line)
        if match and match.group(1) in POINTER_RETURNING:
            yield _f(ctx, index, "c-wrong-return-check", "HIGH",
                     "'%s' returns a pointer, but this compares it with '%s' "
                     "against a number; the failure branch is unreachable."
                     % (match.group(1), match.group(2)),
                     r_wrong_return_check.fix)
            continue
        short_count = SHORT_COUNT_MISCHECK.search(line)
        if short_count and short_count.group(1) in UNSIGNED_RETURNING:
            yield _f(ctx, index, "c-wrong-return-check", "HIGH",
                     "'%s' is checked only against zero, which catches a total "
                     "failure and misses a short transfer -- it returns a "
                     "count, so compare it with the count you asked for."
                     % short_count.group(1), r_wrong_return_check.fix)
            continue
        unsigned = UNSIGNED_MISCHECK.search(line)
        if unsigned and unsigned.group(1) in UNSIGNED_RETURNING:
            yield _f(ctx, index, "c-wrong-return-check", "HIGH",
                     "'%s' returns an unsigned count, so testing it '< 0' is "
                     "a branch that can never run; the short read or write it "
                     "was meant to catch goes unnoticed." % unsigned.group(1),
                     r_wrong_return_check.fix)


# `x = 0;`, `x = 0.0F;`, `x = 0L;` -- a literal zero and nothing else. The
# corrected variant of a divide-by-zero case is byte-identical apart from this
# constant, so the value is the entire discriminator and the division itself
# says nothing.
ZERO_ASSIGN = re.compile(
    r"^\s*(?:[\w \t*]*?\b)?(\w+)\s*=\s*0(?:\.0*)?[FfLlUu]*\s*;")
NONZERO_ASSIGN = re.compile(
    r"^\s*(?:[\w \t*]*?\b)?(\w+)\s*=\s*(?!0(?:\.0*)?[FfLlUu]*\s*;)[^=]")


@rule("c-divide-by-zero", ("c", "cpp"), "HIGH",
      "a value known to be zero is used as a divisor",
      "test the divisor before dividing, or keep the value that guarantees it "
      "is non-zero -- the fault is a crash on every call, not an edge case.")
def r_divide_by_zero(ctx):
    """Divides by a name last assigned a literal zero.

    Both variants divide, at the same line, by the same name. What differs is
    one constant a few lines up, so anything keyed on the division reports the
    corrected code just as loudly. Tracking the assigned value is the only
    thing that separates them.
    """
    for start, end in _c_function_spans(ctx.code):
        zero: set[str] = set()
        for index in range(start, end + 1):
            line = ctx.code[index]

            # A test of the name is a guard, whatever its shape: the corrected
            # `goodB2G` variant checks rather than changing the constant.
            if re.search(r"\b(?:if|while|for)\b", line):
                for name in list(zero):
                    if re.search(r"\b%s\b" % re.escape(name), line):
                        zero.discard(name)

            # Two ways a divisor is known-suspect, and the corpus splits them
            # cleanly: the `*_zero` families assign a literal, while the
            # `*_fgets`/`*_fscanf`/`*_rand` families read one. Only the first
            # was covered at first, and it happened to be the half that landed
            # in the training split -- so the rule scored 0% held out while
            # working perfectly on everything it had been written against.
            if OVERFLOW_SOURCE.search(line):
                target = _ASSIGN_TARGET.match(line)
                if target and target.group(1) not in _NOT_A_BUFFER:
                    zero.add(target.group(1))
                source = OVERFLOW_SOURCE.search(line)
                for name in _buffer_names(line[source.end() - 1:]):
                    zero.add(name)
                continue

            match = ZERO_ASSIGN.match(line)
            if match and match.group(1) not in _NOT_A_BUFFER:
                zero.add(match.group(1))
                continue
            other = NONZERO_ASSIGN.match(line)
            if other:
                zero.discard(other.group(1))

            for name in sorted(zero):
                escaped = re.escape(name)
                # `%%` because the character class holds a literal percent and
                # this pattern is assembled with %-formatting.
                if re.search(r"[/%%]\s*\(*\s*%s\b" % escaped, line):
                    yield _f(ctx, index, "c-divide-by-zero", "HIGH",
                             "'%s' was set to zero and is used here as a "
                             "divisor; this faults on every call." % name,
                             r_divide_by_zero.fix)
                    zero.discard(name)
                    break


# `TYPE name;` with no initialiser. Restricted to the plain scalar and pointer
# forms so that a declaration carrying a call, an array size, or a brace
# initialiser is never mistaken for an empty one.
BARE_DECLARATION = re.compile(
    r"^\s*(?:static\s+|const\s+|unsigned\s+|signed\s+|struct\s+)*"
    r"(?:void|char|short|int|long|float|double|size_t|wchar_t|[A-Z]\w*)"
    r"\s*\**\s*(\w+)\s*;\s*$")


@rule("c-uninitialised-read", ("c", "cpp"), "HIGH",
      "a local is read before anything assigns to it",
      "initialise it at the point of declaration; an automatic variable holds "
      "whatever the stack last left there, which differs per build and per run.")
def r_uninitialised_read(ctx):
    """Declared, never assigned, then used.

    Taking the address of the name clears it: `scanf("%d", &x)` and every
    out-parameter convention initialise through a pointer, and a rule that
    ignored that would report the ordinary way C fills a variable.
    """
    for start, end in _c_function_spans(ctx.code):
        pending: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]

            declared = BARE_DECLARATION.match(line)
            if declared and declared.group(1) not in _NOT_A_BUFFER:
                pending[declared.group(1)] = index
                continue

            for name in list(pending):
                escaped = re.escape(name)
                if not re.search(r"\b%s\b" % escaped, line):
                    continue
                # Assigned, or handed somewhere that can assign through it.
                if re.search(r"\b%s\s*(?:\[[^\]]*\])?\s*=(?!=)" % escaped, line) \
                        or re.search(r"&\s*%s\b" % escaped, line):
                    pending.pop(name, None)
                    continue
                # Passed to a callee this rule cannot read. The corrected
                # variant of a real case is `goodG2BSource(data)` followed by
                # the same use the flaw has, so assuming an unknown call
                # leaves the variable untouched reported working code -- the
                # identical mistake `c-memory-leak` made with its releases.
                callees = set(_CALL_NAME.findall(line))
                if callees and not callees <= READS_WITHOUT_OWNING:
                    pending.pop(name, None)
                    continue
                yield _f(ctx, index, "c-uninitialised-read", "HIGH",
                         "'%s' is read here but nothing has assigned to it "
                         "since its declaration; its value is whatever the "
                         "stack happened to hold." % name,
                         r_uninitialised_read.fix)
                pending.pop(name, None)


# Allocators whose result the caller owns. ALLOCA is deliberately absent: it
# is stack memory, needs no release, and the corrected variant of a leak case
# often switches to it precisely because there is then nothing to forget.
HEAP_ALLOCATOR = re.compile(
    r"=\s*(?:\([^)]*\)\s*)?\b(malloc|calloc|realloc|strdup|_strdup|wcsdup|"
    r"_wcsdup|new\b)\s*[\(\[]?")

# Calls known to read a buffer without taking ownership. Anything *not* here,
# handed the pointer, ends the tracking -- a function whose body this rule
# cannot see may be the one that frees it, and in the corrected variant of a
# real leak case it usually is.
#
# Whitelisting readers rather than blacklisting freers is the safe direction:
# an unknown callee treated as a possible owner costs a detection, while one
# assumed harmless costs a false positive, and this catalog is worth more
# precise than loud.
# Control keywords `_CALL_NAME` picks up because `if (` looks like a call.
_NOT_A_CALL = frozenset({"if", "for", "while", "switch", "return", "sizeof",
                         "else", "do", "catch"})

# A callee whose *name* says it reads. Weaker evidence than a summary and
# used only when the body is not in this file, but far less corpus-specific
# than an exact-name list: the whitelist below is Juliet's vocabulary
# (`printIntLine`, `printStructLine`), which is precisely why this rule scored
# 48.7% on idiom families it was written from and 22.9% on ones it was not.
_READER_NAME = re.compile(
    r"\A(?:print|log|write|dump|show|display|trace|report|puts|fput|fprint)"
    r"\w*\Z", re.IGNORECASE)

READS_WITHOUT_OWNING = frozenset({
    "printLine", "printWLine", "printIntLine", "printStructLine", "printBytes",
    "printf", "wprintf", "fprintf", "puts", "fputs", "sprintf", "swprintf",
    "snprintf", "strcpy", "strncpy", "wcscpy", "wcsncpy", "strcat", "strncat",
    "wcscat", "wcsncat", "memcpy", "memmove", "memset", "strlen", "wcslen",
    "sizeof", "if", "while", "for", "switch", "return", "free", "delete",
    "exit", "realloc", "malloc", "calloc",
})

_CALL_NAME = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


@rule("c-memory-leak", ("c", "cpp"), "MEDIUM",
      "heap memory is allocated and never released on this path",
      "release it with the matching deallocator before the last reference "
      "goes out of scope, or return it and document that the caller owns it.")
def r_memory_leak(ctx):
    """Allocated, used, and dropped without a release.

    The corrected variant either calls `free` or switches the allocation to
    the stack, so the presence of the allocation is not the signal -- both
    variants allocate. What separates them is whether anything gives the
    memory back before the name goes out of scope.

    Conservative about ownership: returning the pointer, storing it into
    another name, or taking its address all count as handing it onward, and
    end the tracking rather than reporting.

    Passing it to a function ends tracking too, unless that function is a
    known reader. The first version of this rule assumed a call was harmless
    and reported 6.5% of *corrected* cases, because the corrected variant of a
    leak is frequently `goodB2G1Sink(data)` with the release inside a function
    this rule cannot see. Whitelisting readers rather than guessing at callees
    trades some detection for not being wrong about working code.
    """
    # Read once for the whole file: which local functions release a parameter,
    # and which merely exist. A callee defined here is a fact, not a guess.
    releasers = _parameter_releasers(ctx.code)
    local_functions = {name for name, _params, _s, _e
                       in _c_function_defs(ctx.code) if name}

    for start, end in _c_function_spans(ctx.code):
        # name -> (line of the allocation, brace depth it was made at)
        owned: dict[str, tuple[int, int]] = {}
        found: list[tuple[int, str]] = []
        depth = 0

        def settle():
            """Close the current function: anything still owned has leaked."""
            for held, (line_number, _) in owned.items():
                found.append((line_number, held))
            owned.clear()

        for index in range(start, end + 1):
            line = ctx.code[index]
            if _FUNCTION_HEAD.match(line):
                # One span can cover several functions when they sit inside a
                # C++ namespace, and an allocation in one must not be tracked
                # into the next.
                settle()
                depth = 0
            depth += line.count("{") - line.count("}")

            if HEAP_ALLOCATOR.search(line):
                target = _ASSIGN_TARGET.match(line)
                if target and target.group(1) not in _NOT_A_BUFFER:
                    owned[target.group(1)] = (index, depth)
                continue

            for name in list(owned):
                escaped = re.escape(name)
                # Released, so nothing is owed.
                if re.search(r"\b(?:free|delete|_aligned_free|LocalFree|"
                             r"GlobalFree)\s*(?:\[\s*\])?\s*\(?\s*&?\s*%s\b"
                             % escaped, line):
                    owned.pop(name, None)
                    continue
                # Handed onward: returned, stored elsewhere, or addressed.
                if re.search(r"\breturn\s+[^;]*\b%s\b" % escaped, line) \
                        or re.search(r"\b\w+\s*=\s*[^=]*\b%s\b" % escaped, line) \
                        or re.search(r"&\s*%s\b" % escaped, line):
                    owned.pop(name, None)
                    continue
                # Handed to a callee. Whether that ends this rule's interest
                # depends on what the callee does, and for a function defined
                # in the same file that is knowable rather than guessable.
                if re.search(r"\b%s\b" % escaped, line):
                    unresolved = False
                    for callee in set(_CALL_NAME.findall(line)) - _NOT_A_CALL:
                        if callee in releasers:
                            unresolved = True          # it frees; nothing owed
                        elif callee in local_functions:
                            continue                   # defined here, frees nothing
                        elif callee in READS_WITHOUT_OWNING \
                                or _READER_NAME.match(callee):
                            continue
                        else:
                            unresolved = True          # unknown; may release
                    if unresolved:
                        owned.pop(name, None)
                        continue
                # A redeclaration in a *nested* scope shadows the name; it
                # does not end the outer allocation's life, and the outer one
                # still leaks. Juliet's reference-alias families close with
                # `{ int *data = dataRef; }`, and treating that inner
                # declaration as the end of tracking dropped the leak that had
                # just been found.
                if _redeclared(name, line) and depth <= owned[name][1]:
                    owned.pop(name, None)

        settle()
        for line_number, name in sorted(found):
            yield _f(ctx, line_number, "c-memory-leak", "MEDIUM",
                     "'%s' is allocated here and never released before the "
                     "function returns; every call leaks the block."
                     % name, r_memory_leak.fix)


# `ptr = buffer - 8` -- a pointer aimed below the object it came from. The
# corrected variant is the same assignment without the subtraction, so the
# arithmetic itself is the whole signal.
UNDERWRITE_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*-\s*(?:\d+|\w+)\s*;")

# Where a buffer comes from, when it is not a declared array. `new T[n]`,
# the malloc family, and the alloca spellings all produce a base pointer that
# it is equally undefined to aim below.
_BUFFER_ORIGIN = re.compile(
    r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)*"
    r"(?:new\b[^\[\n]*\[|(?:malloc|calloc|realloc|alloca|ALLOCA|_alloca)\s*\()")


@rule("c-buffer-underwrite", ("c", "cpp"), "HIGH",
      "a pointer is aimed before the start of the buffer it came from",
      "index forward from the base pointer, and never construct a pointer "
      "below it -- the result is undefined even before it is written through.")
def r_buffer_underwrite(ctx):
    """`data = dataBuffer - 8` and its relatives.

    Restricted to a subtraction from a name known to be a buffer in the same
    function. Without that, every `p = q - n` in ordinary pointer arithmetic
    reports, and the rule becomes noise for the one case it wanted.

    A buffer is not only a declared array. Requiring `name[100];` was measured
    to cost most of the class: on Juliet's CWE-124 the `_declare` family is
    roughly a fifth of the cases, and the rest reach the same
    `data = dataBuffer - 8` through `new wchar_t[100]`, `malloc`, or `alloca`
    -- so the subtraction was seen and ignored because its base had no
    recognised origin. Detection sat at 15% against a ~40% single-flow ceiling.
    """
    for start, end in _c_function_spans(ctx.code):
        arrays: set[str] = set()
        for index in range(start, end + 1):
            line = ctx.code[index]
            declared = re.search(r"\b(\w+)\s*\[\s*\d+\s*\]\s*(?:=|;)", line)
            if declared:
                arrays.add(declared.group(1))
            origin = _BUFFER_ORIGIN.search(line)
            if origin:
                arrays.add(origin.group(1))
            match = UNDERWRITE_ASSIGN.search(line)
            if match and match.group(2) in arrays:
                yield _f(ctx, index, "c-buffer-underwrite", "HIGH",
                         "'%s' points before the start of '%s'; reading or "
                         "writing through it touches memory the buffer never "
                         "owned." % (match.group(1), match.group(2)),
                         r_buffer_underwrite.fix)


# There is deliberately no rule here for CWE-126 (buffer over-read) or CWE-127
# (buffer under-read), and the reason is worth keeping.
#
# The obvious rule works on paper: the corrected variant writes
# `if (data >= 0 && data < 10)` while the flawed one keeps only the half its
# family is named for, so tracking the two bounds independently should
# separate them. Written and measured, it fired on 22.6% of flawed CWE-126
# cases and 22.6% of fixed ones -- and 29.0% against 29.0% on CWE-127.
# Identical. Zero discrimination.
#
# The cause is that Juliet's `goodG2B` variants repair the *source* -- they
# feed a known-safe index -- and leave the one-sided guard at the sink exactly
# as the flaw has it. A rule keyed on the guard cannot see a difference that
# is not there, so it reports correct code at precisely the rate it reports
# defective code.
#
# This is the same failure that removed the CWE-129 rule after 72 false
# positives for no gain. Detecting these two classes needs the index's
# provenance, not its guard, and that is a different rule than this was.


# Both spellings of "give this back". `delete` was missing and is not a
# minor omission: in Juliet's CWE-415 the `new_delete` family is roughly half
# the corpus, so a rule that only knew `free` could not see any of it.
_RELEASE = re.compile(
    r"\b(?:free|_aligned_free|LocalFree|GlobalFree)\s*\(\s*&?\s*(\w+)\s*\)"
    r"|\bdelete\s*(?:\[\s*\])?\s*(\w+)\s*;")

_CALL_STATEMENT = re.compile(r"\A\s*(\w+)\s*\(([^;]*)\)\s*;\s*\Z")

# `else`, `} else`, and `} else {` -- the start of a branch exclusive with the
# one before it.
_ELSE_ARM = re.compile(r"\A\s*(?:\}\s*)?else\b")


def _parameter_releasers(code):
    """{function: which parameter it releases} for functions in this file.

    A summary, and the cheapest one that buys anything. Juliet's `_41` family
    moves the second release into a helper::

        static void badSink(twoIntsStruct *data) { free(data); }
        ...
        free(data);
        badSink(data);          /* the second free, invisible locally */

    The corrected variant drops the direct `free` and keeps only the call, so
    the two differ by exactly the thing a local walk cannot see. Restricted to
    callees defined in the same file: a summary of a function whose body is
    not here would be a guess, and guessing a `free` invents double-frees.
    """
    releasers: dict[str, int] = {}
    for name, parameters, start, end in _c_function_defs(code):
        if not parameters:
            continue
        for index in range(start, end + 1):
            match = _RELEASE.search(code[index])
            if not match:
                continue
            released = match.group(1) or match.group(2)
            if released in parameters:
                releasers[name] = parameters.index(released)
                break
    return releasers


@rule("c-double-free", ("c", "cpp"), "HIGH",
      "the same pointer is released twice",
      "set the pointer to NULL after releasing it, so a second release is a "
      "no-op instead of corruption of the allocator's own bookkeeping.")
def r_double_free(ctx):
    """A second release with nothing in between that could have changed it.

    Distinct from `c-use-after-free`, which reports a *read* through a dead
    pointer. Here the pointer is never dereferenced -- it is handed back to
    the allocator twice, which corrupts the free list rather than the program's
    own memory, and is why the two are separate CWEs.
    """
    releasers = _parameter_releasers(ctx.code)
    for start, end in _c_function_spans(ctx.code):
        # name -> the brace depth it was released at, so releases in exclusive
        # branches can be told apart from releases in sequence.
        freed: dict[str, int] = {}
        depth = 0
        for index in range(start, end + 1):
            line = ctx.code[index]
            if _FUNCTION_HEAD.match(line):
                # `_c_function_spans` hands back a C++ `namespace { ... }`
                # body as a single span, so several functions share it and a
                # release in one was carried into the next. Measured: a
                # `delete` in goodB2G2 reported against a `delete` in
                # goodG2BSink, a function that releases nothing twice.
                freed.clear()
                depth = 0
            after = depth + line.count("{") - line.count("}")

            if _ELSE_ARM.match(line):
                # A release in the `if` arm and one in the `else` arm are on
                # exclusive paths and are not a double free. Juliet writes it
                # out plainly::
                #     if (...) { delete data; } else { delete data; }
                # which is correct, and which a linear walk reads as two
                # releases of the same pointer. Discarding at or below the
                # arm's depth can cost a detection but cannot invent one,
                # which is the right direction to be wrong in.
                for name in [n for n, at in freed.items() if at >= after]:
                    del freed[name]
            # Updated here rather than at the bottom of the loop: the paths
            # below `continue`, and a depth that only advances on lines which
            # happen to reach the end would drift on the first plain statement.
            depth = after

            for name in list(freed):
                # Any fresh assignment -- NULL, a new allocation, anything --
                # means the second release is not the same pointer.
                if re.search(r"\b%s\s*=(?!=)" % re.escape(name), line) \
                        or _redeclared(name, line):
                    freed.pop(name, None)
            match = _RELEASE.search(line)
            name = (match.group(1) or match.group(2)) if match else None
            if name is None:
                # A call to a local function that releases its argument is a
                # release of that argument here.
                invocation = _CALL_STATEMENT.match(line)
                if invocation and invocation.group(1) in releasers:
                    arguments = _split_arguments(invocation.group(2))
                    position = releasers[invocation.group(1)]
                    if position < len(arguments) \
                            and _BARE_NAME.match(arguments[position]):
                        name = arguments[position]
            if name is None:
                continue
            if name in freed:
                yield _f(ctx, index, "c-double-free", "HIGH",
                         "'%s' was already released and has not been "
                         "reassigned since; freeing it again corrupts the "
                         "allocator." % name, r_double_free.fix)
                freed.pop(name, None)
            else:
                freed[name] = depth


# Opening a file named by someone else. The taint machinery is shared with
# `c-command-injection` unchanged -- the ground truth for both classes reads a
# name from a socket or the console, and the corrected variant replaces it with
# a literal in exactly the same way. Only the sink differs, so only the sink is
# redefined here.
PATH_SINK = re.compile(
    r"\b(fopen|_wfopen|_tfopen|freopen|_wfreopen|open|_open|_wopen|_topen|"
    r"CreateFile[AW]?|ifstream|ofstream|fstream|remove|_wremove|unlink|"
    r"_wunlink|rename|_wrename)\s*\(")

# A canonicalising or containment check is the fix in the wild, even though
# the corpus prefers to swap the whole name for a literal. Treated as clearing
# taint so that real code doing the right thing is not reported.
PATH_VALIDATED = re.compile(
    r"\b(realpath|_fullpath|GetFullPathName[AW]?|PathCanonicalize[AW]?|"
    r"PathIsRelative[AW]?|canonicalize_file_name)\s*\(")


@rule("c-path-traversal", ("c", "cpp"), "HIGH",
      "a filename taken from outside the program is opened without validation",
      "resolve the path and confirm it stays inside the intended directory "
      "before opening it; reject anything that escapes, rather than trimming "
      "the parts you recognise.")
def r_path_traversal(ctx):
    """Fires when an externally supplied name reaches a file operation.

    Shares ``_command_taint`` with the command-injection rule rather than
    reimplementing it: the two classes differ in what the value is finally
    handed to, not in how it arrives or in what the corrected variant does
    about it. Reusing the walk means a fix to the taint model reaches both,
    and there is one place to be wrong instead of two.
    """
    macros = _object_macros(ctx.code)
    for start, end in _c_function_spans(ctx.code):
        cleared: set[str] = set()
        for index, line, tainted in _command_taint(ctx.code, start, end,
                                                   macros):
            live = tainted - cleared
            if PATH_VALIDATED.search(line):
                cleared |= {name for name in live
                            if re.search(r"\b%s\b" % re.escape(name), line)}
                continue
            if not live:
                continue
            expanded = _expand(line, macros) if macros else line
            sink = PATH_SINK.search(expanded)
            if not sink:
                continue
            arguments = expanded[sink.end() - 1:]
            carried = [name for name in live
                       if re.search(r"\b%s\b" % re.escape(name), arguments)]
            if carried:
                yield _f(ctx, index, "c-path-traversal", "HIGH",
                         "'%s' names a file and came from outside the program; "
                         "'../' in it reaches wherever the process can."
                         % sorted(carried)[0], r_path_traversal.fix)
                cleared.add(sorted(carried)[0])


# Where an unchecked number comes in. Narrower than the command-injection
# sources: a value only overflows if it is arithmetic, so string readers that
# cannot produce one are left out.
OVERFLOW_SOURCE = re.compile(
    r"\b(fscanf|scanf|sscanf|swscanf|fwscanf|wscanf|atoi|atol|atoll|strtol|"
    r"strtoul|strtoll|wcstol|rand|random|recv|recvfrom|read|fread|getenv|"
    r"_wgetenv|RAND32|RAND64)\s*\(")

# The limits a correct variant tests against before it does the arithmetic.
# This is the whole discriminator: both variants compute, only one checks.
OVERFLOW_LIMIT = re.compile(
    r"\b(CHAR_MAX|CHAR_MIN|SCHAR_MAX|SCHAR_MIN|UCHAR_MAX|SHRT_MAX|SHRT_MIN|"
    r"USHRT_MAX|INT_MAX|INT_MIN|UINT_MAX|LONG_MAX|LONG_MIN|ULONG_MAX|"
    r"LLONG_MAX|LLONG_MIN|ULLONG_MAX|SIZE_MAX|INT8_MAX|INT16_MAX|INT32_MAX|"
    r"INT64_MAX|UINT8_MAX|UINT16_MAX|UINT32_MAX|UINT64_MAX)\b")

# `x + 1`, `x * x`, `x++`, `++x`, `x *= 2`, `x += n` -- built per name.
_OVERFLOW_OPS = (
    r"\b%(n)s\s*(?:\+\+|--)",            # post-increment
    r"(?:\+\+|--)\s*%(n)s\b",            # pre-increment
    r"\b%(n)s\s*(?:\+=|\*=|-=)",         # compound assignment
    r"=[^=]*\b%(n)s\s*[*+-]\s*\w",       # result = x * y
    r"=[^=]*\w\s*[*+-]\s*%(n)s\b",       # result = y * x
)


def _overflow_guarded(name, line):
    """True when this line bounds `name` against a width limit.

    The corrected variant is not the one that avoids the arithmetic -- it does
    the same multiply -- it is the one that asks whether the operands fit
    first.  So the guard is the entire signal, and a rule that ignores it
    reports the fix as loudly as the flaw.

    Conservative in the same direction as ``_null_guarded``: any test of the
    name against a limit clears it for the rest of the function, giving up a
    later genuine overflow rather than risking a false positive on a checked
    one.  ``sqrt(INT_MAX)`` bounds are caught by the same rule, since the
    limit constant is still named.
    """
    if not re.search(r"\b(?:if|while|for|assert|switch)\b", line):
        return False
    if not OVERFLOW_LIMIT.search(line):
        return False
    return bool(re.search(r"\b%s\b" % re.escape(name), line))


@rule("c-integer-overflow", ("c", "cpp"), "HIGH",
      "arithmetic on an unchecked external value can wrap past its type",
      "test the operands against the type's limit before the operation, and "
      "widen the result type or reject the input when they do not fit.")
def r_integer_overflow(ctx):
    """Fires on arithmetic that no bounds check protects.

    Both variants of a real testcase perform the same operation; only one
    tests its operands first.  Anything that keys on the arithmetic alone
    therefore fires on correct code too -- which is the CWE-129 failure, where
    a rule matched a sink that was byte-identical on both sides and cost 72
    false positives for nothing.
    """
    macros = _object_macros(ctx.code)
    for start, end in _c_function_spans(ctx.code):
        tainted: set[str] = set()
        guarded: set[str] = set()
        for index in range(start, end + 1):
            line = ctx.code[index]

            for name in list(tainted):
                if _overflow_guarded(name, line):
                    guarded.add(name)
                # A fresh declaration is a new binding, so old state dies with
                # it -- the same reason `_redeclared` exists for pointers.
                if _redeclared(name, line):
                    tainted.discard(name)
                    guarded.discard(name)

            if OVERFLOW_SOURCE.search(line):
                target = _ASSIGN_TARGET.match(line)
                if target and target.group(1) not in _NOT_A_BUFFER:
                    tainted.add(target.group(1))
                    guarded.discard(target.group(1))
                source = OVERFLOW_SOURCE.search(line)
                for name in _buffer_names(line[source.end() - 1:]):
                    tainted.add(name)
                    guarded.discard(name)
                continue

            expanded = _expand(line, macros) if macros else line
            for name in sorted(tainted - guarded):
                if any(re.search(pattern % {"n": re.escape(name)}, expanded)
                       for pattern in _OVERFLOW_OPS):
                    yield _f(ctx, index, "c-integer-overflow", "HIGH",
                             "'%s' holds a value from outside the program and "
                             "is used in arithmetic with no bounds check; past "
                             "the type's limit it wraps silently." % name,
                             r_integer_overflow.fix)
                    guarded.add(name)      # one report per value, not per use
                    break


EMPTY_CATCH = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")


@rule("empty-catch", ("cpp",), "MEDIUM",
      "an empty catch block silently swallows the exception",
      "log, handle, or rethrow; an empty catch turns a failure into a silent wrong result.")
def r_emptycatch(ctx):
    joined = "\n".join(ctx.code)
    for m in EMPTY_CATCH.finditer(joined):
        idx = joined.count("\n", 0, m.start())
        yield _f(ctx, idx, "empty-catch", "MEDIUM",
                 "this catch discards the exception and continues as if nothing failed.",
                 r_emptycatch.fix)


@rule("weak-rng", ("c", "cpp"), "LOW",
      "rand() is a weak PRNG; never use it for tokens, passwords, or keys",
      "for security use a CSPRNG (getrandom, arc4random, <random> with a secure seed).",
      deep=True)
def r_weakrng(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\brand\s*\(\s*\)", line):
            yield _f(ctx, idx, "weak-rng", "LOW",
                     "rand() is predictable and low-entropy; fine for a toy, dangerous for "
                     "anything security-relevant.", r_weakrng.fix)


REALLOC_SELF = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*realloc\s*\(\s*\1\s*,")


@rule("c-realloc-leak", ("c", "cpp"), "HIGH",
      "assigning realloc() directly back to the same pointer leaks the original on failure",
      "assign realloc to a temporary first; only replace the original pointer after success.")
def r_realloc_leak(ctx):
    for idx, line in enumerate(ctx.code):
        m = REALLOC_SELF.search(line)
        if m:
            yield _f(ctx, idx, "c-realloc-leak", "HIGH",
                     f"if realloc fails, '{m.group(1)}' becomes NULL and the original allocation is lost.",
                     r_realloc_leak.fix)


MEMCMP_OBJECT = re.compile(
    r"\bmemcmp\s*\(\s*&\s*([A-Za-z_]\w*)\s*,\s*&\s*([A-Za-z_]\w*)\s*,\s*sizeof\s*\(?\s*(?:\1|\2|[A-Za-z_]\w*)")


@rule("c-memcmp-padding", ("c", "cpp"), "MEDIUM",
      "memcmp on whole objects/structs compares padding bytes, not logical equality",
      "compare fields explicitly, or serialize to a canonical byte representation first.")
def r_memcmp_padding(ctx):
    for idx, line in enumerate(ctx.code):
        m = MEMCMP_OBJECT.search(line)
        if m:
            yield _f(ctx, idx, "c-memcmp-padding", "MEDIUM",
                     "raw object comparison can read uninitialized padding bytes; two equal structs may compare different.",
                     r_memcmp_padding.fix)


STD_MOVE = re.compile(r"\bstd::move\s*\(\s*([A-Za-z_]\w*)\s*\)")


@rule("cpp-use-after-move", ("cpp",), "MEDIUM",
      "object is used after std::move; moved-from state is valid but unspecified",
      "do not read from a moved-from object except to destroy or reassign it.")
def r_use_after_move(ctx):
    moved = {}
    for idx, line in enumerate(ctx.code):
        for var, moved_line in list(moved.items()):
            if re.search(rf"\b{re.escape(var)}\s*=", line):
                moved.pop(var, None)
                continue
            if re.search(rf"\b{re.escape(var)}\s*(?:\.|->|\[)", line):
                yield _f(ctx, idx, "cpp-use-after-move", "MEDIUM",
                         f"'{var}' was moved on line {moved_line + 1}; reading it here depends on an unspecified moved-from state.",
                         r_use_after_move.fix)
                moved.pop(var, None)
        for m in STD_MOVE.finditer(line):
            var = m.group(1)
            rest = line[m.end():]
            if re.search(rf"\b{re.escape(var)}\s*(?:\.|->|\[)", rest):
                yield _f(ctx, idx, "cpp-use-after-move", "MEDIUM",
                         f"'{var}' is read later on the same line after std::move; the moved-from state is unspecified.",
                         r_use_after_move.fix)
            else:
                moved[var] = idx


FREE_STACK_ADDR = re.compile(r"\bfree\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)|\bdelete\s+&\s*([A-Za-z_]\w*)\s*;")


@rule("c-free-stack-address", ("c", "cpp"), "HIGH",
      "free/delete is called on the address of a stack object",
      "only free/delete pointers returned by malloc/new; never pass &local to the allocator.")
def r_free_stack_address(ctx):
    for idx, line in enumerate(ctx.code):
        m = FREE_STACK_ADDR.search(line)
        if m:
            name = m.group(1) or m.group(2)
            yield _f(ctx, idx, "c-free-stack-address", "HIGH",
                     f"'&{name}' points into the current stack frame; freeing it corrupts the allocator.",
                     r_free_stack_address.fix)


# --------------------------------------------------------------------------- #
# Lifetime rules.  These were written against NIST Juliet ground truth rather
# than against invented fixtures: CWE-416 and CWE-476 are Top-25 classes that
# Attestor previously scored 0% on, in 402 and 280 single-file test cases.
#
# Both flaws are order-dependent inside one function, so a line-by-line match
# cannot see them -- the release and the use are on different lines and each is
# innocent alone.  The scan below walks a function body once, tracks which
# pointers are dead, and clears that state on reassignment.
# --------------------------------------------------------------------------- #
FREED = re.compile(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)|"
                   r"\bdelete\s*(?:\[\s*\])?\s+([A-Za-z_]\w*)\s*;")
NULLED = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*NULL\s*;|"
                    r"^\s*([A-Za-z_]\w*)\s*=\s*nullptr\s*;")
REASSIGNED = re.compile(r"^\s*(?:[A-Za-z_][\w:<>*&\s]*?\s)?([A-Za-z_]\w*)\s*=\s*(?!=)")
# The same thing, but anchored to any statement boundary rather than only the
# start of the line. `p = malloc(...)` after a `free(p)` is a fresh value, not
# a use -- and it stops being recognised as one the moment somebody writes two
# statements on a line:
#
#     bn_set_ui(&a, 1); bn_shl_bits(&a, &a, 64); s = bn_to_dec(&a, NULL);
#
# That line was reported as a use-after-free on real code. The `^` anchor saw
# `bn_set_ui`, not `s =`, so the reassignment guard never ran.
REASSIGNED_ANYWHERE = re.compile(
    r"(?:^|[;{}])\s*(?:[A-Za-z_][\w:<>*&\s]*?\s)?([A-Za-z_]\w*)\s*=\s*(?!=)")
# Bitwise & / | between a null guard and its own dereference: both operands are
# evaluated, so the guard does not guard anything.
NULL_GUARD_BITWISE = re.compile(
    r"\(\s*([A-Za-z_]\w*)\s*(?:!=|==)\s*(?:NULL|nullptr)\s*\)\s*([&|])(?![&|])\s*\(")


# Brace-delimited regions that hold functions rather than being one. `if`,
# `for` and `while` are absent on purpose: those only appear inside a function
# body, where a span is already open and the question never arises.
_CONTAINER_HEAD = re.compile(
    r"\b(?:namespace|class|struct|union|enum)\b|extern\s*\"")

# Keywords that take a parenthesised head and then a brace -- which is exactly
# the shape of a function definition. `while (carry) {` matches
# C_FUNCTION_HEADER perfectly: name `while`, one parameter. Without this every
# loop and branch opened a "function body" of its own, and the real function
# around them never got a span at all. Measured on one 700-line C file: six
# phantom spans, and `mul_kara` -- 100 lines with three declarations of `s` --
# covered by none of them, so its lines fell back to file-wide typing and
# produced false `unsigned-underflow` reports.
_CONTROL_HEAD = re.compile(
    r"\A\s*(?:if|else|for|while|switch|do|catch|return|sizeof)\b")


def _opens_a_function(code, index):
    """Did the block opening at `index` open a function body?

    The brace is often on its own line, so the header is looked for on the
    opening line and the two above it -- the same probe `_c_function_defs`
    uses, for the same reason.
    """
    parts: list[str] = []
    for probe in range(index, max(-1, index - 5), -1):
        text = code[probe].strip()
        if not text:
            continue
        if _CONTAINER_HEAD.search(text) or _CONTROL_HEAD.match(text):
            return False
        # A signature may be spread over several lines, which the previous
        # version could not read: it tested each line on its own, so
        #
        #     static void mul_kara(limb *out, const limb *a, size_t an,
        #                          const limb *b, size_t bn_, limb *scratch)
        #     {
        #
        # matched on neither -- the first line never closes its bracket and
        # the second has no name in front of one. Joining backwards from the
        # brace and testing the accumulation reads it as written.
        parts.insert(0, text)
        if C_FUNCTION_HEADER.match(" ".join(parts)):
            return True
        if probe != index and text[-1] in ";}{":
            return False        # a statement or block boundary, not a header
    return False


def _c_function_spans(code):
    """(start, end) line indexes of each function *body*.

    Descends through containers. The previous version started a span at any
    brace found at depth zero, which is correct for C and wrong for C++: a
    `namespace { ... }` is such a brace, so every function inside it collapsed
    into a single span.

    That mattered to eighteen rules at once, and Juliet's C++ testcases are
    namespace-wrapped. Two consequences were found the hard way before the
    cause was: `c-partial-init` reported a buffer filled in goodB2G against a
    read in goodG2B and fired on 36% of *corrected* files, and `c-double-free`
    matched a `delete` in one function against a `delete` in another. Both
    were worked around locally; this is the actual bug.

    Nesting stays shallow on purpose -- one function body at a time, with
    inner blocks left to the caller. A rule that wants `if` bodies can count
    braces itself; none of them do.
    """
    spans = []
    depth = 0
    start = None
    start_depth = None
    for index, line in enumerate(code):
        opens, closes = line.count("{"), line.count("}")
        if opens and start is None and _opens_a_function(code, index):
            start, start_depth = index, depth
        depth += opens - closes
        if start is not None and depth <= start_depth:
            spans.append((start, index))
            start, start_depth = None, None
        if depth < 0:
            depth = 0
    if start is not None:
        spans.append((start, len(code) - 1))
    return spans


def _uses(name, line):
    return re.search(r"\b%s\b" % re.escape(name), line) is not None


def _redeclared(name, line):
    """True when this line declares `name` afresh.

    Brace counting cannot always tell where one function ends and the next
    begins -- a brace inside a comment or a literal is enough to merge two
    spans -- and a merged span carries a dead pointer into a function that
    merely reuses the name.  A declaration is an unambiguous new binding, so
    it clears the state whether or not the span boundary was found.
    """
    return bool(C_DECLARATION.match(line)) and bool(
        re.search(r"\*+\s*%s\s*(?:[;=,\[]|$)" % re.escape(name), line))


def _null_guarded(name, line):
    """True when this line tests `name` for NULL before using it.

    A guard is what separates the flaw from the fix -- `data = NULL;` followed
    by a bare dereference is the defect, and the same code behind
    `if (data != NULL)` is the correction.  Without this the rule reports both,
    which is worse than reporting neither.  Clearing the pointer's state on any
    test of it is deliberately conservative: a later unguarded dereference in
    the same function is given up rather than risk the false positive.
    """
    if not re.search(r"\b(?:if|while|for|assert)\b", line):
        return False
    esc = re.escape(name)
    return bool(
        re.search(r"\b%s\s*(?:!=|==)\s*(?:NULL|nullptr|0)\b" % esc, line)
        or re.search(r"\b(?:NULL|nullptr)\s*(?:!=|==)\s*%s\b" % esc, line)
        or re.search(r"\(\s*!?\s*%s\s*\)" % esc, line))


@rule("c-use-after-free", ("c", "cpp"), "HIGH",
      "a pointer is used after free/delete released it",
      "set the pointer to NULL after releasing it, and do not read it again.")
def r_use_after_free(ctx):
    for start, end in _c_function_spans(ctx.code):
        dead: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]
            for name, at in list(dead.items()):
                if _redeclared(name, line):
                    dead.pop(name, None)
                    continue
                if _uses(name, line) and not FREED.search(line):
                    if any(found.group(1) == name for found
                           in REASSIGNED_ANYWHERE.finditer(line)):
                        dead.pop(name, None)          # given a fresh value
                        continue
                    yield _f(ctx, index, "c-use-after-free", "HIGH",
                             f"'{name}' was released on line {at + 1} and is read again "
                             f"here; the memory may already belong to something else.",
                             r_use_after_free.fix)
                    dead.pop(name, None)              # report once per release
            match = FREED.search(line)
            if match:
                dead[match.group(1) or match.group(2)] = index


@rule("c-null-deref", ("c", "cpp"), "HIGH",
      "a pointer known to be NULL is dereferenced",
      "assign a real object before dereferencing, or guard with && rather than &.")
def r_null_deref(ctx):
    for start, end in _c_function_spans(ctx.code):
        null_at: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]
            for name, at in list(null_at.items()):
                # The guard is checked first so that a line which both tests and
                # dereferences -- `if ((p != NULL) & (p->x == 5))` -- is left to
                # c-null-guard-bitwise, which describes it correctly.
                if _null_guarded(name, line) or _redeclared(name, line):
                    null_at.pop(name, None)
                    continue
                if re.search(r"\b%s\s*(?:->|\[)" % re.escape(name), line) or \
                        re.search(r"\*\s*%s\b" % re.escape(name), line):
                    yield _f(ctx, index, "c-null-deref", "HIGH",
                             f"'{name}' was set to NULL on line {at + 1} and is "
                             f"dereferenced here without being given a value.",
                             r_null_deref.fix)
                    null_at.pop(name, None)
                    continue
                assignment = REASSIGNED.match(line)
                if assignment and assignment.group(1) == name and \
                        not NULLED.match(line):
                    null_at.pop(name, None)
            match = NULLED.match(line)
            if match:
                null_at[match.group(1) or match.group(2)] = index


@rule("c-null-guard-bitwise", ("c", "cpp"), "HIGH",
      "a NULL guard uses bitwise & or | so both sides are always evaluated",
      "use && or ||; the bitwise operators do not short-circuit, so the guard "
      "never prevents the dereference.")
def r_null_guard_bitwise(ctx):
    for idx, line in enumerate(ctx.code):
        match = NULL_GUARD_BITWISE.search(line)
        if not match:
            continue
        name, operator = match.group(1), match.group(2)
        if not re.search(r"\b%s\s*(?:->|\[|\.)" % re.escape(name),
                         line[match.end() - 1:]):
            continue
        yield _f(ctx, idx, "c-null-guard-bitwise", "HIGH",
                 f"'{operator}' does not short-circuit, so '{name}' is dereferenced "
                 f"even when the NULL check fails.",
                 r_null_guard_bitwise.fix)


# `if (p == NULL) { ... *p ... }`.  The branch is entered *because* the pointer
# is null, so the dereference inside it always faults.  Polarity is the whole
# rule: the corrected form tests the other way round, and a rule that merely
# looked for "a NULL test near a dereference" would report both alike.
NULL_TRUE_BRANCH = re.compile(
    r"\bif\s*\(\s*(?:([A-Za-z_]\w*)\s*==\s*(?:NULL|nullptr)"
    r"|(?:NULL|nullptr)\s*==\s*([A-Za-z_]\w*)"
    r"|!\s*([A-Za-z_]\w*))\s*\)")
# The same test the other way up, on a line of its own -- a real guard.
NULL_FALSE_TEST = re.compile(
    r"\bif\s*\(\s*(?:([A-Za-z_]\w*)\s*!=\s*(?:NULL|nullptr)"
    r"|(?:NULL|nullptr)\s*!=\s*([A-Za-z_]\w*)"
    r"|([A-Za-z_]\w*))\s*\)\s*\{?\s*$")
# `int *p = ...;` declares a pointer, it does not dereference one.  Without
# this the declaration itself counts as a use and every later guard looks late.
C_DECLARATION = re.compile(
    r"^\s*(?:const|static|unsigned|signed|struct|extern|volatile)?\s*"
    r"[A-Za-z_]\w*(?:\s*::\s*\w+)*\s*\*+\s*[A-Za-z_]\w*\s*(?:[;=,\[]|$)")


def _c_block_span(code, index):
    """Line range of the body controlled by the statement on `index`."""
    opener = None
    for probe in range(index, min(index + 3, len(code))):
        if "{" in code[probe]:
            opener = probe
            break
        if probe > index and code[probe].strip():
            return (probe, probe)             # single statement, no braces
    if opener is None:
        return (index, index)
    depth = 0
    for probe in range(opener, len(code)):
        depth += code[probe].count("{") - code[probe].count("}")
        if depth <= 0:
            return (opener, probe)
    return (opener, len(code) - 1)


def _dereferenced(name, line):
    esc = re.escape(name)
    return bool(re.search(r"\b%s\s*(?:->|\[)" % esc, line)
                or re.search(r"\*\s*%s\b" % esc, line))


@rule("c-deref-after-null-check", ("c", "cpp"), "HIGH",
      "a pointer is dereferenced inside the branch that proved it NULL",
      "invert the test -- the body of `if (p == NULL)` is the one place the "
      "pointer is known to be unusable.")
def r_deref_after_null_check(ctx):
    for idx, line in enumerate(ctx.code):
        match = NULL_TRUE_BRANCH.search(line)
        if not match:
            continue
        name = match.group(1) or match.group(2) or match.group(3)
        start, end = _c_block_span(ctx.code, idx)
        for probe in range(start, end + 1):
            assignment = REASSIGNED.match(ctx.code[probe])
            if assignment and assignment.group(1) == name:
                break                         # given a real value first
            if _dereferenced(name, ctx.code[probe]):
                yield _f(ctx, probe, "c-deref-after-null-check", "HIGH",
                         f"'{name}' is dereferenced here, inside the branch "
                         f"line {idx + 1} entered precisely because it is NULL.",
                         r_deref_after_null_check.fix)
                break


@rule("c-null-check-after-deref", ("c", "cpp"), "HIGH",
      "a pointer is tested for NULL only after it has been dereferenced",
      "move the test above the first dereference; checking afterwards cannot "
      "undo a fault that has already happened.")
def r_null_check_after_deref(ctx):
    for start, end in _c_function_spans(ctx.code):
        used: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]
            match = NULL_FALSE_TEST.search(line)
            if match:
                name = match.group(1) or match.group(2) or match.group(3)
                if name in used:
                    yield _f(ctx, index, "c-null-check-after-deref", "HIGH",
                             f"'{name}' is tested for NULL here, but it was "
                             f"already dereferenced on line {used[name] + 1}.",
                             r_null_check_after_deref.fix)
                    used.pop(name, None)
                continue
            if C_DECLARATION.match(line):
                continue
            # A reassignment gives the name a fresh value, so a later `if (p)`
            # tests the new pointer, not the one dereferenced before.  Without
            # this reset, the reuse-a-cursor idiom -- `p = strchr(s, '\r'); if
            # (p) *p = 0; p = strchr(s, '\n'); if (p) ...` -- reads as a check
            # after a dereference and fires on entirely correct code.  Measured
            # on 28 of Juliet's CWE-761 corrected variants before this reset.
            assignment = REASSIGNED.match(line)
            if assignment and not NULLED.match(line):
                used.pop(assignment.group(1), None)
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*->", line):
                used.setdefault(name, index)
            for name in re.findall(r"\*\s*([A-Za-z_]\w*)\b", line):
                used.setdefault(name, index)


# --------------------------------------------------------------------------- #
# Buffer overflow: the destination's capacity is known and the copy is bigger.
#
# This is CWE-121/122/787 as it actually appears -- a buffer declared or
# allocated with a literal size, and a copy into it whose length, or whose
# source buffer, is larger.  Both sides have to resolve to a definite number
# before anything is reported: an unknown size is not a small size, and
# guessing produces exactly the noise that makes an overflow rule unusable.
# --------------------------------------------------------------------------- #
BUFFER_DECL = re.compile(
    r"^\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(char|wchar_t|int|short|long|int64_t|float|double)\s+"
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]")
BUFFER_ALLOC = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
    r"(?:malloc|calloc|ALLOCA|alloca|realloc)\s*\(\s*(.+?)\s*\)\s*;")
BUFFER_ALIAS = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;")
COPY_SIZED = re.compile(
    r"\b(memcpy|memmove|wmemcpy|wmemmove)\s*\(\s*([A-Za-z_]\w*)\s*,"
    r"\s*[^,]+?\s*,\s*(.+?)\s*\)\s*;")
COPY_STRING = re.compile(
    r"\b(strcpy|wcscpy|strcat|wcscat)\s*\(\s*([A-Za-z_]\w*)\s*,"
    r"\s*([A-Za-z_]\w*)\s*\)")
# The bounded spellings, which are not automatically safe: `strncat(data,
# source, 100)` into a 50-byte destination overflows exactly as `strcat`
# would, and the `n` is a bound on the *source* read, not on the destination's
# room. Measured on Juliet's CWE-121 these are a fifth of the sampled sinks
# and had no handler at all, so the copy was seen and skipped.
COPY_BOUNDED = re.compile(
    r"\b(strncat|strncpy|wcsncat|wcsncpy)\s*\(\s*([A-Za-z_]\w*)\s*,"
    r"\s*([A-Za-z_]\w*)\s*,\s*(.+?)\s*\)\s*;")
# How much a buffer actually *holds*, which is not how big it is.  `strcpy` and
# `strcat` copy up to the terminator, so comparing the two buffers' capacities
# reports a 100-byte source into a 50-byte destination as an overflow even when
# the source holds 49 characters -- which is how the corrected code is written.
# Only a known content length can decide this one.
FILL_LENGTH = re.compile(
    r"\b(?:memset|wmemset)\s*\(\s*([A-Za-z_]\w*)\s*,[^,]+,\s*(.+?)\s*\)\s*;")
LITERAL_INIT = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=\s*(\"(?:[^\"\\]|\\.)*\"|L?\"\")")
# `memcpy(s.member, src, sizeof(s))` -- the size of the whole struct used to
# fill one field of it, which runs straight over whatever follows the field.
STRUCT_OVERRUN = re.compile(
    r"\b(?:memcpy|memmove)\s*\(\s*([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)\s*,"
    r"[^;]*?\bsizeof\s*\(\s*\*?\s*([A-Za-z_]\w*)\s*\)")
_SIZEOF_PRODUCT = re.compile(
    r"^\(?\s*(.+?)\s*\)?\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)\s*$")
_ARITH_TOKENS = re.compile(r"\d+|[+\-*()]")


def _const_value(text):
    """Evaluate a small literal integer expression such as `10+1`, else None.

    Written out rather than handed to `eval`: this is a security scanner, and a
    rule that evaluated text taken from the file under analysis would be a
    defect of precisely the kind the rest of this catalog reports.
    """
    tokens = _ARITH_TOKENS.findall(text)
    if not tokens or "".join(tokens) != re.sub(r"\s+", "", text):
        return None
    position = 0

    def atom():
        nonlocal position
        if position >= len(tokens):
            return None
        token = tokens[position]
        if token == "(":
            position += 1
            value = expression()
            if position < len(tokens) and tokens[position] == ")":
                position += 1
                return value
            return None
        if token.isdigit():
            position += 1
            return int(token)
        return None

    def term():
        nonlocal position
        value = atom()
        while value is not None and position < len(tokens) and \
                tokens[position] == "*":
            position += 1
            right = atom()
            if right is None:
                return None
            value *= right
        return value

    def expression():
        nonlocal position
        value = term()
        while value is not None and position < len(tokens) and \
                tokens[position] in "+-":
            operator = tokens[position]
            position += 1
            right = term()
            if right is None:
                return None
            value = value + right if operator == "+" else value - right
        return value

    result = expression()
    return result if position == len(tokens) else None


def _capacity(text):
    """(element count, element type) for a size expression, or (None, None)."""
    match = _SIZEOF_PRODUCT.match(text.strip())
    if match:
        count = _const_value(match.group(1))
        return (count, match.group(2)) if count is not None else (None, None)
    count = _const_value(text)
    return (count, "char") if count is not None else (None, None)


# A buffer's size is fixed in one function and overrun in another -- often in
# another file.  Half of the Juliet corpus is shaped this way: `51a.c` selects
# a ten-byte buffer and hands it to a sink that `51b.c` defines, and the sink
# copies eleven bytes into it.  Neither function contains the defect, so a
# rule that never leaves a function body cannot see any of them.
C_FUNCTION_HEADER = re.compile(
    r"^\s*(?:[A-Za-z_][\w:<>*&\s]*?\s[\*&\s]*)?([A-Za-z_]\w*)\s*"
    r"\(([^;{}]*)\)\s*\{?\s*$")
C_PARAM_NAME = re.compile(r"([A-Za-z_]\w*)\s*(?:\[\s*\])?\s*$")
C_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;()]*)\)\s*;")
# `#define SRC_STRING "AAAAAAAAAA"` -- resolved exactly rather than guessed at,
# because assuming a macro fills its buffer would invent overflows.
# Five files is the longest chain Juliet builds (the 54 family); a couple of
# rounds of slack past that costs nothing and bounds the loop absolutely.
MAX_PROPAGATION_ROUNDS = 8
C_STRING_DEFINE = re.compile(
    r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+L?\"((?:[^\"\\]|\\.)*)\"")


def _c_function_defs(code):
    """[(name, [parameter names], start, end)] for each function body."""
    defs = []
    for start, end in _c_function_spans(code):
        for probe in (start, start - 1, start - 2):
            if probe < 0 or not code[probe].strip():
                continue
            match = C_FUNCTION_HEADER.match(code[probe])
            if not match:
                continue
            params = []
            for piece in match.group(2).split(","):
                piece = piece.strip()
                if not piece or piece == "void":
                    continue
                found = C_PARAM_NAME.search(piece)
                params.append(found.group(1) if found else "")
            defs.append((match.group(1), params, start, end))
            break
    return defs


def _string_macros(code):
    """{macro: character count} for string-valued #defines."""
    out = {}
    for line in code:
        match = C_STRING_DEFINE.match(line)
        if match:
            out[match.group(1)] = len(match.group(2).replace("\\\\", "\\"))
    return out


def _parameter_capacities(ctx):
    """{(function, parameter index): (count, kind, storage)} from call sites.

    One pass to learn what each function's local buffers hold, recording every
    call that passes one of them onward; the callee's parameter then inherits
    that capacity.  It is deliberately one level deep and only accepts a
    capacity when every call site agrees -- a parameter reached with two
    different sizes is left unknown rather than guessed, because an
    over-confident size here invents overflows in correct code.
    """
    defs = _c_function_defs(ctx.code)
    if not defs:
        return {}
    known = {name for name, _, _, _ in defs}
    inherited: dict[tuple, tuple] = {}

    # One pass only learns what a caller hands its *immediate* callee, which
    # is enough for a two-file split and useless for the chained shapes: in
    # Juliet's 52/53/54 families the buffer is handed a->b->c->d->e and every
    # link but the first is a function forwarding a parameter it was given.
    # Re-running with each round's conclusions seeded back in lets the size
    # travel the whole chain. It converges quickly -- the longest chain here
    # is five -- and the round cap is what guarantees it stops at all.
    for _ in range(MAX_PROPAGATION_ROUNDS):
        observed: dict[tuple, set] = {}
        for name, params, start, end in defs:
            seed = {}
            for position, parameter in enumerate(params):
                held = inherited.get((name, position))
                if parameter and held is not None:
                    seed[parameter] = held
            sizes = _local_capacities(ctx.code, start, end, seed=seed)
            for index in range(start, end + 1):
                call = C_CALL.search(ctx.code[index])
                if not call or call.group(1) not in known:
                    continue
                for position, argument in enumerate(call.group(2).split(",")):
                    held = sizes.get(argument.strip())
                    if held is not None:
                        observed.setdefault((call.group(1), position),
                                            set()).add(held)
        # A parameter reached with two different sizes stays unknown: guessing
        # the smaller one invents overflows in code that is correct.
        settled = {key: next(iter(values)) for key, values in observed.items()
                   if len(values) == 1}
        if settled == inherited:
            break
        inherited = settled
    return inherited


def _local_capacities(code, start, end, seed=None):
    """Buffer capacities established inside one function body.

    `seed` carries in what callers were observed to pass for this function's
    parameters, so a function that only forwards a buffer it was handed still
    knows how big it is.
    """
    sizes: dict[str, tuple] = dict(seed or {})
    for index in range(start, end + 1):
        line = code[index]
        match = BUFFER_DECL.match(line)
        if match:
            count = _const_value(match.group(3))
            if count is not None:
                sizes[match.group(2)] = (count, match.group(1), "stack")
            continue
        match = BUFFER_ALLOC.search(line)
        if match:
            count, kind = _capacity(match.group(2))
            storage = "stack" if re.search(r"\b(?:ALLOCA|alloca)\s*\(",
                                           line) else "heap"
            if count is not None:
                sizes[match.group(1)] = (count, kind, storage)
            else:
                sizes.pop(match.group(1), None)
            continue
        match = BUFFER_ALIAS.match(line)
        if match and match.group(2) in sizes:
            sizes[match.group(1)] = sizes[match.group(2)]
    return sizes


def _overflow_reports(ctx):
    """(line, storage, name, capacity, wanted, verb) for each oversized copy.

    Storage is carried because it is what separates CWE-121 from CWE-122: the
    same arithmetic mistake is a stack overflow when the destination is a
    declared array or `alloca`, and a heap overflow when it came from `malloc`.
    Reporting both as the parent CWE-787 would be true but would lose the two
    Top-25 classes the distinction actually names.
    """
    if ctx.overflow_reports is None:
        ctx.overflow_reports = list(_scan_overflows(ctx))
    return ctx.overflow_reports


MACRO_INIT = re.compile(
    r"\b([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=\s*([A-Za-z_]\w*)\s*;")


def _scan_overflows(ctx):
    inherited = _parameter_capacities(ctx)
    macros = _string_macros(ctx.code)
    headers = {(start, end): (name, params)
               for name, params, start, end in _c_function_defs(ctx.code)}
    for start, end in _c_function_spans(ctx.code):
        sizes: dict[str, tuple[int, str, str]] = {}
        holds: dict[str, int] = {}
        # A parameter is only as big as whatever the callers actually passed.
        owner, parameters = headers.get((start, end), ("", []))
        for position, parameter in enumerate(parameters):
            passed = inherited.get((owner, position))
            if parameter and passed is not None:
                sizes[parameter] = passed
        for index in range(start, end + 1):
            line = ctx.code[index]

            report = None
            match = COPY_SIZED.search(line)
            if match:
                name, length = match.group(2), match.group(3)
                count, kind = _capacity(length)
                held = sizes.get(name)
                if count is not None and held and held[0] < count and \
                        (kind == held[1] or kind == "char"):
                    report = (name, held[0], count, "copies", held[2])
            if report is None:
                match = COPY_STRING.search(line)
                if match:
                    call = match.group(1)
                    destination, source = match.group(2), match.group(3)
                    capacity = sizes.get(destination)
                    content = holds.get(source)
                    if capacity is not None and content is not None:
                        # strcat appends, so whatever the destination already
                        # holds counts against its room.
                        existing = holds.get(destination, 0) \
                            if call in ("strcat", "wcscat") else 0
                        needed = existing + content
                        if needed >= capacity[0]:
                            report = (destination, capacity[0], needed + 1,
                                      "writes", capacity[2])
            if report is None:
                match = COPY_BOUNDED.search(line)
                if match:
                    call, destination = match.group(1), match.group(2)
                    capacity = sizes.get(destination)
                    content = holds.get(match.group(3))
                    limit = _const_value(match.group(4))
                    if capacity is not None and content is not None \
                            and limit is not None:
                        existing = holds.get(destination, 0) \
                            if call in ("strncat", "wcsncat") else 0
                        # The copy stops at the source's terminator or at `n`,
                        # whichever comes first, and then writes one more byte
                        # for the terminator it adds.
                        needed = existing + min(limit, content) + 1
                        if needed > capacity[0]:
                            report = (destination, capacity[0], needed,
                                      "writes", capacity[2])
            if report is not None:
                name, held, wanted, verb, storage = report
                yield (index, storage, name, held, wanted, verb)
                sizes.pop(name, None)          # report once per destination
                continue

            match = FILL_LENGTH.search(line)
            if match:
                count = _const_value(match.group(2))
                if count is not None:
                    holds[match.group(1)] = count
                continue
            match = LITERAL_INIT.search(line)
            if match:
                holds[match.group(1)] = len(match.group(2).strip("L").strip('"'))
            else:
                match = MACRO_INIT.search(line)
                if match and match.group(2) in macros:
                    holds[match.group(1)] = macros[match.group(2)]
            match = BUFFER_DECL.match(line)
            if match:
                count = _const_value(match.group(3))
                if count is not None:
                    sizes[match.group(2)] = (count, match.group(1), "stack")
                continue
            match = BUFFER_ALLOC.search(line)
            if match:
                count, kind = _capacity(match.group(2))
                # alloca returns stack memory despite looking like malloc, so
                # an overrun of it is CWE-121 and not CWE-122.
                storage = "stack" if re.search(
                    r"\b(?:ALLOCA|alloca)\s*\(", line) else "heap"
                if count is not None:
                    sizes[match.group(1)] = (count, kind, storage)
                else:
                    sizes.pop(match.group(1), None)
                continue
            match = BUFFER_ALIAS.match(line)
            if match and match.group(2) in sizes:
                sizes[match.group(1)] = sizes[match.group(2)]


@rule("c-stack-buffer-overflow", ("c", "cpp"), "HIGH",
      "a copy writes past the end of a stack buffer",
      "size the destination from the source, or bound the copy with the "
      "destination's own size rather than the source's.")
def r_stack_buffer_overflow(ctx):
    for line, storage, name, held, wanted, verb in _overflow_reports(ctx):
        if storage != "stack":
            continue
        yield _f(ctx, line, "c-stack-buffer-overflow", "HIGH",
                 f"'{name}' is a stack buffer holding {held} elements, but this "
                 f"{verb} up to {wanted}; the write runs off the end of it.",
                 r_stack_buffer_overflow.fix)


@rule("c-heap-buffer-overflow", ("c", "cpp"), "HIGH",
      "a copy writes past the end of a heap buffer",
      "size the destination from the source, or bound the copy with the "
      "destination's own size rather than the source's.")
def r_heap_buffer_overflow(ctx):
    for line, storage, name, held, wanted, verb in _overflow_reports(ctx):
        if storage != "heap":
            continue
        yield _f(ctx, line, "c-heap-buffer-overflow", "HIGH",
                 f"'{name}' was allocated for {held} elements, but this {verb} "
                 f"up to {wanted}; the write runs past the allocation.",
                 r_heap_buffer_overflow.fix)


@rule("c-struct-member-overrun", ("c", "cpp"), "HIGH",
      "a struct's total size is used to fill one of its members",
      "use sizeof of the member being written, not of the structure that "
      "contains it.")
def r_struct_member_overrun(ctx):
    for index, line in enumerate(ctx.code):
        match = STRUCT_OVERRUN.search(line)
        if not match:
            continue
        owner, member, sized = match.group(1), match.group(2), match.group(3)
        if sized != owner:
            continue
        yield _f(ctx, index, "c-struct-member-overrun", "HIGH",
                 f"the copy is bounded by sizeof({owner}), the whole structure, "
                 f"but writes into the member '{member}'; it overruns "
                 f"'{member}' into whatever follows it.",
                 r_struct_member_overrun.fix)


# Deliberately absent: an "array index checked for negative but not for too
# large" rule (CWE-129), which looks like the obvious next one to write.
#
# It was written and measured, and it is being left out.  `if (i >= 0) {
# buf[i] = 1; }` is byte-identical in Juliet's flawed and corrected variants of
# that family -- the correction replaces the *source* of `i` (a constant rather
# than fgets or a socket read), never the check at the sink.  So a rule that
# looks only at the sink fires on the safe version too: 72 findings on
# corrected code, and not one class detected that was not already covered.
#
# Deciding this needs the index to be known tainted, which is a question for
# the dataflow engines (`interprocedural41`, `semantic_graph41`), not for a
# line-shaped rule.  Until it is asked there, the rule would report the same
# thing about safe and unsafe code, and a finding that cannot tell those apart
# carries no information.

# --------------------------------------------------------------------------- #
# Web routes with no access control at all.
#
# CWE-862 and CWE-306 are ranks 4 and 21 of the CWE Top 25 and neither has a
# single case in Juliet, which is C/C++ memory safety and never covers web
# authorisation.  These two rules were written from shapes generated to a
# specification by a local model -- the model wrote code, it was never asked to
# judge whether anything was a defect, and its "fixed" bodies were unreliable
# enough that they are treated as examples of shape and nothing more.  The
# discriminator below came from reading twenty-four generated pairs: every fix
# adds an identity check and a 401/403, and every flaw simply has neither.
#
# The rule is therefore built on absence, which is why the marker list is
# generous.  A false negative here costs a missed finding; a false positive on
# every unauthenticated health check would make the rule unusable.
# --------------------------------------------------------------------------- #
PY_ROUTE_DECORATOR = re.compile(
    r"^\s*@\s*\w+(?:\.\w+)*\s*\.\s*(route|get|post|put|patch|delete)\s*\("
    r"\s*[\"']([^\"']*)")
PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
# Anything that plausibly performs or delegates an identity check.
PY_ACCESS_CONTROL = re.compile(
    r"session|current_user|is_authenticated|login_required|requires?_auth"
    r"|auth_required|jwt_required|token_required|permission_required"
    r"|roles?_required|staff_member_required|user_passes_test|authenticate"
    r"|authoriz|has_permission|check_permission|access_control|Depends\s*\("
    r"|request\.user|g\.user|abort\s*\(\s*40[13]|40[13]", re.I)
# `db.get_note(note_id)` is as much a lookup as `db.get(note_id)`, and an
# exact-name list missed half the shapes; the suffix forms are what real code
# is actually written in.
_PY_LOOKUP_CALL = (r"\.(?:get|filter|find|find_one|query|fetch|load|select"
                   r"|get_or_404|(?:get|find|load|fetch|read|select)_\w+)"
                   r"\s*\([^)]*\b%s\b")


def _keyed_by(body, name):
    """Does the handler use `name` as the key it looks a record up with?"""
    escaped = re.escape(name)
    return bool(re.search(_PY_LOOKUP_CALL % escaped, body)
                or re.search(r"get_object_or_404\s*\([^)]*\b%s\b" % escaped,
                             body)
                or re.search(r"\[\s*%s\s*\]" % escaped, body))
# Route names and paths that describe a privileged operation.
PY_PRIVILEGED = re.compile(
    r"admin|internal|delete|purge|drop|shutdown|refund|rotate|approve|grant"
    r"|revoke|export|config|settings|reset|promote|impersonate|payout", re.I)


def _py_route_handlers(code):
    """(path, name, params, start, end, decorators) for each web route."""
    handlers = []
    for index, line in enumerate(code):
        match = PY_ROUTE_DECORATOR.match(line)
        if not match:
            continue
        decorators, probe = [line], index
        while probe + 1 < len(code):
            probe += 1
            text = code[probe]
            if not text.strip():
                continue
            if text.lstrip().startswith("@"):
                decorators.append(text)
                continue
            break
        definition = PY_DEF.match(code[probe]) if probe < len(code) else None
        if not definition:
            continue
        indent = len(definition.group(1))
        end = probe
        for tail in range(probe + 1, len(code)):
            text = code[tail]
            if text.strip() and (len(text) - len(text.lstrip())) <= indent:
                break
            end = tail
        params = [piece.split(":")[0].split("=")[0].strip()
                  for piece in definition.group(3).split(",")
                  if piece.strip() and piece.split(":")[0].strip()
                  not in ("self", "cls", "request")]
        handlers.append((match.group(2), definition.group(2), params,
                         probe, end, decorators))
    return handlers


def _route_is_unguarded(ctx, start, end, decorators):
    region = "\n".join(decorators + ctx.code[start:end + 1])
    return not PY_ACCESS_CONTROL.search(region)


@rule("py-route-missing-authorization", ("python",), "HIGH",
      "a route returns a record chosen by the caller without checking who owns it",
      "compare the record's owner against the authenticated user and refuse "
      "with 403 when they differ.")
def r_route_missing_authorization(ctx):
    for path, name, params, start, end, decorators in \
            _py_route_handlers(ctx.code):
        if not params or not _route_is_unguarded(ctx, start, end, decorators):
            continue
        body = "\n".join(ctx.code[start:end + 1])
        keyed = [param for param in params if _keyed_by(body, param)]
        if not keyed:
            continue
        yield _f(ctx, start, "py-route-missing-authorization", "HIGH",
                 f"'{name}' looks up a record using '{keyed[0]}', which the "
                 f"caller supplies, and never checks that the caller is "
                 f"entitled to it.",
                 r_route_missing_authorization.fix)


@rule("py-route-missing-authentication", ("python",), "HIGH",
      "a privileged route runs with no authentication check",
      "reject callers without a valid session before the handler does "
      "anything, returning 401.")
def r_route_missing_authentication(ctx):
    for path, name, params, start, end, decorators in \
            _py_route_handlers(ctx.code):
        if not _route_is_unguarded(ctx, start, end, decorators):
            continue
        if not (PY_PRIVILEGED.search(path) or PY_PRIVILEGED.search(name)):
            continue
        yield _f(ctx, start, "py-route-missing-authentication", "HIGH",
                 f"'{name}' serves '{path}', which performs a privileged "
                 f"operation, and runs for any caller at all.",
                 r_route_missing_authentication.fix)


# --------------------------------------------------------------------------- #
# Uploads written under a name the caller chose, and reads with no ceiling.
#
# CWE-434 and CWE-770 are ranks 12 and 25 of the Top 25 and Juliet has no case
# for either. The shapes below were read off pairs a local model generated to a
# specification -- it wrote code, it was never asked to judge anything -- and
# the rules were written by hand from what the fixes consistently added: an
# extension allow-list in one, a size ceiling in the other.
#
# Both are scoped to route handlers. `open(path, "wb")` and `.read()` are
# everywhere in ordinary Python; only inside a request handler does the absence
# of a check mean anything.
# --------------------------------------------------------------------------- #
PY_FILE_WRITE = re.compile(
    r"\.save\s*\(|\bopen\s*\([^)]*[\"'][wa]b?[\"']|shutil\.copyfileobj\s*\(")
PY_REQUEST_NAME = re.compile(
    r"request\.(?:files|form|args|values|json)|\.filename\b|UploadFile", re.I)
PY_EXTENSION_GUARD = re.compile(
    r"secure_filename|splitext|\.suffix\b|endswith\s*\(|rsplit\s*\(|"
    r"ALLOWED|allow(?:ed)?_ext|permitted|whitelist|mimetype|content_type",
    re.I)
# The body accessors are unambiguous. A bare `.read()` is not:
# `open("VERSION").read()` inside a route is a config file, not an unbounded
# request, and the first version of this rule reported exactly that. A bare
# read therefore only counts when the handler is demonstrably taking an upload.
PY_REQUEST_BODY = re.compile(r"request\.(?:get_data|body|data)\b"
                             r"|await\s+request\.body\s*\(")
PY_BARE_READ = re.compile(r"\.read\s*\(\s*\)|\.readlines\s*\(\s*\)")
PY_UPLOAD_SOURCE = re.compile(r"request\.files|request\.FILES|UploadFile"
                              r"|\.stream\b", re.I)
PY_SIZE_GUARD = re.compile(
    r"MAX_|max_size|max_bytes|max_length|max_content|content_length|413|"
    r"\blen\s*\([^)]*\)\s*[<>]|\.read\s*\(\s*[\w\d]|LIMIT|chunk", re.I)


@rule("py-upload-unrestricted", ("python",), "HIGH",
      "an upload is written under a name the caller chose, unchecked",
      "strip the directory part and accept only extensions on an explicit "
      "allow-list -- werkzeug's secure_filename does both.")
def r_upload_unrestricted(ctx):
    for path, name, params, start, end, decorators in \
            _py_route_handlers(ctx.code):
        body = "\n".join(ctx.code[start:end + 1])
        if not PY_FILE_WRITE.search(body) or not PY_REQUEST_NAME.search(body):
            continue
        if PY_EXTENSION_GUARD.search(body):
            continue
        yield _f(ctx, start, "py-upload-unrestricted", "HIGH",
                 f"'{name}' writes an uploaded file using a name that came "
                 f"from the request, with no extension check and no path "
                 f"stripping; the caller picks where and what it lands as.",
                 r_upload_unrestricted.fix)


@rule("py-unbounded-read", ("python",), "MEDIUM",
      "a request body or upload is read whole with no size ceiling",
      "reject anything over a fixed maximum before reading it, or consume the "
      "stream in bounded chunks.")
def r_unbounded_read(ctx):
    for path, name, params, start, end, decorators in \
            _py_route_handlers(ctx.code):
        body = "\n".join(ctx.code[start:end + 1])
        reads_request = bool(PY_REQUEST_BODY.search(body)) or (
            bool(PY_BARE_READ.search(body))
            and bool(PY_UPLOAD_SOURCE.search(body)))
        if not reads_request:
            continue
        if PY_SIZE_GUARD.search(body):
            continue
        yield _f(ctx, start, "py-unbounded-read", "MEDIUM",
                 f"'{name}' reads the whole body into memory before it knows "
                 f"how big it is; one large request is enough to exhaust the "
                 f"process.",
                 r_unbounded_read.fix)


# --------------------------------------------------------------------------- #
# Releasing memory with the wrong routine, or releasing memory that was never
# allocated at all.
#
# These are CWE-762 and CWE-590, together roughly 5,000 of Juliet's cases and
# both previously invisible: no rule fired on the flawed variant even once.
# They are worth having because the shape is unambiguous -- what allocated a
# pointer determines exactly what may release it, and a mismatch is a defect
# regardless of context:
#
#   malloc/calloc/realloc  ->  free
#   new                    ->  delete
#   new[]                  ->  delete[]
#   a declared array or alloca -> nothing may release it
# --------------------------------------------------------------------------- #
C_ALLOC_KIND = re.compile(
    r"^\s*(?:[A-Za-z_][\w:<>*&\s]*?\s[\*&\s]*)?([A-Za-z_]\w*)\s*=\s*"
    r"(?:\([^)]*\)\s*)?"
    r"(?:(?P<newarr>new\s+[\w:<>]+\s*\[)|(?P<new>new\s+[\w:<>(]+)"
    r"|(?P<stack>ALLOCA|alloca)\s*\(|(?P<heap>malloc|calloc|realloc)\s*\()")
C_RELEASE = re.compile(
    r"\b(?P<free>free)\s*\(\s*([A-Za-z_]\w*)\s*\)"
    r"|\b(?P<delarr>delete)\s*\[\s*\]\s*([A-Za-z_]\w*)"
    r"|\b(?P<del>delete)\s+([A-Za-z_]\w*)\s*;")
# What each allocator's memory must be released with.
_RELEASE_FOR = {"heap": "free", "new": "delete", "newarr": "delete[]"}
_RELEASE_NAME = {"free": "free()", "delarr": "delete[]", "del": "delete"}


def _note_allocation(kinds, line):
    """Record how `line` allocated something, if it did."""
    declared = BUFFER_DECL.match(line)
    if declared:
        kinds[declared.group(2)] = "stack"
        return
    match = C_ALLOC_KIND.match(line)
    if match:
        for group in ("newarr", "new", "stack", "heap"):
            if match.group(group):
                kinds[match.group(1)] = "stack" if group == "stack" else group
                return
        return
    alias = BUFFER_ALIAS.match(line)
    if alias and alias.group(2) in kinds:
        kinds[alias.group(1)] = kinds[alias.group(2)]


def _allocation_walk(code, start, end):
    """Yield (line, routine, name, kind) for each release, in order.

    Interleaved on purpose. Building the whole map first and then hunting for
    releases lets the *last* allocation in the span decide how an earlier
    release is judged -- and since brace counting merges Juliet's paired
    functions into one span, that measured `new[] ... delete[]` against a
    `malloc` further down the file. It produced 160 false positives out of 172
    before this became a single pass.
    """
    kinds: dict[str, str] = {}
    for index in range(start, end + 1):
        line = code[index]
        found = _releases(line)
        if found:
            routine, name = found
            yield index, routine, name, kinds.get(name)
            kinds.pop(name, None)          # report once per allocation
            continue
        _note_allocation(kinds, line)


def _releases(line):
    """(routine, name) for a release on this line, or None."""
    match = C_RELEASE.search(line)
    if not match:
        return None
    for group, offset in (("free", 2), ("delarr", 4), ("del", 6)):
        if match.group(group):
            return group, match.group(offset)
    return None


@rule("c-mismatched-free", ("c", "cpp"), "HIGH",
      "memory is released with a routine that does not match its allocator",
      "pair the routines: malloc with free, new with delete, new[] with "
      "delete[]; mixing them is undefined behaviour.")
def r_mismatched_free(ctx):
    for start, end in _c_function_spans(ctx.code):
        for index, routine, name, allocated in \
                _allocation_walk(ctx.code, start, end):
            if allocated in (None, "stack"):
                continue                     # unknown, or CWE-590's business
            expected = _RELEASE_FOR[allocated]
            actual = {"free": "free", "delarr": "delete[]",
                      "del": "delete"}[routine]
            if actual == expected:
                continue
            yield _f(ctx, index, "c-mismatched-free", "HIGH",
                     f"'{name}' was allocated with "
                     f"{allocated.replace('newarr', 'new[]')} but is released "
                     f"with {_RELEASE_NAME[routine]}; it must be {expected}.",
                     r_mismatched_free.fix)


@rule("c-free-not-on-heap", ("c", "cpp"), "HIGH",
      "memory that was never heap-allocated is passed to free or delete",
      "only release what a heap allocator returned; stack arrays and alloca "
      "memory are reclaimed automatically.")
def r_free_not_on_heap(ctx):
    for start, end in _c_function_spans(ctx.code):
        for index, routine, name, allocated in \
                _allocation_walk(ctx.code, start, end):
            if allocated != "stack":
                continue
            yield _f(ctx, index, "c-free-not-on-heap", "HIGH",
                     f"'{name}' is stack memory -- a declared array or alloca -- "
                     f"and {_RELEASE_NAME[routine]} is being called on it; the "
                     f"allocator never owned it.",
                     r_free_not_on_heap.fix)


MALLOC_STRLEN = re.compile(r"\bmalloc\s*\(\s*strlen\s*\([^)]+\)\s*\)")


@rule("c-malloc-strlen-no-nul", ("c", "cpp"), "HIGH",
      "malloc(strlen(s)) forgets space for the trailing NUL byte",
      "allocate strlen(s) + 1 before strcpy/memcpying a C string.")
def r_malloc_strlen_no_nul(ctx):
    for idx, line in enumerate(ctx.code):
        if MALLOC_STRLEN.search(line):
            yield _f(ctx, idx, "c-malloc-strlen-no-nul", "HIGH",
                     "strlen excludes the terminating NUL; the next strcpy writes one byte past the allocation.",
                     r_malloc_strlen_no_nul.fix)


@rule("cpp-return-cstr-local", ("cpp",), "HIGH",
      "returning local std::string::c_str() gives the caller a dangling pointer",
      "return std::string by value, or keep the owning string alive longer than the pointer.")
def r_return_cstr_local(ctx):
    for body in _c_function_bodies(ctx.code):
        locals_ = set()
        for _, line in body:
            m = re.match(r"\s*(?:std::)?string\s+([A-Za-z_]\w*)\b", line)
            if m:
                locals_.add(m.group(1))
        for idx, line in body:
            for name in locals_:
                if re.search(rf"\breturn\s+{re.escape(name)}\.c_str\s*\(\s*\)\s*;", line):
                    yield _f(ctx, idx, "cpp-return-cstr-local", "HIGH",
                             f"'{name}' is destroyed on return, so its c_str() pointer dangles immediately.",
                             r_return_cstr_local.fix)


@rule("cpp-delete-array-mismatch", ("cpp",), "HIGH",
      "memory allocated with new[] is released with delete instead of delete[]",
      "pair new[] with delete[] exactly; mismatching them is undefined behavior.")
def r_delete_array_mismatch(ctx):
    for body in _c_function_bodies(ctx.code):
        arrays = set()
        for idx, line in body:
            for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*new\s+[^;\[]+\[", line):
                arrays.add(m.group(1))
            for name in list(arrays):
                if re.search(rf"\bdelete\s+{re.escape(name)}\s*;", line):
                    yield _f(ctx, idx, "cpp-delete-array-mismatch", "HIGH",
                             f"'{name}' came from new[] but is destroyed with scalar delete.",
                             r_delete_array_mismatch.fix)
                    arrays.remove(name)

# ---- Python --------------------------------------------------------------- #
MUTABLE_DEFAULT = re.compile(
    r"\bdef\s+\w+\s*\([^)]*=\s*(\[\s*\]|\{\s*\}|set\(\)|list\(\)|dict\(\))")


@rule("py-mutable-default", ("python",), "MEDIUM",
      "a mutable default argument ([], {}, set()) is shared across all calls",
      "default to None and create the container inside the function.")
def r_py_mutdef(ctx):
    joined = "\n".join(ctx.code)
    for m in MUTABLE_DEFAULT.finditer(joined):
        idx = joined.count("\n", 0, m.start())
        yield _f(ctx, idx, "py-mutable-default", "MEDIUM",
                 "the default object is created once at def-time and reused, so it accumulates "
                 "state between calls -- a notorious source of 'impossible' bugs.", r_py_mutdef.fix)


@rule("py-bare-except", ("python",), "MEDIUM",
      "a bare 'except:' catches everything, including KeyboardInterrupt and SystemExit",
      "catch a specific exception (or 'except Exception:' at minimum).")
def r_py_bareexcept(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"^\s*except\s*:", line):
            yield _f(ctx, idx, "py-bare-except", "MEDIUM",
                     "bare 'except:' hides real errors and even swallows Ctrl-C and exit "
                     "signals; you lose the traceback and the ability to interrupt.",
                     r_py_bareexcept.fix)


@rule("py-except-pass", ("python",), "MEDIUM",
      "an except block whose only body is 'pass' silently discards the error",
      "at least log the exception; swallowing it hides the failure's cause.")
def r_py_exceptpass(ctx):
    for idx in range(len(ctx.code) - 1):
        if re.search(r"^\s*except\b.*:\s*$", ctx.code[idx]) and \
           re.search(r"^\s*pass\s*$", ctx.code[idx + 1]):
            yield _f(ctx, idx, "py-except-pass", "MEDIUM",
                     "the exception is caught and dropped on the floor; a failure here becomes "
                     "a silent wrong result downstream.", r_py_exceptpass.fix)


FINALLY_HEAD = re.compile(r"^(\s*)finally\s*:\s*$")
RETURNS = re.compile(r"^(\s*)(?:return\b|break\b|continue\b)")


@rule("py-return-in-finally", ("python",), "HIGH",
      "return/break/continue inside a finally block discards an in-flight "
      "exception",
      "move the statement after the try/finally, so a failure still "
      "propagates instead of being silently replaced by a normal return.")
def r_py_return_in_finally(ctx):
    """Written because the catalogue's version of this could not work.

    `advanced_rules` carries `adv-py-return-finally` with the pattern
    `^\\s*return\\b` and the message "return inside finally can suppress
    exceptions". The message describes a real and nasty defect; the pattern
    matches *every return statement in Python* and never mentions `finally`
    at all. Measured on Attestor's own source it produced 1,211 of 1,223
    findings -- 99% of one whole tier's output, every one of them wrong.

    It cannot be fixed where it lives. Python delimits blocks by
    indentation, and a single-line regex cannot see indentation, so a line
    pattern is the wrong shape for this check no matter how it is written.
    Here there is context, so the block can actually be tracked: remember
    the indent of a `finally:` and report jumps nested deeper than it, until
    something dedents back to that level and closes the block.
    """
    depth = None
    for index, line in enumerate(ctx.code):
        if not line.strip():
            continue
        head = FINALLY_HEAD.match(line)
        if head:
            depth = len(head.group(1))
            continue
        if depth is None:
            continue
        found = RETURNS.match(line)
        indent = len(line) - len(line.lstrip())
        if found and indent > depth:
            word = line.strip().split()[0]
            yield _f(ctx, index, "py-return-in-finally", "HIGH",
                     "this '%s' runs while an exception is propagating and "
                     "throws it away; the caller sees a normal return and "
                     "never learns the operation failed." % word,
                     r_py_return_in_finally.fix)
        elif indent <= depth:
            depth = None                  # the finally block ended


IS_LITERAL = re.compile(r"\bis\s+(?:not\s+)?(-?\d+\b|['\"]|\(\s*\)|\[\s*\]|\{\s*\})")


@rule("py-is-literal", ("python",), "MEDIUM",
      "'is' / 'is not' compared to a literal tests identity, not value (works by luck)",
      "use == / != for value comparison; reserve 'is' for None / True / False / sentinels.")
def r_py_isliteral(ctx):
    for idx, line in enumerate(ctx.code):
        if IS_LITERAL.search(line):
            yield _f(ctx, idx, "py-is-literal", "MEDIUM",
                     "identity ('is') with a number/string/empty-literal only happens to work "
                     "when the interpreter caches that object; it breaks unpredictably.",
                     r_py_isliteral.fix)


@rule("py-eq-none", ("python",), "LOW",
      "comparing to None with == / != instead of 'is' / 'is not'",
      "use 'is None' / 'is not None'; == can be overridden and misbehave.")
def r_py_eqnone(ctx):
    # Both operand orders: 'None == x' calls the same overridable __eq__.
    for idx, line in enumerate(ctx.code):
        if re.search(r"[!=]=\s*None\b|\bNone\s*[!=]=(?!=)", line):
            yield _f(ctx, idx, "py-eq-none", "LOW",
                     "None is a singleton; '== None' invokes __eq__ and can be fooled by a "
                     "custom class. Use 'is None'.", r_py_eqnone.fix)


@rule("py-eq-bool", ("python",), "LOW",
      "comparing to True/False with == (redundant and subtly wrong for truthiness)",
      "use the value directly ('if x:') or 'is True' only when you truly mean the singleton.")
def r_py_eqbool(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"[!=]=\s*(True|False)\b", line):
            yield _f(ctx, idx, "py-eq-bool", "LOW",
                     "'== True' only matches the bool True, not other truthy values like 1 or "
                     "a non-empty list; usually you meant a plain truthiness test.",
                     r_py_eqbool.fix)


SQL_EXEC = re.compile(r"\.execute\w*\s*\(")


@rule("py-sql-injection", ("python",), "HIGH",
      "SQL built with string formatting/concatenation (SQL injection)",
      "use parameterized queries: cursor.execute(sql, (params,)); never interpolate user input.")
def r_py_sql(ctx):
    for idx, line in enumerate(ctx.literal):
        if not SQL_EXEC.search(line) or not SQL_EXEC.search(ctx.code[idx]):
            continue
        seg = line[SQL_EXEC.search(line).start():]
        if re.search(r"f['\"]", seg) or re.search(r"%\s*\(|%\s*[a-zA-Z(]|\.format\s*\(|['\"]\s*\+|\+\s*\w", seg):
            yield _f(ctx, idx, "py-sql-injection", "HIGH",
                     "the query string is assembled with f-strings/format/concatenation; user "
                     "input reaching it is a classic SQL-injection vector.", r_py_sql.fix)


OS_SHELL_EXEC = re.compile(
    r"\bos\.(?:system|popen)\s*\(|\bos\.exec(?:l|v)p?e?\s*\(\s*['\"]/bin/(?:ba)?sh")


@rule("py-os-command-injection", ("python",), "HIGH",
      "shell command built with formatting/concatenation and handed to os.system/os.popen",
      "use subprocess with an argv list and shell=False; never interpolate input "
      "into a shell string.")
def r_py_os_command(ctx):
    # subprocess(shell=True) already has a rule; os.system and os.popen are
    # always a shell and had none, so the same injection walked straight past.
    for idx, line in enumerate(ctx.literal):
        match = OS_SHELL_EXEC.search(line)
        if not match or not OS_SHELL_EXEC.search(ctx.code[idx]):
            continue
        seg = line[match.start():]
        if re.search(r"f['\"]", seg) or re.search(
                r"%\s*\(|%\s*[a-zA-Z(]|\.format\s*\(|['\"]\s*\+|\+\s*\w", seg):
            yield _f(ctx, idx, "py-os-command-injection", "HIGH",
                     "os.system/os.popen always run a shell, so anything interpolated into "
                     "this string can append its own commands.", r_py_os_command.fix)


DICT_FROMKEYS_MUTABLE = re.compile(
    r"\bdict\.fromkeys\s*\([^\n]*,\s*(?:\[\s*\]|\{\s*\}|set\s*\(\s*\)|list\s*\(\s*\)|dict\s*\(\s*\))")


@rule("py-dict-fromkeys-mutable", ("python",), "MEDIUM",
      "dict.fromkeys(keys, []) shares one mutable value across every key",
      "use a comprehension: {k: [] for k in keys}.")
def r_dict_fromkeys_mutable(ctx):
    for idx, line in enumerate(ctx.code):
        if DICT_FROMKEYS_MUTABLE.search(line):
            yield _f(ctx, idx, "py-dict-fromkeys-mutable", "MEDIUM",
                     "every key receives the same mutable object; mutating one entry mutates them all.",
                     r_dict_fromkeys_mutable.fix)


@rule("py-assert-validation", ("python",), "LOW",
      "using assert for runtime validation (assertions are stripped under python -O)",
      "raise a real exception (ValueError, etc.); never guard production logic with assert.",
      deep=True)
def r_py_assert(ctx):
    base = os.path.basename(getattr(ctx, "_path", "") or "")
    if base.startswith("test_") or base.endswith("_test.py") or "test" in base:
        return
    for idx, line in enumerate(ctx.code):
        if re.search(r"^\s*assert\b", line):
            yield _f(ctx, idx, "py-assert-validation", "LOW",
                     "running with python -O removes asserts, so any check or side effect here "
                     "vanishes in production.", r_py_assert.fix)


RANDOM_SECURITY = re.compile(
    r"\b(?:token|secret|password|passwd|api[_-]?key|session|nonce)\w*\s*=.*\brandom\.", re.I)


@rule("py-random-security", ("python",), "MEDIUM",
      "the random module is predictable and unsuitable for tokens/secrets",
      "use secrets.token_urlsafe/token_bytes or os.urandom for security-sensitive randomness.")
def r_random_security(ctx):
    for idx, line in enumerate(ctx.code):
        if RANDOM_SECURITY.search(line):
            yield _f(ctx, idx, "py-random-security", "MEDIUM",
                     "random.* is deterministic enough to reproduce when seeded; tokens built from it can be guessed.",
                     r_random_security.fix)

# ---- Security (multi-language) -------------------------------------------- #
@rule("tls-verify-disabled", ("python", "js"), "HIGH",
      "TLS certificate verification is turned off (man-in-the-middle risk)",
      "never disable verification; fix the trust store / CA bundle instead.")
def r_tls(ctx):
    # verify=FLAG where FLAG is a module constant assigned False disables
    # exactly as much certificate checking as verify=False does.
    names = "|".join(re.escape(name) for name in sorted(ctx.false_flags))
    rx = re.compile(r"verify\s*=\s*(?:False%s)\b|_create_unverified_context|"
                    r"CERT_NONE|rejectUnauthorized\s*:\s*false"
                    % (("|" + names) if names else ""))
    env_rx = re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")
    for idx, line in enumerate(ctx.literal):
        env_hit = env_rx.search(line) and re.search(
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=", ctx.code[idx])
        if rx.search(ctx.code[idx]) or env_hit:
            yield _f(ctx, idx, "tls-verify-disabled", "HIGH",
                     "disabling certificate verification makes every HTTPS call trivially "
                     "interceptable; the padlock becomes a lie.", r_tls.fix)


@rule("weak-hash", ("python", "c", "cpp", "js"), "MEDIUM",
      "MD5/SHA-1 used where a secure hash is needed (both are broken for security)",
      "use SHA-256+; for passwords use bcrypt/scrypt/argon2, never a raw fast hash.")
def r_weakhash(ctx):
    rx = re.compile(r"\bhashlib\.(md5|sha1)\b|\bMD5\s*\(|\bSHA1\s*\(")
    js_rx = re.compile(r"createHash\s*\(\s*['\"](md5|sha1)['\"]")
    # An aliased module, a reflective lookup, or a name imported straight from
    # hashlib all reach the same broken primitive as the literal spelling.
    # Structural forms are matched on blanked code; the ones that name the
    # algorithm in a string have to read ctx.literal, then confirm the call
    # itself is real code rather than text inside another string.
    structural, quoted_forms = [], []
    for alias in sorted(name for name in ctx.hash_module_aliases if name):
        safe = re.escape(alias)
        structural.append(r"\b%s\.(?:md5|sha1)\b" % safe)
        quoted_forms.append((
            r"\b%s\.new\s*\(\s*['\"](?:md5|sha1)['\"]" % safe,
            r"\b%s\.new\s*\(" % safe))
        quoted_forms.append((
            r"\bgetattr\s*\(\s*%s\s*,\s*['\"](?:md5|sha1)['\"]" % safe,
            r"\bgetattr\s*\(\s*%s\s*," % safe))
    for name in sorted(ctx.weak_hash_names):
        structural.append(r"\b%s\s*\(" % re.escape(name))
    alias_rx = re.compile("|".join(structural)) if structural else None
    quoted_rx = [(re.compile(text), re.compile(shape))
                 for text, shape in quoted_forms]
    for idx, line in enumerate(ctx.literal):
        js_hit = js_rx.search(line) and re.search(r"\bcreateHash\s*\(", ctx.code[idx])
        alias_hit = alias_rx.search(ctx.code[idx]) if alias_rx else None
        quoted_hit = any(text.search(line) and shape.search(ctx.code[idx])
                         for text, shape in quoted_rx)
        if rx.search(ctx.code[idx]) or js_hit or alias_hit or quoted_hit:
            yield _f(ctx, idx, "weak-hash", "MEDIUM",
                     "MD5 and SHA-1 are collision-broken; fine for a checksum, dangerous for "
                     "signatures, passwords, or anything security-relevant.", r_weakhash.fix)


@rule("dangerous-eval", ("python", "js"), "HIGH",
      "eval/exec on a non-literal runs arbitrary code (injection)",
      "parse/dispatch explicitly; use ast.literal_eval for data, never eval on input.")
def r_eval(ctx):
    rx = re.compile(r"(?<![\w.])(?<!literal_)eval\s*\(|(?<![\w.])exec\s*\(|new\s+Function\s*\(")
    for idx, line in enumerate(ctx.code):
        if rx.search(line):
            yield _f(ctx, idx, "dangerous-eval", "HIGH",
                     "eval/exec/new Function turns any string that reaches it into executable "
                     "code -- a direct path to RCE if input is involved.", r_eval.fix)


@rule("py-yaml-load", ("python",), "HIGH",
      "yaml.load() without a safe Loader can construct arbitrary Python objects",
      "use yaml.safe_load(), or pass Loader=yaml.SafeLoader.")
def r_yaml(ctx):
    # getattr(yaml, "load") reaches the unsafe loader without ever writing
    # yaml.load; the algorithm name lives in a string, so it is read from
    # ctx.literal and the call shape confirmed against blanked code.
    reflective = re.compile(r"\bgetattr\s*\(\s*yaml\s*,\s*['\"]load['\"]")
    reflective_shape = re.compile(r"\bgetattr\s*\(\s*yaml\s*,")
    for idx, line in enumerate(ctx.code):
        direct = (re.search(r"\byaml\.load\s*\(", line)
                  and "Loader" not in line and "safe_load" not in line)
        indirect = (reflective.search(ctx.literal[idx])
                    and reflective_shape.search(line)
                    and "Loader" not in line)
        if direct or indirect:
            yield _f(ctx, idx, "py-yaml-load", "HIGH",
                     "yaml.load with the default loader can instantiate arbitrary types from a "
                     "crafted document -- effectively code execution.", r_yaml.fix)


@rule("py-subprocess-shell", ("python",), "MEDIUM",
      "subprocess with shell=True invites command injection",
      "pass an argv list and shell=False; never interpolate input into a shell string.")
def r_shell(ctx):
    # shell=FLAG where FLAG is a module constant assigned True is the same
    # defect as shell=True; only the spelling moved.
    names = "|".join(re.escape(name) for name in sorted(ctx.true_flags))
    rx = re.compile(r"shell\s*=\s*(?:True%s)\b"
                    % (("|" + names) if names else ""))
    for idx, line in enumerate(ctx.code):
        if rx.search(line):
            yield _f(ctx, idx, "py-subprocess-shell", "MEDIUM",
                     "shell=True runs your command through /bin/sh, so any input in it can add "
                     "its own commands.", r_shell.fix)


SUBPROCESS_CALL = re.compile(r"\bsubprocess\.(run|call|check_call|check_output)\s*\(")


def _logical_call(lines, start_idx, open_col):
    """Join a possibly multi-line call from its '(' at lines[start_idx][open_col]
    until the parens balance, so a rule can see kwargs (like timeout=) passed on a
    continuation line. `lines` is blanked code, so parens inside strings/comments
    are already spaces and never miscount."""
    depth = 0
    buf = []
    for i in range(start_idx, len(lines)):
        segment = lines[i][open_col:] if i == start_idx else lines[i]
        for ch in segment:
            buf.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return "".join(buf)
        buf.append("\n")
    return "".join(buf)


@rule("py-subprocess-no-timeout", ("python",), "MEDIUM",
      "a subprocess call with no timeout can hang the process forever",
      "pass timeout= and handle TimeoutExpired so child processes cannot wedge the parent.")
def r_subprocess_timeout(ctx):
    for idx, line in enumerate(ctx.code):
        m = SUBPROCESS_CALL.search(line)
        if m and "timeout" not in _logical_call(ctx.code, idx, m.end() - 1):
            yield _f(ctx, idx, "py-subprocess-no-timeout", "MEDIUM",
                     "this child process has no timeout; a stuck command can wedge the "
                     "caller or CI job indefinitely.", r_subprocess_timeout.fix)

@rule("py-insecure-deserialize", ("python",), "MEDIUM",
      "pickle/marshal on untrusted data executes code during load",
      "use JSON for data interchange; only unpickle data you fully control.")
def r_pickle(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\b(pickle|cPickle|marshal)\.loads?\s*\(", line):
            yield _f(ctx, idx, "py-insecure-deserialize", "MEDIUM",
                     "unpickling runs __reduce__ hooks in the payload; a malicious blob is "
                     "arbitrary code execution.", r_pickle.fix)


@rule("debug-enabled", ("python",), "MEDIUM",
      "a debug flag left True in production leaks internals (Flask/Django debug = RCE)",
      "drive debug from an env var and default it to False in production.")
def r_debug(ctx):
    # debug=FLAG where FLAG is a module constant assigned True turns debug on
    # just as surely as the literal does.
    names = "|".join(re.escape(name) for name in sorted(ctx.true_flags))
    rx = re.compile(r"\b(?:debug|DEBUG)\s*=\s*(?:True%s)\b"
                    % (("|" + names) if names else ""))
    for idx, line in enumerate(ctx.code):
        if rx.search(line):
            yield _f(ctx, idx, "debug-enabled", "MEDIUM",
                     "debug mode exposes tracebacks and, in Flask, an interactive console an "
                     "attacker can reach -- keep it off in production.", r_debug.fix)


# Which argument carries the format, per sink. A table rather than a widened
# regex because the position varies -- `printf(fmt)`, `fprintf(f, fmt)`,
# `snprintf(dst, n, fmt)` -- and encoding three positions in one alternation
# is how the previous pattern ended up matching only the first two shapes with
# a fixed argument count.
#
# The v-family is here because it was measured, not recalled: on a 200-case
# held-out sample of Juliet's CWE-134, `vfprintf` accounted for 70 misses and
# `vsnprintf` for 31, against 29 `printf` hits. The rule knew neither, which
# is most of why a class with a rule present measured 0% detection.
FORMAT_SINKS = {
    "printf": 0, "vprintf": 0, "wprintf": 0, "vwprintf": 0,
    "fprintf": 1, "vfprintf": 1, "sprintf": 1, "vsprintf": 1,
    "fwprintf": 1, "vfwprintf": 1, "syslog": 1, "dprintf": 1,
    "snprintf": 2, "vsnprintf": 2, "_snprintf": 2, "_vsnprintf": 2,
    "swprintf": 2, "vswprintf": 2,
}

FORMAT_CALL = re.compile(
    r"\b(%s)\s*\(" % "|".join(sorted(FORMAT_SINKS, key=len, reverse=True)))

_BARE_NAME = re.compile(r"[A-Za-z_]\w*\Z")


def _split_arguments(text):
    """Top-level comma split, respecting nesting and string literals.

    `text.split(",")` is the obvious version and gets the position wrong on
    exactly the calls that matter: `recv(s, (char *)(data + n), sizeof(char) *
    (100 - n), 0)` has commas inside a cast and inside an expression, and a
    naive split puts the format argument at the wrong index.
    """
    parts, current = [], []
    depth, quote = 0, None
    for character in text:
        if quote:
            current.append(character)
            if character == quote and (len(current) < 2
                                       or current[-2] != "\\"):
                quote = None
            continue
        if character in "\"'":
            quote = character
            current.append(character)
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}":
            if depth == 0:
                break
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    parts.append("".join(current))
    return [part.strip() for part in parts]


def _format_arguments(line):
    """Yield (sink, name) where a bare identifier is used as the format."""
    for match in FORMAT_CALL.finditer(line):
        position = FORMAT_SINKS[match.group(1)]
        arguments = _split_arguments(line[match.end():])
        if len(arguments) <= position:
            continue
        candidate = arguments[position]
        # A literal format is the correct spelling, not the defect.
        if _BARE_NAME.match(candidate):
            yield match.group(1), candidate


def _literal_format(code, start, end):
    """Per line: which names provably hold a string literal at that point.

    Not the complement of ``_command_taint``, and not interchangeable with it.
    Requiring *taint* at a format sink would be stricter and wrong: a format
    string arriving from a function parameter is a real defect Attestor cannot
    trace to a source, and demanding proof of taint would silently drop it.

    What can be proved cheaply is the other side -- that the name was just
    handed a literal -- and that is exactly what distinguishes the corrected
    variant from the flawed one. Measured on Juliet's CWE-134, the two differ
    in a single line::

        recv(sock, (char *)(data + len), ...);   strcpy(data, "fixedstring");
        fprintf(stdout, data);                   fprintf(stdout, data);

    The sink is identical, so a rule matching on shape alone fires on both and
    the differential criterion cancels it to nothing -- which is why this
    class measured 0% detection with a rule present and firing.

    Literalness is deliberately *not* propagated across assignment. Both
    variants open with ``char dataBuffer[100] = ""; data = dataBuffer;``, so
    carrying the binding from ``dataBuffer`` to ``data`` would mark the flawed
    variant literal too and suppress the defect being looked for.
    """
    bound: set[str] = set()
    for index in range(start, end + 1):
        line = code[index]
        yield index, line, frozenset(bound)

        # A read from outside overwrites whatever was there, literal or not.
        source = COMMAND_TAINT_SOURCE.search(line)
        if source:
            target = _ASSIGN_TARGET.match(line)
            if target:
                bound.discard(target.group(1))
            bound -= _buffer_names(line[source.end() - 1:])
            continue

        literal = COMMAND_LITERAL.search(line)
        if literal:
            # `strcpy(data, "x")` names its target; `data = "x"` does not.
            target = literal.group(1)
            if target:
                bound.add(target)
            else:
                assigned = _ASSIGN_TARGET.match(line)
                if assigned and assigned.group(1) not in _NOT_A_BUFFER:
                    bound.add(assigned.group(1))
            continue

        # Assigned from something that is not a literal: no longer provable.
        target = _ASSIGN_TARGET.match(line)
        if target and target.group(1) not in _NOT_A_BUFFER:
            bound.discard(target.group(1))


@rule("format-string", ("c", "cpp"), "HIGH",
      "a non-literal format string (printf(user)) is a format-string vulnerability",
      "always use a literal format: printf(\"%s\", user).")
def r_format(ctx):
    """Fires unless the format argument is provably a literal.

    Scoped per function rather than per file: a name bound to a literal in one
    function says nothing about the same name in the next, and a file-wide set
    would let one corrected function suppress a defect in another.
    """
    for start, end in _c_function_spans(ctx.code):
        for index, line, literal in _literal_format(ctx.code, start, end):
            for _sink, name in _format_arguments(line):
                if name in literal:
                    continue
                yield _f(ctx, index, "format-string", "HIGH",
                         "passing a variable as the format string lets input smuggle in %n/%s and "
                         "read or corrupt memory.", r_format.fix)
                break


_FOR_HEAD = re.compile(r"\bfor\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*([^;)]+(?:\([^)]*\))?[^;]*?)\s*;")
_SUBSCRIPT_WRITE = re.compile(r"\A\s*(?:\.\w+\s*|->\s*\w+\s*)?=(?!=)")

# A definition header, used to sub-divide a span that covers several
# functions. The lookahead keeps `if (...)`, `for (...)` and `while (...)`
# out; the trailing anchor keeps ordinary calls out, since those end in `;`.
_FUNCTION_HEAD = re.compile(
    r"\A\s*(?!(?:if|for|while|switch|return|else|do|catch)\b)"
    r"[A-Za-z_][\w:*&<>\s]*?\b\w+\s*\([^;]*\)\s*(?:const\s*)?\{?\s*\Z")


def _bound_value(text):
    """A loop bound that is pure arithmetic on literals, or None.

    Deliberately not `eval`. The inputs here are strings out of the file under
    analysis, and a static analyser that evaluates its own input is a worse
    bug than anything it could report -- the character-class guard that would
    make `eval` safe is most of the work of just doing the arithmetic.
    """
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    if text.isdigit():
        return int(text)
    match = re.fullmatch(r"(\d+)\s*([*/+-])\s*(\d+)", text)
    if not match:
        return None
    left, operator, right = int(match.group(1)), match.group(2), int(match.group(3))
    if operator == "/":
        return left // right if right else None
    return {"*": left * right, "+": left + right, "-": left - right}[operator]


@rule("c-partial-init", ("c", "cpp"), "MEDIUM",
      "a buffer is filled by a loop that stops short of the loop that reads it",
      "initialise every element you later read -- match the fill bound to the "
      "allocation, or memset the buffer before use.")
def r_partial_init(ctx):
    """Fires when a buffer is written to a lower bound than it is read from.

    The defect model is Juliet's CWE-457 shape and a real one::

        for (i = 0; i < 10/2; i++) data[i].intOne = i;   /* fills half   */
        for (i = 0; i < 10;   i++) printIntLine(data[i].intOne);  /* reads all */

    The correction changes the fill bound to match, so the two bounds being
    *equal* is the fixed variant and reporting on shape alone would fire on
    both. Comparing the bounds is what discriminates.

    Bounds that are not literal arithmetic are skipped rather than guessed at:
    a loop to `n` and a loop to `count` may or may not differ, and a rule that
    assumes they do would report every two-loop function in the tree.
    """
    for start, end in _c_function_spans(ctx.code):
        writes: dict[str, tuple[int, int]] = {}
        reads: dict[str, int] = {}
        found: list[tuple[int, str, int, int]] = []

        def settle():
            """Close off the current function and start a fresh one.

            Necessary because `_c_function_spans` hands back a C++
            ``namespace { ... }`` body as a single span: measured on Juliet's
            CWE-457, one span covered lines 19-193 containing goodG2B,
            goodB2G1 and goodB2G2 together. goodB2G fills to 5 and goodG2B
            reads to 10, so merging them invents a defect that is in neither
            -- the rule fired on 38% of *corrected* files before this.
            """
            for name, (written, line) in sorted(writes.items()):
                consumed = reads.get(name)
                if consumed is not None and written < consumed:
                    found.append((line, name, written, consumed))
            writes.clear()
            reads.clear()

        for index in range(start, end + 1):
            if _FUNCTION_HEAD.match(ctx.code[index]):
                settle()
            head = _FOR_HEAD.search(ctx.code[index])
            if not head:
                continue
            variable = head.group(1)
            bound = _bound_value(head.group(2))
            if bound is None:
                continue
            subscript = re.compile(r"\b(\w+)\s*\[\s*%s\s*\]"
                                   % re.escape(variable))
            # A bounded look-ahead rather than brace matching: the body of
            # these loops is a handful of lines, and a mis-paired brace in a
            # macro would otherwise swallow the rest of the function.
            for offset in range(1, 12):
                if index + offset > end:
                    break
                body = ctx.code[index + offset]
                for match in subscript.finditer(body):
                    name = match.group(1)
                    if _SUBSCRIPT_WRITE.match(body[match.end():]):
                        # The *furthest* a fill loop reaches, not the nearest.
                        # Juliet's goodB2G keeps the partial loop and adds a
                        # full re-initialisation before the read; taking the
                        # minimum reports that corrected function as defective,
                        # which it measurably did on 36% of fixed files.
                        known = writes.get(name)
                        if known is None or bound > known[0]:
                            writes[name] = (bound, index)
                    else:
                        reads[name] = max(reads.get(name, bound), bound)
        settle()
        for line, name, written, consumed in found:
            yield _f(ctx, line, "c-partial-init", "MEDIUM",
                     "%s is filled to %d but read to %d, so the elements "
                     "in between are used uninitialised."
                     % (name, written, consumed), r_partial_init.fix)


# Which argument of each call is a size or a count. A negative value reaching
# any of these is converted to an enormous unsigned one, which is the whole
# defect -- the call does not fail, it copies or allocates gigabytes.
SIZE_SINKS = {
    "memcpy": 2, "memmove": 2, "memset": 2, "wmemcpy": 2, "wmemmove": 2,
    "wmemset": 2, "strncpy": 2, "strncat": 2, "wcsncpy": 2, "wcsncat": 2,
    "malloc": 0, "alloca": 0, "ALLOCA": 0, "calloc": 0,
    "fread": 1, "fwrite": 1, "recv": 2, "read": 2,
}
SIZE_CALL = re.compile(
    r"\b(%s)\s*\(" % "|".join(sorted(SIZE_SINKS, key=len, reverse=True)))

# short/int/long, and the explicitly signed spellings. `char` is left out:
# its signedness is implementation-defined, so a rule that assumed it would be
# right on gcc and wrong on an ARM compiler.
SIGNED_DECL = re.compile(
    r"\A\s*(?:signed\s+)?(?:short|int|long|int16_t|int32_t|int64_t|ssize_t|"
    r"ptrdiff_t)\b[\w\s*]*?\b(\w+)\s*(?:=|;|,)")

# A guard that establishes the value is not negative. Deliberately narrow:
# `data < 100` is the *flawed* variant's guard and must not count, because
# bounding a signed value from above says nothing about it being negative.
NONNEGATIVE_GUARD = re.compile(
    r"\b(\w+)\s*(?:>=?\s*0|>\s*-\s*1|>=\s*1)\b"
    r"|\b0\s*<=?\s*(\w+)\b")

NEGATIVE_ASSIGN = re.compile(r"\A\s*(\w+)\s*=\s*-\s*\d")


@rule("c-signed-size", ("c", "cpp"), "HIGH",
      "a signed value that may be negative is used as a size or count",
      "check for a negative value before the call, or hold the length in an "
      "unsigned type so the conversion cannot happen silently.")
def r_signed_size(ctx):
    """Sign extension into a size parameter.

    The defect model is Juliet's CWE-194 and a real one::

        short data;
        data = -1;                     /* or read from input */
        if (data < 100)                /* bounds it above, not below */
            memmove(dest, source, data);

    `data` converts to `size_t` as roughly 2^64, so the copy runs off the end
    of everything. The corrected variants are instructive about what the
    discriminator has to be: one fixes the *source* (`data = 100-1`) and the
    other keeps the negative source and adds `if (data > 0)`. So neither the
    assignment alone nor the call alone separates them -- only "can be
    negative, and nothing has ruled that out by the time it is used".

    An upper bound is not a guard here, and treating `data < 100` as one would
    silence the flawed variant along with the fixed one.
    """
    for start, end in _c_function_spans(ctx.code):
        signed: set[str] = set()
        risky: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]

            declared = SIGNED_DECL.match(line)
            if declared:
                signed.add(declared.group(1))

            guard = NONNEGATIVE_GUARD.search(line)
            if guard:
                risky.pop(guard.group(1) or guard.group(2), None)

            negative = NEGATIVE_ASSIGN.match(line)
            if negative and negative.group(1) in signed:
                risky[negative.group(1)] = index
            else:
                source = COMMAND_TAINT_SOURCE.search(line)
                if source:
                    # `fscanf(stdin, "%hd", &data)` fills a signed variable
                    # with whatever was typed, which includes negatives.
                    for name in re.findall(r"&\s*(\w+)", line):
                        if name in signed:
                            risky[name] = index
                target = _ASSIGN_TARGET.match(line)
                if target and target.group(1) in signed and not negative:
                    # Reassigned from something that is not a negative
                    # literal; no longer known to be negative.
                    if not source:
                        risky.pop(target.group(1), None)

            if not risky:
                continue
            call = SIZE_CALL.search(line)
            if not call:
                continue
            position = SIZE_SINKS[call.group(1)]
            arguments = _split_arguments(line[call.end():])
            if len(arguments) <= position:
                continue
            candidate = arguments[position].strip()
            if candidate in risky:
                yield _f(ctx, index, "c-signed-size", "HIGH",
                         "'%s' is signed and may be negative here; passing it "
                         "as the size argument of %s converts it to an "
                         "enormous unsigned value."
                         % (candidate, call.group(1)), r_signed_size.fix)
                risky.pop(candidate, None)


# A value whose magnitude nothing in the function bounds: parsed text, a
# random number, or an expression built from a type's maximum.
UNBOUNDED_SOURCE = re.compile(
    r"\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|_wtoi|wcstol)\s*\("
    r"|\b(?:rand|RAND32|RAND64|random)\s*\("
    r"|\b(?:SHRT_MAX|INT_MAX|LONG_MAX|UINT_MAX|ULONG_MAX)\b\s*[+*]")

# Narrowing, in both the spellings Juliet uses and the ones real code does.
NARROWING_CAST = re.compile(
    r"\(\s*(?:unsigned\s+|signed\s+)?"
    r"(char|short|int8_t|uint8_t|int16_t|uint16_t)\s*\)\s*(\w+)")
NARROWING_INIT = re.compile(
    r"\A\s*(?:unsigned\s+|signed\s+)?"
    r"(char|short|int8_t|uint8_t|int16_t|uint16_t)\s+\w+\s*=\s*(\w+)\s*;")


@rule("c-numeric-truncation", ("c", "cpp"), "MEDIUM",
      "an unbounded value is narrowed to a smaller type, discarding the high bits",
      "range-check before narrowing, or keep the value in a type wide enough "
      "to hold everything the source can produce.")
def r_numeric_truncation(ctx):
    """Truncation of a value nothing has bounded.

    Juliet's CWE-197 states the discriminator in its own description: the bad
    source is `atoi()` on console input, the good source is "less than
    CHAR_MAX", and *both* variants perform the same narrowing::

        data = atoi(inputBuffer);      /* or  data = CHAR_MAX - 1  */
        ...
        charData = (char)data;

    So the cast is not the signal -- the provenance of what is cast is. A rule
    reporting every narrowing conversion would fire on both variants and on
    most correct C besides, because narrowing *after* a range check is the
    ordinary way to write this.
    """
    for start, end in _c_function_spans(ctx.code):
        unbounded: dict[str, int] = {}
        for index in range(start, end + 1):
            line = ctx.code[index]

            target = _ASSIGN_TARGET.match(line)
            if target and target.group(1) not in _NOT_A_BUFFER:
                name = target.group(1)
                if UNBOUNDED_SOURCE.search(line):
                    unbounded[name] = index
                else:
                    # Reassigned from something ordinary -- a literal, or a
                    # value already checked. No longer unbounded.
                    unbounded.pop(name, None)

            for pattern in (NARROWING_CAST, NARROWING_INIT):
                found = pattern.search(line)
                if found and found.group(2) in unbounded:
                    yield _f(ctx, index, "c-numeric-truncation", "MEDIUM",
                             "'%s' holds a value nothing here bounds; "
                             "narrowing it to %s keeps only the low bits."
                             % (found.group(2), found.group(1)),
                             r_numeric_truncation.fix)
                    unbounded.pop(found.group(2), None)
                    break


# ---- Java ------------------------------------------------------------------ #
#
# Attestor had no Java rules at all until now, which mattered more than a missing
# language usually does: `.java` resolved to `text`, so a file containing a
# command injection and an MD5 digest returned zero findings -- the same
# output a clean file gives. `language_coverage42` now reports that state
# rather than letting it read as a pass, and these are the first rules that
# make Java genuinely examined.
#
# Each one follows the discipline the C rules were built under: the pattern
# has to separate the defect from its *correction*, not merely match the
# shape. A rule that fires on both is worth nothing, however plausible it
# looks.

# Concatenation or formatting inside the call is the discriminator throughout.
# `exec("git status")` is a fixed command; `exec("git " + branch)` is not, and
# the corrected form of nearly every one of these is a literal or an array.
_JAVA_BUILT = re.compile(r"\+|String\.format\s*\(|\.concat\s*\(|%s")

# Where a Java value can arrive from outside the program. Taken from what
# Juliet actually uses as its bad sources, plus the servlet and property
# readers any real application has.
JAVA_TAINT_SOURCE = re.compile(
    r"\.\s*readLine\s*\(|\bSystem\s*\.\s*getenv\s*\(|"
    r"\.\s*getProperty\s*\(|\.\s*getParameter\s*\(|"
    r"\.\s*getHeader\s*\(|\.\s*getQueryString\s*\(|\.\s*getCookies\s*\(|"
    r"\.\s*getInputStream\s*\(|\bScanner\s*\(|\.\s*nextLine\s*\(|"
    r"\bgetenv\s*\(|\.\s*getRequestURI\s*\(|"
    # A row out of the database is not trusted input. Somebody else put it
    # there, and second-order injection -- store now, execute later -- is
    # the whole point of the class. Juliet models it exactly this way
    # ("FLAW: Read data from a database query resultset") and without it
    # every `_database` variant across every family read as clean.
    r"\.\s*get(?:String|Int|Long|Short|Double|Float|Object|Bytes)\s*\(")

# A name assigned a string literal is no longer attacker-controlled. This is
# the whole discriminator: Juliet's goodG2B keeps the concatenation and
# replaces the source with `data = "foo"`.
JAVA_LITERAL_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*\"[^\"]*\"\s*;")
# The trailing `(?:\[\s*\])?` is not decoration. Juliet carries taint through
# `String names[] = data.split("-")` and then uses `names[i]` at the sink.
# Without it that declaration is not recognised as an assignment at all, the
# taint stops dead at `data`, and every rule depending on it goes quiet --
# measured at 100% silent on CWE-89 before this was added.
#
# The brackets have to be allowed on either side of the name, and with spaces
# around them: `String names[] =`, `String[] t =` and `String [] t =` are all
# the same declaration. Only the first two parsed at first, so CWE-643 -- whose
# flow opens with `String [] tokens = data.split("||")` -- was 100% silent for
# exactly this reason and nothing else.
JAVA_ASSIGN_TARGET = re.compile(
    r"\s*(?:[\w.<>]+(?:\s*\[\s*\])*\s+)?(\w+)\s*(?:\[\s*\])?\s*=(?!=)")

# A method declaration, used to reset taint between the concatenated bodies
# of `bad()`, `goodG2B()` and `goodB2G()`, and to name the parameters that a
# call site can carry taint into.
JAVA_METHOD_HEAD = re.compile(
    r"\A\s*(?:public|private|protected|static|final|abstract|synchronized|\s)*"
    r"[\w.<>\[\]]+\s+(\w+)\s*\(([^;]*)\)\s*(?:throws [\w,\s.]+)?\s*\{?\s*\Z")
# Deliberately refuses nested parentheses: `f(g(x))` is not resolved, and
# guessing at it would be worse than admitting the gap.
# One level of nesting is allowed inside the argument list, and it has to be:
# `([^()]*)` cannot match `badSink(holder.get(0))` at all, so the only call
# the walk saw there was the inner `get(0)` and the outer one -- the call
# that actually carries the tainted value across -- was invisible. Any
# `sink(helper(x))` was affected, not only the container shapes.
#
# Written as an unrolled loop rather than `(?:[^()]|\(...\))*`. The
# alternation-inside-repetition form matches the same strings but backtracks
# exponentially on a line with an unbalanced parenthesis, and this runs over
# every line of every Java file.
JAVA_CALL = re.compile(r"\b(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)")
JAVA_RETURN = re.compile(r"\s*return\b(.*)")
JAVA_FIELD = re.compile(
    r"\A\s*(?:private|protected|public)\s+"
    r"(?:static\s+|final\s+|transient\s+|volatile\s+)*"
    r"[\w.<>\[\]]+\s+(\w+)\s*(?:=[^;]*)?;")


def _java_fields(code):
    """Names declared at class scope, whose taint outlives a method.

    A local dies with its method; a field does not, and Juliet's `_45`
    variants carry the value from one method to another through exactly that.
    Brace depth is what separates the two -- a field sits at depth one, inside
    the class and outside every method.
    """
    fields, depth = set(), 0
    for line in code:
        if depth == 1:
            found = JAVA_FIELD.match(line)
            if found and not JAVA_METHOD_HEAD.match(line):
                fields.add(found.group(1))
        depth += line.count("{") - line.count("}")
    return fields


def _java_param_names(declaration):
    """`String data, int count` -> {"data", "count"}."""
    names = set()
    for part in declaration.split(","):
        found = re.search(r"(\w+)\s*(?:\[\s*\])?\s*\Z", part.strip())
        if found:
            names.add(found.group(1))
    return names


def _java_step_taint(tainted, line, returning=()):
    """Apply one line's effect to `tainted`, in place.

    `returning` names methods that hand back a value from outside, so that
    `data = badSource();` taints `data` without the source being on this line.
    """
    _java_step_container_taint(tainted, line)
    literal = JAVA_LITERAL_ASSIGN.search(line)
    if literal:
        tainted.discard(literal.group(1))
        return
    # `data = URLEncoder.encode(data, "UTF-8");` -- the corrected half of
    # Juliet's CWE-113. Percent-encoding is a real fix for a header, and the
    # value cannot carry a newline through it, so taint genuinely ends here.
    # Without this the assignment would re-taint from its own right-hand side.
    if JAVA_ESCAPED.search(line):
        encoded = JAVA_ASSIGN_TARGET.match(line)
        if encoded:
            tainted.discard(encoded.group(1))
            return
    if JAVA_TAINT_SOURCE.search(line):
        target = JAVA_ASSIGN_TARGET.match(line)
        if target:
            tainted.add(target.group(1))
        return
    target = JAVA_ASSIGN_TARGET.match(line)
    if not target:
        return
    right = line[target.end(1):]
    if any(re.search(r"\b%s\s*\(" % re.escape(name), right)
           for name in returning):
        tainted.add(target.group(1))
        return
    if any(re.search(r"\b%s\b" % re.escape(name), right) for name in tainted):
        tainted.add(target.group(1))


# A tainted value put into a container taints the container. Over-approximate
# on purpose, in the same direction as the branch merge: Juliet's `_66`
# through `_75` variants move the value through an array, a Vector, a
# LinkedList, a HashMap or a field on a holder object purely to break a
# single-file analysis, and the sink then reads it straight back out.
#
# `dataArray[2] = data` was not recognised as an assignment at all --
# JAVA_ASSIGN_TARGET allows only empty brackets, `String[] a =` -- so the
# array never became tainted and every one of those shapes scored zero.
JAVA_ELEMENT_ASSIGN = re.compile(r"\A\s*([A-Za-z_]\w*)\s*\[[^\]]+\]\s*=(?!=)")
JAVA_MEMBER_ASSIGN = re.compile(
    r"\A\s*([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*=(?!=)")
JAVA_CONTAINER_ADD = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*(?:add|addElement|addFirst|addLast|put|set|"
    r"offer|push|append)\s*\(([^;]*)\)")


def _java_step_container_taint(tainted, line):
    """Taint a container that a tainted value was just placed into."""
    for pattern in (JAVA_ELEMENT_ASSIGN, JAVA_MEMBER_ASSIGN):
        holder = pattern.match(line)
        if holder:
            right = line[holder.end():]
            if any(re.search(r"\b%s\b" % re.escape(name), right)
                   for name in tainted):
                tainted.add(holder.group(1))
            return
    for holder in JAVA_CONTAINER_ADD.finditer(line):
        if any(re.search(r"\b%s\b" % re.escape(name), holder.group(2))
               for name in tainted):
            tainted.add(holder.group(1))


@dataclass(frozen=True)
class CrossFileTaint:
    """What one file's analysis tells the others.

    Two directions, because Juliet uses both and they are not the same
    question. `received` is methods somebody calls with a value from
    outside -- the source is here, the sink is over there. `returned` is
    methods that hand one back -- the source is over there, the sink is
    here. A single-file scan sees neither.
    """

    received: frozenset = frozenset()
    returned: frozenset = frozenset()

    def __bool__(self) -> bool:
        return bool(self.received or self.returned)


def _java_calls_passing_taint(code):
    """Method names this file calls with an argument that came from outside.

    The cross-file half of `_java_call_taint`. That function drops any call
    whose callee is not declared in the same file -- it has no way to know
    what the parameters are called -- and for Juliet's `_5x` variants the
    callee is the whole point: `_51a` reads the environment and hands it to
    `(new _51b()).badSink(data)`, with the sink in the other file. Single
    file analysis cannot see that flow in either direction, and 36% of
    CWE-89 is written that way.

    Returns bare method names. The callee's own file resolves them against
    its declarations, so nothing here needs to know the parameter list.
    """
    exported: set[str] = set()
    tainted: set[str] = set()
    returning: set[str] = set()
    fields = _java_fields(code)
    field_taint: set[str] = set()
    for line in code:
        head = JAVA_METHOD_HEAD.match(line)
        if head:
            tainted = set(field_taint)
            continue
        for call in JAVA_CALL.finditer(line):
            name, arguments = call.group(1), call.group(2)
            if not arguments.strip():
                continue
            if any(re.search(r"\b%s\b" % re.escape(value), arguments)
                   for value in tainted):
                exported.add(name)
        _java_step_taint(tainted, line, returning)
        field_taint |= tainted & fields
    return exported


def _java_call_taint(code, external=()):
    """How a value from outside crosses a method boundary, in both directions.

    Juliet's `_41` variants put the source in `bad()` and the sink in
    `badSink(String data)`; `_42` instead returns it, `data = badSource();`.
    Taint that stops at the method boundary never arrives in either, and
    those two shapes were most of the silent held-out CWE-89 pairs.

    Returns (parameters a call site taints, methods that hand taint back,
    fields ever assigned something from outside). Fields need the same
    repeated pass for a different reason: `badSink()` is often declared
    *before* the `bad()` that fills the field it reads, and a single forward
    walk reaches the sink while the assignment is still in the future.

    Passing or returning a literal taints nothing, which is the whole point:
    `goodG2BSink("literal")` has to stay quiet or the rule discriminates
    nothing. The pass repeats until it learns nothing new, so a source that
    reaches a sink through two hops resolves as well.
    """
    declared = {}
    for line in code:
        head = JAVA_METHOD_HEAD.match(line)
        if head:
            declared[head.group(1)] = _java_param_names(head.group(2))

    fields = _java_fields(code)
    receiving: dict[str, set[str]] = {}
    # Seeded from what other files were seen handing to these methods. A name
    # only counts if this file actually declares it -- an unrelated class
    # elsewhere with a `process(data)` of its own must not taint this one's.
    inbound = getattr(external, "received", external) or ()
    for name in inbound:
        if name in declared:
            receiving[name] = set(declared[name])
    # The other direction needs no such check: `returning` names methods
    # whose *result* is tainted, and this file is the caller, so the callee
    # is exactly the one it does not declare.
    returning: set[str] = set(getattr(external, "returned", ()) or ())
    field_taint: set[str] = set()
    for _ in range(4):
        learned = sum(len(names) for names in receiving.values())
        learned += len(returning) + len(field_taint)
        tainted: set[str] = set()
        current = None
        for line in code:
            head = JAVA_METHOD_HEAD.match(line)
            if head:
                # Skip the declaration itself: its own parameter list would
                # otherwise read as a call passing its own tainted names.
                current = head.group(1)
                tainted = set(receiving.get(current, ())) | field_taint
                continue
            for call in JAVA_CALL.finditer(line):
                name, arguments = call.group(1), call.group(2)
                if name not in declared or not arguments.strip():
                    continue
                if any(re.search(r"\b%s\b" % re.escape(value), arguments)
                       for value in tainted):
                    receiving.setdefault(name, set()).update(declared[name])
            handed_back = JAVA_RETURN.match(line)
            if current and handed_back and any(
                    re.search(r"\b%s\b" % re.escape(value),
                              handed_back.group(1)) for value in tainted):
                returning.add(current)
            _java_step_taint(tainted, line, returning)
            field_taint |= tainted & fields
        if sum(len(names) for names in receiving.values()) \
                + len(returning) + len(field_taint) == learned:
            break
    return receiving, returning, field_taint


def _java_taint(code, unbounded=None, external=()):
    """Per line: which local names hold something from outside.

    The same shape as `_command_taint`, for the same reason and against the
    same failure. Measured on Juliet Java's CWE-89, matching concatenation at
    the sink reported the corrected variant 78% of the time and scored zero:
    `goodG2B` keeps the identical `addBatch("..." + name)` and only changes
    the source to a literal.

    Taint clears on assignment from a literal, because that is a real
    correction. It does not clear on a length check or a comparison, neither
    of which makes a value safe to paste into a statement.

    Branches join rather than run on
    -------------------------------
    A literal assignment clears taint, and for a while it cleared it for code
    that never runs alongside it. Juliet's `_12` variants put both halves in
    one method behind a runtime condition:

        if (cond) { data = readLine(); }     // tainted here
        else      { data = "foo"; }          // cleared here
        ...
        addHeader("..." + data);             // was reported clean

    Walking straight down, the `else` arm's clear survived into a sink it
    never reaches, and five held-out CWE-113 pairs were missed for exactly
    that reason -- the rule was silent on both halves rather than confused
    between them.

    So a conditional block's entry state is remembered and merged back at its
    close: a name is tainted afterwards if it was tainted on *any* path.
    Clearing counts only when every path clears it. That is the sound
    direction for taint -- the failure it avoids is a missed defect, and the
    price is that a value cleared in all arms is still treated as tainted.

    The `unbounded` set
    -------------------
    Pass a set and it is maintained in place, under the same branch merging,
    holding names whose value has no ceiling -- a full-range random draw or
    MAX_VALUE. It is kept out of `tainted` because neither is attacker
    controlled and neither belongs in an injection report, but it needs the
    identical branch handling: Juliet's `_02` variants write

        count = (new SecureRandom()).nextInt();   // unbounded here
        count = 0;                                // dead branch clears it

    and tracking it outside the walker missed every one of those, for exactly
    the reason the taint merge exists.
    """
    receiving, returning, field_taint = _java_call_taint(code, external)
    tainted: set[str] = set()
    # (brace depth outside the block, taint on entry, unbounded on entry) for
    # each conditional block still open.
    branches: list[tuple[int, set[str], set[str]]] = []
    depth = 0
    pending_conditional = False
    for index, line in enumerate(code):
        head = JAVA_METHOD_HEAD.match(line)
        if head:
            # Juliet puts bad() and goodG2B() in one file, and a testcase is
            # scanned as the concatenation of its methods; carrying taint
            # across the boundary would let one method's source condemn
            # another's sink. Two things legitimately cross: a parameter some
            # call site hands a tainted value, and a field, which outlives the
            # method that assigned it.
            tainted = set(receiving.get(head.group(1), ())) | field_taint
            if unbounded is not None:
                unbounded.clear()
            branches.clear()
            depth = 0
        yield index, line, frozenset(tainted)
        _java_step_taint(tainted, line, returning)
        if unbounded is not None:
            _java_track_unbounded(line, unbounded)

        # A conditional block is remembered on the way in and merged on the
        # way out. Closes are processed *before* opens, and the order is the
        # whole of it: `} else {` closes one arm and opens the next on a
        # single line, so handling the open first pops the frame immediately
        # and the else arm has nothing left to restore it. Taking the close
        # first means the snapshot pushed for the else arm is the state at
        # the end of the if arm -- so merging at the final brace gives
        # exactly (if arm) union (else arm).
        opens, closes = line.count("{"), line.count("}")
        depth -= closes
        while branches and depth <= branches[-1][0]:
            _, entry_tainted, entry_unbounded = branches.pop()
            tainted |= entry_tainted
            if unbounded is not None:
                unbounded |= entry_unbounded
        # The keyword and its brace are often on separate lines -- Juliet is
        # written that way throughout:
        #
        #     if(IO.staticReturnsTrueOrFalse())
        #     {
        #
        # Requiring both on one line meant this never fired on the corpus it
        # was written for, and the same brace-on-its-own-line assumption had
        # already cost `_opens_a_function` every multi-line signature.
        if opens and (JAVA_CONDITIONAL_HEAD.match(line) or pending_conditional):
            branches.append((
                depth, set(tainted),
                set(unbounded) if unbounded is not None else set()))
        depth += opens
        if line.strip():
            pending_conditional = bool(
                JAVA_CONDITIONAL_HEAD.match(line)) and not opens


# Blocks whose body may or may not run, or may run repeatedly. A clear inside
# one of these cannot be assumed to have happened. A plain `{ ... }` block and
# a method body are absent on purpose: those execute exactly once, so walking
# straight through them is correct and merging would only lose precision.
JAVA_CONDITIONAL_HEAD = re.compile(
    r"\A\s*\}?\s*(?:else|if|for|while|do|switch|case|default|try|catch|"
    r"finally)\b")


JAVA_EXEC = re.compile(
    r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|"
    r"new\s+ProcessBuilder)\s*\(")
JAVA_SQL_EXEC = re.compile(
    r"\.\s*(?:executeQuery|executeUpdate|execute|addBatch)\s*\(")
JAVA_STATEMENT = re.compile(r"\bcreateStatement\s*\(\s*\)")
JAVA_WEAK_DIGEST = re.compile(
    r"\b(?:MessageDigest|Mac)\s*\.\s*getInstance\s*\(\s*\"("
    r"MD2|MD4|MD5|SHA-?0|SHA-?1|HmacMD5|HmacSHA1)\"", re.IGNORECASE)
JAVA_DESERIALIZE = re.compile(
    r"\bnew\s+ObjectInputStream\s*\(|\.\s*readObject\s*\(\s*\)")
JAVA_WEAK_RANDOM = re.compile(
    r"\bnew\s+java\.util\.Random\s*\(|\bnew\s+Random\s*\(|"
    r"\bMath\s*\.\s*random\s*\(")
JAVA_SECURITY_CONTEXT = re.compile(
    r"\b(?:token|secret|salt|nonce|password|passwd|key|iv|session|otp|"
    r"apikey|api_key)\b", re.IGNORECASE)
# `setSeed` with a value fixed at build time. Distinct from JAVA_WEAK_RANDOM:
# the generator here is usually SecureRandom, chosen correctly, and then made
# reproducible by seeding it with a constant.
JAVA_SET_SEED = re.compile(r"\.\s*setSeed\s*\(([^)]*)\)")
JAVA_CONSTANT_SEED = re.compile(
    r"\A\s*(?:-?\d[\dA-Fa-fxX_]*[LlFfDd]?|[A-Z_][A-Z0-9_]{2,}|\"[^\"]*\")\s*\Z")
JAVA_XML_FACTORY = re.compile(
    r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|"
    r"TransformerFactory|SchemaFactory)\s*\.\s*newInstance\s*\(")
JAVA_XML_HARDENED = re.compile(
    r"setFeature\s*\(|setProperty\s*\(|setXIncludeAware\s*\(|"
    r"setExpandEntityReferences\s*\(|ACCESS_EXTERNAL|disallow-doctype-decl|"
    r"IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD")


@rule("java-command-injection", ("java",), "HIGH",
      "a shell command is built from a value the code did not fix",
      "pass the program and each argument separately -- ProcessBuilder with a "
      "list, or exec(String[]) -- so no input can add a command of its own.")
def r_java_exec(ctx):
    """`exec("git " + branch)` and its relatives.

    Concatenation is the whole test. `exec("ls -la")` is a fixed command and
    reporting it would flag correct code; the corrected form of this defect is
    always either a literal or an argument array, so the `+` is what separates
    them.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        found = JAVA_EXEC.search(line)
        if not found:
            continue
        arguments = line[found.end() - 1:]
        if not _JAVA_BUILT.search(arguments):
            continue
        # Concatenation alone reports the correction too: Juliet's goodG2B
        # keeps the same `exec("cmd " + data)` and only makes `data` a
        # literal. The value has to have come from outside.
        if any(re.search(r"\b%s\b" % re.escape(name), arguments)
               for name in tainted):
            yield _f(ctx, index, "java-command-injection", "HIGH",
                     "this command is assembled from values in the program "
                     "rather than fixed, so anything reaching them can append "
                     "a command of its own.", r_java_exec.fix)


@rule("java-sql-injection", ("java",), "HIGH",
      "SQL is assembled by string concatenation instead of a bound parameter",
      "use PreparedStatement with ? placeholders and setString/setInt; never "
      "concatenate a value into the statement text.")
def r_java_sql(ctx):
    """Concatenation reaching `executeQuery` and friends.

    A `PreparedStatement` with `?` placeholders is the fix, and it never
    concatenates -- so, again, the `+` is the discriminator rather than the
    call.

    The statement is not always assembled at the sink. The commoner shape,
    in Juliet and in real code alike, builds the query into a variable, hands
    it to `prepareStatement`, and then calls `executeQuery()` with no
    arguments at all. Taint has already reached the receiver by then, so the
    receiver is the second place worth looking; that shape accounted for 53
    of the 130 silent held-out CWE-89 pairs.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        found = JAVA_SQL_EXEC.search(line)
        if not found:
            continue
        arguments = line[found.end() - 1:]
        if "?" in arguments:
            continue
        if _JAVA_BUILT.search(arguments):
            # Same discriminator as the exec rule, and for the same measured
            # reason: the fixed variant concatenates identically.
            if not any(re.search(r"\b%s\b" % re.escape(name), arguments)
                       for name in tainted):
                continue
        else:
            # `resultSet = sqlStatement.executeQuery();` -- nothing on this
            # line but the receiver, which is tainted only if the statement
            # it holds was prepared from a joined string. The corrected
            # variant prepares a `?` template, which taint never reaches.
            receiver = re.search(r"(\w+)\s*\Z", line[:found.start()])
            if not receiver or receiver.group(1) not in tainted:
                continue
        yield _f(ctx, index, "java-sql-injection", "HIGH",
                 "this statement is built by joining strings, so a value "
                 "inside it can close the quote and continue the query.",
                 r_java_sql.fix)


@rule("java-weak-hash", ("java",), "MEDIUM",
      "a broken digest is requested by name",
      "use SHA-256 or stronger; for passwords use a deliberately slow KDF "
      "such as PBKDF2, bcrypt, scrypt or Argon2.")
def r_java_weak_hash(ctx):
    """Reads `ctx.literal`, not `ctx.code`.

    The algorithm name lives *inside* a string, and `ctx.code` exists to stop
    rules matching there -- it hands back `getInstance("   ")` with the
    contents blanked out. This is one of the few rules whose entire signal is
    the literal, so it reads the view that keeps literals and drops only
    comments.
    """
    for index, line in enumerate(ctx.literal):
        found = JAVA_WEAK_DIGEST.search(line)
        if found:
            yield _f(ctx, index, "java-weak-hash", "MEDIUM",
                     "%s is collision-broken; it is acceptable as a checksum "
                     "and unsafe for signatures, passwords, or anything an "
                     "attacker benefits from forging." % found.group(1),
                     r_java_weak_hash.fix)


@rule("java-insecure-deserialize", ("java",), "HIGH",
      "Java native deserialisation is used on a stream the code does not own",
      "prefer a data format that does not construct arbitrary types -- JSON "
      "with an explicit schema -- or restrict the stream with a "
      "ObjectInputFilter allow-list.")
def r_java_deserialize(ctx):
    """`ObjectInputStream.readObject()`.

    There is no benign spelling of this on untrusted input: the stream decides
    which classes are constructed, which is why the fix is a different format
    or an explicit filter rather than a safer argument.
    """
    for index, line in enumerate(ctx.code):
        if JAVA_DESERIALIZE.search(line):
            yield _f(ctx, index, "java-insecure-deserialize", "HIGH",
                     "readObject builds whatever types the stream names, so a "
                     "crafted stream can reach code the program never meant "
                     "to run.", r_java_deserialize.fix)


@rule("java-weak-random", ("java",), "MEDIUM",
      "a predictable generator produces a security-relevant value",
      "use java.security.SecureRandom for tokens, keys, salts, session ids "
      "and anything an attacker must not be able to guess.")
def r_java_weak_random(ctx):
    """`new Random()` is only a defect where the value must be unguessable.

    Reporting every `Math.random()` would flag shuffles, jitter and test data,
    so the line must also name something security-relevant. That is a
    deliberately narrow test: it misses a token built two lines later, and it
    does not report a game's dice roll.
    """
    for index, line in enumerate(ctx.code):
        if JAVA_WEAK_RANDOM.search(line) and JAVA_SECURITY_CONTEXT.search(line):
            yield _f(ctx, index, "java-weak-random", "MEDIUM",
                     "java.util.Random is a predictable generator; a value "
                     "used for security has to come from SecureRandom.",
                     r_java_weak_random.fix)


@rule("java-fixed-seed", ("java",), "MEDIUM",
      "a generator is seeded with a value fixed at build time",
      "drop the setSeed call; SecureRandom seeds itself from the platform "
      "entropy source, and seeding it yourself only narrows the output.")
def r_java_fixed_seed(ctx):
    """A constant seed, which `java-weak-random` deliberately does not cover.

    That rule asks whether the generator is predictable by construction.
    This one catches the opposite shape and the more common mistake: the
    right generator, `SecureRandom`, made reproducible by handing it a
    constant. Juliet's CWE-336 is exactly this -- `setSeed(SEED)` in the
    flawed half, and a corrected half that simply does not seed at all.

    The seed has to be constant. `setSeed(System.currentTimeMillis())` is
    weak for other reasons but is not this defect, and reporting it here
    would blur two findings that have different fixes.
    """
    for index, line in enumerate(ctx.code):
        found = JAVA_SET_SEED.search(line)
        if found and JAVA_CONSTANT_SEED.match(found.group(1)):
            yield _f(ctx, index, "java-fixed-seed", "MEDIUM",
                     "this generator is seeded with a fixed value, so it "
                     "produces the same sequence on every run.",
                     r_java_fixed_seed.fix)


@rule("java-xxe", ("java",), "HIGH",
      "an XML parser is created without disabling external entities",
      "disable DTDs on the factory -- "
      "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", "
      "true) -- before parsing anything you did not write.", deep=True)
def r_java_xxe(ctx):
    """A parser factory with no hardening near it.

    Java's XML factories resolve external entities by default, so the *absence*
    of configuration is the defect. Hardening always follows the
    `newInstance()` on later lines, so the test needs a window rather than a
    line -- checking the line alone would report every correctly configured
    parser in the tree.

    The window is a fixed line count, not the enclosing function. This rule
    first used `_c_function_spans` and found nothing at all: that helper reads
    C headers, and `void run() throws Exception {` is not one, so every Java
    method fell outside every span. Reusing C's shape for Java looked like
    reuse and was really a silent no-op.
    """
    limit = len(ctx.code) - 1
    for index, line in enumerate(ctx.code):
        if not JAVA_XML_FACTORY.search(line):
            continue
        window = "\n".join(ctx.code[index:min(limit, index + 24) + 1])
        if JAVA_XML_HARDENED.search(window):
            continue
        yield _f(ctx, index, "java-xxe", "HIGH",
                 "this parser is left with its defaults, which resolve "
                 "external entities: a document can read local files or "
                 "make the parser fetch a URL.", r_java_xxe.fix)


# Four more sinks that a value from outside must not reach unescaped. Each is
# the same question the SQL rule asks -- does a tainted name appear in this
# call's arguments -- so they are written against one helper rather than four
# near-copies of the same loop.
JAVA_LDAP_SEARCH = re.compile(r"\.\s*search\s*\(")
JAVA_LDAP_CONTEXT = re.compile(
    r"DirContext|NamingEnumeration|LdapCtxFactory|\bldap\b", re.IGNORECASE)
JAVA_XPATH_EVAL = re.compile(r"\.\s*(?:evaluate|compile)\s*\(")
JAVA_XPATH_CONTEXT = re.compile(r"\bXPath\b")
# `sendError` puts its message straight into the generated error page, so it
# is the same defect as writing to the response body -- that is Juliet's
# CWE-81, which scored 0% while CWE-83 scored 100% purely because the second
# writes through getWriter() and the first does not.
JAVA_WRITER_SINK = re.compile(
    r"getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\(|"
    r"\.\s*sendError\s*\(")
JAVA_HEADER_SINK = re.compile(
    r"\.\s*(?:addHeader|setHeader|sendRedirect)\s*\(|\bnew\s+Cookie\s*\(")
# Escapers that render a value inert as text: percent-encoding for a header,
# entity-encoding for markup and XPath. These are the corrections Juliet's
# `goodB2G` halves actually make -- CWE-113 wraps the value in
# `URLEncoder.encode`, CWE-643 in `StringEscapeUtils.escapeXml`.
#
# Note what is deliberately absent: `replaceAll`. CWE-80's *flawed* half
# filters with `replaceAll("(<script>)", "")` and is still the defect, because
# a blacklist is not an escaper. Accepting it here would suppress a real
# finding, which is the more expensive mistake of the two.
JAVA_ESCAPED = re.compile(
    r"URLEncoder\s*\.\s*encode\s*\(|"
    r"StringEscapeUtils\s*\.\s*escape\w*\s*\(|"
    r"ESAPI\s*\.\s*encoder\s*\(")


def _java_reaches(line, tainted, sink):
    """Tainted names appearing in a sink call's arguments on this line.

    Returns None when the line holds no such call at all, so a caller can tell
    "no sink here" apart from "a sink with nothing tainted in it".
    """
    found = sink.search(line)
    if not found:
        return None
    arguments = line[found.end() - 1:]
    return [name for name in tainted
            if re.search(r"\b%s\b" % re.escape(name), arguments)]


@rule("java-ldap-injection", ("java",), "HIGH",
      "an LDAP filter is built from a value that came from outside",
      "escape the value for LDAP (RFC 4515) or bind it through a filter "
      "argument: directoryContext.search(base, \"(cn={0})\", args, controls).")
def r_java_ldap(ctx):
    """A tainted name inside `directoryContext.search(...)`.

    `.search(` on its own is far too common a method name to report -- binary
    searches and matchers use it constantly -- so the file also has to look
    like it is talking to a directory. That narrowing costs recall on code
    that reaches LDAP through a wrapper, and is worth it.
    """
    if not JAVA_LDAP_CONTEXT.search("\n".join(ctx.code)):
        return
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        if _java_reaches(line, tainted, JAVA_LDAP_SEARCH):
            yield _f(ctx, index, "java-ldap-injection", "HIGH",
                     "this directory filter contains a value from outside, "
                     "so a `*` or `)` in it can rewrite the query.",
                     r_java_ldap.fix)


@rule("java-xpath-injection", ("java",), "HIGH",
      "an XPath expression is built from a value that came from outside",
      "use XPathExpression with variables through an XPathVariableResolver "
      "instead of joining the value into the expression text.")
def r_java_xpath(ctx):
    """A tainted name inside `xPath.evaluate(...)` or `.compile(...)`.

    Same narrowing as the LDAP rule and for the same reason: `compile` and
    `evaluate` belong to plenty of things that are not XPath.
    """
    if not JAVA_XPATH_CONTEXT.search("\n".join(ctx.code)):
        return
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        if _java_reaches(line, tainted, JAVA_XPATH_EVAL):
            yield _f(ctx, index, "java-xpath-injection", "HIGH",
                     "this XPath expression contains a value from outside, "
                     "so a quote in it can select nodes you did not intend.",
                     r_java_xpath.fix)


@rule("java-xss-reflected", ("java",), "HIGH",
      "a value from outside is written into the response body unescaped",
      "escape for the HTML context you are writing into -- a template engine "
      "with automatic escaping, or an encoder such as OWASP Java Encoder.")
def r_java_xss(ctx):
    """A tainted name reaching `response.getWriter().println(...)`.

    Juliet's CWE-80 flawed half already calls `replaceAll("(<script>)", "")`,
    which is exactly why a blacklist is not a fix and why this rule does not
    accept one as clearing the value.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        if _java_reaches(line, tainted, JAVA_WRITER_SINK):
            yield _f(ctx, index, "java-xss-reflected", "HIGH",
                     "this value is written into the page as it arrived, so "
                     "markup inside it becomes part of the document.",
                     r_java_xss.fix)


@rule("java-response-splitting", ("java",), "HIGH",
      "a value from outside is placed into a response header",
      "percent-encode the value (URLEncoder.encode) or reject anything "
      "carrying CR or LF before it reaches a header.")
def r_java_response_split(ctx):
    """A tainted name reaching a header, cookie or redirect.

    Unlike the other three this one has a real corrective form to recognise:
    `goodB2G` wraps the value in `URLEncoder.encode`, on the sink line or the
    line that produced it, and a newline cannot survive that.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        if JAVA_ESCAPED.search(line):
            continue
        if _java_reaches(line, tainted, JAVA_HEADER_SINK):
            yield _f(ctx, index, "java-response-splitting", "HIGH",
                     "this header carries a value from outside, so a newline "
                     "in it can inject a header or split the response.",
                     r_java_response_split.fix)


# ---- Java: values used without being bounded ------------------------------ #
#
# CWE-129, 190, 191 and 369 are 20,171 of Juliet Java's files and had no rule
# at all. They are one shape: a value from outside reaches arithmetic or an
# index, and the corrected variant differs *only* by testing it first. So the
# guard is the entire discriminator -- keying on the operation matches both
# halves byte for byte, which is what cost the C version 72 false positives
# before it tracked guards.

JAVA_INDEX_USE = re.compile(r"\[\s*([A-Za-z_]\w*)\s*\]")
JAVA_DIVIDE_BY = re.compile(r"[/%]\s*\(?\s*([A-Za-z_]\w*)")
JAVA_NARROWING = re.compile(r"\(\s*(?:byte|short|int|char)\s*\)\s*\(")
JAVA_ARITHMETIC = re.compile(r"[-+*]")
JAVA_LIMIT_NAMED = re.compile(r"\b(?:MAX_VALUE|MIN_VALUE)\b")


def _java_lower_bounded(name, line):
    """Does this line test `name` against zero from below?

    `> 0` has to count as well as `>= 0`. It is the strictly stronger claim --
    everything it admits, `>= 0` admits too -- so a rule that accepts the
    weaker guard and rejects the stronger one reports the corrected variant
    and stays quiet on the flawed one. That is what it was doing: 22% of
    held-out CWE-129 pairs came back inverted, every one of them a case whose
    fix reads `if (data > 0)`.
    """
    escaped = re.escape(name)
    return bool(re.search(r"\b%s\s*(?:>=?\s*0\b|>\s*-\s*1\b)" % escaped, line)
                or re.search(r"\b0\s*<=?\s*%s\b" % escaped, line))


def _java_compared_to_zero(name, line):
    """Has this line established that `name` is not zero?

    Integers get compared to 0 directly. Floats cannot be -- 0.1+0.2 is not
    0.3 and a float divisor is dangerous well before it reaches exactly zero
    -- so the correct guard is an epsilon test, and Juliet writes it as
    `Math.abs(data) > 0.000001`. Matching only `!= 0` missed every float
    case: the rule then fired on the corrected variant too, on 44% of pairs,
    which is worse than not having it.
    """
    escaped = re.escape(name)
    if re.search(r"Math\s*\.\s*abs\s*\(\s*%s\s*\)\s*(?:>|>=|!=|<|<=)"
                 % escaped, line):
        return True
    return bool(re.search(r"\b%s\s*(?:!=|==|>|<|>=|<=)\s*0" % escaped, line)
                or re.search(r"\b0\s*(?:!=|==|<|>|<=|>=)\s*%s\b" % escaped,
                             line))


@rule("java-array-index-unchecked", ("java",), "HIGH",
      "an array is indexed by a value from outside without a lower bound",
      "check the index against both ends -- `if (i >= 0 && i < a.length)`; "
      "testing only the length still admits a negative index.")
def r_java_array_index(ctx):
    """Fires on an index that only half the range was checked for.

    Juliet's flawed variant does test `data < array.length`, so a rule asking
    "is it checked?" answers yes and finds nothing. What the corrected
    variant adds is the *other* end, and a negative index is what actually
    throws.
    """
    guarded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        for name in tainted:
            if _java_lower_bounded(name, line):
                guarded.add(name)
        found = JAVA_INDEX_USE.search(line)
        if found and found.group(1) in tainted and found.group(1) not in guarded:
            yield _f(ctx, index, "java-array-index-unchecked", "HIGH",
                     "'%s' comes from outside and is used as an index with "
                     "no check that it is not negative." % found.group(1),
                     r_java_array_index.fix)


@rule("java-divide-by-zero", ("java",), "MEDIUM",
      "a divisor comes from outside and is never tested for zero",
      "reject or substitute the value before dividing; integer division by "
      "zero throws, and floating-point division yields infinity or NaN.")
def r_java_divide_by_zero(ctx):
    guarded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        for name in tainted:
            if _java_compared_to_zero(name, line):
                guarded.add(name)
        found = JAVA_DIVIDE_BY.search(line)
        if found and found.group(1) in tainted and found.group(1) not in guarded:
            yield _f(ctx, index, "java-divide-by-zero", "MEDIUM",
                     "'%s' is used as a divisor without being tested for "
                     "zero first." % found.group(1),
                     r_java_divide_by_zero.fix)


@rule("java-integer-overflow", ("java",), "MEDIUM",
      "arithmetic on an unchecked external value can wrap past its type",
      "test the operand against the type's limit before the operation, or "
      "widen the result type so the value cannot wrap.")
def r_java_integer_overflow(ctx):
    """Narrowing arithmetic on a value nothing has bounded.

    Restricted to expressions carrying an explicit narrowing cast -- which is
    how Juliet writes both halves -- because plain `a + b` on a tainted value
    is most of the arithmetic in most programs, and a rule that fires on all
    of it reports the corrected variant just as loudly.
    """
    guarded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        for name in tainted:
            if JAVA_LIMIT_NAMED.search(line) and re.search(
                    r"\b%s\b" % re.escape(name), line):
                guarded.add(name)
        if not JAVA_NARROWING.search(line) or not JAVA_ARITHMETIC.search(line):
            continue
        # Only the operands count, never the variable being assigned. In
        #
        #     if (data < Byte.MAX_VALUE) { byte result = (byte)(data + 1); }
        #
        # `result` is itself tainted -- it is computed from `data` -- and the
        # guard names only `data`, so scanning the whole line finds `result`
        # unguarded and reports a case that is correctly written. That was
        # every one of the 4% this rule fired on both halves of.
        target = JAVA_ASSIGN_TARGET.match(line)
        operands = line[target.end(1):] if target else line
        for name in tainted:
            if name in guarded or (target and name == target.group(1)):
                continue
            if re.search(r"\b%s\b" % re.escape(name), operands):
                yield _f(ctx, index, "java-integer-overflow", "MEDIUM",
                         "'%s' comes from outside and is used in narrowing "
                         "arithmetic with nothing bounding it." % name,
                         r_java_integer_overflow.fix)
                break


# `nextInt()` with no argument draws from the whole int range, negatives
# included; `nextInt(1000)` cannot exceed 1000. Only the first is a size
# nobody has bounded, so the empty parentheses are the whole point here.
JAVA_UNBOUNDED_RANDOM = re.compile(
    r"\.\s*next(?:Int|Long)\s*\(\s*\)|\bMath\s*\.\s*random\s*\(\s*\)")

JAVA_NUMERIC_LITERAL_ASSIGN = re.compile(
    r"\s*(?:[\w.<>]+\s+)?\w+\s*=\s*-?\d+\s*;")

# `Integer.MAX_VALUE` is not attacker-controlled -- it is worse. Nothing can
# make it smaller, so a loop counted to it or a sleep of that many
# milliseconds (24 days) is unbounded by construction. MIN_VALUE is excluded
# deliberately: Juliet opens every one of these cases with
# `count = Integer.MIN_VALUE` as initialisation, and treating that as a
# finding would report all 875 files on both halves.
JAVA_MAX_VALUE = re.compile(
    r"\b(?:Integer|Long|Short|Byte)\s*\.\s*MAX_VALUE\b")


def _java_track_unbounded(line, unbounded):
    """Update the set of names holding a value with no ceiling.

    Two ways in -- a full-range random draw and MAX_VALUE -- and one way out,
    assignment of a plain numeric literal, which is how every corrected
    Juliet variant of these families is written. Kept separate from the taint
    set on purpose: neither of these is attacker-controlled, and letting them
    flow into the injection rules would report `new Random()` as SQL
    injection.
    """
    assigned = JAVA_ASSIGN_TARGET.match(line)
    if not assigned:
        return
    name = assigned.group(1)
    right = line[assigned.end():]
    if JAVA_UNBOUNDED_RANDOM.search(right) or JAVA_MAX_VALUE.search(right):
        unbounded.add(name)
    elif JAVA_NUMERIC_LITERAL_ASSIGN.match(line):
        unbounded.discard(name)

JAVA_SIZED_ALLOC = re.compile(
    r"\bnew\s+(?:java\.util\.)?(?:ArrayList|HashMap|HashSet|LinkedHashMap|"
    r"LinkedHashSet|Hashtable|Vector|StringBuilder|StringBuffer|"
    r"PriorityQueue|ArrayDeque)\s*<[^>]*>?\s*\(\s*([A-Za-z_]\w*)\s*\)"
    r"|\bnew\s+(?:java\.util\.)?(?:ArrayList|HashMap|HashSet|LinkedHashMap|"
    r"LinkedHashSet|Hashtable|Vector|StringBuilder|StringBuffer|"
    r"PriorityQueue|ArrayDeque)\s*\(\s*([A-Za-z_]\w*)\s*\)"
    r"|\bnew\s+[\w.]+\s*\[\s*([A-Za-z_]\w*)\s*\]")


def _java_upper_bounded(name, line):
    """Has this line put a ceiling on `name`?

    Juliet never needs this -- not one of its 941 CWE-789 files corrects the
    flaw with a check, they all just swap the source for a literal -- so the
    corpus score is identical with or without it. Real code does bound its
    allocations, and a rule that reported those would be noise nobody keeps.
    """
    escaped = re.escape(name)
    return bool(re.search(r"\b%s\s*(?:<|<=)\s*[\w.]" % escaped, line)
                or re.search(r"[\w.]\s*(?:>|>=)\s*%s\b" % escaped, line)
                or re.search(r"Math\s*\.\s*min\s*\([^)]*\b%s\b" % escaped, line))


@rule("java-unbounded-allocation", ("java",), "MEDIUM",
      "a collection or array is sized by a value from outside",
      "clamp the size to a sane maximum before allocating; a caller that "
      "supplies a huge count otherwise decides how much memory you use.")
def r_java_unbounded_alloc(ctx):
    """A capacity argument nothing has capped.

    The sink is the constructor's size argument, not the constructor -- an
    `ArrayList` is not a defect, an `ArrayList` sized by whatever arrived from
    outside is. 2,553 files in Juliet Java and no rule for any of them until
    now; the flawed half parses an integer from the environment and hands it
    straight to `new HashMap(data)`.
    """
    guarded: set[str] = set()
    unbounded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, unbounded, external=ctx.cross_file_taint):
        for name in tainted | unbounded:
            if _java_upper_bounded(name, line):
                guarded.add(name)
        found = JAVA_SIZED_ALLOC.search(line)
        if not found:
            continue
        size = found.group(1) or found.group(2) or found.group(3)
        if size in guarded:
            continue
        if size in tainted:
            yield _f(ctx, index, "java-unbounded-allocation", "MEDIUM",
                     "'%s' comes from outside and decides how much memory "
                     "this allocates, with no ceiling on it." % size,
                     r_java_unbounded_alloc.fix)
        elif size in unbounded:
            yield _f(ctx, index, "java-unbounded-allocation", "MEDIUM",
                     "'%s' is a random draw across the whole integer range "
                     "and decides how much memory this allocates." % size,
                     r_java_unbounded_alloc.fix)


# The bound of a counted loop: the name on the far side of the comparison in
# the middle clause. `i < data.length` deliberately does not match -- the
# capture cannot span the dot, so iterating a collection is not a finding.
JAVA_LOOP_BOUND = re.compile(
    r"\bfor\s*\([^;]*;[^;]*?[<>]=?\s*([A-Za-z_]\w*)\s*[;)]"
    r"|\bwhile\s*\([^)]*?[<>]=?\s*([A-Za-z_]\w*)\s*\)")

JAVA_SLEEP_SINK = re.compile(
    r"\b(?:Thread\s*\.\s*)?sleep\s*\(\s*([A-Za-z_]\w*)\s*[,)]")


@rule("java-unbounded-loop", ("java",), "MEDIUM",
      "how long this runs is decided by a value from outside",
      "bound the count before looping on it -- `if (n > 0 && n <= LIMIT)`; "
      "a caller that supplies a huge number otherwise decides how long the "
      "process is busy.")
def r_java_unbounded_loop(ctx):
    """A loop, or a sleep, whose length nothing has capped.

    The loop is identical in both halves of every Juliet case; only the
    corrected one bounds its counter first, so the guard is the whole
    discriminator here exactly as it is for the array-index family. 2,412
    files and no rule covered any of them.

    Sleeping for an attacker-supplied duration is the same defect wearing
    different clothes -- the resource being consumed is the thread rather
    than the CPU -- so both sinks report through this one rule.
    """
    guarded: set[str] = set()
    unbounded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, unbounded, external=ctx.cross_file_taint):
        for name in tainted | unbounded:
            if _java_upper_bounded(name, line):
                guarded.add(name)
        for pattern, what in ((JAVA_LOOP_BOUND, "decides how many times this "
                               "loop runs"),
                              (JAVA_SLEEP_SINK, "decides how long this "
                               "sleeps")):
            found = pattern.search(line)
            if not found:
                continue
            bound = next((g for g in found.groups() if g), None)
            if bound is None or bound in guarded:
                continue
            if bound in tainted:
                yield _f(ctx, index, "java-unbounded-loop", "MEDIUM",
                         "'%s' comes from outside and %s, with no ceiling "
                         "on it." % (bound, what),
                         r_java_unbounded_loop.fix)
            elif bound in unbounded:
                yield _f(ctx, index, "java-unbounded-loop", "MEDIUM",
                         "'%s' has no upper bound and %s."
                         % (bound, what),
                         r_java_unbounded_loop.fix)


# Java's primitive widths in bits. `char` is 16 and unsigned, which makes a
# cast from it to `short` lossy in the other direction, but Juliet does not
# exercise that and neither does this rule -- it compares widths only.
JAVA_PRIMITIVE_WIDTH = {
    "byte": 8, "short": 16, "char": 16, "int": 32, "long": 64,
    "float": 32, "double": 64,
}

JAVA_PRIMITIVE_DECL = re.compile(
    r"\b(byte|short|char|int|long|float|double)\s+([A-Za-z_]\w*)\s*[;=,)]")

JAVA_NARROWING_CAST = re.compile(
    r"\(\s*(byte|short|char|int|long|float|double)\s*\)\s*([A-Za-z_]\w*)")


@rule("java-numeric-truncation", ("java",), "MEDIUM",
      "a value from outside is cast down to a type too small to hold it",
      "check the value is inside the destination's range before narrowing "
      "it -- `if (n >= Byte.MIN_VALUE && n <= Byte.MAX_VALUE)`; the cast "
      "itself discards the high bits silently.")
def r_java_numeric_truncation(ctx):
    """A cast that discards bits of a value the caller chose.

    The cast is identical in both halves of every one of Juliet's 726 cases
    -- `(byte) data` on both sides -- so what separates them is only where
    `data` came from. That makes this a taint rule, not a pattern rule.

    Whether a cast truncates depends on the *declared width of the operand*,
    which is why the declarations are tracked: `(int) longValue` loses bits
    and `(int) shortValue` cannot. A rule that fired on the cast alone would
    report every widening conversion in the codebase.
    """
    declared: dict[str, str] = {}
    unbounded: set[str] = set()
    for index, line, tainted in _java_taint(
            ctx.code, unbounded, external=ctx.cross_file_taint):
        for kind, name in JAVA_PRIMITIVE_DECL.findall(line):
            declared[name] = kind
        for target, name in JAVA_NARROWING_CAST.findall(line):
            source = declared.get(name)
            if source is None:
                continue
            if JAVA_PRIMITIVE_WIDTH[target] >= JAVA_PRIMITIVE_WIDTH[source]:
                continue          # widening, or same width: nothing is lost
            if name in tainted:
                why = "comes from outside"
            elif name in unbounded:
                why = "has no upper bound"
            else:
                continue
            yield _f(ctx, index, "java-numeric-truncation", "MEDIUM",
                     "'%s' %s and is cast from %s to %s, which silently "
                     "discards the bits that do not fit."
                     % (name, why, source, target),
                     r_java_numeric_truncation.fix)


# The tainted value has to *be* the format string, not one of the arguments
# it formats. `String.format("%s", data)` is the correct spelling and must
# stay quiet; `String.format(data)` lets the caller choose the conversions.
# So the name is matched immediately after the opening parenthesis.
JAVA_FORMAT_SINK = re.compile(
    r"\.\s*(?:format|printf)\s*\(\s*([A-Za-z_]\w*)\s*[,)]"
    r"|\bString\s*\.\s*format\s*\(\s*([A-Za-z_]\w*)\s*[,)]")

JAVA_FILE_SINK = re.compile(
    r"\bnew\s+(?:java\.io\.)?File\s*\(|"
    r"\bnew\s+(?:File(?:Input|Output)Stream|FileReader|FileWriter)\s*\(|"
    r"\bPaths\s*\.\s*get\s*\(|\bFiles\s*\.\s*(?:newInputStream|newOutputStream|"
    r"readAllBytes|delete|copy|move)\s*\(")

JAVA_REFLECTION_SINK = re.compile(
    r"\bClass\s*\.\s*forName\s*\(|\.\s*loadClass\s*\(|"
    r"\.\s*getMethod\s*\(|\.\s*getDeclaredMethod\s*\(")

JAVA_CONFIG_SINK = re.compile(
    r"\bSystem\s*\.\s*(?:setProperty|setProperties)\s*\(|"
    r"\.\s*setCatalog\s*\(|\.\s*setSchema\s*\(|"
    r"\.\s*setReadOnly\s*\(|\.\s*setTransactionIsolation\s*\(")


@rule("java-format-string", ("java",), "HIGH",
      "a value from outside is used as a format string",
      "pass the value as an argument, never as the format -- "
      "`String.format(\"%s\", value)`; a caller who controls the format "
      "controls how many arguments are read.")
def r_java_format_string(ctx):
    """CWE-134. The format string itself came from outside.

    Juliet's corrected variant keeps the identical `format()` call and only
    changes where the string came from, so this discriminates on the source
    exactly as the injection rules do.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        found = JAVA_FORMAT_SINK.search(line)
        if not found:
            continue
        name = found.group(1) or found.group(2)
        if name in tainted:
            yield _f(ctx, index, "java-format-string", "HIGH",
                     "'%s' comes from outside and is the format string, so "
                     "the caller decides what gets read." % name,
                     r_java_format_string.fix)


@rule("java-path-traversal", ("java",), "HIGH",
      "a path is built from a value the caller supplied",
      "resolve the path and confirm it stays inside the directory you "
      "intended -- `p.normalize().startsWith(root)`; joining a base to an "
      "attacker's string does not contain it, because `../` climbs out.")
def r_java_path_traversal(ctx):
    """CWE-23 and CWE-36, which are one analysis.

    Relative and absolute traversal differ only in whether the flawed half
    concatenates a base directory first -- `new File(root + data)` versus
    `new File(data)` -- and neither containment is real, so both report here.
    """
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        reached = _java_reaches(line, tainted, JAVA_FILE_SINK)
        if reached:
            yield _f(ctx, index, "java-path-traversal", "HIGH",
                     "'%s' comes from outside and decides which file this "
                     "opens." % sorted(reached)[0],
                     r_java_path_traversal.fix)


@rule("java-unsafe-reflection", ("java",), "HIGH",
      "the class or method to load is named by a value from outside",
      "map the input to a fixed set of permitted classes; loading a name "
      "the caller chose lets them reach any type on the classpath.")
def r_java_unsafe_reflection(ctx):
    """CWE-470."""
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        reached = _java_reaches(line, tainted, JAVA_REFLECTION_SINK)
        if reached:
            yield _f(ctx, index, "java-unsafe-reflection", "HIGH",
                     "'%s' comes from outside and names the class to load."
                     % sorted(reached)[0],
                     r_java_unsafe_reflection.fix)


@rule("java-external-config", ("java",), "MEDIUM",
      "a value from outside changes a system or connection setting",
      "validate against a fixed allow-list before applying it; a setting "
      "the caller chooses is a setting they control for everyone.")
def r_java_external_config(ctx):
    """CWE-15."""
    for index, line, tainted in _java_taint(
            ctx.code, external=ctx.cross_file_taint):
        reached = _java_reaches(line, tainted, JAVA_CONFIG_SINK)
        if reached:
            yield _f(ctx, index, "java-external-config", "MEDIUM",
                     "'%s' comes from outside and changes a setting this "
                     "process runs under." % sorted(reached)[0],
                     r_java_external_config.fix)


# ---- Java: the pattern families ------------------------------------------- #
#
# Everything below reports the presence of a construct rather than a flow.
# That is the right shape here and the wrong shape for injection: these are
# defects you can see in one line, and Juliet's corrected variant replaces
# the construct outright rather than sanitising a value.

JAVA_STRING_IDENTITY = re.compile(
    r"\b(?:if|while)\s*\([^)]*?\b(\w+)\s*(?:==|!=)\s*(\w+)\b")
JAVA_WEAK_PRNG = re.compile(
    r"\bMath\s*\.\s*random\s*\(|\bnew\s+Random\s*\(")
JAVA_BROKEN_CIPHER = re.compile(
    r"getInstance\s*\(\s*\"(?:DES|DESede|RC2|RC4|ARCFOUR|Blowfish)\b", re.I)
JAVA_SUSPICIOUS_COMMENT = re.compile(
    r"(?://|/\*|\*)\s*.*?\b(TODO|FIXME|XXX|HACK|BUG|KLUDGE)\b")
JAVA_SYSTEM_EXIT = re.compile(r"\bSystem\s*\.\s*exit\s*\(")
JAVA_BROAD_CATCH = re.compile(
    r"\bcatch\s*\(\s*(?:final\s+)?(Exception|Throwable|RuntimeException|"
    r"NullPointerException)\s+\w+\s*\)")
JAVA_GENERIC_THROW = re.compile(
    r"\bthrow\s+new\s+(Exception|Throwable|RuntimeException)\s*\(")
JAVA_EXPLICIT_FINALIZE = re.compile(r"\.\s*finalize\s*\(\s*\)")
JAVA_THREAD_RUN = re.compile(r"\.\s*run\s*\(\s*\)\s*;")
# `DataInputStream.readLine()` is the deprecated one; BufferedReader is what
# the corrected variant swaps to. Declaring the stream is the marker, because
# the deprecation is on the class's readLine, not on reading as such.
JAVA_OBSOLETE = re.compile(
    r"\bnew\s+DataInputStream\s*\(|"
    r"\bDataInputStream\s+\w+\s*=|"
    r"\.\s*(?:stop|suspend|resume)\s*\(\s*\)\s*;|"
    r"\bnew\s+Date\s*\(\s*\)\s*\.\s*get(?:Year|Month|Day)\s*\(|"
    # The deprecated `getBytes(int, int, byte[], int)` overload, which
    # truncates every character to its low byte. Told apart from the modern
    # `getBytes()` and `getBytes(charset)` by having more than one argument.
    r"\.\s*getBytes\s*\([^)]*,")
JAVA_COOKIE_INSECURE = re.compile(r"\bnew\s+Cookie\s*\(")
JAVA_COOKIE_SECURED = re.compile(r"\.\s*setSecure\s*\(\s*true\s*\)")


def _java_simple(ctx, name, pattern, severity, message, fix, skip=None,
                 keep_strings=False):
    """One-line pattern rules share this walk.

    Comments and string literals are both blanked out of `ctx.code`, so a
    rule written here cannot fire on a defect that only appears inside a
    quoted example -- the mistake that made `adv-py-return-finally` unusable.

    `keep_strings` switches to `ctx.literal`, which blanks comments but keeps
    string contents. Some defects *are* a string: the whole of CWE-327 is
    `getInstance("DESede")` versus `getInstance("AES")`, and against blanked
    code both read as `getInstance("      ")`. That scored the rule 0% until
    it was pointed at the right text.
    """
    lines = ctx.literal if keep_strings else ctx.code
    for index, line in enumerate(lines):
        if skip is not None and skip.search(line):
            continue
        if pattern.search(line):
            yield _f(ctx, index, name, severity, message, fix)


@rule("java-string-identity-compare", ("java",), "MEDIUM",
      "two strings are compared with == instead of equals()",
      "compare contents with `a.equals(b)`; == asks whether they are the "
      "same object, which is true only by accident of interning.")
def r_java_string_identity(ctx):
    """CWE-597. `if (string1 == string2)`.

    Restricted to names both sides, so `x == null` and `count == 0` -- the
    correct uses of == -- are not reported.
    """
    for index, line in enumerate(ctx.code):
        found = JAVA_STRING_IDENTITY.search(line)
        if not found:
            continue
        left, right = found.group(1), found.group(2)
        if left in {"null", "true", "false"} or right in {"null", "true", "false"}:
            continue
        if not re.search(r"\bString\s+(?:%s|%s)\b"
                         % (re.escape(left), re.escape(right)),
                         "\n".join(ctx.code)):
            continue
        yield _f(ctx, index, "java-string-identity-compare", "MEDIUM",
                 "'%s' and '%s' are Strings compared with ==, which tests "
                 "identity rather than contents." % (left, right),
                 r_java_string_identity.fix)


@rule("java-weak-prng", ("java",), "MEDIUM",
      "an ordinary random generator is used where the value must be unguessable",
      "use `java.security.SecureRandom`; `Math.random()` and `new Random()` "
      "are predictable from a handful of prior outputs.")
def r_java_weak_prng(ctx):
    """CWE-338."""
    yield from _java_simple(
        ctx, "java-weak-prng", JAVA_WEAK_PRNG, "MEDIUM",
        "this random value is predictable; SecureRandom is the one that is not.",
        r_java_weak_prng.fix)


@rule("java-broken-cipher", ("java",), "HIGH",
      "a cipher that is no longer considered safe is requested by name",
      "use AES with an authenticated mode -- AES/GCM/NoPadding; DES, RC2 "
      "and RC4 are broken, not merely old.")
def r_java_broken_cipher(ctx):
    """CWE-327."""
    yield from _java_simple(
        ctx, "java-broken-cipher", JAVA_BROKEN_CIPHER, "HIGH",
        "this algorithm is broken; the name is the whole defect.",
        r_java_broken_cipher.fix, keep_strings=True)


@rule("java-suspicious-comment", ("java",), "LOW",
      "a comment marks work that was never finished",
      "resolve it or track it somewhere that is not the source; a TODO in "
      "shipped code is a defect nobody has been assigned.")
def r_java_suspicious_comment(ctx):
    """CWE-546 and CWE-615.

    Reads `ctx.raw`, not `ctx.code` -- comments are blanked out of the
    latter, which is exactly the text this rule is about.
    """
    for index, line in enumerate(ctx.raw):
        found = JAVA_SUSPICIOUS_COMMENT.search(line)
        if found:
            yield _f(ctx, index, "java-suspicious-comment", "LOW",
                     "a %s comment marks unfinished work left in the source."
                     % found.group(1),
                     r_java_suspicious_comment.fix)


@rule("java-system-exit", ("java",), "MEDIUM",
      "library or servlet code shuts down the whole process",
      "throw or return an error instead; System.exit takes the container "
      "and every other request down with it.")
def r_java_system_exit(ctx):
    """CWE-382."""
    yield from _java_simple(
        ctx, "java-system-exit", JAVA_SYSTEM_EXIT, "MEDIUM",
        "this stops the entire process, not just this operation.",
        r_java_system_exit.fix)


@rule("java-overbroad-catch", ("java",), "LOW",
      "a catch block swallows every failure class at once",
      "catch the specific exceptions you can actually handle; catching "
      "Exception hides the ones you cannot.")
def r_java_overbroad_catch(ctx):
    """CWE-396 and CWE-395."""
    yield from _java_simple(
        ctx, "java-overbroad-catch", JAVA_BROAD_CATCH, "LOW",
        "this catch covers failures the code has no plan for.",
        r_java_overbroad_catch.fix)


@rule("java-generic-throw", ("java",), "LOW",
      "a generic exception type is thrown",
      "throw a type that names the failure; callers cannot handle "
      "`Exception` without catching everything else too.")
def r_java_generic_throw(ctx):
    """CWE-397."""
    yield from _java_simple(
        ctx, "java-generic-throw", JAVA_GENERIC_THROW, "LOW",
        "the type thrown says nothing about what went wrong.",
        r_java_generic_throw.fix)


@rule("java-explicit-finalize", ("java",), "LOW",
      "finalize() is called directly",
      "let the collector call it, and prefer try-with-resources; calling "
      "it yourself runs cleanup on an object still in use.")
def r_java_explicit_finalize(ctx):
    """CWE-586."""
    yield from _java_simple(
        ctx, "java-explicit-finalize", JAVA_EXPLICIT_FINALIZE, "LOW",
        "calling finalize() by hand cleans up an object that is still live.",
        r_java_explicit_finalize.fix)


@rule("java-obsolete-api", ("java",), "LOW",
      "a deprecated or unsafe legacy API is used",
      "replace it with the documented modern equivalent; these are "
      "deprecated because they are wrong, not because they are old.")
def r_java_obsolete_api(ctx):
    """CWE-477."""
    yield from _java_simple(
        ctx, "java-obsolete-api", JAVA_OBSOLETE, "LOW",
        "this API is deprecated and unsafe in the way it is used here.",
        r_java_obsolete_api.fix)


@rule("java-insecure-cookie", ("java",), "MEDIUM",
      "a cookie is set without the Secure flag",
      "call `cookie.setSecure(true)` so it is never sent over plain HTTP.")
def r_java_insecure_cookie(ctx):
    """CWE-614. The flag is set on a later line, so the file is the scope."""
    whole = "\n".join(ctx.code)
    if JAVA_COOKIE_SECURED.search(whole):
        return
    yield from _java_simple(
        ctx, "java-insecure-cookie", JAVA_COOKIE_INSECURE, "MEDIUM",
        "this cookie has no Secure flag, so it travels over plain HTTP.",
        r_java_insecure_cookie.fix)


# No rule for CWE-379/378 (insecure temporary files). One was written and
# then deleted: both halves of every Juliet case call `File.createTempFile`
# in the same place, so a rule keyed on that construct fired on the corrected
# variant too -- 100% of pairs, which is the one result that is worse than no
# rule at all. What actually separates them is the permissions the file ends
# up with, which is not visible in the line that creates it. Left uncovered
# rather than reported dishonestly.


# ---- JavaScript / TypeScript ---------------------------------------------- #
LOOSE_EQ = re.compile(r"(?<![=!<>])==(?!=)|(?<![!<>=])!=(?!=)")


@rule("js-loose-equality", ("js",), "MEDIUM",
      "== / != do type coercion in JS (0 == '' , null == undefined ...)",
      "use strict equality === / !== unless you specifically want coercion.")
def r_js_eq(ctx):
    for idx, line in enumerate(ctx.code):
        if LOOSE_EQ.search(line):
            yield _f(ctx, idx, "js-loose-equality", "MEDIUM",
                     "loose == coerces types before comparing, so 0 == '', '' == false and "
                     "many other surprises are true. Prefer ===.", r_js_eq.fix)


@rule("js-innerhtml", ("js",), "MEDIUM",
      "assigning to innerHTML / document.write with dynamic data is an XSS sink",
      "use textContent, or sanitize before setting innerHTML.")
def r_js_html(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\.innerHTML\s*=", line) or re.search(r"\bdocument\.write\s*\(", line):
            yield _f(ctx, idx, "js-innerhtml", "MEDIUM",
                     "writing unsanitized data into innerHTML/document.write injects it as live "
                     "HTML -- the classic cross-site-scripting hole.", r_js_html.fix)


JS_CLIENT_SECRET_STORAGE = re.compile(
    r"\b(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"]"
    r"(?:token|jwt|auth|api[_-]?key|secret|password)", re.I)


@rule("js-client-secret-storage", ("js",), "MEDIUM",
      "browser local/session storage is a poor place for tokens and secrets",
      "prefer httpOnly secure cookies or short-lived in-memory tokens; never store API keys client-side.")
def r_js_client_secret_storage(ctx):
    for idx, line in enumerate(ctx.literal):
        if JS_CLIENT_SECRET_STORAGE.search(line) and re.search(
                r"\b(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(",
                ctx.code[idx]):
            yield _f(ctx, idx, "js-client-secret-storage", "MEDIUM",
                     "tokens or secrets in localStorage/sessionStorage are exposed to any XSS "
                     "that lands on the page and persist longer than intended.",
                     r_js_client_secret_storage.fix)

@rule("js-var", ("js",), "LOW",
      "'var' is function-scoped and hoisted; prefer let/const",
      "use const by default, let when you reassign; avoid var.",
      deep=True)
def r_js_var(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"(^|[^.\w])var\s+[A-Za-z_$]", line):
            yield _f(ctx, idx, "js-var", "LOW",
                     "var hoists to the top of the function and ignores block scope, which "
                     "causes subtle closure/loop bugs. Use let/const.", r_js_var.fix)


# ---- more Python ---------------------------------------------------------- #
REQUESTS_CALL = re.compile(r"\brequests\.(get|post|put|delete|head|patch|options|request)\s*\(")


@rule("py-requests-no-timeout", ("python",), "MEDIUM",
      "an HTTP request with no timeout can hang the process forever",
      "always pass timeout=; a stalled peer otherwise blocks the thread indefinitely.")
def r_req_timeout(ctx):
    for idx, line in enumerate(ctx.code):
        m = REQUESTS_CALL.search(line)
        if m and "timeout" not in _logical_call(ctx.code, idx, m.end() - 1):
            yield _f(ctx, idx, "py-requests-no-timeout", "MEDIUM",
                     "requests without a timeout will wait forever if the server never "
                     "responds -- a classic silent production hang.", r_req_timeout.fix)


@rule("py-tempfile-insecure", ("python",), "MEDIUM",
      "tempfile.mktemp()/os.tmpnam() are race-prone (the file can be hijacked)",
      "use tempfile.mkstemp() or NamedTemporaryFile, which create the file atomically.")
def r_tempfile(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\btempfile\.mktemp\s*\(|\bos\.tmpnam\s*\(", line):
            yield _f(ctx, idx, "py-tempfile-insecure", "MEDIUM",
                     "mktemp only returns a name; between that and opening it, an attacker can "
                     "create the path -- a TOCTOU symlink race.", r_tempfile.fix)


@rule("py-bind-all-interfaces", ("python",), "LOW",
      "binding to 0.0.0.0 exposes the service on every network interface",
      "bind to 127.0.0.1 for local-only, or make the host explicit and intentional.",
      deep=True)
def r_bindall(ctx):
    for idx, line in enumerate(ctx.literal):
        if re.search(r"host\s*=\s*['\"]0\.0\.0\.0['\"]", line) and \
                re.search(r"\bhost\s*=", ctx.code[idx]):
            yield _f(ctx, idx, "py-bind-all-interfaces", "LOW",
                     "0.0.0.0 listens on all interfaces, including public ones; make sure that "
                     "is intended.", r_bindall.fix)


# ---- more C / C++ (a touch of dataflow) ----------------------------------- #
DECL_ARR = re.compile(r"^\s*[A-Za-z_][\w ]*\s+([A-Za-z_]\w*)\s*\[[^\]]*\]\s*[;=]")
DECL_SCALAR = re.compile(
    r"^\s*(?!(?:return|if|while|for|switch|else|do|goto|case|sizeof|typedef|break|"
    r"continue|static|const)\b)[A-Za-z_][\w ]*\s+([A-Za-z_]\w*)\s*[;=]")
RET_ADDR = re.compile(r"\breturn\s*&\s*([A-Za-z_]\w*)\s*;")
RET_NAME = re.compile(r"\breturn\s+([A-Za-z_]\w*)\s*;")


def _c_function_bodies(code):
    joined = "\n".join(code)
    for m in FUNC_HEAD.finditer(joined):
        start = joined.count("\n", 0, m.start())
        yield list(_block_lines(code, start))


@rule("c-return-local-address", ("c", "cpp"), "HIGH",
      "returning the address of a local (or a local array) yields a dangling pointer",
      "return heap memory, a caller-provided buffer, or a value -- never &local.")
def r_return_local(ctx):
    for body in _c_function_bodies(ctx.code):
        scalars, arrays = set(), set()
        for _, line in body:
            am = DECL_ARR.match(line)
            if am and "static" not in line:
                arrays.add(am.group(1))
                continue
            sm = DECL_SCALAR.match(line)
            if sm:
                scalars.add(sm.group(1))
        for idx, line in body:
            m = RET_ADDR.search(line)
            if m and (m.group(1) in scalars or m.group(1) in arrays):
                yield _f(ctx, idx, "c-return-local-address", "HIGH",
                         f"'&{m.group(1)}' points at a local whose lifetime ends when the "
                         f"function returns; the caller dereferences freed stack.",
                         r_return_local.fix)
                continue
            m2 = RET_NAME.search(line)
            if m2 and m2.group(1) in arrays:
                yield _f(ctx, idx, "c-return-local-address", "HIGH",
                         f"local array '{m2.group(1)}' decays to a pointer into this frame's "
                         f"stack; it dangles the moment the function returns.",
                         r_return_local.fix)


@rule("c-strncpy-truncation", ("c", "cpp"), "MEDIUM",
      "strncpy does not NUL-terminate when the source fills the buffer",
      "terminate explicitly (dst[n-1] = '\\0'), or use snprintf/strlcpy.")
def r_strncpy(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bstrncpy\s*\(", line):
            yield _f(ctx, idx, "c-strncpy-truncation", "MEDIUM",
                     "if the source is at least as long as the count, strncpy leaves the "
                     "destination without a terminating NUL -- later reads run off the end.",
                     r_strncpy.fix)


# ---- more JavaScript ------------------------------------------------------ #
@rule("js-settimeout-string", ("js",), "MEDIUM",
      "setTimeout/setInterval with a string argument is a hidden eval",
      "pass a function reference, not a string of code.")
def r_settimeout(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bset(Timeout|Interval)\s*\(\s*['\"]", line):
            yield _f(ctx, idx, "js-settimeout-string", "MEDIUM",
                     "a string first argument is compiled and run like eval, with the same "
                     "injection risk.", r_settimeout.fix)


@rule("js-async-foreach", ("js",), "MEDIUM",
      "Array.forEach ignores async callback promises; await does not wait for the loop body",
      "use for...of with await, or Promise.all(array.map(async ...)).")
def r_js_async_foreach(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\.forEach\s*\(\s*async\b", line):
            yield _f(ctx, idx, "js-async-foreach", "MEDIUM",
                     "forEach does not await or collect promises from an async callback, so errors and ordering escape the caller.",
                     r_js_async_foreach.fix)


@rule("js-nan-compare", ("js",), "MEDIUM",
      "NaN is never equal to itself; comparisons with NaN are always false",
      "use Number.isNaN(value) or value !== value for the deliberate NaN idiom.")
def r_js_nan_compare(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"(?:==={0,1}|!==?)\s*NaN\b|\bNaN\s*(?:==={0,1}|!==?)", line):
            yield _f(ctx, idx, "js-nan-compare", "MEDIUM",
                     "x == NaN / x === NaN can never be true, even when x is NaN.",
                     r_js_nan_compare.fix)


@rule("js-date-getyear", ("js",), "MEDIUM",
      "Date.getYear() returns year minus 1900, not the full year",
      "use getFullYear() instead.")
def r_js_date_getyear(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\.getYear\s*\(\s*\)", line):
            yield _f(ctx, idx, "js-date-getyear", "MEDIUM",
                     "getYear() returns 124 for 2024; almost everyone meant getFullYear().",
                     r_js_date_getyear.fix)


PROTO_POLLUTION = re.compile(r"(?:\.__proto__\s*=|\[['\"]__proto__['\"]\]\s*=|constructor\.prototype)")


@rule("js-prototype-pollution", ("js",), "HIGH",
      "writing __proto__/constructor.prototype can poison every object that inherits from it",
      "treat these keys as forbidden user input; use Object.create(null) or a Map for dictionaries.")
def r_js_proto_pollution(ctx):
    for idx, line in enumerate(ctx.literal):
        structural = re.search(r"\.__proto__\s*=|constructor\.prototype", ctx.code[idx]) \
            or re.search(r"\[[^\]]*\]\s*=", ctx.code[idx])
        if PROTO_POLLUTION.search(line) and structural:
            yield _f(ctx, idx, "js-prototype-pollution", "HIGH",
                     "prototype mutation can turn one crafted key into process-wide object corruption.",
                     r_js_proto_pollution.fix)


# ---- Universal (deep) ----------------------------------------------------- #
# The exclusions are not leniency. A loopback address never leaves the machine,
# an XML namespace URI is an identifier rather than an endpoint, and the RFC 2606
# reserved names exist precisely so documentation can show a URL that resolves
# nowhere. Reporting "traffic is unencrypted" about any of those is a false
# positive: there is no traffic.
#
# `www.` is now matched optionally because the original lookahead anchored only
# the bare form -- `http://example.org` was correctly skipped while
# `http://www.example.org` was reported, the same placeholder wearing a
# subdomain. On NIST Juliet Java that single gap produced 22 of this rule's 23
# reports, all of them on the corpus's own documentation host.
# Scope is deliberately limited to the measured defect. `.test` and `.localhost`
# are also RFC 2606 reserved, but they are what local development environments
# actually use, four existing tests treat `http://a.test` as a reportable
# plaintext URL, and there is no evidence they cause false positives -- so they
# keep firing. Widening an exclusion because it would look tidy, against a
# contract already covered by tests, is how a scanner quietly loses detections.
HTTP_URL = re.compile(
    r"http://(?!(?:www\.)?(?:"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]"   # loopback: never on the wire
    r"|schemas[.\w]|w3\.org|xmlns"                 # namespace URIs, not endpoints
    r"|example\.(?:com|org|net)\b|example\b"       # RFC 2606 documentation names
    r"))")


@rule("insecure-http-url", ("*",), "LOW",
      "a hardcoded http:// endpoint sends traffic unencrypted",
      "use https://; plaintext HTTP is open to interception and tampering.",
      deep=True)
def r_httpurl(ctx):
    for idx, line in enumerate(ctx.literal):
        if HTTP_URL.search(line):
            yield _f(ctx, idx, "insecure-http-url", "LOW",
                     "traffic to an http:// URL is unencrypted and trivially readable or "
                     "modifiable in transit.", r_httpurl.fix)


@rule("todo-fixme", ("*",), "LOW",
      "a TODO/FIXME/HACK/XXX marker -- unfinished or known-broken code",
      "track it in an issue and resolve it; markers rot silently in the codebase.",
      deep=True)
def r_todo(ctx):
    for idx, line in enumerate(ctx.raw):
        m = re.search(r"\b(TODO|FIXME|HACK|XXX)\b", line)
        if m:
            yield _f(ctx, idx, "todo-fixme", "LOW",
                     f"a {m.group(1)} marker flags unfinished or known-broken code here.",
                     r_todo.fix)


# ---- Go, Rust, C# --------------------------------------------------------- #
#
# These three already had coverage before this pack: `multilang.py` carries
# three rules each and `advanced_rules.py` carries the `adv-*` family. What
# they did not have was any presence in `detect.RULES`, which is the only
# registry `language_coverage42` counts -- so the coverage report showed six
# languages while the scanner actually inspected nine.
#
# This pack therefore adds only what those registries do not already detect,
# and deliberately does not restate a defect they cover. Duplicated rule
# identifiers were the specific hazard: `rust-unsafe-block` and
# `rust-transmute` exist verbatim in `multilang.py`, so defining them here as
# well emitted one identifier from two registries with two different messages.
#
# All three are C-family for masking purposes, so `blank()` already blanks
# their comments and string *contents* while preserving structure and quote
# positions. That decides how the rules below are written:
#
#   * an API name, a field name or an operator survives masking, so structural
#     matching runs on `ctx.code` and cannot be fooled by a mention inside a
#     comment or a string;
#   * the text *inside* a literal does not survive, so the few rules that need
#     to see a word like "password" read `ctx.literal`, which keeps literals
#     and blanks comments -- a TODO about passwords is not evidence.
#
# Every rule here is a syntactic candidate, not a proof. They are deliberately
# anchored on APIs whose insecure use is unambiguous (disabled certificate
# verification, a broken hash, a shell interpreter) rather than on
# interprocedural reachability, which this layer does not have.

SECRET_CONTEXT = re.compile(
    r"(?i)\b(?:token|secret|password|passwd|api ?key|apikey|nonce|salt|session|"
    r"credential|private ?key)\b")
CONCAT_OR_FORMAT = re.compile(r"\+|fmt\.Sprintf|format!|\$\"|String::from|\.format\(")


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_WORD = re.compile(r"[^A-Za-z0-9]+")


def _split_identifiers(text: str) -> str:
    """`sessionToken`/`password_salt` -> `session Token`/`password salt`.

    Both transforms are needed and neither is sufficient. Splitting only at
    camelCase leaves `password_salt` unmatched because `_` is a word
    character, so `\\bpassword\\b` does not end before it; replacing only
    punctuation leaves `sessionToken` as one word.
    """
    return _NON_WORD.sub(" ", _CAMEL_BOUNDARY.sub(" ", text))


def _has_secret_context(ctx, idx: int, radius: int = 3) -> bool:
    """Does a security-sensitive word appear within a few lines of `idx`?

    Read from `ctx.literal` so a string constant counts and a comment does
    not. The radius exists because the sensitive name is usually on the
    assignment line next to the generator call, not on it.

    Identifiers are split at camelCase boundaries first. Without that,
    `\\btoken\\b` does not match `sessionToken` and `\\bpassword\\b` does not
    match `passwordSalt` -- which is how these names are actually spelled in
    Go and C#, so the rule would have been silent on its own motivating case.
    Splitting rather than dropping the word boundary keeps `salt` from
    matching `asphalt`.
    """
    lines = ctx.literal or ctx.raw
    lo, hi = max(0, idx - radius), min(len(lines), idx + radius + 1)
    return any(SECRET_CONTEXT.search(_split_identifiers(lines[index]))
               for index in range(lo, hi))


# ---- Go -------------------------------------------------------------------- #

@rule("go-command-injection", ("go",), "HIGH",
      "an argument to exec.Command is composed rather than passed as a value",
      "pass a fixed program and separate argument strings; never build one from data.")
def r_go_command_injection(ctx):
    """Only the composed-argument case.

    `multilang.go-command-shell` already reports `exec.Command("sh", ...)`, so
    restating the shell-literal case here would emit two findings for one line.
    Concatenation into a non-shell command is the case neither registry had.
    """
    for idx, line in enumerate(ctx.code):
        if (re.search(r"\bexec\.Command(?:Context)?\s*\(", line)
                and CONCAT_OR_FORMAT.search(line)):
            yield _f(ctx, idx, "go-command-injection", "HIGH",
                     "an argument to exec.Command is built by concatenation or Sprintf, so "
                     "anything flowing into it becomes part of the command.",
                     r_go_command_injection.fix)


@rule("go-http-no-timeout", ("go",), "MEDIUM",
      "an http.Client is constructed without a Timeout",
      "set an explicit Timeout; the zero value means the request can hang forever.")
def r_go_http_no_timeout(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bhttp\.Client\s*\{", line) and "Timeout" not in line:
            # A multi-line literal keeps its fields on following lines, so look
            # ahead to the closing brace before reporting a client that may in
            # fact set the field two lines down.
            window = "\n".join(ctx.code[idx:idx + 6])
            if "Timeout" not in window.split("}")[0]:
                yield _f(ctx, idx, "go-http-no-timeout", "MEDIUM",
                         "http.Client's zero Timeout means no timeout at all, so one slow "
                         "or hostile peer can hold this goroutine indefinitely.",
                         r_go_http_no_timeout.fix)


# ---- Rust ------------------------------------------------------------------ #

@rule("rust-command-injection", ("rust",), "HIGH",
      "a command argument is built with format!",
      "pass a fixed program and separate .arg() values; never compose one from data.")
def r_rust_command_injection(ctx):
    """`multilang.rust-command-shell` covers `Command::new("sh")`; this covers
    a formatted argument to any program, shell or not."""
    for idx, line in enumerate(ctx.code):
        if (re.search(r"\bCommand::new\s*\(|\.arg\s*\(", line)
                and re.search(r"\bformat!\s*\(", line)):
            yield _f(ctx, idx, "rust-command-injection", "HIGH",
                     "a command argument is built with format!, so a value reaching it "
                     "becomes part of the command line.", r_rust_command_injection.fix)


@rule("rust-unwrap-panic", ("rust",), "LOW",
      "unwrap()/expect() turns a recoverable error into a panic",
      "propagate with ? or handle the None/Err case explicitly.",
      deep=True)
def r_rust_unwrap(ctx):
    for idx, line in enumerate(ctx.code):
        m = re.search(r"\.(unwrap|expect)\s*\(", line)
        if m:
            yield _f(ctx, idx, "rust-unwrap-panic", "LOW",
                     f"{m.group(1)}() aborts the thread on the error path; in a server that "
                     f"is a denial of service reachable from whatever produced the value.",
                     r_rust_unwrap.fix)


# ---- C# -------------------------------------------------------------------- #

@rule("cs-sql-injection", ("csharp",), "HIGH",
      "a SQL statement is assembled by concatenation or interpolation",
      "use SqlParameter and a parameterised CommandText; never interpolate into SQL.")
def r_cs_sql_injection(ctx):
    for idx, line in enumerate(ctx.code):
        if (re.search(r"\bnew\s+Sql(?:Command|DataAdapter)\s*\(|\bCommandText\s*=", line)
                and re.search(r"\+|\$\"", line)):
            yield _f(ctx, idx, "cs-sql-injection", "HIGH",
                     "this command text is built from parts rather than parameterised, so a "
                     "value reaching it can change the statement.", r_cs_sql_injection.fix)


@rule("cs-command-injection", ("csharp",), "HIGH",
      "a process is started with a composed command line",
      "pass ProcessStartInfo.ArgumentList entries; never build one argument string.")
def r_cs_command_injection(ctx):
    for idx, line in enumerate(ctx.code):
        if (re.search(r"\bProcess\.Start\s*\(|\bArguments\s*=", line)
                and re.search(r"\+|\$\"", line)):
            yield _f(ctx, idx, "cs-command-injection", "HIGH",
                     "the argument string is composed, so anything flowing into it is "
                     "re-parsed by the command processor.", r_cs_command_injection.fix)


@rule("cs-weak-hash", ("csharp",), "MEDIUM",
      "MD5 or SHA-1 used where a collision-resistant hash is expected",
      "use SHA256.Create(), or Rfc2898DeriveBytes/argon2 for passwords.")
def r_cs_weak_hash(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\b(?:MD5|SHA1)\.Create\s*\(|\bnew\s+(?:MD5|SHA1)"
                     r"(?:CryptoServiceProvider|Managed)\s*\(", line):
            yield _f(ctx, idx, "cs-weak-hash", "MEDIUM",
                     "MD5/SHA-1 are collision-broken and cannot back an integrity or "
                     "uniqueness claim.", r_cs_weak_hash.fix)


@rule("cs-cert-validation-disabled", ("csharp",), "HIGH",
      "the certificate validation callback accepts every certificate",
      "remove the override; a callback that returns true defeats TLS authentication.")
def r_cs_cert_validation(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\b(?:ServerCertificateValidationCallback|"
                     r"ServerCertificateCustomValidationCallback)\b", line):
            window = " ".join(ctx.code[idx:idx + 4])
            if re.search(r"=>\s*true\b|return\s+true\s*;", window):
                yield _f(ctx, idx, "cs-cert-validation-disabled", "HIGH",
                         "this validation callback returns true unconditionally, so any "
                         "certificate is accepted, including an attacker's.",
                         r_cs_cert_validation.fix)


@rule("cs-xxe", ("csharp",), "HIGH",
      "XML parsing resolves external entities",
      "leave DtdProcessing at Prohibit and XmlResolver null.")
def r_cs_xxe(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bDtdProcessing\s*=\s*DtdProcessing\.(?:Parse|Ignore)\b", line) or \
                re.search(r"\bProhibitDtd\s*=\s*false\b", line):
            yield _f(ctx, idx, "cs-xxe", "HIGH",
                     "enabling DTD processing lets a document pull in external entities, "
                     "which reads local files and reaches internal hosts.", r_cs_xxe.fix)


@rule("cs-weak-random", ("csharp",), "MEDIUM",
      "System.Random used for a value that looks security-sensitive",
      "use RandomNumberGenerator.GetBytes for tokens, keys, nonces and salts.")
def r_cs_weak_random(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bnew\s+Random\s*\(", line) and _has_secret_context(ctx, idx):
            yield _f(ctx, idx, "cs-weak-random", "MEDIUM",
                     "System.Random is a deterministic PRNG seeded from the clock; a secret "
                     "derived from it is predictable.", r_cs_weak_random.fix)


# ---- End-stage attacker artifacts (last-offense) -------------------------- #
#
# Everything above answers "could an attacker get in here?". This pack answers
# a different question -- "is an attacker already inside?" -- and it is the one
# that matters when every perimeter control has already been passed. The
# targets are the code of an intrusion's endgame: an implant that runs a
# payload, a persistence mechanism, a channel out, a destructive command, or a
# step that erases the trail.
#
# Two design choices separate this pack from the vulnerability rules:
#
#   * It matches `ctx.raw`, not the masked code. A dropped payload lives inside
#     a string literal -- a base64 blob, a one-line reverse shell -- and
#     masking that away would blind the check to exactly the bytes that are the
#     attack. A comment describing an implant is a rarer and far less dangerous
#     miss than an implant sitting in a quoted string.
#
#   * Every pattern is *compound*. `os.system` alone is ordinary; `curl ... |
#     sh` in one line is not. Anchoring on the combination -- download and
#     execute, decode and execute, socket and /bin/sh -- is what keeps the pack
#     from firing on every codebase that merely runs a subprocess.
#
# Each rule carries a MITRE ATT&CK technique in RULE_ATTACK, so a SOC reading
# the output sees the tactic (Persistence, Exfiltration, Impact, Defense
# Evasion) it already tracks rather than a private taxonomy. A hit here is
# high-signal but still a candidate, not a conviction: the responder confirms.

RULE_ATTACK = {
    "implant-download-exec": "T1105",       # Ingress Tool Transfer
    "implant-decode-exec": "T1140",         # Deobfuscate/Decode Files or Information
    "implant-reverse-shell": "T1059",       # Command and Scripting Interpreter
    "implant-webshell": "T1505.003",        # Server Software Component: Web Shell
    "persistence-cron": "T1053.003",        # Scheduled Task/Job: Cron
    "persistence-authorized-keys": "T1098.004",  # SSH Authorized Keys
    "persistence-systemd": "T1543.002",     # Systemd Service
    "antiforensics-history": "T1070.003",   # Clear Command History
    "antiforensics-log-clear": "T1070",     # Indicator Removal
    "antiforensics-immutable": "T1222",     # File and Directory Permissions Modification
    "destructive-wipe": "T1485",            # Data Destruction
    "destructive-forkbomb": "T1499",        # Endpoint Denial of Service
    # Assembly-level implant primitives. These are techniques, not weakness
    # classes -- a NOP sled is not a "bug" in any CWE sense, it is a
    # construction that only exists to make an imprecise jump land.
    "asm-nop-sled": "T1027",               # Obfuscated Files or Information
    "asm-stack-pivot": "T1055",            # Process Injection
    "asm-direct-execve": "T1059",          # Command and Scripting Interpreter
}


def attack_technique(rule_id: str) -> str:
    """The MITRE ATT&CK technique a rule maps to, or "" if it is not end-stage."""
    return RULE_ATTACK.get(rule_id, "")


# curl/wget fetching a URL whose output is piped straight into a shell. The
# hallmark of a stager: no file touches disk to be scanned later.
_DOWNLOAD_EXEC = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\bhttps?://[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b")


@rule("implant-download-exec", ("*",), "HIGH",
      "a remote payload is downloaded and piped directly into a shell",
      "never pipe a network fetch into a shell; fetch, verify a known hash, then run.",
      deep=False)
def r_implant_download_exec(ctx):
    for idx, line in enumerate(ctx.raw):
        if _DOWNLOAD_EXEC.search(line):
            yield _f(ctx, idx, "implant-download-exec", "HIGH",
                     "this fetches a remote payload and executes it in one step, so whatever "
                     "the URL serves at run time runs here -- the classic stager pattern.",
                     r_implant_download_exec.fix)


# base64 (or hex) decoded and handed straight to an interpreter. Legitimate
# code decodes base64 constantly; decoding it *into exec/eval/a shell* is the
# obfuscated-payload signature.
_DECODE_EXEC = re.compile(
    r"(?:exec|eval)\s*\(\s*(?:compile\s*\()?\s*(?:base64|codecs|binascii|bytes\.fromhex|"
    r"__import__\s*\(\s*['\"]base64)"
    r"|base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:ba|z)?sh\b"
    r"|[A-Za-z0-9+/]{60,}={0,2}\s*['\"]?\s*\)?\s*\.decode\s*\([^)]*\)\s*\)?\s*\)")


@rule("implant-decode-exec", ("*",), "HIGH",
      "an encoded blob is decoded and executed",
      "remove the encode-then-execute step; run only code that can be read and reviewed.",
      deep=False)
def r_implant_decode_exec(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"(?:exec|eval)\s*\(", line) and re.search(
                r"base64|b64decode|fromhex|binascii|codecs\.decode", line):
            yield _f(ctx, idx, "implant-decode-exec", "HIGH",
                     "code is decoded from an encoded blob and executed, which hides the "
                     "payload from review -- the standard obfuscated-implant shape.",
                     r_implant_decode_exec.fix)
        elif re.search(r"base64\s+(?:-d|--decode)\b.*\|\s*(?:ba|z)?sh\b", line):
            yield _f(ctx, idx, "implant-decode-exec", "HIGH",
                     "a base64 blob is decoded and piped into a shell; the executed command "
                     "is deliberately unreadable in source.", r_implant_decode_exec.fix)


# Interactive shell wired to a socket: the several idioms that all mean "give
# the far end a prompt on this host".
_REVERSE_SHELL = re.compile(
    r"/dev/tcp/\d|/dev/udp/\d"                       # bash pseudo-device
    r"|\bnc\b[^\n]*\s-[a-z]*e[a-z]*\s"               # nc -e /bin/sh
    r"|bash\s+-i\s*>&\s*/dev/(?:tcp|udp)"            # bash -i >& /dev/tcp/...
    r"|\bsh\s+-i\b[^\n]*<&\d[^\n]*>&\d"              # sh -i <&3 >&3
    r"|socket\.SOCK_STREAM[^\n]*"                    # python reverse shell (paired below)
)


@rule("implant-reverse-shell", ("*",), "HIGH",
      "an interactive shell is connected to a network socket",
      "there is no benign reason for this in application code; treat the host as compromised.",
      deep=False)
def r_implant_reverse_shell(ctx):
    joined_window = 6
    for idx, line in enumerate(ctx.raw):
        if re.search(r"/dev/tcp/\d|/dev/udp/\d", line) or \
                re.search(r"\bnc\b[^\n]*\s-[a-z]*e[a-z]*\s.*(?:/bin/|sh\b)", line) or \
                re.search(r"bash\s+-i\s*>&\s*/dev/(?:tcp|udp)", line):
            yield _f(ctx, idx, "implant-reverse-shell", "HIGH",
                     "this wires an interactive shell to a network endpoint -- a reverse "
                     "shell. Application code does not do this.", r_implant_reverse_shell.fix)
            continue
        # Python idiom spans lines: a socket plus dup2 onto the shell's fds.
        if "dup2" in line and "socket" in "\n".join(
                ctx.raw[max(0, idx - joined_window):idx + joined_window]):
            if re.search(r"dup2\s*\([^)]*\.fileno\(\)\s*,\s*[012]\s*\)", line):
                yield _f(ctx, idx, "implant-reverse-shell", "HIGH",
                         "a socket's file descriptor is duplicated onto stdio next to a "
                         "shell spawn -- a Python reverse shell.", r_implant_reverse_shell.fix)


# A request parameter handed straight to an interpreter in a web handler: the
# one-line web shell. Kept distinct from command injection because the intent
# is different -- this is a planted backdoor, not an accidental sink.
_WEBSHELL = re.compile(
    r"(?:eval|exec|assert|passthru|popen|system|shell_exec)\s*\(\s*"
    r"\$?_?(?:GET|POST|REQUEST|COOKIE|request\.(?:args|form|values|GET|POST))\b")


@rule("implant-webshell", ("*",), "HIGH",
      "a request parameter is passed directly to a code or command interpreter",
      "delete this handler; a parameter reaching eval/system unfiltered is a web shell.",
      deep=False)
def r_implant_webshell(ctx):
    for idx, line in enumerate(ctx.raw):
        if _WEBSHELL.search(line):
            yield _f(ctx, idx, "implant-webshell", "HIGH",
                     "an incoming request field is executed as code or a command with no "
                     "validation, which is the definition of a web shell.",
                     r_implant_webshell.fix)


# Persistence: a foothold that survives a reboot or a logout.
@rule("persistence-cron", ("*",), "HIGH",
      "a scheduled job is installed pointing at a shell or a downloaded payload",
      "confirm this cron/at entry is expected; attacker cron jobs re-establish access on a timer.",
      deep=False)
def r_persistence_cron(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"(?:/etc/cron|/var/spool/cron|crontab\s+-|@reboot\b)", line) and \
                re.search(r"(?:curl|wget|/bin/|\bsh\b|bash|python|/tmp/|nc\b)", line):
            yield _f(ctx, idx, "persistence-cron", "HIGH",
                     "a scheduled job is being written that runs a shell or fetches a "
                     "payload; that is how an implant survives a reboot.",
                     r_persistence_cron.fix)


@rule("persistence-authorized-keys", ("*",), "HIGH",
      "an SSH key is appended to an authorized_keys file",
      "verify this key rotation is intended; writing authorized_keys grants standing remote login.",
      deep=False)
def r_persistence_authorized_keys(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"authorized_keys\b", line) and re.search(
                r">>|\.write|echo\b|tee\b|cat\b|append", line):
            yield _f(ctx, idx, "persistence-authorized-keys", "HIGH",
                     "an SSH public key is being added to authorized_keys, which grants "
                     "whoever holds the private key a permanent way back in.",
                     r_persistence_authorized_keys.fix)


@rule("persistence-systemd", ("*",), "HIGH",
      "a systemd service is written and enabled at runtime",
      "install services through configuration management, not from application or script code.",
      deep=False)
def r_persistence_systemd(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"/etc/systemd/system/|/lib/systemd/system/", line) and \
                re.search(r"\.service\b|systemctl\s+enable|\.write|>>|tee\b", line):
            yield _f(ctx, idx, "persistence-systemd", "HIGH",
                     "a systemd unit is being written and enabled from code, a common way "
                     "to run an implant as a managed service on every boot.",
                     r_persistence_systemd.fix)


# Anti-forensics: erasing the evidence of the intrusion.
@rule("antiforensics-history", ("*",), "HIGH",
      "shell history is disabled or cleared",
      "there is no operational reason for application code to erase shell history.",
      deep=False)
def r_antiforensics_history(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null"
                     r"|HISTSIZE=0\b|rm\b[^\n]*\.bash_history|set\s+\+o\s+history", line):
            yield _f(ctx, idx, "antiforensics-history", "HIGH",
                     "this disables or wipes shell history, which is done to remove the "
                     "record of what an intruder ran.", r_antiforensics_history.fix)


@rule("antiforensics-log-clear", ("*",), "HIGH",
      "system logs are truncated, deleted, or vacuumed",
      "investigate before running; clearing logs during an incident destroys evidence.",
      deep=False)
def r_antiforensics_log_clear(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"(?:rm|truncate|shred)\b[^\n]*\s/var/log\b"  # flags may sit between
                     r"|:>\s*/var/log|>\s*/var/log/\w"
                     r"|journalctl\b[^\n]*--vacuum"
                     r"|wevtutil\s+cl\b"
                     r"|Clear-EventLog\b", line):
            yield _f(ctx, idx, "antiforensics-log-clear", "HIGH",
                     "this removes or empties system logs, a defense-evasion step that "
                     "erases the trail of an intrusion.", r_antiforensics_log_clear.fix)


@rule("antiforensics-immutable", ("*",), "MEDIUM",
      "a file is made immutable with chattr +i",
      "confirm intent; attackers set +i to stop responders deleting a dropped payload.",
      deep=False)
def r_antiforensics_immutable(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r"\bchattr\s+[+]i\b", line):
            yield _f(ctx, idx, "antiforensics-immutable", "MEDIUM",
                     "chattr +i locks a file so even root cannot delete it without first "
                     "clearing the flag -- used to protect a dropped implant.",
                     r_antiforensics_immutable.fix)


# Impact: destroying data or availability.
# Deliberately narrow. `rm -rf "$tmpdir"` is ordinary cleanup and must not
# fire; the signal is destruction aimed at a filesystem *root* or a raw device,
# or the `--no-preserve-root` flag whose only purpose is to defeat rm's own
# guard. A variable target is not evidence -- it is what every safe temp-dir
# teardown looks like.
_WIPE = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/(?:\s|\*|$)|/\s*\*)"   # rm -rf /  or  / *
    r"|\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+/(?:\s|\*|$)"
    r"|--no-preserve-root"
    r"|\bmkfs\.\w+\s+/dev/"
    r"|\bdd\b[^\n]*\bif=/dev/(?:zero|random|urandom)[^\n]*\bof=/dev/")


@rule("destructive-wipe", ("*",), "HIGH",
      "a command recursively deletes a filesystem root or overwrites a device",
      "this destroys data irrecoverably; do not run it -- treat its presence as sabotage.",
      deep=False)
def r_destructive_wipe(ctx):
    for idx, line in enumerate(ctx.raw):
        if _WIPE.search(line):
            yield _f(ctx, idx, "destructive-wipe", "HIGH",
                     "this recursively deletes from a filesystem root or overwrites a raw "
                     "device -- data destruction, not maintenance.", r_destructive_wipe.fix)


@rule("destructive-forkbomb", ("*",), "HIGH",
      "a fork bomb is present",
      "remove it; it exhausts process tables and takes the host down.",
      deep=False)
def r_destructive_forkbomb(ctx):
    for idx, line in enumerate(ctx.raw):
        if re.search(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", line) or \
                re.search(r"while\s+True\s*:\s*os\.fork\(\)", line):
            yield _f(ctx, idx, "destructive-forkbomb", "HIGH",
                     "this is a fork bomb: it spawns processes without bound until the host "
                     "can no longer function.", r_destructive_forkbomb.fix)


# ---- Fail-open / defense-in-depth (last-defense) -------------------------- #
#
# The rules above find controls that are missing or exploitable. This pack
# finds a subtler and more dangerous thing: a control that is *present* but
# fails in the wrong direction. When an authorization check throws and the
# handler swallows the exception, or a permission variable defaults to allow
# and something forgets to flip it, the system does not error -- it grants
# access. That is the last line, the one that runs after every earlier control
# has already been passed, and a scanner that only looks for missing checks
# walks straight past it.
#
# The signal is deliberately compound. `except: pass` is ordinary; `except:
# pass` wrapped around an authorization call is a security decision made by
# accident. Each rule therefore requires both a security-sensitive operation
# and a permissive failure mode in the same neighbourhood, which is what keeps
# it off the millions of benign try/except blocks that swallow an I/O error.

_SECURITY_OP = re.compile(
    r"\b(?:authenticate|authorize|authoriz|check_permission|has_permission|"
    r"require_permission|verify_token|verify_signature|verify_jwt|verify_password|"
    r"check_password|validate_token|decode_token|check_auth|require_auth|"
    r"is_authenticated|is_authorized|permission_required|login_required|"
    r"check_csrf|verify_csrf|check_access|ensure_access|check_scope)\b",
    re.IGNORECASE)

# An except body that lets execution proceed as though the check had passed.
# `return 1` is deliberately excluded: in a CLI a 1 is a *failure* exit, so it
# is as likely to be fail-closed as fail-open. `return True` carries no such
# ambiguity, and a wrong flag on a rejection path would be the worst kind of
# false positive -- calling correct code the bug.
_PERMISSIVE_RETURN = re.compile(
    r"\breturn\s+(?:True|['\"](?:allow|allowed|ok|granted|admin|yes)['\"]"
    r"|HttpResponse\s*\(\s*(?:status\s*=\s*)?200|Response\s*\(\s*(?:status\s*=\s*)?200)")
_PERMISSIVE_ASSIGN = re.compile(
    r"\b(?:authenticated|authorized|is_admin|is_authenticated|is_authorized|"
    r"access_granted|allowed|has_access|is_valid|permitted)\s*=\s*True\b")


def _python_indent(line: str) -> int:
    stripped = line.lstrip(" \t")
    return len(line) - len(stripped)


@rule("py-auth-fail-open", ("python",), "HIGH",
      "an authorization or authentication check can fail open",
      "deny on error: an except around a security check must return/raise a denial, never proceed.",
      deep=False)
def r_py_auth_fail_open(ctx):
    """A security check inside a try whose except swallows or allows.

    The except body is read from the lines more indented than the `except`
    keyword; the try body is the window above it back to the enclosing `try`.
    Requiring a security operation in that try body is what separates a
    dangerous fail-open from an ordinary swallowed I/O error.
    """
    code = ctx.code
    for idx, line in enumerate(code):
        stripped = line.lstrip()
        if not stripped.startswith("except"):
            continue
        except_indent = _python_indent(line)
        # The try body: walk up to the matching `try:` at the same indent.
        try_has_security = False
        probe = idx - 1
        seen = 0
        while probe >= 0 and seen < 40:
            current = code[probe]
            if current.strip():
                indent = _python_indent(current)
                if indent < except_indent and current.lstrip().startswith("try"):
                    break
                if indent > except_indent and _SECURITY_OP.search(current):
                    try_has_security = True
            probe -= 1
            seen += 1
        if not try_has_security and not _SECURITY_OP.search(line):
            continue
        # The except body: the more-indented lines below.
        permissive = False
        swallowed = False
        for follow in range(idx + 1, min(idx + 12, len(code))):
            body = code[follow]
            if not body.strip():
                continue
            if _python_indent(body) <= except_indent:
                break
            if _PERMISSIVE_RETURN.search(body) or _PERMISSIVE_ASSIGN.search(body):
                permissive = True
                break
            if body.strip() in {"pass", "continue"} or re.match(r"\.\.\.\s*$", body.strip()):
                swallowed = True
        if permissive:
            yield _f(ctx, idx, "py-auth-fail-open", "HIGH",
                     "a security check runs inside this try, and the except lets execution "
                     "proceed as authorized -- when the check errors, access is granted.",
                     r_py_auth_fail_open.fix)
        elif swallowed:
            yield _f(ctx, idx, "py-auth-fail-open", "HIGH",
                     "a security check runs inside this try, and the except swallows the "
                     "failure -- an error in the check becomes a silent pass.",
                     r_py_auth_fail_open.fix)


@rule("py-verify-disabled-on-error", ("python",), "HIGH",
      "certificate or signature verification is disabled in a fallback path",
      "never retry insecurely; a security downgrade on error is an attacker-triggerable bypass.",
      deep=False)
def r_py_verify_disabled_on_error(ctx):
    """`verify=False` (or equivalent) reached only after something failed.

    An attacker who can force the first attempt to fail then gets the insecure
    retry for free, so a downgrade inside an except is worse than one at the
    top level -- it is bypass-on-demand.
    """
    code = ctx.code
    downgrade = re.compile(
        r"\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b"
        r"|\bcheck_hostname\s*=\s*False\b|\bCERT_NONE\b|\bverify_mode\s*=\s*ssl\.CERT_NONE")
    for idx, line in enumerate(code):
        if not line.lstrip().startswith("except"):
            continue
        except_indent = _python_indent(line)
        for follow in range(idx + 1, min(idx + 15, len(code))):
            body = code[follow]
            if not body.strip():
                continue
            if _python_indent(body) <= except_indent:
                break
            if downgrade.search(body):
                yield _f(ctx, follow, "py-verify-disabled-on-error", "HIGH",
                         "this disables transport or signature verification inside an error "
                         "handler, so forcing the secure path to fail hands over the insecure "
                         "one.", r_py_verify_disabled_on_error.fix)
                break


@rule("py-access-default-allow", ("python",), "MEDIUM",
      "an access decision defaults to allow",
      "default to deny: initialise the decision to False and grant only on an explicit pass.",
      deep=False)
def r_py_access_default_allow(ctx):
    """A permission variable initialised to the permissive value.

    Fail-open access control is usually born here: the decision starts as allow
    and some later branch is supposed to revoke it. A missed branch, an early
    return, or a raised exception then leaves the allow standing. Default-deny
    does not have this failure mode, which is why the default is the bug.
    """
    # An *assignment* is `x = True` -- spaces around `=`, statement to end of
    # line. A *keyword argument* is `x=True,` inside a call, which merely
    # records a decision already made (`AccessDecision(allowed=True, ...)`).
    # Requiring assignment spacing and no trailing comma tells them apart
    # directly, which is more robust than counting the enclosing parens.
    decision = re.compile(
        r"^\s*(?:is_admin|is_authorized|authorized|access_granted|allowed|"
        r"has_access|permitted|can_access|is_allowed)\s+=\s+True\s*(?:#.*)?$")
    guard = re.compile(r"^\s*(?:if|elif|else|for|while|try|except|with|case|match)\b")
    code = ctx.code
    for idx, line in enumerate(code):
        if not decision.match(line):
            continue
        # `x = True` inside a conditional is a deliberate grant on an explicit
        # pass -- the correct shape -- while `x = True` at the function's own
        # indent is an initialization a later branch must remember to revoke.
        indent = _python_indent(line)
        parent_is_conditional = False
        probe = idx - 1
        while probe >= 0:
            above = code[probe]
            if above.strip() and _python_indent(above) < indent:
                parent_is_conditional = bool(guard.match(above))
                break
            probe -= 1
        if parent_is_conditional:
            continue
        yield _f(ctx, idx, "py-access-default-allow", "MEDIUM",
                 "this access decision starts as allow, so any path that forgets to deny "
                 "-- a missed branch or a raised error -- leaves access granted. Default "
                 "to deny instead.", r_py_access_default_allow.fix)


# ---- Assembly: x86-64 and IBM High Level Assembler ------------------------ #
#
# `nativescan` already carries three assembly rules, and they are deliberately
# structural: a duplicate label, a missing `.note.GNU-stack`, an unbalanced
# prologue. This pack is the security half, and it keeps the same bar that
# module set -- a rule must be decidable from the text alone, because real
# assembly defects mostly need dataflow and a guess dressed as a finding is
# worse than silence.
#
# Two dialects that share nothing but the word "assembler":
#
# * **x86-64** is free-form. The rules below look for primitives that are rare
#   in compiler output and ordinary hand-written code, but characteristic of an
#   implant: a stack pivot, a NOP sled, a direct `execve`.
# * **HLASM** is IBM's mainframe assembler for System/360 and its
#   z/Architecture descendants. Its security-relevant instructions are about
#   *privilege* -- entering supervisor state, changing a storage key, calling
#   the supervisor directly -- which have no x86 equivalent and no coverage
#   anywhere else in this distribution.
#
# The HLASM rules exist because mainframe assembler is still load-bearing in
# banking, insurance and government systems, and is largely unserved by modern
# scanners. A rule here reports a review point, never a verdict: `MODESET
# KEY=ZERO` is legitimate in authorised system code and alarming in an
# application, and only a human knows which one they are reading.

# --- x86-64 ---------------------------------------------------------------- #

@rule("asm-legacy-int80", ("asm",), "MEDIUM",
      "int 0x80 in 64-bit code truncates its arguments to 32 bits",
      "use the `syscall` instruction on x86-64; int 0x80 silently drops the high half of every pointer.")
def r_asm_int80(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bint\s+(?:0x80|128)\b", line, re.I):
            yield _f(ctx, idx, "asm-legacy-int80", "MEDIUM",
                     "the legacy 32-bit syscall gate truncates 64-bit pointers, so a "
                     "buffer above 4 GiB is passed as a different address entirely.",
                     r_asm_int80.fix)


@rule("asm-writable-executable-section", ("asm",), "HIGH",
      "a section is declared both writable and executable",
      "split the data and code sections; W^X exists so a memory-corruption bug cannot become code execution.")
def r_asm_wx(ctx):
    # Read `literal`: the section flags live inside quotes, so the instruction
    # view has already blanked them. `ctx.code` still gates it -- the directive
    # must survive masking there, which proves this line is code, not a comment
    # that happens to mention a section.
    for idx, line in enumerate(ctx.literal):
        masked = ctx.code[idx] if idx < len(ctx.code) else ""
        if ".section" not in masked:
            continue
        match = re.search(r"\.section\b[^\n\"]*\"([a-zA-Z]+)\"", line)
        if match:
            flags = match.group(1)
            if "w" in flags and "x" in flags:
                yield _f(ctx, idx, "asm-writable-executable-section", "HIGH",
                         "this section is mapped writable and executable, so anything that "
                         "can corrupt its contents can execute them.", r_asm_wx.fix)


@rule("asm-stack-pivot", ("asm",), "HIGH",
      "the stack pointer is loaded from a general register",
      "confirm this is an intended context switch; a stack pivot is the standard way a ROP chain takes control.")
def r_asm_stack_pivot(ctx):
    pivot = re.compile(
        r"\b(?:mov|xchg)\s+(?:%?e?rsp)\s*,\s*(?!%?e?[sb]p\b)(%?[re]?[a-d]x|%?[re]?[sd]i|%?r\d+)\b",
        re.I)
    for idx, line in enumerate(ctx.code):
        if pivot.search(line):
            yield _f(ctx, idx, "asm-stack-pivot", "HIGH",
                     "loading rsp from a general-purpose register relocates the stack; "
                     "outside a scheduler or coroutine switch this is a ROP pivot.",
                     r_asm_stack_pivot.fix)


@rule("asm-nop-sled", ("asm",), "HIGH",
      "a long run of NOP instructions",
      "a sled exists to make an imprecise jump land in code; alignment padding does not need this many.")
def r_asm_nop_sled(ctx):
    run = start = 0
    for idx, line in enumerate([*ctx.code, ""]):
        if re.fullmatch(r"\s*(?:nop|0x90|\.byte\s+0x90)\s*(?:;.*)?", line, re.I):
            if not run:
                start = idx
            run += 1
            continue
        if run >= 16:
            yield _f(ctx, start, "asm-nop-sled", "HIGH",
                     "%d consecutive NOPs form a landing pad for an imprecise jump, which "
                     "is a shellcode construction rather than alignment." % run,
                     r_asm_nop_sled.fix)
        run = 0


@rule("asm-direct-execve", ("asm",), "HIGH",
      "a direct execve syscall is assembled inline",
      "confirm this is an intended exec; inline execve with a shell path is the core of a shellcode payload.")
def r_asm_execve(ctx):
    # A shellcode payload puts its path wherever it likes -- commonly *below*
    # the code, as a labelled constant -- so the shell-path check is file-wide
    # rather than a backward window. That is still narrow: an assembly file
    # containing both a raw syscall and an inline `/bin/sh` is exec shellcode,
    # because ordinary programs reach execve through libc rather than by
    # assembling the path themselves.
    shell_path = any(re.search(r"/bin/(?:sh|bash)", line) for line in ctx.literal)
    window = 8
    for idx, line in enumerate(ctx.code):
        if not re.search(r"\bsyscall\b|\bint\s+0x80\b", line, re.I):
            continue
        # 59 / 0x3b is execve on x86-64, 11 / 0xb on i386.
        near = " ".join(ctx.code[max(0, idx - window):idx + 1])
        call_number = re.search(
            r"\b(?:mov|movq)\s+(?:%?e?ax|%?rax)\s*,\s*(?:\$?59|\$?0x3b)\b", near, re.I)
        if call_number or shell_path:
            yield _f(ctx, idx, "asm-direct-execve", "HIGH",
                     "an execve syscall is issued directly, with a shell path in the file "
                     "or the execve call number set just above it.", r_asm_execve.fix)


# --- IBM High Level Assembler (System/360 and z/Architecture) --------------- #

@rule("hlasm-authorized-mode", ("hlasm",), "HIGH",
      "the program requests supervisor state or storage key zero",
      "confirm the authorisation is required and the module is APF-authorised for it; key 0 bypasses storage protection entirely.")
def r_hlasm_modeset(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"\bMODESET\b", line, re.I) and \
                re.search(r"\bKEY\s*=\s*ZERO\b|\bMODE\s*=\s*SUP\b", line, re.I):
            yield _f(ctx, idx, "hlasm-authorized-mode", "HIGH",
                     "this enters supervisor state or storage key 0, where storage "
                     "protection no longer applies to this program.",
                     r_hlasm_modeset.fix)


@rule("hlasm-storage-key-change", ("hlasm",), "HIGH",
      "the PSW or storage key is set directly",
      "key manipulation defeats storage protection between address spaces; restrict it to reviewed system code.")
def r_hlasm_key(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"^\s*\S*\s+(SPKA|SSKE|IVSK|RRBE)\b", line, re.I):
            yield _f(ctx, idx, "hlasm-storage-key-change", "HIGH",
                     "setting the PSW or storage key changes which storage this program "
                     "may reach, which is a privilege boundary.", r_hlasm_key.fix)


@rule("hlasm-supervisor-call", ("hlasm",), "MEDIUM",
      "a numeric SVC is issued instead of the documented macro",
      "use the documented macro; a raw SVC number bypasses the interface that validates its parameters.")
def r_hlasm_svc(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"^\s*\S*\s+SVC\s+\d+", line, re.I):
            yield _f(ctx, idx, "hlasm-supervisor-call", "MEDIUM",
                     "a raw supervisor call skips the macro layer that normally validates "
                     "the parameter list before entering the kernel.", r_hlasm_svc.fix)


@rule("hlasm-execute-variable-length", ("hlasm",), "MEDIUM",
      "EX supplies a move length from a register at run time",
      "bound the length register before the EX; an unchecked length overlays storage past the target field.")
def r_hlasm_execute(ctx):
    for idx, line in enumerate(ctx.code):
        if re.search(r"^\s*\S*\s+EX\s+R?\d+\s*,", line, re.I):
            yield _f(ctx, idx, "hlasm-execute-variable-length", "MEDIUM",
                     "EX patches the length byte of the target instruction from a register, "
                     "so an unvalidated value overlays storage beyond the field -- the "
                     "classic HLASM overflow.", r_hlasm_execute.fix)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
def scan_source(text: str, path: str = "<code>", lang: str = "text",
                deep: bool = False, cross_file_taint=None) -> list[Finding]:
    """Scan already-decoded source, including conservatively discovered text."""
    if not isinstance(text, str) or not isinstance(lang, str):
        raise ValueError("text and language must be strings")
    lang = _shebang_language(path, text, lang)
    raw = text.split("\n")
    code = blank(text, lang)
    literal = blank_comments(text, lang)
    if len(code) < len(raw):
        code += [""] * (len(raw) - len(code))
    if len(literal) < len(raw):
        literal += [""] * (len(raw) - len(literal))
    ctx = build_ctx(lang, raw, code, literal)
    ctx.cross_file_taint = cross_file_taint or CrossFileTaint()
    ctx._path = path
    findings: list[Finding] = []
    for fn in RULES:
        if fn.deep and not deep:
            continue
        if lang not in fn.langs and "*" not in fn.langs:
            continue
        for finding in fn(ctx):
            finding.path = path
            findings.append(finding)
    findings.sort(key=Finding.sort_key)
    return findings


def java_cross_file_taint(sources) -> frozenset:
    """Which method names anybody hands a value from outside.

    `sources` is an iterable of Java source strings -- one program's worth.
    Returns the names to seed a per-file scan with, so a source in one file
    reaches a sink in another.

    Keyed on the bare method name, which is coarse and deliberately so. Two
    unrelated classes with a `process(String)` each will share the seed, and
    a name is only honoured by a file that actually declares it. The failure
    that buys is a false positive on a same-named method; the failure it
    avoids is missing every flow that crosses a file, which is 36% of
    Juliet's CWE-89 and the single largest category Attestor could not see.
    """
    received: set[str] = set()
    returned: set[str] = set()
    bodies = [blank(text, "java") for text in sources if isinstance(text, str)]
    # Twice, so a two-hop flow resolves: file b learns its parameter is
    # tainted from file a's pass, and only then can it report that its own
    # method hands the value on. One pass finds the first hop and stops.
    for _ in range(2):
        state = CrossFileTaint(frozenset(received), frozenset(returned))
        for code in bodies:
            received |= _java_calls_passing_taint(code)
            _, handing_back, _fields = _java_call_taint(code, state)
            returned |= handing_back
    return CrossFileTaint(frozenset(received), frozenset(returned))


def scan_project(files, deep: bool = False) -> list[Finding]:
    """Scan a group of files together, following taint between them.

    `files` maps a path to its source text. Java is analysed in two passes:
    the first learns which methods are handed something from outside, the
    second scans each file with that knowledge. Every other language is
    scanned exactly as `scan_source` would -- there is no cross-file
    analysis for them, and claiming otherwise by running the same two passes
    would just be slower.
    """
    items = list(files.items() if hasattr(files, "items") else files)
    java = [text for path, text in items
            if isinstance(text, str) and path.endswith(".java")]
    seeds = java_cross_file_taint(java) if len(java) > 1 else CrossFileTaint()

    findings: list[Finding] = []
    for path, text in items:
        lang = "java" if path.endswith(".java") else (
            language_for(path) or "text")
        findings.extend(scan_source(
            text, path, lang, deep=deep,
            cross_file_taint=seeds if lang == "java" else CrossFileTaint()))
    findings.sort(key=Finding.sort_key)
    return findings


def scan_file(path: str, deep: bool = False) -> list[Finding]:
    lang = language_for(path)
    if lang is None:
        raise ScanError("unsupported input type: %s" % path)
    problem = _input_problem(path)
    if problem:
        raise ScanError("%s: %s" % (path, problem))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise ScanError("%s: cannot read: %s" % (path, exc)) from exc
    return scan_source(text, path, lang, deep)


def collect_paths(paths: list[str], errors: list[str] | None = None) -> list[str]:
    """Collect safe, supported inputs. Explicit bad inputs are always reported."""
    files: list[str] = []
    own_errors = errors if errors is not None else []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(
                    p, onerror=lambda exc: own_errors.append(
                        "%s: cannot traverse: %s" % (getattr(exc, "filename", p), exc))):
                dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
                for nm in sorted(names):
                    candidate = os.path.join(root, nm)
                    if language_for(candidate) is None:
                        continue
                    problem = _input_problem(candidate)
                    if problem is None:
                        files.append(candidate)
                    elif problem.startswith("cannot read"):
                        own_errors.append("%s: %s" % (candidate, problem))
        elif os.path.isfile(p):
            if language_for(p) is None:
                own_errors.append("%s: unsupported input type" % p)
                continue
            problem = _input_problem(p)
            if problem:
                own_errors.append("%s: %s" % (p, problem))
            else:
                files.append(p)
        else:
            own_errors.append("%s: path does not exist" % p)
    if errors is None:
        for message in own_errors:
            print("scan error: " + message, file=sys.stderr)
    return files


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
COLOR = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m", "0": "\033[0m"}


def fmt_human(findings: list[Finding], use_color: bool) -> str:
    """Worst first, grouped, saying only what varies.

    The shape this replaced gave every finding an identical five-line block --
    including a confidence/exploitability/autofix trailer repeated verbatim on
    all of them -- and ordered by path, so HIGH findings sat interleaved among
    LOW ones. Uniform emphasis is the same as none: a reader could not tell
    from the shape of the output which line was the one that mattered.

    So: severity bands in descending order, messages wrapped rather than run
    off the edge, and a trailer only where it carries information -- an
    autofix that exists, a confidence low enough to be worth doubting, or an
    exploitability that disagrees with the severity. The rest was identical on
    every line, and a line that is always the same is not worth printing.
    """
    import textwrap

    def paint(text, key):
        return f"{COLOR[key]}{text}{COLOR['0']}" if use_color else text

    lines: list[str] = []
    for severity in ("HIGH", "MEDIUM", "LOW"):
        band = sorted((f for f in findings if f.severity == severity),
                      key=lambda f: (os.path.relpath(f.path), f.line, f.rule))
        if not band:
            continue
        lines.append(paint("%s  (%d)" % (severity, len(band)), severity))
        for finding in band:
            location = "%s:%d" % (os.path.relpath(finding.path), finding.line)
            lines.append("  %-36s %s" % (location, finding.rule))
            for chunk in textwrap.wrap(finding.message, 72):
                lines.append("      " + chunk)
            if finding.snippet:
                lines.append("      > " + finding.snippet.strip()[:72])
            for chunk in textwrap.wrap("fix: " + finding.fix, 72):
                lines.append("      " + chunk)
            notes = []
            if finding.safe_to_autofix:
                notes.append("autofixable")
            if finding.confidence < 0.70:
                notes.append("confidence %d%%" % int(finding.confidence * 100))
            if finding.exploitability != finding.severity:
                notes.append("exploitability %s"
                             % finding.exploitability.lower())
            if notes:
                lines.append("      - " + ", ".join(notes))
            lines.append("")
    return "\n".join(lines)


def fmt_summary(findings: list[Finding], files_scanned: int,
                severity_floor: str) -> str:
    """The line that tells you the shape of the problem and what to do next.

    The previous ending was a bare count, which answers "how many" and none of
    the questions a reader actually has: how bad, how much of it can be dealt
    with mechanically, and what to run now.
    """
    if not findings:
        return ("nothing found in %d file%s at severity >= %s."
                % (files_scanned, "" if files_scanned == 1 else "s",
                   severity_floor))
    counts = {level: sum(1 for f in findings if f.severity == level)
              for level in ("HIGH", "MEDIUM", "LOW")}
    shape = ", ".join("%d %s" % (counts[level], level.lower())
                       for level in ("HIGH", "MEDIUM", "LOW") if counts[level])
    autofixable = sum(1 for f in findings if f.safe_to_autofix)
    lines = ["%d finding%s in %d file%s   %s"
             % (len(findings), "" if len(findings) == 1 else "s",
                files_scanned, "" if files_scanned == 1 else "s", shape)]
    if autofixable:
        lines.append("%d can be repaired automatically -- planner41.py <dir> "
                     "--rank shows the plan, --apply carries it out."
                     % autofixable)
    if severity_floor != "LOW":
        lines.append("(severity floor %s; lower it to see the rest)"
                     % severity_floor)
    return "\n".join(lines)


SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
TOOL_URI = "https://github.com/mangeshgwagle/python/tree/main/ErrorDetection/detector"


def to_sarif(findings: list[Finding]) -> dict:
    """Render findings as SARIF 2.1.0 -- ingestible by GitHub code scanning / CI."""
    used = {}
    for fn in RULES:
        used[fn.rid] = {
            "id": fn.rid,
            "name": fn.rid.replace("-", "_"),
            "shortDescription": {"text": fn.title},
            "defaultConfiguration": {"level": SARIF_LEVEL[fn.severity]},
            "properties": {"languages": list(fn.langs)},
        }
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message} Fix: {f.fix}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": os.path.relpath(f.path)},
                    "region": {"startLine": f.line, "snippet": {"text": f.snippet}},
                }
            }],
            "properties": {
                "confidence": f.confidence,
                "exploitability": f.exploitability,
                "safe_to_autofix": f.safe_to_autofix,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AttestorVonLuneberg",
                "informationUri": TOOL_URI,
                "version": "3.0.0",
                "rules": list(used.values()),
            }},
            "results": results,
        }],
    }


def list_rules() -> str:
    rows = sorted(RULES, key=lambda fn: (fn.langs, fn.rid))
    out = []
    for fn in rows:
        out.append(f"{fn.rid}  [{'/'.join(fn.langs)}]  {fn.severity}")
        out.append(f"    {fn.title}")
        out.append(f"    fix: {fn.fix}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Self-test: scan the bundled corpus and assert every planted bug is found.
# (file basename, rule id) pairs that MUST appear.
# --------------------------------------------------------------------------- #
EXPECTED = {
    # the curated "almost no-one can find" corpus
    ("01_unsigned_underflow.c", "unsigned-underflow"),
    ("02_strict_aliasing.c", "strict-aliasing"),
    ("03_signed_overflow_ub.c", "signed-overflow-check"),
    ("04_sizeof_pointer.c", "sizeof-pointer-arg"),
    ("01_map_operator_insert.cpp", "map-operator-insert"),
    ("02_object_slicing.cpp", "object-slicing"),
    ("03_rangefor_copy.cpp", "rangefor-copy"),
    ("04_vector_bool_proxy.cpp", "vector-bool-proxy"),
    ("01_int_overflow.hs", "hs-int-overflow"),
    ("02_foldl_space_leak.hs", "hs-lazy-foldl"),
    ("03_lazy_io.hs", "hs-lazy-io"),
    ("04_laziness_masks_bug.hs", "hs-lazy-error-field"),
    # the "bugs real teams actually ship" corpus
    ("payments.py", "hardcoded-secret"),
    ("payments.py", "py-mutable-default"),
    ("payments.py", "py-sql-injection"),
    ("payments.py", "py-eq-none"),
    ("payments.py", "py-eq-bool"),
    ("payments.py", "py-bare-except"),
    ("payments.py", "py-except-pass"),
    ("payments.py", "py-is-literal"),
    ("upload.c", "scanf-unbounded"),
    ("upload.c", "unsafe-libc"),
    ("upload.c", "command-exec"),
    ("upload.c", "float-equality"),
    ("config.env", "hardcoded-secret"),
    # the security + JavaScript corpus
    ("insecure.py", "weak-hash"),
    ("insecure.py", "tls-verify-disabled"),
    ("insecure.py", "py-yaml-load"),
    ("insecure.py", "py-insecure-deserialize"),
    ("insecure.py", "py-subprocess-shell"),
    ("insecure.py", "dangerous-eval"),
    ("insecure.py", "debug-enabled"),
    ("app.js", "js-loose-equality"),
    ("app.js", "js-innerhtml"),
    ("app.js", "dangerous-eval"),
    ("app.js", "tls-verify-disabled"),
    ("app.js", "js-settimeout-string"),
    ("log.c", "format-string"),
    ("insecure.py", "py-requests-no-timeout"),
    ("insecure.py", "py-tempfile-insecure"),
    ("dangle.c", "c-return-local-address"),
    ("dangle.c", "c-strncpy-truncation"),
}


def self_test() -> int:
    files = collect_paths([os.path.join(CORPUS, d)
                           for d in ("c", "cpp", "haskell", "realworld")])
    found = set()
    all_findings = []
    for path in files:
        fs = scan_file(path)
        all_findings += fs
        for f in fs:
            found.add((os.path.basename(path), f.rule))
    missing = EXPECTED - found
    print(f"corpus files scanned : {len(files)}")
    print(f"total findings        : {len(all_findings)}")
    print(f"planted bugs expected : {len(EXPECTED)}")
    print(f"planted bugs detected : {len(EXPECTED) - len(missing)}")
    if missing:
        print("\nMISSED:")
        for base, rid in sorted(missing):
            print(f"  - {base}: {rid}")
        return 1
    print("\nOK: every planted bug was detected.")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--sarif", action="store_true",
                    help="emit SARIF 2.1.0 (for GitHub code scanning / CI)")
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                    help="minimum severity to report")
    ap.add_argument("--deep", action="store_true",
                    help="enable the higher-recall (noisier) deep rules")
    ap.add_argument("--list-rules", action="store_true", help="describe every rule and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="scan the bundled corpus and assert all planted bugs are found")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = ap.parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return 0
    if args.self_test:
        return self_test()

    paths = args.paths or [os.path.join(CORPUS, d)
                           for d in ("c", "cpp", "haskell", "realworld")]
    threshold = SEVERITY_ORDER[args.severity]
    findings = []
    scan_errors: list[str] = []
    files = collect_paths(paths, scan_errors)
    if not files and not scan_errors:
        scan_errors.append("no scannable source or text files were found")
    for path in files:
        try:
            scanned = scan_file(path, deep=args.deep)
        except (ScanError, OSError) as exc:
            scan_errors.append(str(exc))
            continue
        findings += [f for f in scanned if SEVERITY_ORDER[f.severity] >= threshold]
    findings.sort(key=Finding.sort_key)

    for message in scan_errors:
        print("scan error: " + message, file=sys.stderr)

    if args.sarif:
        print(json.dumps(to_sarif(findings), indent=2))
    elif args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if findings:
            print(fmt_human(findings, use_color=not args.no_color and sys.stdout.isatty()))
        print(fmt_summary(findings,
                          len({f.path for f in findings}) or len(paths),
                          args.severity))
    if scan_errors:
        return 2
    return min(len(findings), 250)


if __name__ == "__main__":
    sys.exit(main())
