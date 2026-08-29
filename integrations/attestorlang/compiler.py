"""Compiler for the deliberately small AttestorLang 4.2 source language.

The structured syntax provides immutable ``let`` bindings and C++-style
braces.  Embedded ASM, Brainfuck, and A1Z26 blocks all lower to the same ATVM
instruction stream, so none is an escape hatch around bytecode verification.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

if __package__:
    from . import bytecode as bc
    from .model import (
        ALLOWED_CAPABILITIES, I64_MAX, I64_MIN, MAX_CODE_INSTRUCTIONS,
        MAX_CONSTANTS, MAX_SOURCE_BYTES, 0, SourceError,
    )
else:  # pragma: no cover - standalone CLI imports this as a sibling module
    import bytecode as bc
    from model import (
        ALLOWED_CAPABILITIES, I64_MAX, I64_MIN, MAX_CODE_INSTRUCTIONS,
        MAX_CONSTANTS, MAX_SOURCE_BYTES, 0, SourceError,
    )


_IDENT_START = re.compile(r"[A-Za-z_]", re.ASCII)
_IDENT_CONTINUE = re.compile(r"[A-Za-z0-9_]", re.ASCII)
_SYMBOLS = frozenset("{}();,:=+-*/%<>[].")
MAX_PARSE_NESTING = 128


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: object
    raw: str
    line: int
    column: int


def tokenize(source: str) -> tuple[Token, ...]:
    if type(source) is not str:
        raise SourceError("source must be text")
    try:
        source_size = len(source.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise SourceError("source is not valid UTF-8 text") from exc
    if source_size > MAX_SOURCE_BYTES or "\x00" in source:
        raise SourceError("source exceeds its byte boundary or contains NUL")

    tokens: list[Token] = []
    index = 0
    line = 1
    column = 1
    in_a1z26 = False

    def advance(text: str) -> None:
        nonlocal line, column
        breaks = text.count("\n")
        if breaks:
            line += breaks
            column = len(text.rsplit("\n", 1)[-1]) + 1
        else:
            column += len(text)

    def add(kind: str, value: object, raw: str, at_line: int, at_column: int) -> None:
        tokens.append(Token(kind, value, raw, at_line, at_column))
        if len(tokens) > 0:
            raise SourceError("source token count exceeds its boundary")

    while index < len(source):
        character = source[index]
        if character in " \t\r\n":
            start = index
            while index < len(source) and source[index].isspace():
                index += 1
            advance(source[start:index])
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            advance(source[index:end])
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise SourceError(f"unterminated comment at {line}:{column}")
            end += 2
            advance(source[index:end])
            index = end
            continue

        at_line, at_column = line, column
        if character == '"':
            start = index
            index += 1
            escaped = False
            while index < len(source):
                current = source[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    index += 1
                    break
                elif current in "\r\n":
                    raise SourceError(
                        f"text literal crosses a line at {at_line}:{at_column}")
                index += 1
            else:
                raise SourceError(
                    f"unterminated text literal at {at_line}:{at_column}")
            raw = source[start:index]
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                raise SourceError(
                    f"invalid text literal at {at_line}:{at_column}") from exc
            add("STRING", value, raw, at_line, at_column)
            advance(raw)
            continue

        if character.isascii() and character.isdigit():
            start = index
            while index < len(source) and source[index].isdigit():
                index += 1
            hyphenated = False
            while (in_a1z26 and index + 1 < len(source) and source[index] == "-"
                   and source[index + 1].isdigit()):
                hyphenated = True
                index += 1
                while index < len(source) and source[index].isdigit():
                    index += 1
            raw = source[start:index]
            add("A1" if hyphenated else "NUMBER", raw, raw, at_line, at_column)
            advance(raw)
            continue

        if character.isascii() and _IDENT_START.fullmatch(character):
            start = index
            index += 1
            while (index < len(source) and source[index].isascii()
                   and _IDENT_CONTINUE.fullmatch(source[index])):
                index += 1
            # Capability names are the only dotted identifiers.  Keeping the
            # dot here avoids turning console.write into three grammar tokens.
            while (index < len(source) and source[index] == "."
                   and index + 1 < len(source)
                   and _IDENT_START.fullmatch(source[index + 1])):
                index += 1
                while (index < len(source) and source[index].isascii()
                       and _IDENT_CONTINUE.fullmatch(source[index])):
                    index += 1
            raw = source[start:index]
            add("IDENT", raw, raw, at_line, at_column)
            advance(raw)
            continue

        if character in _SYMBOLS:
            add("SYMBOL", character, character, at_line, at_column)
            if character == "{" and len(tokens) >= 2 \
                    and tokens[-2].value == "a1z26":
                in_a1z26 = True
            elif character == "}" and in_a1z26:
                in_a1z26 = False
        else:
            # Brainfuck permits arbitrary commentary.  Retaining unknown
            # characters as tokens lets a brainfuck block ignore them while
            # every structured-language position still rejects them.
            add("OTHER", character, character, at_line, at_column)
        index += 1
        advance(character)

    tokens.append(Token("EOF", "", "", line, column))
    return tuple(tokens)


class _Parser:
    def __init__(self, source: str) -> None:
        self.tokens = tokenize(source)
        self.position = 0
        self.code: list[tuple[int, ...]] = []
        self.constants: list[str] = []
        self.locals: dict[str, tuple[int, str]] = {}
        self.local_types: list[str] = []
        self.declared_capabilities: set[str] = set()
        self.used_capabilities: set[str] = set()
        self.expression_depth = 0
        self.unary_depth = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.position]

    def _error(self, message: str, token: Token | None = None) -> SourceError:
        here = token or self.current
        return SourceError(f"{message} at {here.line}:{here.column}")

    def _advance(self) -> Token:
        token = self.current
        if token.kind != "EOF":
            self.position += 1
        return token

    def _match(self, value: str) -> bool:
        if self.current.value == value:
            self._advance()
            return True
        return False

    def _expect(self, value: str) -> Token:
        if self.current.value != value:
            raise self._error(f"expected {value!r}, got {self.current.raw!r}")
        return self._advance()

    def _expect_kind(self, kind: str, label: str) -> Token:
        if self.current.kind != kind:
            raise self._error(f"expected {label}, got {self.current.raw!r}")
        return self._advance()

    def _emit(self, opcode: int, operand: int | None = None) -> int:
        if len(self.code) >= MAX_CODE_INSTRUCTIONS - 1:
            raise self._error("compiled instruction count exceeds its boundary")
        instruction = (opcode,) if operand is None else (opcode, operand)
        self.code.append(instruction)
        return len(self.code) - 1

    def _constant(self, value: str) -> int:
        try:
            return self.constants.index(value)
        except ValueError:
            if len(self.constants) >= MAX_CONSTANTS:
                raise self._error("text constant count exceeds its boundary")
            self.constants.append(value)
            return len(self.constants) - 1

    def parse(self) -> bc.Program:
        self._expect("attestor")
        self._expect("4")
        self._expect(".")
        self._expect("2")
        self._expect(";")

        while self._match("requires"):
            capability = self._expect_kind("IDENT", "capability name")
            if capability.value not in ALLOWED_CAPABILITIES:
                raise self._error(
                    f"unsupported capability {capability.value!r}", capability)
            if capability.value in self.declared_capabilities:
                raise self._error("duplicate capability declaration", capability)
            self.declared_capabilities.add(str(capability.value))
            self._expect(";")

        self._expect("scene")
        scene = self._expect_kind("IDENT", "scene name")
        if scene.value != "Main":
            raise self._error("the MVP entry scene must be exactly Main", scene)
        self._expect("{")
        while not self._match("}"):
            if self.current.kind == "EOF":
                raise self._error("scene Main is not closed")
            self._statement()
        if self.current.kind != "EOF":
            raise self._error("only one scene is supported by the MVP")

        missing = self.used_capabilities - self.declared_capabilities
        if missing:
            raise self._error(
                "source uses undeclared capabilities: " + ", ".join(sorted(missing)),
                scene,
            )
        self._emit(bc.HALT)
        program = bc.Program(
            code=tuple(self.code),
            constants=tuple(self.constants),
            local_types=tuple(self.local_types),
            capabilities=tuple(sorted(self.used_capabilities)),
        )
        bc.verify(program)
        return program

    def _statement(self) -> None:
        if self._match("let"):
            self._let()
            return
        if self._match("asm"):
            self._asm_block()
            self._match(";")
            return
        if self._match("brainfuck"):
            self._brainfuck_block()
            self._match(";")
            return
        if self._match("a1z26"):
            self._a1z26_block()
            self._match(";")
            return
        if self.current.kind == "IDENT":
            actor = self._advance()
            if not self._match("says"):
                raise self._error(
                    f"expected Shakespeare-style 'says' after {actor.value!r}")
            self._say()
            return
        raise self._error(f"unsupported statement {self.current.raw!r}")

    def _let(self) -> None:
        name = self._expect_kind("IDENT", "binding name")
        if name.value in self.locals:
            raise self._error("immutable binding is already defined", name)
        annotation: str | None = None
        if self._match(":"):
            annotation_token = self._expect_kind("IDENT", "type name")
            annotation = str(annotation_token.value)
            if annotation not in {"i64", "text"}:
                raise self._error("MVP type must be i64 or text", annotation_token)
        self._expect("=")
        kind = self._expression()
        if annotation is not None and annotation != kind:
            raise self._error(
                f"binding type {annotation} does not match expression type {kind}", name)
        self._expect(";")
        slot = len(self.local_types)
        self.locals[str(name.value)] = (slot, kind)
        self.local_types.append(kind)
        self._emit(bc.STORE_LOCAL, slot)

    def _say(self) -> None:
        kind_token = self._expect_kind("IDENT", "output kind")
        kinds = {
            "number": ("i64", bc.PRINT_NUMBER),
            "letter": ("i64", bc.PRINT_CHAR),
            "text": ("text", bc.PRINT_TEXT),
        }
        if kind_token.value not in kinds:
            raise self._error("output kind must be number, letter, or text", kind_token)
        self._expect("(")
        actual = self._expression()
        self._expect(")")
        self._expect(";")
        expected, opcode = kinds[str(kind_token.value)]
        if actual != expected:
            raise self._error(
                f"{kind_token.value} output expects {expected}, got {actual}", kind_token)
        self.used_capabilities.add("console.write")
        self._emit(opcode)

    def _expression(self) -> str:
        if self.expression_depth >= MAX_PARSE_NESTING:
            raise self._error("expression nesting exceeds its boundary")
        self.expression_depth += 1
        try:
            return self._additive()
        finally:
            self.expression_depth -= 1

    def _additive(self) -> str:
        kind = self._multiplicative()
        while self.current.value in {"+", "-"}:
            operator = self._advance()
            right = self._multiplicative()
            if kind != "i64" or right != "i64":
                raise self._error("arithmetic operands must be i64", operator)
            self._emit(bc.ADD if operator.value == "+" else bc.SUB)
            kind = "i64"
        return kind

    def _multiplicative(self) -> str:
        kind = self._unary()
        while self.current.value in {"*", "/", "%"}:
            operator = self._advance()
            right = self._unary()
            if kind != "i64" or right != "i64":
                raise self._error("arithmetic operands must be i64", operator)
            self._emit({"*": bc.MUL, "/": bc.DIV, "%": bc.MOD}[str(operator.value)])
            kind = "i64"
        return kind

    def _unary(self) -> str:
        if self.unary_depth >= MAX_PARSE_NESTING:
            raise self._error("unary nesting exceeds its boundary")
        self.unary_depth += 1
        try:
            if self._match("-"):
                if (self.current.kind == "NUMBER"
                        and int(str(self.current.value)) == 2 ** 63):
                    self._advance()
                    self._emit(bc.PUSH_I64, I64_MIN)
                    return "i64"
                kind = self._unary()
                if kind != "i64":
                    raise self._error("unary minus expects i64")
                self._emit(bc.NEG)
                return "i64"
            return self._primary()
        finally:
            self.unary_depth -= 1

    def _primary(self) -> str:
        token = self.current
        if token.kind == "NUMBER":
            self._advance()
            value = int(str(token.value))
            if not I64_MIN <= value <= I64_MAX:
                raise self._error("integer literal is outside signed 64-bit range", token)
            self._emit(bc.PUSH_I64, value)
            return "i64"
        if token.kind == "STRING":
            self._advance()
            self._emit(bc.PUSH_TEXT, self._constant(str(token.value)))
            return "text"
        if self._match("("):
            kind = self._expression()
            self._expect(")")
            return kind
        if token.kind == "IDENT":
            self._advance()
            name = str(token.value)
            if self._match("("):
                return self._builtin(name, token)
            binding = self.locals.get(name)
            if binding is None:
                raise self._error(f"unknown immutable binding {name!r}", token)
            self._emit(bc.LOAD_LOCAL, binding[0])
            return binding[1]
        raise self._error(f"expected expression, got {token.raw!r}", token)

    def _builtin(self, name: str, token: Token) -> str:
        arity = {"asr": 2, "crazy": 2, "rotrit": 1}
        opcode = {"asr": bc.ASR, "crazy": bc.CRAZY, "rotrit": bc.ROTRIT}
        if name not in arity:
            raise self._error(f"unknown pure builtin {name!r}", token)
        count = 0
        if not self._match(")"):
            while True:
                if self._expression() != "i64":
                    raise self._error(f"{name} arguments must be i64", token)
                count += 1
                if self._match(")"):
                    break
                self._expect(",")
        if count != arity[name]:
            raise self._error(f"{name} expects {arity[name]} arguments, got {count}", token)
        self._emit(opcode[name])
        return "i64"

    def _asm_block(self) -> None:
        self._expect("{")
        while not self._match("}"):
            if self.current.kind == "EOF":
                raise self._error("asm block is not closed")
            if self._match(";"):
                continue
            token = self._expect_kind("IDENT", "assembly mnemonic")
            mnemonic = str(token.value).upper()
            if mnemonic == "PUSH":
                sign = -1 if self._match("-") else 1
                number = self._expect_kind("NUMBER", "PUSH integer")
                value = sign * int(str(number.value))
                if not I64_MIN <= value <= I64_MAX:
                    raise self._error("PUSH literal is outside signed 64-bit range", number)
                self._emit(bc.PUSH_I64, value)
            else:
                self._emit_asm_word(mnemonic, token)
            self._match(";")

    def _emit_asm_word(self, mnemonic: str, token: Token) -> None:
        words = {
            "DROP": bc.POP, "DUP": bc.DUP, "SWAP": bc.SWAP,
            "ADD": bc.ADD, "ADDW": bc.ADD_WRAP, "SUB": bc.SUB,
            "SUBW": bc.SUB_WRAP, "MUL": bc.MUL, "MULW": bc.MUL_WRAP,
            "DIV": bc.DIV, "MOD": bc.MOD, "NEG": bc.NEG,
            "ASR": bc.ASR, "EQ": bc.EQ, "LT": bc.LT, "GT": bc.GT,
            "AND": bc.BIT_AND, "OR": bc.BIT_OR, "XOR": bc.BIT_XOR,
            "NOT": bc.BIT_NOT, "SHL": bc.SHL, "LSR": bc.LSR,
            "CRAZY": bc.CRAZY, "ROTRIT": bc.ROTRIT,
            "PRINT": bc.PRINT_NUMBER, "PUTC": bc.PRINT_CHAR,
            "EMIT": bc.PRINT_CHAR, "READ": bc.READ_BYTE,
        }
        opcode = words.get(mnemonic)
        if opcode is None:
            raise self._error(f"unknown assembly mnemonic {mnemonic!r}", token)
        if opcode in {bc.PRINT_NUMBER, bc.PRINT_CHAR}:
            self.used_capabilities.add("console.write")
        elif opcode == bc.READ_BYTE:
            self.used_capabilities.add("input.read")
        self._emit(opcode)

    def _brainfuck_block(self) -> None:
        self._expect("{")
        commands: list[tuple[str, Token]] = []
        while not self._match("}"):
            token = self.current
            if token.kind == "EOF":
                raise self._error("brainfuck block is not closed")
            self._advance()
            for character in token.raw:
                if character in "><+-.,[]":
                    commands.append((character, token))

        loop_stack: list[tuple[int, Token]] = []
        for command, token in commands:
            if command == ">":
                self._emit(bc.BF_RIGHT)
            elif command == "<":
                self._emit(bc.BF_LEFT)
            elif command == "+":
                self._emit(bc.BF_INC)
            elif command == "-":
                self._emit(bc.BF_DEC)
            elif command == ".":
                self.used_capabilities.add("console.write")
                self._emit(bc.BF_OUT)
            elif command == ",":
                self.used_capabilities.add("input.read")
                self._emit(bc.BF_IN)
            elif command == "[":
                loop_stack.append((self._emit(bc.BF_JZ, 0), token))
            elif command == "]":
                if not loop_stack:
                    raise self._error("brainfuck ']' has no matching '['", token)
                opening, _opening_token = loop_stack.pop()
                closing = self._emit(bc.BF_JNZ, opening)
                self.code[opening] = (bc.BF_JZ, closing + 1)
        if loop_stack:
            _index, token = loop_stack[-1]
            raise self._error("brainfuck '[' is not closed", token)

    def _a1z26_block(self) -> None:
        self._expect("{")
        while not self._match("}"):
            token = self.current
            if token.kind == "EOF":
                raise self._error("A1Z26 block is not closed")
            if self._match(";"):
                continue
            if token.kind not in {"A1", "NUMBER"}:
                raise self._error("A1Z26 blocks accept only digits and hyphens", token)
            self._advance()
            raw = str(token.value)
            values = [int(part) for part in raw.split("-")]
            if values[0] == 0:
                digits = raw.split("-")[1:]
                if not digits or any(len(digit) != 1 for digit in digits):
                    raise self._error("A1Z26 literal digits must be single decimal digits", token)
                value = int("".join(digits))
                if value > I64_MAX:
                    raise self._error("A1Z26 literal is outside signed 64-bit range", token)
                self._emit(bc.PUSH_I64, value)
                continue
            if any(not 1 <= value <= 26 for value in values):
                raise self._error("A1Z26 letters must be numbered 1 through 26", token)
            word = "".join(chr(64 + value) for value in values)
            self._emit_asm_word(word, token)


def compile_source(source: str) -> bc.Program:
    """Compile strict UTF-8 AttestorLang source and verify its ATVM program."""
    return _Parser(source).parse()
