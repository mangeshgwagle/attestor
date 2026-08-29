"""A1Z26 notation helpers used by AttestorLang source and its CLI.

A1Z26 is notation, not encryption.  A leading zero marks a decimal literal;
all other components must be letters numbered 1 through 26.
"""
from __future__ import annotations

import re

if __package__ and "." in __package__:
    from ..model import I64_MAX, SourceError
else:  # pragma: no cover
    from model import I64_MAX, SourceError


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
TOKEN = re.compile(r"\A\d+(?:-\d+)*\Z", re.ASCII)


def encode_word(word: str) -> str:
    if type(word) is not str or not word or any(
            not character.isascii() or not character.isalpha()
            for character in word):
        raise SourceError("A1Z26 words must contain ASCII letters only")
    return "-".join(str(ALPHABET.index(character.upper()) + 1)
                    for character in word)


def encode_literal(value: int) -> str:
    if type(value) is not int or not 0 <= value <= I64_MAX:
        raise SourceError("A1Z26 literal must be a non-negative signed i64")
    return "0-" + "-".join(str(value))


def encode_assembly(text: str) -> str:
    if type(text) is not str:
        raise SourceError("assembly text must be text")
    result = []
    for raw in text.split():
        token = raw.strip(";")
        if not token:
            continue
        if token.startswith("#"):
            try:
                value = int(token[1:], 10)
            except ValueError as exc:
                raise SourceError(f"invalid A1Z26 literal {token!r}") from exc
            result.append(encode_literal(value))
        else:
            result.append(encode_word(token))
    return " ".join(result)


def decode_token(token: str) -> int | str:
    if type(token) is not str or TOKEN.fullmatch(token) is None:
        raise SourceError("A1Z26 token must contain digits and hyphens only")
    parts = token.split("-")
    values = [int(part) for part in parts]
    if values[0] == 0:
        digits = parts[1:]
        if not digits or any(len(digit) != 1 for digit in digits):
            raise SourceError("A1Z26 literal digits must be single decimal digits")
        value = int("".join(digits))
        if value > I64_MAX:
            raise SourceError("A1Z26 literal is outside signed 64-bit range")
        return value
    if any(not 1 <= value <= 26 for value in values):
        raise SourceError("A1Z26 letters must be numbered 1 through 26")
    return "".join(ALPHABET[value - 1] for value in values)


def decode_assembly(text: str) -> str:
    if type(text) is not str:
        raise SourceError("A1Z26 source must be text")
    return " ".join(
        f"#{value}" if type(value := decode_token(token)) is int else value
        for token in text.split()
    )
