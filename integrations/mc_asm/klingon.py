#!/usr/bin/env python3
"""Klingon keyword aliases for mc.asm.

What is honest about this
-------------------------
The words below are taken from published Klingon vocabulary where a sensible
match exists -- ``ja'`` (tell) for PRINT, ``taH`` (continue) for WHILE,
``mev`` (stop) for END -- and are approximations where none does. This is a
keyword table, not Klingon: there is no grammar here, and the author does not
speak the language.

Two things the cipher destroys, which are worth stating rather than hiding:

* **Case is meaningful in Klingon and A1Z26 has none.** ``q`` and ``Q`` are
  different consonants; ``D``, ``S`` and ``H`` are distinct from their
  lowercase forms. Encoded to numbers, all of that flattens.
* **The apostrophe is a letter** (a glottal stop), and A1Z26 has no room for
  it. ``ja'`` and ``ja`` become the same token.

So a Klingon speaker would read this as mangled. It is decoration on a real
language, and pretending otherwise would be the same mistake as calling the
cipher a security boundary.

Why aliases and not a replacement
---------------------------------
Both spellings compile to the same opcode, so a program can be written in
either and the tests exercise one implementation rather than two. A second
keyword set that shared no code path would be a second language to keep
correct.
"""
from __future__ import annotations

# Klingon spelling -> the canonical mc.asm word it stands for. Uppercased on
# lookup, because the cipher has already lost the distinction anyway.
KLINGON = {
    # arithmetic
    "CHEL": "ADD",        # chel  - add, append
    "NGE": "SUB",         # nge'  - take away
    "GHURMOH": "MUL",     # ghurmoH - cause to increase
    "HAJ": "DIV",         # approximation
    "CHAV": "MOD",        # approximation
    "NGIL": "NEG",        # approximation
    # stack
    "CHALOGH": "DUP",     # cha'logh - twice
    "WOD": "DROP",        # woD   - throw away
    "CHOH": "SWAP",       # choH  - change
    "DUNG": "OVER",       # approximation
    # comparison
    "RAP": "EQ",          # rap   - be the same
    "PUS": "LT",          # puS   - be few
    "LAW": "GT",          # law'  - be many
    "GHOBE": "NOT",       # ghobe' - no
    # output
    "JA": "PRINT",        # ja'   - tell
    "JATLH": "EMIT",      # jatlh - speak
    "CHOL": "NL",         # approximation
    # memory
    "POL": "STORE",       # pol   - keep, save
    "TLHAP": "LOAD",      # tlhap - take
    # control
    "CHUGH": "IF",        # chugh - if
    "PAGH": "ELSE",       # pagh  - none, or
    "MEV": "END",         # mev   - stop
    "TAH": "WHILE",       # taH   - continue, endure
    "RUCH": "DO",         # ruch  - proceed!
}


def canonical(word: str) -> str:
    """The mc.asm word this token means, whichever language it came from."""
    return KLINGON.get(word.upper(), word.upper())
