#!/usr/bin/env python3
"""Other notations that lower onto the mc.asm machine.

The shape of this
-----------------
mc.asm is a stack machine with a 4,096-cell tape, a bytecode, and three
implementations that can be compared (interpreter, C++, x86-64). A *frontend* is
anything that produces its instruction list. The A1Z26 notation is one; the
Klingon keywords are the same one with a different keyword table; these are
others.

That is the whole reason to add them here rather than write separate
interpreters: a Brainfuck program compiled through this path gets the same
differential verification as everything else. Native C++/x86 execution now
requires an exact explicit opt-in; AttestorLang 4.2 itself never supplies it.

Which of these can honestly exist
---------------------------------
**Brainfuck** -- yes, and cleanly. A tape, a pointer, eight operations, all of
which the machine already has once the tape is big enough and PUTC exists.

**Whitespace** -- yes. It is a stack machine with heap access and labelled
flow, which is close enough to this one that the mapping is mostly mechanical.
Only the structured subset is accepted; see `whitespace` for what is left out
and why.

**Shakespeare** -- a subset, and the docstring is explicit about which. Full
SPL needs a noun/adjective dictionary where every noun is +/-1 and adjectives
double it, plus two-character dialogue with implicit second-person reference.
The arithmetic and the I/O are here; the poetry is thin.

**INTERCAL** -- not implemented, and not for want of trying to be clever. Its
arithmetic is `select` and `mingle` over bit-interleaved 16- and 32-bit
quantities, its flow is `COME FROM` (a goto that reaches backwards from the
target), and its `PLEASE` politeness ratio is checked at compile time. Any of
those is a day's work; together they are a different project, and a half
INTERCAL that silently ignored `COME FROM` would be worse than none.

**Malbolge** -- no, and this one is a statement about the language rather than
about the effort. Malbolge encrypts each instruction after executing it, using
the instruction pointer as part of the key, so the meaning of a byte depends
on when control reaches it. Programs are not written in it; they are *found*,
by search. The first "Hello, world" was produced by a beam search in Lisp, not
by a person. An interpreter is possible -- a frontend, in the sense used here,
is not, because there is no source anyone can author for it to translate.
"""
from __future__ import annotations

import re

import mc_asm

SCHEMA = "attestor.mc_asm-frontends/1.0"
VERSION = "4.1.4"

# Slot 0 is the Brainfuck data pointer; the tape proper starts at 1. Keeping
# the pointer inside the same memory the tape uses means no second mechanism
# and no extra opcode -- it is just a cell the generated code maintains.
TAPE_POINTER = 0
TAPE_BASE = 1


class FrontendError(mc_asm.McAsmError):
    """The source could not be translated."""


# ---- Brainfuck ------------------------------------------------------------ #

def brainfuck(source: str, base: int = 0) -> str:
    """Brainfuck to mc.asm assembly.

    The tape and the pointer both live in mc.asm memory, so every cell access
    is `pointer -> LOAD -> use`. That is verbose in the generated form and
    costs nothing at run time, because the backends compile it to the same
    indexed load a hand-written version would use.

    `base` relocates the whole thing. Without it the pointer is slot 0 and the
    tape starts at 1, which is fine alone and useless in company: Shakespeare
    also starts at 1, so concatenating the two makes each overwrite the
    other's memory. The pointer holds an absolute slot number, so moving the
    base moves the indirection with it and nothing else has to change.

    `,` (read a byte) is accepted and pushes 0. mc.asm has no input: the
    machine exists to be verified by re-running it and comparing output, and a
    program that consumed stdin would produce a different answer per run,
    which is precisely what the three-backend check cannot tolerate.
    """
    pointer_slot = base + TAPE_POINTER
    tape_start = base + TAPE_BASE
    out: list[str] = ["#%d #%d STORE" % (tape_start, pointer_slot)]
    depth = 0

    def cell() -> str:
        return "#%d LOAD LOAD" % pointer_slot

    for character in source:
        if character == ">":
            out.append("#%d LOAD #1 ADD #%d STORE"
                       % (pointer_slot, pointer_slot))
        elif character == "<":
            out.append("#%d LOAD #1 SUB #%d STORE"
                       % (pointer_slot, pointer_slot))
        elif character in "+-":
            # value = cell +/- 1; then store it back through the pointer.
            out.append("%s #1 %s #%d LOAD STORE"
                       % (cell(), "ADD" if character == "+" else "SUB",
                          pointer_slot))
        elif character == ".":
            out.append("%s PUTC" % cell())
        elif character == ",":
            out.append("#0 #%d LOAD STORE" % pointer_slot)
        elif character == "[":
            depth += 1
            out.append("WHILE %s DO" % cell())
        elif character == "]":
            depth -= 1
            if depth < 0:
                raise FrontendError("']' with no matching '['")
            out.append("END")
        # Everything else is a comment, which is how Brainfuck has always
        # carried its documentation.
    if depth:
        raise FrontendError("%d unclosed '['" % depth)
    return mc_asm.assemble(" ".join(out))


# ---- Whitespace ----------------------------------------------------------- #

_WS = {" ": "S", "\t": "T", "\n": "L"}


def whitespace(source: str) -> str:
    """Whitespace to mc.asm assembly.

    Only the structured subset: push, arithmetic, heap store/fetch, output,
    and `jz`/`jmp` to labels that form properly nested loops. Whitespace's
    flow is arbitrary labelled jumps, and mc.asm's is structured blocks, so a
    program using labels as a general goto is refused rather than mistranslated
    -- a frontend that silently dropped a jump would produce a program that
    runs and is wrong, which is the one outcome worth ruling out.
    """
    tokens = [_WS[c] for c in source if c in _WS]
    if not tokens:
        raise FrontendError("no whitespace instructions found")
    stream = "".join(tokens)
    out: list[str] = []
    position = 0

    def number() -> int:
        nonlocal position
        if position >= len(stream):
            raise FrontendError("number ran off the end")
        sign = -1 if stream[position] == "T" else 1
        position += 1
        bits = ""
        while position < len(stream) and stream[position] != "L":
            bits += "0" if stream[position] == "S" else "1"
            position += 1
        position += 1                     # consume the terminating L
        return sign * (int(bits, 2) if bits else 0)

    while position < len(stream):
        if stream.startswith("SS", position):
            position += 2
            out.append("#%d" % abs(number()))
        elif stream.startswith("TSSS", position):
            position += 4
            out.append("ADD")
        elif stream.startswith("TSST", position):
            position += 4
            out.append("SUB")
        elif stream.startswith("TSSL", position):
            position += 4
            out.append("MUL")
        elif stream.startswith("TTS", position):
            position += 3
            out.append("SWAP STORE")      # whitespace pushes value then addr
        elif stream.startswith("TTT", position):
            position += 3
            out.append("LOAD")
        elif stream.startswith("TLSS", position):
            position += 4
            out.append("PUTC")
        elif stream.startswith("TLST", position):
            position += 4
            out.append("PRINT")
        elif stream.startswith("SLS", position):
            position += 3
            out.append("DUP")
        elif stream.startswith("SLL", position):
            position += 3
            out.append("DROP")
        elif stream.startswith("LLL", position):
            position += 3
            break                          # end of program
        else:
            raise FrontendError(
                "unsupported whitespace instruction at token %d (%s...); this "
                "frontend accepts the structured subset only"
                % (position, stream[position:position + 4]))
    return mc_asm.assemble(" ".join(out))


# ---- Shakespeare ---------------------------------------------------------- #

# Every noun in SPL is worth +1 or -1, and each adjective doubles it. The real
# dictionary runs to hundreds of words; this is enough of it to write a
# program, and unknown nouns are refused rather than assumed positive.
_POSITIVE_NOUNS = {"flower", "hero", "king", "lord", "angel", "summer",
                   "heaven", "sun", "rose", "joy", "peace", "friend"}
_NEGATIVE_NOUNS = {"pig", "devil", "villain", "toad", "war", "death",
                   "hell", "plague", "curse", "winter", "coward", "bastard"}
_ADJECTIVES = {"big", "fair", "sweet", "noble", "brave", "handsome", "golden",
               "warm", "bold", "foul", "rotten", "cursed", "lying", "dirty",
               "evil", "black", "hard", "little", "small", "old"}

_SPEAKER = re.compile(r"\A\s*([A-Z][a-z]+):\s*(.*)\Z")

# First person is the speaker, second person is whoever else is on stage.
_FIRST_PERSON = {"i", "me", "myself"}
_SECOND_PERSON = {"you", "thou", "thee", "thyself", "yourself", "thy", "your"}

# SPL's four arithmetic phrases. Only "sum of" was handled before, which left
# the language able to add and nothing else.
_BINARY = (
    ("the sum of", "ADD"),
    ("the difference between", "SUB"),
    ("the product of", "MUL"),
    ("the quotient between", "DIV"),
)

# Comparisons. "not as good as" has to be tested before "as good as", or the
# shorter phrase matches first and the sense inverts.
_COMPARISONS = (
    ("not as good as", "NE"),
    ("as good as", "EQ"),
    ("better than", "GT"),
    ("worse than", "LT"),
)

_INTERROGATIVE = re.compile(r"\A\s*(?:am|are|art|is|be)\b", re.IGNORECASE)

# The whole of "Thou art as good as ..." before the value begins. Stripping it
# matters: `_value_tokens` resolves pronouns to characters, so leaving the
# "Thou" in front made every assignment read as "copy the target's current
# value" and the noun after it was never reached.
_ASSIGNMENT = re.compile(
    r"\A\s*(?:thou art|thou be|thou is|you are|you be)\s*"
    r"(?:as\s+\w+\s+as\s*)?", re.IGNORECASE)


def _split_and(phrase: str) -> tuple[str, str]:
    """Split an operand pair on its joining word."""
    parts = re.split(r"\band\b", phrase, maxsplit=1)
    if len(parts) != 2:
        raise FrontendError("expected two values joined by 'and' in %r"
                            % phrase.strip()[:60])
    return parts[0], parts[1]


def _who(phrase: str, slots, speaker, target):
    """The character a phrase refers to, or None if it names no one."""
    words = re.findall(r"[A-Za-z]+", phrase)
    for word in words:
        if word in slots:
            return word
    lowered = {w.lower() for w in words}
    if lowered & _FIRST_PERSON:
        return speaker
    if lowered & _SECOND_PERSON:
        return target
    return None


def _value_tokens(phrase, slots, speaker, target) -> str:
    """mc.asm that leaves the phrase's value on the stack.

    A value is one of three things, tried in that order: an arithmetic phrase
    joining two more values, a character (by name or pronoun), or a noun
    scaled by its adjectives.
    """
    lowered = phrase.lower()
    for marker, operation in _BINARY:
        position = lowered.find(marker)
        if position >= 0:
            left, right = _split_and(phrase[position + len(marker):])
            return "%s %s %s" % (
                _value_tokens(left, slots, speaker, target),
                _value_tokens(right, slots, speaker, target),
                operation)

    name = _who(phrase, slots, speaker, target)
    if name is not None and name in slots:
        return "#%d LOAD" % slots[name]

    value = _noun_value(phrase)
    if value is None:
        raise FrontendError("no value this frontend knows in %r"
                            % phrase.strip()[:60])
    return _push(value)


def _push(value: int) -> str:
    """Tokens that leave `value` on the stack, negatives included.

    `assemble` has no way to write a negative literal, and that is not an
    oversight: A1Z26 has no minus sign, and a token beginning with 0 is
    already spoken for as "a number follows". The machine's answer is the NEG
    word, so a negative constant is a positive one that gets negated -- which
    matters here because half of Shakespeare's nouns are worth -1.
    """
    return "#%d" % value if value >= 0 else "#%d NEG" % -value


def _noun_value(phrase: str) -> int | None:
    words = re.findall(r"[a-z]+", phrase.lower())
    for index, word in enumerate(words):
        if word in _POSITIVE_NOUNS or word in _NEGATIVE_NOUNS:
            doubles = sum(1 for w in words[:index] if w in _ADJECTIVES)
            base = 1 if word in _POSITIVE_NOUNS else -1
            return base * (2 ** doubles)
    return None


def shakespeare(source: str, base: int = 0) -> str:
    """A Shakespeare Programming Language subset to mc.asm assembly.

    What is here: characters as named variables, noun/adjective constants
    ("thou art as good as the sum of a fair flower and a pig"), assignment,
    addition and subtraction, "Open thy heart" (print a number) and "Speak
    thy mind" (print a character).

    What is not: stacks ("Remember"/"Recall"), conditionals ("Am I as good
    as..." with "Let us proceed to scene"), and goto by scene. SPL's control
    flow is scene labels jumped to by name, which has the same mismatch with a
    structured machine that Whitespace's labels do, and the same reason to
    refuse rather than approximate.

    A character is a memory slot, assigned in order of first appearance.
    """
    # Stage directions carry no punctuation, so `[Enter Romeo and Juliet]`
    # runs into the speech that follows it and the whole chunk stops looking
    # like dialogue -- the assignment is silently skipped and the program
    # prints an uninitialised slot. Removing them first is the fix.
    source = re.sub(r"\[[^\]]*\]", " ", source)

    slots: dict[str, int] = {}
    out: list[str] = []
    # Slot 0 of this region holds the answer to the last question. Characters
    # start at TAPE_BASE, so it cannot collide with one of them.
    flag_slot = base

    def slot_of(name: str) -> int:
        if name not in slots:
            if len(slots) >= 32:
                raise FrontendError("more than 32 characters")
            slots[name] = base + TAPE_BASE + len(slots)
        return slots[name]

    # The dramatis personae, first: "Romeo, a young man." Registering
    # characters up front is what makes "thou" resolvable at all -- without
    # it the first speaker addresses an empty stage, assigns to himself, and
    # the program prints whatever the other slot was initialised to.
    for raw in re.split(r"[.!?]", source):
        introduction = re.match(r"\A\s*([A-Z][a-z]+),\s+\w",
                                raw.strip().replace("\n", " "))
        if introduction:
            slot_of(introduction.group(1))

    speaker = None
    for raw in re.split(r"[.!?]", source):
        line = raw.strip().replace("\n", " ")
        if not line:
            continue
        header = _SPEAKER.match(line)
        if header:
            speaker, line = header.group(1), header.group(2).strip()
            if not line:
                continue
        if speaker is None:
            continue                       # the title, or stage directions

        lowered = line.lower()
        # The addressee is whoever is not speaking; with two characters on
        # stage that is unambiguous, which is why the subset assumes two.
        others = [n for n in slots if n != speaker]
        target = others[-1] if others else speaker

        # A question sets the flag; the "If so" that follows reads it. SPL
        # separates the two into different sentences, so the answer has to
        # outlive the sentence that produced it -- hence a slot rather than
        # something left on the stack.
        condition = None
        if lowered.startswith(("if so", "if not")):
            condition = "so" if lowered.startswith("if so") else "not"
            line = re.sub(r"\A\s*if (?:so|not)\s*,?\s*", "", line,
                          flags=re.IGNORECASE)
            lowered = line.lower()

        # A question cannot be spotted by its question mark: sentences are
        # split on [.!?], so the mark is gone before this sees the line. What
        # survives is the interrogative opening, which is what SPL actually
        # requires anyway -- "Am I...", "Art thou...", "Is Romeo...".
        comparison = None
        if _INTERROGATIVE.match(line):
            for phrase, operation in _COMPARISONS:
                if phrase in lowered:
                    position = lowered.find(phrase)
                    left = line[:position]
                    right = line[position + len(phrase):]
                    # "Am I better than you" -- strip the interrogative so the
                    # left operand is just the subject.
                    left = re.sub(r"\A\s*(?:am|are|is|be)\b", "", left,
                                  flags=re.IGNORECASE)
                    comparison = "%s %s %s #%d STORE" % (
                        _value_tokens(left, slots, speaker, target),
                        _value_tokens(right, slots, speaker, target),
                        operation, flag_slot)
                    break
            if comparison is None:
                raise FrontendError(
                    "a question this frontend cannot read: %r" % line[:60])
            out.append(comparison)
            continue

        if "open thy heart" in lowered or "open your heart" in lowered:
            body = "#%d LOAD PRINT" % slot_of(target)
        elif "speak thy mind" in lowered or "speak your mind" in lowered:
            body = "#%d LOAD PUTC" % slot_of(target)
        elif lowered.startswith(("thou art", "you are", "thou be", "you be",
                                 "thou is")):
            body = "%s #%d STORE" % (
                _value_tokens(_ASSIGNMENT.sub("", line), slots, speaker,
                              target),
                slot_of(target))
        elif re.match(r"\A[A-Z][a-z]+,\s*$", line):
            slot_of(line.rstrip(",").strip())      # entering the stage
            continue
        else:
            continue

        if condition == "so":
            out.append("#%d LOAD IF %s END" % (flag_slot, body))
        elif condition == "not":
            out.append("#%d LOAD NOT IF %s END" % (flag_slot, body))
        else:
            out.append(body)
    if not out:
        raise FrontendError("nothing executable found")
    return mc_asm.assemble(" ".join(out))


FRONTENDS = {"brainfuck": brainfuck, "whitespace": whitespace,
             "shakespeare": shakespeare}

# Frontends whose memory can be moved. Both address their storage through
# slot numbers this module chooses, so handing them a different base is the
# whole of it. Whitespace is absent on purpose -- see `compose`.
RELOCATABLE = frozenset({"brainfuck", "shakespeare"})

# Slots reserved per section. 256 is arbitrary but generous: a Brainfuck tape
# and 32 Shakespeare characters both fit, and 16 sections still fit in the
# machine's 4,096 cells.
REGION = 256


def compose(sections, region: int = REGION) -> str:
    """Several notations in one mc.asm program.

    They lower onto the same machine, so composing them is concatenation --
    but only once each has been given somewhere separate to live. Brainfuck
    puts its pointer in slot 0 and its tape at 1; Shakespeare puts its first
    character at 1. Joined as written, each silently overwrites the other and
    the result is a program that runs and is wrong.

    So every section gets its own region and the stack stays shared, which is
    the interesting part: a value one notation leaves behind is a value the
    next can use. Memory is partitioned; the stack is the common ground.

    Whitespace is refused. Its heap access takes the address off the stack at
    run time (`SWAP STORE`), so the addresses are the program's own data
    rather than something this module emitted, and relocating it would mean
    rewriting values that only exist while it runs. Refusing is the same
    choice `whitespace` itself makes about arbitrary labels: a frontend that
    silently mistranslates is worse than one that declines.
    """
    sections = list(sections)
    if len(sections) * region > mc_asm.MEMORY_SLOTS:
        raise FrontendError(
            "%d sections of %d slots exceed the machine's %d cells"
            % (len(sections), region, mc_asm.MEMORY_SLOTS))

    parts: list[str] = []
    for index, (language, source) in enumerate(sections):
        if language not in FRONTENDS:
            raise FrontendError("no frontend named %r (have %s)"
                                % (language, ", ".join(sorted(FRONTENDS))))
        if language not in RELOCATABLE:
            raise FrontendError(
                "%s addresses memory from its own runtime values, so it "
                "cannot be given a private region; it may be run alone but "
                "not composed" % language)
        parts.append(FRONTENDS[language](source, base=index * region))
    return " ".join(parts)
