#!/usr/bin/env python3
"""Piet: programs that are pictures.

Two things live here, and the difference matters.

`interpret(image)` runs a Piet program directly. It is an *interpreter*, not a
frontend, and it does not compose with the other notations or get the mc.asm
differential check. Full Piet needs that: the Direction Pointer and Codel
Chooser are changed at run time by the `pointer` and `switch` commands, taking
their new values off the stack, so where control goes next is a function of
data. Nothing can linearise that ahead of time.

`piet(image)` is the frontend, and it is honest about being a subset. With no
`pointer` and no `switch`, the walk depends only on the picture's geometry, so
it can be traced at translation time and emitted as ordinary mc.asm. The catch
is a real one and worth stating plainly: a program whose path never depends on
data also never revisits a block, so that subset has no loops. It buys the
verification the other frontends get, and pays for it in expressiveness.

That is the same bargain `whitespace` strikes over arbitrary labels and
`shakespeare` strikes over scene-jumps: implement the part that maps, refuse
the part that does not, and say which is which.

Why Piet is possible at all where Malbolge is not: Piet programs are *drawn*.
A person authors one. Malbolge programs are found by search, so there is no
source for a translator to accept.
"""
from __future__ import annotations

import mc_asm

SCHEMA = "attestor.mc_asm-piet/1.0"
VERSION = "4.2"

# Six hues x three lightnesses, then the two achromatic codels. Index is
# (hue, lightness); hue cycles red -> yellow -> green -> cyan -> blue ->
# magenta, lightness light -> normal -> dark.
COLOURS = {
    (0xFF, 0xC0, 0xC0): (0, 0), (0xFF, 0xFF, 0xC0): (1, 0),
    (0xC0, 0xFF, 0xC0): (2, 0), (0xC0, 0xFF, 0xFF): (3, 0),
    (0xC0, 0xC0, 0xFF): (4, 0), (0xFF, 0xC0, 0xFF): (5, 0),
    (0xFF, 0x00, 0x00): (0, 1), (0xFF, 0xFF, 0x00): (1, 1),
    (0x00, 0xFF, 0x00): (2, 1), (0x00, 0xFF, 0xFF): (3, 1),
    (0x00, 0x00, 0xFF): (4, 1), (0xFF, 0x00, 0xFF): (5, 1),
    (0xC0, 0x00, 0x00): (0, 2), (0xC0, 0xC0, 0x00): (1, 2),
    (0x00, 0xC0, 0x00): (2, 2), (0x00, 0xC0, 0xC0): (3, 2),
    (0x00, 0x00, 0xC0): (4, 2), (0xC0, 0x00, 0xC0): (5, 2),
}
WHITE = (0xFF, 0xFF, 0xFF)
BLACK = (0x00, 0x00, 0x00)

# [hue change][lightness change]. The command is decided by the *transition*
# between two blocks, never by a block on its own -- which is why a Piet
# program cannot be read one codel at a time.
COMMANDS = (
    (None,       "push",     "pop"),
    ("add",      "subtract", "multiply"),
    ("divide",   "mod",      "not"),
    ("greater",  "pointer",  "switch"),
    ("duplicate", "roll",    "in_number"),
    ("in_char",  "out_number", "out_char"),
)

# DP: 0 right, 1 down, 2 left, 3 up.
STEPS = ((1, 0), (0, 1), (-1, 0), (0, -1))


class PietError(mc_asm.McAsmError):
    """The picture could not be read, or asks for something unsupported."""


def load(path) -> list[list]:
    """A picture to a grid of colour keys. Requires Pillow."""
    try:
        from PIL import Image
    except ImportError:                                  # pragma: no cover
        raise PietError("reading Piet programs needs Pillow installed")
    with Image.open(path) as handle:
        rgb = handle.convert("RGB")
        width, height = rgb.size
        pixels = rgb.load()
        return [[pixels[x, y] for x in range(width)] for y in range(height)]


def _block_at(grid, start):
    """Every codel connected to `start` sharing its colour."""
    colour = grid[start[1]][start[0]]
    seen = {start}
    pending = [start]
    while pending:
        x, y = pending.pop()
        for dx, dy in STEPS:
            nx, ny = x + dx, y + dy
            if (0 <= ny < len(grid) and 0 <= nx < len(grid[0])
                    and (nx, ny) not in seen
                    and grid[ny][nx] == colour):
                seen.add((nx, ny))
                pending.append((nx, ny))
    return seen


def _corner(block, dp, cc):
    """The codel a transition leaves from, for this DP and CC."""
    # Furthest in the DP direction, then furthest to the CC side of it.
    dx, dy = STEPS[dp]
    edge = max(block, key=lambda p: p[0] * dx + p[1] * dy)
    limit = edge[0] * dx + edge[1] * dy
    candidates = [p for p in block if p[0] * dx + p[1] * dy == limit]
    side = STEPS[(dp + (3 if cc == 0 else 1)) % 4]
    return max(candidates, key=lambda p: p[0] * side[0] + p[1] * side[1])


def _colour_of(grid, position):
    return grid[position[1]][position[0]]


def _inside(grid, position):
    x, y = position
    return 0 <= y < len(grid) and 0 <= x < len(grid[0])


# A walk that revisits a block revisits it forever, because without `pointer`
# or `switch` nothing about the state can have changed. Two colour blocks side
# by side are enough: the pointer runs to the end, is blocked, turns back, and
# oscillates. So the walk is bounded like everything else on this machine --
# the first version of this had no limit and hung on a five-codel picture.
MAX_TRANSITIONS = 100_000


def walk(grid, limit: int = MAX_TRANSITIONS):
    """Yield (command, block_size) for each transition the picture makes.

    Stops when eight consecutive attempts to leave a block are blocked, which
    is Piet's own termination rule -- or when `limit` transitions have gone by,
    which is this implementation's.
    """
    position = (0, 0)
    dp, cc = 0, 0
    taken = 0
    while True:
        taken += 1
        if taken > limit:
            raise PietError(
                "still walking after %d transitions; the picture does not "
                "terminate" % limit)
        block = _block_at(grid, position)
        size = len(block)
        colour = _colour_of(grid, position)

        moved = False
        for attempt in range(8):
            corner = _corner(block, dp, cc)
            dx, dy = STEPS[dp]
            nxt = (corner[0] + dx, corner[1] + dy)

            if _inside(grid, nxt) and _colour_of(grid, nxt) == WHITE:
                # White is a corridor: slide through it without a command.
                while (_inside(grid, nxt)
                       and _colour_of(grid, nxt) == WHITE):
                    nxt = (nxt[0] + dx, nxt[1] + dy)
                if _inside(grid, nxt) and _colour_of(grid, nxt) != BLACK:
                    yield None, size
                    position = nxt
                    moved = True
                    break
            elif (_inside(grid, nxt)
                  and _colour_of(grid, nxt) != BLACK):
                if colour in COLOURS and _colour_of(grid, nxt) in COLOURS:
                    hue_from, light_from = COLOURS[colour]
                    hue_to, light_to = COLOURS[_colour_of(grid, nxt)]
                    command = COMMANDS[(hue_to - hue_from) % 6][
                        (light_to - light_from) % 3]
                else:
                    command = None
                yield command, size
                position = nxt
                moved = True
                break

            # Blocked: alternate turning the chooser and the pointer.
            if attempt % 2 == 0:
                cc = 1 - cc
            else:
                dp = (dp + 1) % 4
        if not moved:
            return


STATIC = {None, "push", "pop", "add", "subtract", "multiply", "divide",
          "mod", "not", "greater", "duplicate", "out_number", "out_char"}

# What each Piet command becomes in mc.asm. `roll` and the `in_*` commands are
# absent deliberately: roll needs an arbitrary-depth rotate the machine does
# not have, and mc.asm has no run-time input at all.
TO_MC_ASM = {
    "pop": "DROP",
    "add": "ADD",
    "subtract": "SUB",
    "multiply": "MUL",
    "divide": "DIV",
    "mod": "MOD",
    "not": "NOT",
    "greater": "GT",
    "duplicate": "DUP",
    "out_number": "PRINT",
    "out_char": "PUTC",
}


def piet(source, base: int = 0) -> str:
    """A Piet picture to mc.asm assembly, for the subset that can be traced.

    `base` is accepted so this matches the other relocatable frontends, and
    is unused: the translation touches no memory, only the stack.
    """
    grid = source if isinstance(source, list) else load(source)
    out: list[str] = []
    for command, size in walk(grid):
        if command is None:
            continue
        if command in ("pointer", "switch"):
            raise PietError(
                "'%s' changes the direction pointer from a stack value, so "
                "the path depends on data and cannot be translated ahead of "
                "time; run this picture with interpret() instead" % command)
        if command in ("roll", "in_number", "in_char"):
            raise PietError(
                "'%s' has no mc.asm equivalent (roll needs an arbitrary-depth "
                "rotate; mc.asm has no run-time input)" % command)
        if command == "push":
            out.append("#%d" % size)
        else:
            out.append(TO_MC_ASM[command])
    if not out:
        raise PietError("the picture produced no instructions")
    return mc_asm.assemble(" ".join(out))
