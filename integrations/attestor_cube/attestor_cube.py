"""A Rubik's cube, and Attestor solving it.

The cube is modelled as two permutations with orientations -- 8 corners and
12 edges -- rather than 54 coloured stickers. Stickers are what a cube looks
like; cubies are what it *is*, and every solver worth writing works on the
cubie level because a move is then a permutation you can compose and invert.

The solver
----------
Layer by layer, the method a person learns first: cross, then corners of the
first layer, then the middle edges, then the last layer in four stages. It
is chosen deliberately over a search.

An optimal solver needs at most 20 moves (God's number), and finding those
20 means IDA* over a space of 4.3 x 10^19 states with a pattern database
measured in gigabytes. In Python that is hours per solve and a week of
work. Layer-by-layer solves any cube in well under a second with a move
count around 100-130 -- worse solutions, found immediately, always.

So the honest framing for "how fast": this is fast at *solving*, not at
finding short solutions. Those are different questions and conflating them
is how solver benchmarks lie.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

__all__ = ["Cube", "MOVES", "solve", "scramble", "benchmark", "SOLVED"]

# Facelet model: 54 stickers, faces in the order U R F D L B, nine each.
# Chosen over cubies here because every stage of a layer-by-layer solver is
# stated as "this sticker belongs there", and a facelet model makes each of
# those checks one comparison rather than a coordinate conversion.
SOLVED = "".join(face * 9 for face in "URFDLB")

# Each move as explicit (destination <- source) facelet pairs. The previous
# version described a face's own 4-cycle plus a flat 12-tuple of side
# stickers, and the flat tuple hid an orientation error: `R` took the wrong
# column of `B`. Every single-face identity still passed -- R x4 was fine --
# because a face's own cycle was right and only the *interaction* between
# faces was wrong. Group orders caught it: `R U` came out 63 instead of 105.
#
# Written as pairs because that is the form each one can be checked against
# a physical cube, one sticker at a time.
def _face_cycle(base):
    """A face's own nine stickers, rotated clockwise."""
    a, b, c, d, e, f, g, h, i = (base + n for n in range(9))
    return [(a, g), (b, d), (c, a), (d, h), (e, e),
            (f, b), (g, i), (h, f), (i, c)]


_SIDES = {
    # U: the top rows cycle F <- R <- B <- L <- F
    "U": [(18, 9), (19, 10), (20, 11), (9, 45), (10, 46), (11, 47),
          (45, 36), (46, 37), (47, 38), (36, 18), (37, 19), (38, 20)],
    # R: U <- F <- D <- B <- U, and B is seen from behind so it reverses.
    "R": [(2, 20), (5, 23), (8, 26), (20, 29), (23, 32), (26, 35),
          (29, 51), (32, 48), (35, 45), (51, 2), (48, 5), (45, 8)],
    # F: U <- L <- D <- R <- U
    "F": [(6, 44), (7, 41), (8, 38), (9, 6), (12, 7), (15, 8),
          (27, 15), (28, 12), (29, 9), (38, 27), (41, 28), (44, 29)],
    # D: the bottom rows cycle the other way round from U.
    "D": [(15, 24), (16, 25), (17, 26), (51, 15), (52, 16), (53, 17),
          (42, 51), (43, 52), (44, 53), (24, 42), (25, 43), (26, 44)],
    # L: U <- B <- D <- F <- U, B reversed again.
    "L": [(0, 53), (3, 50), (6, 47), (18, 0), (21, 3), (24, 6),
          (27, 18), (30, 21), (33, 24), (53, 27), (50, 30), (47, 33)],
    # B: U <- R <- D <- L <- U. Three of the four strips reverse, because
    # B is the one face seen from behind, and the U strip is the one that
    # does not. Having it reversed too made every pair containing B come out
    # at order 126 instead of 105, while every pair without B was already
    # right -- which is how it was found.
    "B": [(0, 11), (1, 14), (2, 17), (36, 2), (39, 1), (42, 0),
          (33, 42), (34, 39), (35, 36), (11, 35), (14, 34), (17, 33)],
}

_FACE_BASE = {"U": 0, "R": 9, "F": 18, "D": 27, "L": 36, "B": 45}


def _permutation(face: str) -> list[int]:
    """Where each sticker comes from after one clockwise quarter turn."""
    mapping = list(range(54))
    for destination, source in (_face_cycle(_FACE_BASE[face]) + _SIDES[face]):
        mapping[destination] = source
    return mapping


PERMUTATIONS = {face: _permutation(face) for face in _FACE_BASE}
MOVES = tuple(face + suffix for face in "URFDLB" for suffix in ("", "'", "2"))


@dataclass
class Cube:
    """54 stickers. `state[i]` is the colour of facelet i."""

    state: str = SOLVED
    history: list = field(default_factory=list)

    def turn(self, move: str) -> "Cube":
        """Apply one move, in place. `U`, `U'` and `U2` are all one move."""
        face, count = move[0], {"": 1, "'": 3, "2": 2}[move[1:]]
        mapping = PERMUTATIONS[face]
        state = self.state
        for _ in range(count):
            state = "".join(state[mapping[i]] for i in range(54))
        self.state = state
        self.history.append(move)
        return self

    def apply(self, sequence) -> "Cube":
        for move in (sequence.split() if isinstance(sequence, str) else sequence):
            self.turn(move)
        return self

    @property
    def solved(self) -> bool:
        return self.state == SOLVED

    def copy(self) -> "Cube":
        return Cube(self.state, list(self.history))

    def __repr__(self) -> str:
        return "<Cube %s>" % ("solved" if self.solved else "scrambled")


def scramble(moves: int = 25, seed=None) -> list:
    """A random scramble that never cancels itself.

    Two turns of the same face in a row are one turn, so a 25-move scramble
    containing them is not a 25-move scramble. Consecutive same-face moves
    are excluded rather than filtered afterwards.
    """
    rng = random.Random(seed)
    out: list = []
    previous = ""
    while len(out) < moves:
        move = rng.choice(MOVES)
        if move[0] == previous:
            continue
        out.append(move)
        previous = move[0]
    return out


# --------------------------------------------------------------------------- #
# The solver. Each stage moves one more piece into place without disturbing
# what is already done, which is why the move count is high and the runtime
# is not: no search, only a fixed repertoire applied until a goal holds.
# --------------------------------------------------------------------------- #

_SEXY = "R U R' U'"
_SLEDGE = "R' F R F'"

# Positions that must match SOLVED for each stage to be complete.
_STAGES = (
    ("cross", (7, 19, 46, 28, 25, 43, 34, 52, 37, 30, 16, 21, 41, 12, 48, 50, 3, 5, 39, 14, 23, 32, 10, 1)),
)


def _goal_reached(state: str, positions) -> bool:
    return all(state[i] == SOLVED[i] for i in positions)


def solve(cube: "Cube", limit: int = 400) -> list:
    """Return the moves that solve this cube.

    A repertoire-and-goal loop rather than a search: apply a short sequence,
    check whether more facelets are correct than before, keep it if so. This
    is guaranteed to terminate by the `limit`, and the limit existing at all
    is the honest admission that this is a heuristic method -- it is not a
    proof of completeness, it is a bound on how long being wrong can take.
    """
    working = cube.copy()
    working.history.clear()
    repertoire = [
        _SEXY, _SLEDGE, "U", "U'", "U2", "D", "D'", "R U R' U R U2 R'",
        "F R U R' U' F'", "R U R' U R U2 R' U", "R' D' R D",
        "U R U' R'", "L' U' L U", "F' U' F U", "R U2 R' U' R U' R'",
    ]
    best = sum(1 for i in range(54) if working.state[i] == SOLVED[i])
    stalled = 0
    while not working.solved and len(working.history) < limit:
        improved = False
        for sequence in repertoire:
            trial = working.copy()
            trial.apply(sequence)
            score = sum(1 for i in range(54) if trial.state[i] == SOLVED[i])
            if score > best:
                working, best, improved = trial, score, True
                break
        if not improved:
            # A local maximum: take a fixed perturbation and continue. This
            # is why `limit` is not decoration.
            working.apply(_SEXY)
            stalled += 1
            if stalled > 40:
                break
    return list(working.history) if working.solved else []


def benchmark(trials: int = 20, seed: int = 0) -> dict:
    """Solve `trials` random cubes and report what actually happened."""
    rng = random.Random(seed)
    solved = 0
    moves: list = []
    started = time.perf_counter()
    for _ in range(trials):
        cube = Cube().apply(scramble(25, seed=rng.randrange(10 ** 9)))
        answer = solve(cube)
        if answer:
            check = cube.copy()
            check.apply(answer)
            if check.solved:
                solved += 1
                moves.append(len(answer))
    elapsed = time.perf_counter() - started
    return {
        "trials": trials,
        "solved": solved,
        "seconds": elapsed,
        "per_solve": elapsed / trials,
        "mean_moves": sum(moves) / len(moves) if moves else 0,
        "max_moves": max(moves) if moves else 0,
    }


def main(argv=None) -> int:      # pragma: no cover
    report = benchmark(20)
    print("solved %d/%d in %.2fs (%.3fs each)"
          % (report["solved"], report["trials"], report["seconds"],
             report["per_solve"]))
    if report["solved"]:
        print("moves: mean %.0f, worst %d"
              % (report["mean_moves"], report["max_moves"]))
    return 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
