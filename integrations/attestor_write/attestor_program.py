"""Attestor assembles a whole program out of synthesized parts.

`attestor_synth` finds one expression. That is not a program -- it has no
imports, no entry point, no way to be run. This turns a set of named tasks
into a module you can execute: a docstring, whatever imports the parts
actually need, one function per task, a `main` that dispatches on argv, and
the `__name__` guard.

Nothing here is a template in the sense `codegen.py` is. The bodies are
searched for, and the module is assembled around whatever the search
returned -- imports appear only because a synthesized body used `functools`,
and the dispatch table is built from the tasks that were solved.

Three gates, in order, and the third is the one that matters:

1. every task must synthesize, or the program is not emitted at all;
2. Attestor's analyzer must find nothing in the assembled file;
3. the file must **run** -- it is executed in a subprocess and its own
   examples are replayed through the entry point.

A file that passes an analyzer and then crashes on import is not a program,
so the last gate is not optional. It is a subprocess rather than an `exec`
so a syntax error, an import loop, or a hang is caught as a failure here
rather than taking this process down with it.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve()
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

import attestor_polish as polish  # noqa: E402
import attestor_synth as syn      # noqa: E402
import attestor_write             # noqa: E402

__all__ = ["Task", "Chain", "ProgramResult", "build_program", "write_program",
           "solve", "RUN_TIMEOUT", "SEARCH_BUDGET", "999999_SIZE"]

#: Seconds a single task may spend being searched for before the escalation
#: gives up. Wall-clock rather than a node count: the cost of a level varies
#: enormously with the grammar, and a caller cares about waiting, not nodes.
SEARCH_BUDGET = 20.0
#: The largest program the escalation will reach for on its own.

#: A synthesized program is straight-line and finite, so anything slower
#: than this is a defect in the assembly, not a slow program.
RUN_TIMEOUT = 30


@dataclass
class Task:
    """One function the program should contain, given by examples."""

    name: str
    examples: tuple
    ops: tuple = syn.INT_OPS
    #: The largest program to consider. None means "let the escalation
    #: decide", which is the usual case -- a caller should not have to know
    #: that a fold is size 6. Setting it is a *cap* and is honoured as one:
    #: it briefly acted as a floor instead, so a task deliberately given a
    #: tiny budget was solved anyway and two tests that asserted failure
    #: started passing for the wrong reason.
    max_size: int | None = None
    loops: bool = False
    #: One line for the docstring. Without it the function says
    #: how many examples it came from, which is true but dull.
    summary: str | None = None

    def __post_init__(self):
        if not self.name.isidentifier():
            raise ValueError("%r is not a usable function name" % self.name)
        if not self.examples:
            raise ValueError("task %r has no examples" % self.name)


@dataclass
class Chain:
    """One function built by feeding each step's result into the next.

    The steps name tasks in the same program, applied left to right, so
    `Chain("report", ("keep_evens", "total"))` emits a function that filters
    and then sums. Nothing is synthesized for the chain itself -- it is
    composition of parts that were, which is why a chain costs nothing to
    search and can be arbitrarily long.

    `examples` are optional and end-to-end. They are worth giving: the parts
    can each be right while the composition is nonsense, because nothing
    checks that step two accepts what step one produces. Supply them and the
    run gate replays the whole chain.
    """

    name: str
    steps: tuple
    examples: tuple = ()
    summary: str | None = None

    def __post_init__(self):
        if not self.name.isidentifier():
            raise ValueError("%r is not a usable function name" % self.name)
        if len(self.steps) < 2:
            raise ValueError("a chain needs at least two steps")


def solve(task, budget: float = SEARCH_BUDGET,
    """Search harder and harder until it finds one or runs out of time.

    The caller used to have to know that `2x+1` is size 5 and a fold is size
    6, and guess wrong. This escalates instead: cheapest configuration
    first, widening only when the cheap one is exhausted.

    Order matters. Loops multiply the search by the size of the body pool,
    so every size is tried without them before any size is tried with them --
    a loop-free program of size 6 is found far faster than a looping one of
    size 4, and if both exist the caller wants the one that arrives first.
    """
    import time

    started = time.monotonic()
    ceiling = hard_max if task.max_size is None else task.max_size
    attempts = 0
    for loops in ((False, True) if task.loops else (False,)):
        for size in range(2, ceiling + 1):
            if time.monotonic() - started > budget:
                return None, attempts
            attempts += 1
            program = syn.synthesize(task.examples, ops=task.ops,
                                     max_size=size, loops=loops)
            if program is not None:
                return program, attempts
    return None, attempts


@dataclass
class ProgramResult:
    source: str | None = None
    solved: dict = field(default_factory=dict)
    unsolved: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    ran: bool = False
    output: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.source) and not self.unsolved and not self.findings \
            and self.ran

    def summary(self) -> str:
        if self.ok:
            return ("program written: %d function(s), analyzer clean, "
                    "executed successfully." % len(self.solved))
        why = []
        if self.unsolved:
            why.append("%d task(s) not synthesized: %s"
                       % (len(self.unsolved), ", ".join(self.unsolved)))
        if self.findings:
            why.append("%d finding(s) in the assembled file" % len(self.findings))
        if self.source and not self.ran:
            why.append("the file did not run")
        return "not emitted -- " + "; ".join(why or ["unknown"])


_HEADER = '''"""%s

Written by Attestor: every function body below was found by searching for a
program that reproduces the examples it was given, not selected from a
template. The dispatch table lists what was solved.
"""
'''


def _imports_for(bodies) -> list[str]:
    """Only what the synthesized bodies actually reference."""
    joined = "\n".join(bodies)
    needed = []
    if "functools." in joined:
        needed.append("import functools")
    if "itertools." in joined:
        needed.append("import itertools")
    return needed


def _render_main(names) -> str:
    rows = "\n".join('    "%s": %s,' % (n, n) for n in names)
    return (
        "COMMANDS = {\n%s\n}\n\n\n"
        "def main(argv=None):\n"
        "    argv = list(sys.argv[1:] if argv is None else argv)\n"
        "    if not argv or argv[0] not in COMMANDS:\n"
        "        sys.stdout.write(\"usage: %%s {%%s} VALUE\\n\"\n"
        "                         %% (\"program\", \"|\".join(sorted(COMMANDS))))\n"
        "        return 2\n"
        "    name, rest = argv[0], argv[1:]\n"
        "    if not rest:\n"
        "        sys.stdout.write(\"missing argument for %%s\\n\" %% name)\n"
        "        return 2\n"
        "    value = _parse(rest[0])\n"
        "    sys.stdout.write(repr(COMMANDS[name](value)) + \"\\n\")\n"
        "    return 0\n\n\n"
        "def _parse(text):\n"
        "    \"\"\"Arguments arrive as text; the functions want values.\n\n"
        "    Written as a test rather than a caught ValueError because Attestor\n"
        "    reports `except: pass` -- and it was right to: this ran on the\n"
        "    assembled file and refused to emit it.\n"
        "    \"\"\"\n"
        "    if text.lstrip(\"-\").isdigit():\n"
        "        return int(text)\n"
        "    if text.startswith(\"[\") and text.endswith(\"]\"):\n"
        "        inner = text[1:-1].strip()\n"
        "        if not inner:\n"
        "            return []\n"
        "        return [_parse(part.strip()) for part in inner.split(\",\")]\n"
        "    return text\n\n\n"
        "if __name__ == \"__main__\":\n"
        "    raise SystemExit(main())\n" % rows)


def _render_chain(chain) -> str:
    """A function that feeds each step's result into the next.

    Named from the chain's own examples where it has them, so the pipeline
    reads like the parts do rather than reverting to `value` the moment
    composition starts.
    """
    param = "value"
    hint = ""
    if chain.examples:
        param = polish.name_for(chain.examples)
        given, wanted = polish.hint_for(chain.examples)
        if given:
            param = "%s: %s" % (param, given)
        if wanted:
            hint = " -> %s" % wanted
    bare = param.split(":")[0].strip()
    doc = chain.summary or "%s, one step at a time." % " then ".join(chain.steps)
    lines = ["def %s(%s)%s:" % (chain.name, param, hint),
             '    """%s"""' % doc]
    # The parameter name describes the input, and only the input. Reusing it
    # for every step left `numbers = total(numbers)` -- an integer in a
    # variable called `numbers`, which is worse than the `value` it replaced.
    # An intermediate gets a neutral name, and the last step is returned
    # directly rather than parked first.
    source = bare
    for step in chain.steps[:-1]:
        lines.append("    result = %s(%s)" % (step, source))
        source = "result"
    lines.append("    return %s(%s)" % (chain.steps[-1], source))
    return "\n".join(lines) + "\n"


def build_program(tasks, title: str = "A program Attestor wrote.",
                  chains=(), budget: float = SEARCH_BUDGET):
    """Synthesize every task, compose the chains, assemble a module.

    Returns (source, solved, unsolved). Source is None when any task was
    not solved -- a program missing a function it was asked for is not a
    partial success, it is a different program. A chain naming a step that
    does not exist is the same kind of failure and fails the same way.
    """
    solved: dict = {}
    unsolved: list = []
    bodies: list = []
    for task in tasks:
        program, _attempts = solve(task, budget=budget)
        if program is None:
            unsolved.append(task.name)
            continue
        source = polish.polish(syn.render(program, name=task.name),
                               task.examples, name=task.name,
                               summary=task.summary)
        # render() adds its own imports; the module hoists them instead.
        body = source.split("def ", 1)[1]
        bodies.append("def " + body.rstrip() + "\n")
        solved[task.name] = program

    chains = list(chains)
    for chain in chains:
        missing = [s for s in chain.steps if s not in solved]
        if missing:
            unsolved.append("%s (needs %s)" % (chain.name, ", ".join(missing)))
            continue
        bodies.append(_render_chain(chain))

    if unsolved:
        return None, solved, unsolved

    names = list(solved) + [c.name for c in chains]
    header = _HEADER % title
    imports = _imports_for(bodies) + ["import sys"]
    parts = [header, "", "\n".join(sorted(set(imports))), "", ""]
    parts.extend("\n" + b for b in bodies)
    parts.append("\n" + _render_main(names))
    return "\n".join(parts), solved, unsolved


def _replay(path: Path, tasks) -> tuple[bool, str]:
    """Run the emitted file for real and check it answers its own examples."""
    for task in tasks:
        value, expected = task.examples[0]
        # A string argument goes on the command line as itself. Passing
        # repr() wrapped it in quotes, the program parsed those quotes as
        # part of the text, and `shout('hi')` came back as "'HI'" -- a
        # defect in the plumbing between the CLI and the functions that no
        # analyzer would ever see, and the reason this gate runs the file.
        argument = value if isinstance(value, str) else repr(value)
        completed = subprocess.run(
            [sys.executable, "-B", str(path), task.name, argument],
            capture_output=True, text=True, timeout=RUN_TIMEOUT, check=False)
        if completed.returncode != 0:
            return False, "%s exited %d: %s" % (
                task.name, completed.returncode, completed.stderr.strip()[:200])
        got = completed.stdout.strip()
        if got != repr(expected):
            return False, "%s(%r) printed %s, expected %s" % (
                task.name, value, got, repr(expected))
    return True, "replayed %d entry point(s)" % len(tasks)


def write_program(tasks, title: str = "A program Attestor wrote.",
                  filename: str = "program.py", chains=(),
                  budget: float = SEARCH_BUDGET) -> ProgramResult:
    """Synthesize, assemble, analyze, and run. All four, or nothing."""
    tasks = list(tasks)
    chains = list(chains)
    source, solved, unsolved = build_program(tasks, title=title, chains=chains,
                                             budget=budget)
    result = ProgramResult(solved=solved, unsolved=unsolved)
    if source is None:
        return result

    checked = attestor_write.write({filename: source})
    if not checked.clean:
        result.findings = list(checked.remaining)
        result.source = source
        return result
    source = checked.files[filename]
    result.source = source

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / filename
        path.write_text(source, encoding="utf-8")
        replayable = list(tasks) + [c for c in chains if c.examples]
        try:
            ran, note = _replay(path, replayable)
        except subprocess.TimeoutExpired:
            ran, note = False, "the program did not finish in %ds" % RUN_TIMEOUT
    result.ran = ran
    result.output = note
    return result


def main(argv=None) -> int:      # pragma: no cover - demonstration entry
    tasks = [
        Task("keep_evens",
             (([1, 2, 3, 4], [2, 4]), ([1, 3], []), ([6], [6])),
             ops=syn.LIST_OPS, loops=True),
        Task("squares", (([1, 2, 3], [1, 4, 9]), ([4], [16])),
             ops=syn.LIST_OPS, loops=True),
        Task("total", (([1, 2, 3], 6), ([10], 10), ([], 0)),
             ops=syn.LIST_OPS),
    ]
    chains = [
        Chain("sum_of_even_squares", ("keep_evens", "squares", "total"),
              examples=(([1, 2, 3, 4], 20), ([5], 0), ([2, 6], 40))),
    ]
    result = write_program(tasks, chains=chains,
                           title="Three parts and a pipeline built from them.")
    print(result.summary())
    if result.output:
        print(" ", result.output)
    if result.source:
        print("-" * 60)
        print(result.source, end="")
    return 0 if result.ok else 1


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
