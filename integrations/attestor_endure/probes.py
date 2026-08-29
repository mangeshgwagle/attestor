"""The claims Attestor makes, expressed as things that can be re-measured.

Each probe returns a value, not a verdict. `attestor_endure` records the first
value it sees and reports any later disagreement, so a probe's job is only
to produce the same number every time the claim still holds.

Chosen to be cheap. A probe that takes a minute is a probe that gets
commented out on hour three of a long run, and the whole point is that
nobody is there to uncomment it.
"""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[2]
for extra in ("detector", "integrations/mc_asm", "integrations/attestor_write",
              "integrations/attestor_cube", "integrations/attestor_machine"):
    candidate = str(_ROOT / extra)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from attestor_endure import Probe          # noqa: E402


def _mcasm_backends_agree() -> str:
    """The interpreter and the bytecode VM on a real program.

    fizzbuzz is the right program for this: it exercises EMIT, which is
    where the two engines last disagreed, and no test I wrote caught it
    because every program I invented printed numbers.
    """
    import compiler
    import mc_asm
    source = (_ROOT / "integrations/mc_asm/fizzbuzz.mcasm").read_text(
        encoding="utf-8")
    program = mc_asm.parse(source)
    interpreted = mc_asm.run(program)
    executed = compiler.run_bytecode(compiler.to_bytecode(program))
    return "agree" if interpreted == executed else "DISAGREE"


def _mcasm_word_coverage() -> int:
    """How many of the language's words have a bytecode form."""
    import compiler
    import mc_asm
    structural = {"IF", "ELSE", "END", "DO", "WHILE", "DEF"}
    return sum(1 for word in mc_asm.WORDS
               if word in structural or word in compiler.OPCODES
               or word in compiler.LOWERED)


def _analyzer_rule_count() -> int:
    import detect
    return len(detect.RULES)


def _java_family_detection() -> str:
    """One small Juliet family, measured differentially.

    CWE-336 is 17 held-out pairs -- small enough to run every cycle, and it
    is a real differential measurement rather than a unit test: it fails if
    the rule stops separating the flawed variant from the corrected one.
    """
    import detect
    # The seed shape the rule actually targets: `setSeed(constant)`. My
    # first attempt used `new Random(12345)` and the probe reported BROKEN
    # -- which was the probe being wrong, not the rule. Worth recording,
    # because a probe that tests a shape nothing produces is a probe that
    # will cry wolf for a thousand hours.
    flawed = ("public class A {\n  public void bad() throws Throwable {\n"
              "    SecureRandom r = new SecureRandom();\n"
              "    r.setSeed(12345L);\n  }\n}\n")
    fixed = ("public class A {\n  public void good() throws Throwable {\n"
             "    SecureRandom r = new SecureRandom();\n"
             "    r.setSeed(System.currentTimeMillis());\n  }\n}\n")
    hits_bad = any(f.rule == "java-fixed-seed"
                   for f in detect.scan_source(flawed, "A.java", "java",
                                               deep=True))
    hits_good = any(f.rule == "java-fixed-seed"
                    for f in detect.scan_source(fixed, "A.java", "java",
                                                deep=True))
    return "detects" if (hits_bad and not hits_good) else "BROKEN"


def _synth_renders_what_it_verified() -> str:
    """The synthesizer's contract: emitted text computes the examples.

    This is the one that was silently wrong -- a search that succeeded and
    then rendered a different program.
    """
    import attestor_synth
    examples = ((1, 3), (2, 5), (3, 7), (10, 21))
    program = attestor_synth.synthesize(examples, max_size=5)
    if program is None:
        return "NOT FOUND"
    namespace: dict = {}
    exec(compile(attestor_synth.render(program, name="f"), "f.py", "exec"),  # noqa: S102
         namespace)
    return "correct" if all(namespace["f"](v) == w for v, w in examples) \
        else "RENDER MISMATCH"


def _writer_refuses_what_it_cannot_fix() -> str:
    """Attestor's writer must hold back code it cannot make clean."""
    import attestor_write
    result = attestor_write.write(
        {"x.py": "import subprocess\nsubprocess.run(c, shell=True)\n"})
    return "refuses" if not result.clean else "EMITTED ANYWAY"


def _cube_group_orders() -> str:
    """Known group orders. Currently failing, on purpose.

    `B` is wrong and every pair containing it comes out 126 instead of 105.
    Recording it as a baseline of "3 wrong" means the day someone fixes it,
    this reports drift -- which is the correct behaviour for an improvement
    as much as for a regression.
    """
    import attestor_cube

    def order(sequence, cap=400):
        cube = attestor_cube.Cube()
        for turn in range(1, cap + 1):
            cube.apply(sequence)
            if cube.solved:
                return turn
        return None

    expected = {"R": 4, "R U": 105, "R U R' U'": 6, "R B": 105,
                "B U": 105, "B D": 105, "R L": 4}
    return "%d/%d correct" % (
        sum(1 for seq, want in expected.items() if order(seq) == want),
        len(expected))


def _machine_class_is_stable() -> str:
    """The hardware tier this machine reports. Drifts if the thresholds move."""
    import attestor_machine
    return attestor_machine.probe().machine_class


PROBES = (
    Probe("mcasm.backends_agree", _mcasm_backends_agree,
          "the interpreter and the VM disagreed on EMIT once already"),
    Probe("mcasm.words_compiled", _mcasm_word_coverage,
          "a word losing its bytecode form silently shrinks the language"),
    Probe("analyzer.rule_count", _analyzer_rule_count,
          "a rule vanishing is a coverage loss nothing else reports"),
    Probe("java.cwe336_differential", _java_family_detection,
          "fires on flawed and not on fixed -- the whole criterion"),
    Probe("synth.render_matches", _synth_renders_what_it_verified,
          "emitted source must compute what the search verified"),
    Probe("writer.refuses_unfixable", _writer_refuses_what_it_cannot_fix,
          "a writer that emits what it cannot vouch for is worse than none"),
    Probe("cube.group_orders", _cube_group_orders,
          "known-failing: B is wrong; drift here means someone fixed it"),
    Probe("machine.class", _machine_class_is_stable,
          "the billing tier depends on this staying put"),
)
