#!/usr/bin/env python3
"""
Tests for the AttestorVonLuneberg persona layer (attestor.py + personalities.py).

These check the *wrapper*, not the detection engine (that's test_detector.py):
the two personalities, the seeded determinism, the profanity toggle, and the
guarantee that the persona never alters the technical content of a finding.
"""
import io
import os
import random
import unittest
from contextlib import redirect_stdout

import detect
import attestor
import personalities as P

C_SAMPLE = os.path.join(detect.CORPUS, "realworld", "upload.c")


def run_attestor(args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = attestor.main(args)
    return code, buf.getvalue()


class AttestorTests(unittest.TestCase):
    def test_two_personalities_exist_and_attestor_is_a_he(self):
        self.assertEqual(set(P.PERSONAS), {"helpful", "savage"})
        for persona in P.PERSONAS.values():
            self.assertEqual(persona.pronoun, "he")

    def test_persona_is_random_but_seedable(self):
        # Same seed -> same persona (reproducible); the choice is otherwise random.
        a, _ = attestor.pick_persona(0)
        b, _ = attestor.pick_persona(0)
        self.assertEqual(a.key, b.key)
        keys = {attestor.pick_persona(s)[0].key for s in range(30)}
        self.assertEqual(keys, {"helpful", "savage"})   # both do occur

    def test_same_findings_regardless_of_personality(self):
        # The engine output is what matters; persona must not change which bugs
        # are reported. Compare a helpful run and a savage run by rule+line.
        import re

        def rules_lines(text):
            got = set()
            for line in text.splitlines():
                m = re.match(r"\S+:(\d+)\s+\[[A-Z]+\]\s+(\S+)", line)
                if m:
                    got.add((int(m.group(1)), m.group(2)))
            return got

        _, help_out = run_attestor(["--no-color", "--seed", str(_seed_for("helpful")), C_SAMPLE])
        _, sav_out = run_attestor(["--no-color", "--seed", str(_seed_for("savage")), C_SAMPLE])
        self.assertEqual(rules_lines(help_out), rules_lines(sav_out))
        self.assertTrue(rules_lines(help_out))         # and it's non-empty

    def test_profanity_on_by_default_and_muzzled_by_sfw(self):
        sav_seed = str(_seed_for("savage"))
        _, loud = run_attestor(["--no-color", "--seed", sav_seed, C_SAMPLE])
        _, clean = run_attestor(["--no-color", "--sfw", "--seed", sav_seed, C_SAMPLE])
        # real, uncensored profanity in the default savage output...
        self.assertTrue(any(tok in loud.lower() for tok in ("fuck", "shit", "knobhead")))
        # ...and the strong words are gone under --sfw
        for tok in ("fuck", "shit", "knobhead"):
            self.assertNotIn(tok, clean.lower())

    def test_persona_preserves_engine_message_and_fix(self):
        findings = detect.scan_file(C_SAMPLE)
        f = findings[0]
        rng = random.Random(0)
        out = P.render_finding(P.HELPFUL, f, rng, sfw=False)
        self.assertIn(f.message, out)          # technical message verbatim
        self.assertIn(f.fix, out)              # fix verbatim
        self.assertIn(f.rule, out)

    def test_meet_mentions_both_faces(self):
        text = attestor.meet()
        self.assertIn(P.HELPFUL.name, text)
        self.assertIn(P.SAVAGE.name, text)


def _seed_for(key):
    for s in range(100):
        if attestor.pick_persona(s)[0].key == key:
            return s
    raise AssertionError(f"no seed produced persona {key}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
