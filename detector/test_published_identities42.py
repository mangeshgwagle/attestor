#!/usr/bin/env python3
"""The identities the documentation publishes must be the ones the code computes.

Why this test exists
--------------------
README, RELEASE_NOTES_4.2 and VERIFICATION_4.2 each print an exact analyzer
build SHA-256 and a profile/report SHA-256 pair per compiled profile, and the
prose around them says those identities change with the exact detector bytes.
Nothing checked that. They had already drifted: the documented analyzer build
was `88b5f71d...` while `detect.py` actually hashed to something else entirely,
and all three profile pairs were stale with it.

For a product whose whole claim is content-addressed, replayable evidence, a
published identity that does not match the artifact is the worst kind of wrong
-- it is confidently checkable and confidently false. `test_variant414` already
pins the code side, so a change to `detect.py` cannot pass unnoticed there. This
pins the *documentation* side, which is the half that silently rotted.

How it fails
------------
Two directions, both of which the drift above would have caught:

* a current identity missing from a document means the document was not updated
  after the detector changed;
* an unrecognised 64-hex string in a document means a stale identity is still
  sitting there. That is the case that matters, because a leftover digest still
  looks authoritative to a reader.

`ALLOWED_UNRELATED` exists for digests that are genuinely not derived from the
detector -- a fixed artifact file's own hash. It is a short, explicit list
rather than a pattern, so adding to it is a deliberate act.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import variant414  # noqa: E402


ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCUMENTS = ("README.md", "RELEASE_NOTES_4.2.md", "VERIFICATION_4.2.md")
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")

# Digests published in the documentation that do not derive from `detect.py`:
# the blind-escape-arena artifact is a fixed file with its own SHA-256 and its
# own checkpoint, and neither moves when the rule engine does.
ALLOWED_UNRELATED = frozenset({
    "4135168f50c4b8e465d4f7e44ecd62b2cc259ba5b3d8b0376da84cffaa941bac",
    "c0eafd4c302722ca6d12157babfbaf9274100b0f1d652aa11fe26909008bf8d1",
})


def computed_identities() -> dict[str, str]:
    """Every identity the documentation is expected to reproduce."""
    identities = {"analyzer build": variant414.ANALYZER_BUILD_SHA256}
    for profile in variant414.COMPILED_PROFILES:
        identities["%s profile" % profile.slug] = variant414.profile_identity(profile)
        identities["%s report" % profile.slug] = (
            variant414.selection_report(profile)["report_sha256"])
    return identities


class PublishedIdentities(unittest.TestCase):
    def setUp(self):
        self.identities = computed_identities()

    def test_there_are_seven_identities_to_publish(self):
        """One analyzer build plus a profile/report pair per compiled profile."""
        self.assertEqual(1 + 2 * len(variant414.COMPILED_PROFILES),
                         len(self.identities))

    def test_every_document_publishes_the_current_identities(self):
        for name in DOCUMENTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            present = set(HEX64.findall(text))
            for label, digest in self.identities.items():
                with self.subTest(document=name, identity=label):
                    self.assertIn(
                        digest, present,
                        "%s does not publish the current %s identity; it was "
                        "not updated after the detector changed" % (name, label))

    def test_no_document_carries_a_stale_identity(self):
        """A leftover digest still reads as authoritative, so it must fail."""
        known = set(self.identities.values()) | ALLOWED_UNRELATED
        for name in DOCUMENTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            unknown = sorted(set(HEX64.findall(text)) - known)
            with self.subTest(document=name):
                self.assertEqual(
                    [], unknown,
                    "%s publishes %d SHA-256 value(s) that are neither a "
                    "current identity nor a known unrelated artifact digest: %s"
                    % (name, len(unknown), unknown))

    def test_the_analyzer_identity_is_the_detector_file_hash(self):
        """The same equality `test_variant414` asserts, restated at this seam.

        Kept here so this file fails on its own terms if the constant and the
        file ever diverge: a documentation check that trusted a stale constant
        would confirm the wrong number in three documents at once.
        """
        import hashlib
        actual = hashlib.sha256(
            (ROOT / "detector" / "detect.py").read_bytes()).hexdigest()
        self.assertEqual(variant414.ANALYZER_BUILD_SHA256, actual)


if __name__ == "__main__":
    unittest.main()
