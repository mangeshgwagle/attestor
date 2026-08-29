#!/usr/bin/env python3
"""Who Attestor is, computed from what he actually contains.

The problem this solves
-----------------------
Two different things go wrong when a tool describes itself.

The first is the local model. Told in a system prompt that it is Attestor, one
model here opened three replies in a row with "Qwythos here, built by Empero
AI". Identity training is not reachable by instruction, so asking harder does
not work; `attestor_chat.strip_persona` removes the greeting after the fact.

The second is worse and quieter: *remembered* facts drift. A rule count stated
once gets restated, and restated again, long after it stopped being true --
during this project "15,338 rules" was repeated confidently when the real
figure was 89. Nothing caught it, because nothing was measuring it; it was
just a number that had been said before.

So nothing here is written down. Every field is read out of the artifact that
defines it at the moment it is asked for:

    detect.RULES        ──▶ how many rules, and for which CWEs
    neural_gate_model   ──▶ the gate's shape, digest and held-out accuracy
    VERSION             ──▶ which Attestor this is

If a rule is added, the card says so on the next call. If the gate is
retrained, the digest changes. There is no path by which this file can assert
something Attestor does not contain, because it does not contain any assertions.

What "remembering who he is" means here
---------------------------------------
Not the model's self-description, which is not Attestor's to give. Attestor's identity
is his provenance: which rules ran, which artifact scored, what the score is
not. That travels with every answer, so a reader can check it rather than
believe it -- the same reason `neural_gate.infer` returns `model_sha256` and
its own limitations alongside every score.
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

SCHEMA = "attestor.identity/1.0"

# Attestor makes no claim of absence. This is the one part of the card that is
# written rather than measured, because it is a statement about what the
# measurements *cannot* support -- and that does not change when the rules do.
DISCLAIMS = (
    "a finding is evidence of a defect; no finding is not evidence of safety",
    "the gate's score is a learned opinion, not a probability and not a finding",
    "coverage is per-rule: a class with no rule is unexamined, not clean",
)


class IdentityError(RuntimeError):
    """Attestor's own artifacts could not be read."""


def _detector_on_path(detector: str) -> None:
    if detector not in sys.path:
        sys.path.insert(0, detector)


def rules_fact(detector: str) -> dict[str, Any]:
    """Rule count and CWE coverage, from the loaded module."""
    _detector_on_path(detector)
    import detect

    rules = getattr(detect, "RULES", [])
    mapped = getattr(detect, "RULE_CWE", {})
    languages: set[str] = set()
    for rule in rules:
        languages.update(getattr(rule, "langs", ()) or ())
    return {"rules": len(rules),
            "cwes_mapped": len(mapped),
            "languages": sorted(languages - {"*"})}


def gate_fact(detector: str) -> dict[str, Any]:
    """The gate's shape and provenance, from the artifact itself."""
    path = pathlib.Path(detector) / "neural_gate_model.json"
    if not path.is_file():
        return {"present": False}
    _detector_on_path(detector)
    import neural_gate

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
        resolved = neural_gate.load_model(artifact)
    except (ValueError, neural_gate.NeuralGateError) as error:
        # A gate that will not validate is reported as absent rather than
        # described, because describing it would mean trusting fields the
        # digest check just refused.
        return {"present": False, "error": str(error)[:100]}

    return {
        "present": True,
        "shape": "%d x %d" % (resolved.get("feature_dim"),
                              resolved.get("hidden")),
        "parameters": (resolved["feature_dim"] * resolved["hidden"]
                       + 2 * resolved["hidden"] + 1),
        "sha256": resolved["model_sha256"][:16],
        "held_out_accuracy": artifact.get("held_out_accuracy_percent"),
        "held_out_auc": artifact.get("held_out_auc"),
        # The control matters more than the accuracy. A model scoring 98% on
        # real labels and 50% on shuffled ones learned the task; one scoring
        # well on both learned the corpus's scaffolding.
        "shuffled_label_control": artifact.get("shuffled_label_control_percent"),
        "trained_on": (artifact.get("training_data") or "")[:120],
    }


def version_fact(root: str) -> str:
    path = pathlib.Path(root) / "VERSION"
    try:
        return path.read_text(encoding="utf-8").strip()[:32]
    except OSError:
        return "unknown"


def card(detector: str, root: str | None = None) -> dict[str, Any]:
    """Everything Attestor can say about himself, measured now."""
    root = root or str(pathlib.Path(detector).parent)
    try:
        facts = rules_fact(detector)
    except ImportError as error:
        raise IdentityError("cannot read detect.py: %s" % error) from error
    return {"schema": SCHEMA,
            "name": "Attestor",
            "version": version_fact(root),
            **facts,
            "gate": gate_fact(detector),
            "disclaims": list(DISCLAIMS)}


def render(facts: dict[str, Any]) -> str:
    """The card as a block to ride along with every turn."""
    lines = ["IDENTITY (measured from this installation, not remembered):",
             "- You are Attestor %s, a static analyser." % facts["version"],
             "- You have %d rules covering %d CWEs%s."
             % (facts["rules"], facts["cwes_mapped"],
                (" across " + ", ".join(facts["languages"]))
                if facts["languages"] else "")]
    gate = facts["gate"]
    if gate.get("present"):
        lines.append(
            "- Your neural gate is %s (%d parameters, sha %s), %s%% held-out "
            "accuracy against a %s%% shuffled-label control."
            % (gate["shape"], gate["parameters"], gate["sha256"],
               gate["held_out_accuracy"], gate["shuffled_label_control"]))
    else:
        lines.append("- You have no loadable neural gate on this installation.")
    for item in facts["disclaims"]:
        lines.append("- %s" % item)
    lines.append("Never state a number about yourself that is not above.")
    return "\n".join(lines)


def footer(facts: dict[str, Any]) -> str:
    """A one-line provenance stamp for the reader, not for the model."""
    gate = facts["gate"]
    return ("-- Attestor %s | %d rules / %d CWEs | gate %s"
            % (facts["version"], facts["rules"], facts["cwes_mapped"],
               gate["sha256"] if gate.get("present") else "absent"))


def main(argv: list[str] | None = None) -> int:
    import argparse

    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        facts = card(args.detector)
    except IdentityError as error:
        print("error: %s" % error)
        return 1
    print(json.dumps(facts, indent=2) if args.json else render(facts))
    print()
    print(footer(facts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
