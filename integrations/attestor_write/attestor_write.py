"""Attestor writes code that Attestor cannot fault.

Attestor could already emit code: `codegen.py` scaffolds a ~4,000-line service
from a spec, and its docstring promises the output passes both engines at
zero findings. It emits one -- the generated OpenAPI descriptor advertises
an `http://` server URL. The promise was true when it was written and then
drifted, because nothing re-checked it.

That drift is the whole argument for this module. Generation is the cheap
half; anyone can emit a template. What Attestor has that a template does not is
a *verifier* -- 124 rules measured differentially at 0.0% false positives.
So the writer is built as a loop rather than a generator:

    draft  ->  scan with Attestor  ->  repair what is repairable  ->  scan again
                                        |
                                        +-- still faulted? refuse to emit

The guarantee is deliberately narrow and worth stating exactly: emitted code
carries no finding from a rule Attestor has. That is not "the code is correct"
and it is not "the code is secure". It is the one claim the analyzer can
actually support, and unlike a docstring it is re-established on every run.

Repairs are conservative. Each one is a rewrite whose meaning is obvious
from the finding, and anything else is reported rather than guessed at --
a writer that silently "fixes" code by changing what it does is worse than
one that refuses.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve()
_DETECTOR = _HERE.parent.parent.parent / "detector"
if str(_DETECTOR) not in sys.path:
    sys.path.insert(0, str(_DETECTOR))

import detect  # noqa: E402

__all__ = [
    "Draft",
    "WriteResult",
    "Repair",
    "REPAIRS",
    "scan_text",
    "repair_once",
    "write",
    "MAX_ROUNDS",
]

#: A repair may expose a further finding, so the loop runs more than once --
#: but a repair that keeps finding work forever is a bug in the repair, not a
#: reason to keep going.
MAX_ROUNDS = 4


@dataclass(frozen=True)
class Repair:
    """One mechanical rewrite, keyed to the rule that asks for it."""

    rule: str
    pattern: re.Pattern
    replacement: str
    note: str

    def apply(self, line: str) -> str | None:
        fixed, count = self.pattern.subn(self.replacement, line)
        return fixed if count and fixed != line else None


REPAIRS: tuple[Repair, ...] = (
    Repair(
        rule="insecure-http-url",
        pattern=re.compile(r'(["\'])http://'),
        replacement=r"\1https://",
        note="http:// -> https://",
    ),
    Repair(
        rule="weak-hash",
        pattern=re.compile(r"\bhashlib\s*\.\s*(?:md5|sha1)\s*\("),
        replacement="hashlib.sha256(",
        note="md5/sha1 -> sha256",
    ),
    Repair(
        rule="py-return-in-finally",
        pattern=re.compile(r"\A(\s*)return\b.*$"),
        replacement=r"\1pass  # return removed: it discards the pending exception",
        note="dropped a return inside finally",
    ),
)

_BY_RULE: dict[str, list[Repair]] = {}
for _repair in REPAIRS:
    _BY_RULE.setdefault(_repair.rule, []).append(_repair)


@dataclass
class Draft:
    """A file on its way out: a path and the text proposed for it."""

    path: str
    text: str


@dataclass
class WriteResult:
    """What the writer produced, and what it could not fix.

    `clean` is the only thing a caller should branch on. It means every
    emitted file was scanned after the last edit and nothing was reported.
    """

    files: dict[str, str] = field(default_factory=dict)
    repairs: list[str] = field(default_factory=list)
    remaining: list[str] = field(default_factory=list)
    rounds: int = 0

    @property
    def clean(self) -> bool:
        return not self.remaining

    def summary(self) -> str:
        if self.clean:
            return ("%d file(s) written, %d repair(s), no findings left."
                    % (len(self.files), len(self.repairs)))
        return ("%d file(s) held back: %d finding(s) Attestor has no safe repair "
                "for.\n  %s" % (len(self.files), len(self.remaining),
                                "\n  ".join(self.remaining)))


def _language(path: str) -> str:
    return detect.language_for(path) or "text"


def scan_text(path: str, text: str):
    """Attestor's findings for a proposed file, without writing it anywhere."""
    return detect.scan_source(text, path, _language(path), deep=True)


def repair_once(path: str, text: str) -> tuple[str, list[str], list[str]]:
    """One pass: scan, rewrite what is mechanically repairable.

    Returns the new text, the repairs made, and the findings left behind.
    Edits are applied by line number from the finding, so a repair can never
    touch a line Attestor did not object to.
    """
    lines = text.split("\n")
    made: list[str] = []
    left: list[str] = []
    for finding in scan_text(path, text):
        index = finding.line - 1
        if not 0 <= index < len(lines):
            left.append("%s:%d %s" % (path, finding.line, finding.rule))
            continue
        for repair in _BY_RULE.get(finding.rule, ()):
            fixed = repair.apply(lines[index])
            if fixed is not None:
                lines[index] = fixed
                made.append("%s:%d %s (%s)"
                            % (path, finding.line, finding.rule, repair.note))
                break
        else:
            left.append("%s:%d %s -- %s"
                        % (path, finding.line, finding.rule, finding.message))
    return "\n".join(lines), made, left


def write(drafts) -> WriteResult:
    """Run drafts through scan-and-repair until clean or out of rounds.

    Accepts a mapping of path -> text, or an iterable of Draft. Files are
    only placed in the result once they carry no finding; anything still
    faulted is named in `remaining` and the result is not clean.
    """
    if hasattr(drafts, "items"):
        drafts = [Draft(path, text) for path, text in drafts.items()]
    drafts = list(drafts)

    result = WriteResult()
    for draft in drafts:
        text = draft.text
        made_total: list[str] = []
        left: list[str] = []
        rounds = 0
        for rounds in range(1, MAX_ROUNDS + 1):
            text, made, left = repair_once(draft.path, text)
            made_total.extend(made)
            if not made:
                # Nothing changed this round, so another round cannot help.
                break
        result.rounds = max(result.rounds, rounds)
        result.repairs.extend(made_total)
        if left:
            result.remaining.extend(left)
        else:
            result.files[draft.path] = text
    return result


def main(argv=None) -> int:
    """Scan and repair files in place-ish: prints, never overwrites silently."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: attestor_write.py FILE [FILE...]")
        return 2
    drafts = []
    for name in argv:
        path = Path(name)
        if not path.is_file():
            print("not a file: %s" % name)
            return 2
        drafts.append(Draft(str(path), path.read_text(encoding="utf-8")))
    result = write(drafts)
    for line in result.repairs:
        print("repaired  %s" % line)
    for line in result.remaining:
        print("UNFIXED   %s" % line)
    print(result.summary())
    return 0 if result.clean else 1


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
