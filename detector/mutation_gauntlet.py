#!/usr/bin/env python3
"""
mutation_gauntlet.py -- mutate code and see whether Attestor notices.

Generated code that looks clean can still hide blind spots. The gauntlet injects
small, realistic bugs, runs Attestor plus optional behavior tests, and turns any
surviving mutant into a new detector-rule target.
"""
from __future__ import annotations

import argparse
import ast
import collections
import os
import re

import crucible
import detect
import harvest
import quality


MUTATORS = [
    {
        "id": "none-identity-regression",
        "expected_rule": "py-eq-none",
        "pattern": re.compile(r"\bis\s+None\b"),
        "replacement": "== None",
        "why": "turn identity None check into overloaded equality",
    },
    {
        "id": "tls-verification-disabled",
        "expected_rule": "tls-verify-disabled",
        "pattern": re.compile(r"\bverify\s*=\s*True\b"),
        "replacement": "verify=False",
        "why": "disable TLS certificate verification",
    },
    {
        "id": "weak-hash-md5",
        "expected_rule": "weak-hash",
        "pattern": re.compile(r"\bhashlib\.sha256\b"),
        "replacement": "hashlib.md5",
        "why": "downgrade hashing to MD5",
    },
    {
        "id": "debug-enabled",
        "expected_rule": "debug-enabled",
        "pattern": re.compile(r"\b(debug|DEBUG)\s*=\s*False\b"),
        "replacement": r"\1=True",
        "why": "turn production debug mode on",
    },
    {
        "id": "assert-validation",
        "expected_rule": "py-assert-validation",
        "pattern": re.compile(r"\bif\s+(.+?):\n(\s+)raise\s+ValueError\((.*?)\)"),
        "replacement": r"assert not (\1)",
        "why": "replace runtime validation with an optimizable assert",
    },
    {
        "id": "unsafe-yaml-loader",
        "expected_rule": "py-yaml-load",
        "pattern": re.compile(r"\byaml\.safe_load\b"),
        "replacement": "yaml.load",
        "why": "replace the safe YAML loader with an object-constructing loader",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "subprocess-shell-enabled",
        "expected_rule": "py-subprocess-shell",
        "pattern": re.compile(r"\bshell\s*=\s*False\b"),
        "replacement": "shell=True",
        "why": "enable shell interpretation for a subprocess call",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "strict-equality-weakened",
        "expected_rule": "js-loose-equality",
        "pattern": re.compile(r"(?<![=!])===(?!=)"),
        "replacement": "==",
        "why": "weaken strict JavaScript equality and allow coercion",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "safe-dom-write-weakened",
        "expected_rule": "js-innerhtml",
        "pattern": re.compile(r"\.textContent\b"),
        "replacement": ".innerHTML",
        "why": "replace a text-only DOM write with HTML interpretation",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
]

# ---------------------------------------------------------------------------
# Equivalence mutators.
#
# Every mutator above injects a defect in the exact shape its target rule was
# written for, so catching it proves only that the rule matches its own
# fixture.  These inject the *same* defect in a spelling the canonical pattern
# cannot reach: a value reached through a name, an aliased or reflective
# import, a reversed comparison.  The defect is identical; only the surface
# differs.  A survivor here is a genuine blind spot rather than a missing
# literal, and it is exactly the class that needs aliasing or dataflow
# awareness to see -- which is to say, the class worth learning.
# ---------------------------------------------------------------------------
EQUIVALENCE_MUTATORS = [
    {
        "id": "weak-hash-reflective",
        "expected_rule": "weak-hash",
        "pattern": re.compile(r"\bhashlib\.sha256\b"),
        "replacement": 'getattr(hashlib, "md5")',
        "why": "reach MD5 reflectively so no literal attribute access appears",
        "equivalence_of": "weak-hash-md5",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "weak-hash-aliased-import",
        "expected_rule": "weak-hash",
        "pattern": re.compile(r"\bhashlib\.sha256\b"),
        "replacement": "_digestlib.md5",
        "prelude": "import hashlib as _digestlib",
        "why": "downgrade to MD5 through an aliased module name",
        "equivalence_of": "weak-hash-md5",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "tls-verification-indirect",
        "expected_rule": "tls-verify-disabled",
        "pattern": re.compile(r"\bverify\s*=\s*True\b"),
        "replacement": "verify=_TLS_VERIFY_ENABLED",
        "prelude": "_TLS_VERIFY_ENABLED = False",
        "why": "disable TLS verification through a module-level flag",
        "equivalence_of": "tls-verification-disabled",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "subprocess-shell-indirect",
        "expected_rule": "py-subprocess-shell",
        "pattern": re.compile(r"\bshell\s*=\s*False\b"),
        "replacement": "shell=_USE_SHELL",
        "prelude": "_USE_SHELL = True",
        "why": "enable shell interpretation through a module-level flag",
        "equivalence_of": "subprocess-shell-enabled",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "debug-enabled-indirect",
        "expected_rule": "debug-enabled",
        "pattern": re.compile(r"\b(debug|DEBUG)\s*=\s*False\b"),
        "replacement": r"\1=_DEBUG_ENABLED",
        "prelude": "_DEBUG_ENABLED = True",
        "why": "turn debug on through a module-level flag",
        "equivalence_of": "debug-enabled",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "unsafe-yaml-loader-reflective",
        "expected_rule": "py-yaml-load",
        "pattern": re.compile(r"\byaml\.safe_load\b"),
        "replacement": 'getattr(yaml, "load")',
        "why": "reach the object-constructing YAML loader reflectively",
        "equivalence_of": "unsafe-yaml-loader",
        "extensions": {".py", ".pyw"},
    },
    {
        "id": "none-identity-reversed",
        "expected_rule": "py-eq-none",
        "pattern": re.compile(r"\b([A-Za-z_]\w*)\s+is\s+None\b"),
        "replacement": r"None == \1",
        "why": "overloaded equality with the operands written the other way round",
        "equivalence_of": "none-identity-regression",
        "extensions": {".py", ".pyw"},
    },
]

MUTATORS = MUTATORS + EQUIVALENCE_MUTATORS


def _blanked_view(source: str, extension: str) -> str:
    """Source with string and comment bodies blanked, aligned to the original.

    The blankers are length-preserving, so an offset means the same thing in
    both views.  If that ever stops holding we return an empty view and every
    offset is treated as live code, which is the pre-check behavior.
    """
    language = detect.language_for("mutant" + extension) or "text"
    blanked = "\n".join(detect.blank(source, language))
    return blanked if len(blanked) == len(source) else ""


def _is_live_code(source: str, blanked: str, offset: int) -> bool:
    """False when this offset sits inside a string literal or a comment."""
    if not blanked or offset >= len(blanked):
        return True
    return not (blanked[offset] == " " and source[offset] != " ")


def _prelude_offset(source: str, extension: str) -> int | None:
    """Where a helper definition can be inserted without breaking the file.

    Python is the only language here with a hard ordering rule: ``from
    __future__`` must precede every other statement, and the module docstring
    must stay first to remain a docstring.  We therefore insert after both.
    ``None`` means the source could not be parsed, so no prelude is safe.
    """
    if extension not in {".py", ".pyw"}:
        return 0
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    end_line = 0
    for node in tree.body:
        docstring = (isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Constant)
                     and isinstance(node.value.value, str))
        future = (isinstance(node, ast.ImportFrom)
                  and node.module == "__future__")
        if not (docstring or future):
            break
        end_line = node.end_lineno or end_line
    offset = 0
    for index, line in enumerate(source.splitlines(keepends=True)):
        if index >= end_line:
            break
        offset += len(line)
    return offset


def mutate(source: str, extension: str = ".py") -> list[dict]:
    """Inject one defect per applicable mutator, in executable code only.

    A pattern that only occurs inside a string or comment is skipped.  Editing
    such a span changes no behavior, so a scanner that stays silent about it is
    correct -- counting it as a survivor invents a blind spot that does not
    exist, and mislabels the row for anything downstream that learns from these
    verdicts.

    A mutator carrying a ``prelude`` also gets a ``baseline_code``: the same
    prelude applied to the *unmutated* source.  Comparing against that keeps
    line numbers aligned, so the inserted helper does not make every
    pre-existing finding look newly introduced.
    """
    blanked = _blanked_view(source, extension)
    insert_at = _prelude_offset(source, extension)
    out = []
    for mut in MUTATORS:
        if mut.get("extensions") and extension not in mut["extensions"]:
            continue
        prelude = mut.get("prelude", "")
        if prelude and insert_at is None:
            continue
        for match in mut["pattern"].finditer(source):
            if not _is_live_code(source, blanked, match.start()):
                continue
            mutated = (source[:match.start()]
                       + match.expand(mut["replacement"])
                       + source[match.end():])
            rec = dict(mut)
            if prelude:
                block = prelude if prelude.endswith("\n") else prelude + "\n"
                rec["code"] = (mutated[:insert_at] + block
                               + mutated[insert_at:])
                rec["baseline_code"] = (source[:insert_at] + block
                                        + source[insert_at:])
            else:
                rec["code"] = mutated
                rec["baseline_code"] = source
            rec["offset"] = match.start()
            out.append(rec)
            break
    return out


def _fingerprint(finding) -> tuple:
    return (finding.rule, int(getattr(finding, "line", 0)),
            str(getattr(finding, "message", "")))


def run(source: str, path: str = "candidate.py", request: str = "",
        execute: bool = False) -> dict:
    """Run mutation analysis; dynamic candidate execution is explicit opt-in."""
    ext = os.path.splitext(path)[1].lower() or ".py"
    label, smoke = quality.behavior_check(request) if request else ("", "")
    # Deep rules are part of the mutator catalog's expectations (for example
    # py-assert-validation), so a shallow scan would report them as permanent
    # survivors that no rule change could ever fix.
    baseline = harvest.scan_content(source, ext, deep=True)
    # A mutator with a prelude shifts every line below it, so it needs its own
    # baseline with that same prelude applied to the unmutated source; without
    # it every pre-existing finding moves line and looks newly introduced.
    scanned: dict[str, list] = {source: baseline}

    def baseline_for(text: str) -> collections.Counter:
        if text not in scanned:
            scanned[text] = harvest.scan_content(text, ext, deep=True)
        return collections.Counter(_fingerprint(item) for item in scanned[text])

    mutants = []
    gaps = []
    for mutant in mutate(source, ext):
        findings = harvest.scan_content(mutant["code"], ext, deep=True)
        rules = {f.rule for f in findings}
        counts = collections.Counter(_fingerprint(item) for item in findings)
        baseline_counts = baseline_for(mutant.get("baseline_code", source))
        introduced = list((counts - baseline_counts).elements())
        introduced_rules = sorted({item[0] for item in introduced})
        expected_before = sum(count for item, count in baseline_counts.items()
                              if item[0] == mutant["expected_rule"])
        expected_after = sum(count for item, count in counts.items()
                             if item[0] == mutant["expected_rule"])
        caught_static = bool(introduced)
        caught_expected = expected_after > expected_before
        runtime = (crucible.verify(mutant["code"], snippet=smoke)
                   if execute and ext in {".py", ".pyw"} else None)
        caught_behavior = bool(runtime is not None and not runtime.ok)
        caught = caught_static or caught_behavior
        rec = {
            "id": mutant["id"],
            "expected_rule": mutant["expected_rule"],
            "why": mutant["why"],
            "equivalence_of": mutant.get("equivalence_of", ""),
            "caught": caught,
            "caught_expected_rule": caught_expected,
            "rules": sorted(rules),
            "introduced_rules": introduced_rules,
            "behavior": label or "none",
            "execution": "enabled" if execute else "disabled",
            "runtime_ok": None if runtime is None else runtime.ok,
        }
        mutants.append(rec)
        if not caught:
            gaps.append({
                "mutation": mutant["id"],
                "target_rule": mutant["expected_rule"],
                "why": mutant["why"],
                "seed": mutant["code"],
            })
    total = len(mutants)
    caught = sum(1 for mutant in mutants if mutant["caught"])
    return {
        "path": path,
        "baseline_findings": len(baseline),
        "execution_enabled": execute,
        "mutants": mutants,
        "caught": caught,
        "mutation_score": round(100.0 * caught / total, 1) if total else None,
        "gaps": gaps,
    }


def render(result: dict) -> str:
    out = ["Mutation Gauntlet for %s" % result["path"], "=" * (22 + len(result["path"]))]
    if not result["mutants"]:
        out.append("No applicable mutators for this file.")
        return "\n".join(out)
    out.append("Baseline findings: %d; dynamic execution: %s" % (
        result["baseline_findings"], "enabled" if result["execution_enabled"] else "disabled"))
    for mutant in result["mutants"]:
        verdict = "caught" if mutant["caught"] else "SURVIVED"
        out.append("  %s: %s (expected %s, saw %s)" % (
            mutant["id"], verdict, mutant["expected_rule"],
            ", ".join(mutant["introduced_rules"]) or "no newly introduced finding"))
    out.append("Mutation score: %d/%d (%s%%)" % (
        result["caught"], len(result["mutants"]),
        "n/a" if result["mutation_score"] is None else result["mutation_score"]))
    if result["gaps"]:
        out.append("")
        out.append("new rule targets:")
        for gap in result["gaps"]:
            out.append("  %s -> %s" % (gap["mutation"], gap["target_rule"]))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--request", default="")
    ap.add_argument("--execute", action="store_true",
                    help="explicitly run Python mutants in Attestor's restricted runner")
    ap.add_argument("--corpus", default="",
                    help="also record this run into a labelled corpus file")
    ap.add_argument("--corpus-provenance", default="",
                    help="required with --corpus: where the source came from")
    args = ap.parse_args(argv)
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    result = run(source, args.file, request=args.request, execute=args.execute)
    print(render(result))
    if args.corpus:
        # Imported here so the gauntlet keeps working with no corpus configured.
        import mutation_corpus
        provenance = args.corpus_provenance or ("local-file:" + args.file)
        try:
            with mutation_corpus.MutationCorpus(args.corpus) as corpus:
                counts = corpus.record_gauntlet(
                    result, source, path=args.file, provenance=provenance)
        except mutation_corpus.MutationCorpusError as exc:
            print("corpus not recorded: %s" % exc)
            return 2
        print("")
        print("corpus %s: +%d survivor(s), +%d caught, +%d baseline, %d duplicate" % (
            args.corpus, counts["survivor"], counts["caught"],
            counts["baseline"], counts["duplicate"]))
    return 1 if result["gaps"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
