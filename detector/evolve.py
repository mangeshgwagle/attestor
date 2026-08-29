#!/usr/bin/env python3
"""
evolve.py -- Attestor harvests GitHub code, rereads it, fixes it, and rereads it.

This is the self-improvement loop in concrete form. Attestor is not silently training
himself or pretending a linter is a brain. He does something better and testable:
he pulls real code from GitHub, builds a structural picture with comprehend.py,
finds defects with both engines, applies only safe mechanical fixes, scans again,
and repeats until the file stabilizes or the cycle budget runs out.

    python3 evolve.py https://github.com/owner/repo/blob/main/app.py --out-dir evolved
    python3 evolve.py "verify=False" --lang python --limit 3 --cycles 5

Respect source licenses. The output includes provenance and the remaining issues
that still need a human or an LLM-backed forge pass.
"""
from __future__ import annotations

import argparse
import os
import sys
import urllib.error

import comprehend
import detect
import fixmemory
import harvest


def _ext(path: str, lang: str | None = None) -> str:
    found = os.path.splitext(path)[1].lower()
    if found:
        return found
    return harvest.LANG_EXT.get((lang or "").lower(), ".txt")


def _record(content: str, repo: str, path: str, url: str | None, lic: str | None, lang: str | None = None) -> dict:
    return {
        "content": content,
        "repo": repo,
        "path": path,
        "url": url or "",
        "license": lic,
        "ext": _ext(path, lang),
    }


def load_targets(target: str, lang: str | None = None, pick: int = 0, limit: int = 1) -> tuple[list[dict], int | None]:
    """Load one direct GitHub URL, or search GitHub and fetch a window of results."""
    parsed = harvest.parse_github_url(target)
    if parsed:
        repo, ref, path = parsed
        content, repo, path, url, lic = harvest.fetch_url(repo, ref, path)
        return [_record(content, repo, path, url, lic, lang)], None

    per_page = max(1, pick + limit)
    items, total = harvest.search(target, lang, per_page=per_page)
    chosen = items[pick:pick + limit]
    out = []
    for item in chosen:
        content, repo, path, url, lic = harvest.fetch(item)
        out.append(_record(content, repo, path, url, lic, lang))
    return out, total


def _scan(content: str, ext: str) -> list:
    return harvest.scan_content(content, ext)


def _applied_notes(applied) -> list[str]:
    return ["%s x%d" % (note, count) for _, count, note in applied]


def evolve_source(source: dict, cycles: int = 5) -> dict:
    """Repeatedly review and safely improve one source record."""
    current = source["content"]
    ext = source["ext"]
    history = []
    all_applied = []

    for number in range(1, max(1, cycles) + 1):
        report = comprehend.comprehend(current, source["path"])
        before = report["findings"]
        candidate = report["improved"]
        applied = report["applied"]
        after = _scan(candidate, ext)
        accepted = len(after) <= len(before)
        changed = accepted and candidate != current

        history.append({
            "cycle": number,
            "passes": len(report["passes"]),
            "findings_before": len(before),
            "findings_after": len(after) if accepted else len(before),
            "applied": applied,
            "accepted": accepted,
            "changed": changed,
        })

        if accepted:
            current = candidate
            all_applied.extend(applied)

        if not accepted or not changed or not applied or (accepted and not after):
            break

    final_findings = _scan(current, ext)
    return {
        "source": source,
        "history": history,
        "code": current,
        "findings": sorted(final_findings, key=detect.Finding.sort_key),
        "applied": all_applied,
    }


def evolve(target: str, lang: str | None = None, pick: int = 0, limit: int = 1, cycles: int = 5) -> dict:
    sources, total = load_targets(target, lang=lang, pick=pick, limit=limit)
    return {
        "target": target,
        "total": total,
        "results": [evolve_source(source, cycles=cycles) for source in sources],
    }


def _safe_name(result: dict) -> str:
    src = result["source"]
    repo = (src.get("repo") or "github").replace("/", "__")
    base = os.path.basename(src.get("path") or "code.txt") or "code.txt"
    return repo + "__" + base


def write_results(run: dict, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for result in run["results"]:
        src = result["source"]
        path = os.path.join(out_dir, _safe_name(result))
        header = harvest.header(
            src["ext"], src.get("repo") or "unknown", src.get("path") or "unknown",
            src.get("url") or "", src.get("license"), result["applied"], result["findings"])
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(header)
            fh.write(result["code"])
        written.append(path)
    return written


def render(run: dict) -> str:
    total = run["total"]
    head = "Attestor evolved GitHub code for: %s" % run["target"]
    out = [head, "=" * len(head)]
    if total is not None:
        out.append("GitHub search saw about %s matching file(s)." % f"{total:,}")
    if not run["results"]:
        out.append("No files fetched. Try a broader query, --lang, or a direct GitHub file URL.")
        return "\n".join(out)

    fixed_notes = {}
    for result in run["results"]:
        src = result["source"]
        out += ["", "%s/%s" % (src.get("repo") or "unknown", src.get("path") or "unknown")]
        out.append("license: %s" % (src.get("license") or "UNKNOWN - check before reuse"))
        for rec in result["history"]:
            notes = "; ".join(_applied_notes(rec["applied"])) or "no safe fixes"
            verdict = "accepted" if rec["accepted"] else "rejected"
            out.append("  cycle %d: %d read passes, findings %d -> %d, %s (%s)" % (
                rec["cycle"], rec["passes"], rec["findings_before"],
                rec["findings_after"], notes, verdict))
            for _rid, count, note in rec["applied"]:
                fixed_notes[note] = fixed_notes.get(note, 0) + count
        if result["findings"]:
            out.append("  remaining issues: %d" % len(result["findings"]))
            for finding in result["findings"][:8]:
                out.append("    line %d [%s] %s: %s" % (
                    finding.line, finding.severity, finding.rule, finding.fix))
            if len(result["findings"]) > 8:
                out.append("    ... %d more" % (len(result["findings"]) - 8))
        else:
            out.append("  remaining issues: 0")

    out.append("")
    if fixed_notes:
        out.append("learned fixes from this harvest:")
        for note, count in sorted(fixed_notes.items()):
            out.append("  %s x%d" % (note, count))
    else:
        out.append("learned fixes from this harvest: none safe to apply automatically")
    out.append("honest note: Attestor improves the harvested code, not his own rules, unless you edit him.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="a GitHub file URL or a GitHub code-search query")
    ap.add_argument("--lang", help="restrict search mode to a language")
    ap.add_argument("--pick", type=int, default=0, help="first search result index to fetch")
    ap.add_argument("--limit", type=int, default=1, help="number of search results to evolve")
    ap.add_argument("--cycles", type=int, default=5, help="max review/fix/reread cycles per file")
    ap.add_argument("--out-dir", default="attestor_evolved", help="directory for improved files")
    ap.add_argument("--no-write", action="store_true", help="print the report without writing files")
    ap.add_argument("--memory", default=fixmemory.DEFAULT_MEMORY,
                    help="JSON file where repeated safe fix patterns are recorded")
    ap.add_argument("--no-memory", action="store_true",
                    help="do not update Fix Memory for this evolve run")
    args = ap.parse_args(argv)

    try:
        run = evolve(args.target, lang=args.lang, pick=args.pick,
                     limit=args.limit, cycles=args.cycles)
    except urllib.error.HTTPError as exc:
        print("GitHub said HTTP %d (private, missing auth, or rate-limited?)" % exc.code,
              file=sys.stderr)
        return 2
    except Exception as exc:                    # noqa: BLE001
        print("GitHub harvest failed: %s %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2

    print(render(run))
    if run["results"] and not args.no_memory:
        memory = fixmemory.learn_from_evolve_run(run, args.memory)
        print("\nupdated Fix Memory -> %s (%d pattern(s))" % (
            args.memory, len(memory.get("patterns", {}))))
    if not args.no_write and run["results"]:
        written = write_results(run, args.out_dir)
        print("\nwrote improved file(s):")
        for path in written:
            print("  " + path)
    return 0 if run["results"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
