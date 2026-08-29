#!/usr/bin/env python3
"""distill42 -- the teacher farm: directory -> lessons -> corpus -> brain.

Architecture (why dolphin needs no filesystem access):
    Owen's harness reads YOUR directories directly (full disk access).
    Each file is chunked into context-sized pieces and handed to the
    teacher model as a PROMPT. The teacher returns lessons -- extracted
    patterns, safe/unsafe example pairs, annotated explanations -- which
    join the training corpus. The model never touches the disk; the
    harness never trusts the model.

    bulk corpus  = your own repos + stdlib      (instant, free, huge)
    seasoning    = teacher lessons              (slow, rich, nightly)

    brain42 trains on the MIX.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

import local_brain42 as lb  # noqa: E402
import brain42 as brain  # noqa: E402

DS_SCHEMA = "attestor-distill-farm-4.2"
EXIT_CLEAN = 0
EXIT_OPERATIONAL = 4

TEACH_PROMPTS = [
    "Read this code and write one security lesson it teaches, then one "
    "safe/unsafe example pair in Python. Be concise.\n\nCODE:\n{chunk}",
    "Extract the core logic of this code and rewrite it as a clean, "
    "secure teaching example with brief comments.\n\nCODE:\n{chunk}",
    "List every risky pattern in this code with a one-line fix each. "
    "If none, state the strongest defensive pattern used.\n\nCODE:\n{chunk}",
]

CODE_EXTS = {".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
             ".go", ".rs", ".md", ".json", ".sql", ".sh"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
             ".pytest_cache"}


class DsError(ValueError):
    pass


def iter_source_files(root):
    root_path = Path(root)
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in CODE_EXTS:
            yield path


def chunk_text(text, chunk_chars=6000):
    for start in range(0, len(text), chunk_chars):
        piece = text[start:start + chunk_chars]
        if len(piece.strip()) > 50:
            yield piece


def harvest_lessons(root, teacher_model, lessons_target,
                    base="http://127.0.0.1:11434", num_ctx=8192,
                    progress=False):
    """Walk the directory, feed chunks to the teacher, collect lessons."""
    lessons = []
    started = time.time()
    for path in iter_source_files(root):
        if len(lessons) >= lessons_target:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for chunk in chunk_text(text):
            if len(lessons) >= lessons_target:
                break
            prompt = TEACH_PROMPTS[len(lessons) % len(TEACH_PROMPTS)].format(
                chunk=chunk)
            try:
                result = lb.draft(prompt, model=teacher_model,
                                  base=base)
                lesson = result.get("response", "").strip()
            except Exception as exc:  # noqa: BLE001
                if progress:
                    print("  teacher error:", str(exc)[:80], flush=True)
                continue
            if len(lesson) > 40:
                lessons.append({
                    "source": str(path),
                    "prompt_kind": len(lessons) % len(TEACH_PROMPTS),
                    "lesson": lesson,
                })
                if progress:
                    rate = len(lessons) / max(time.time() - started, 1)
                    print("  lesson %d/%d (%.2f/s) <- %s"
                          % (len(lessons), lessons_target, rate,
                             path.name), flush=True)
    return lessons


def build_mixed_corpus(root, lessons, max_code_bytes=50_000_000):
    """Bulk = your real code (the harness reads it, no teacher needed).
    Seasoning = teacher lessons. Mixed and returned as bytes."""
    bulk = []
    used = 0
    for path in iter_source_files(root):
        if used >= max_code_bytes:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bulk.append(text)
        used += len(text)
    lesson_text = "\n\n".join(
        "# teacher lesson\n" + entry["lesson"] for entry in lessons)
    return ("\n\n".join(bulk) + "\n\n" + lesson_text).encode("utf-8")


def farm(root, teacher_model, hours=None, lessons_target=50,
         config="mx330", steps=300, base="http://127.0.0.1:11434"):
    started = time.time()
    deadline = time.time() + hours * 3600 if hours else None

    all_lessons = []
    rounds = 0
    result = None
    while True:
        rounds += 1
        remaining = lessons_target - len(all_lessons)
        if remaining <= 0:
            break
        batch = harvest_lessons(root, teacher_model, remaining,
                                base=base, progress=True)
        all_lessons.extend(batch)
        corpus = build_mixed_corpus(root, all_lessons)
        result = brain.train_torch(corpus, config=config, steps=steps,
                                   seed=rounds)
        print("round %d: lessons=%d corpus=%dB loss %.3f -> %.3f"
              % (rounds, len(all_lessons), len(corpus),
                 result["loss_first"], result["loss_last"]), flush=True)
        if deadline and time.time() >= deadline:
            break
        if not batch:
            break

    return {
        "schema": DS_SCHEMA,
        "tool": "distill-farm",
        "teacher": teacher_model,
        "rounds": rounds,
        "lessons_total": len(all_lessons),
        "final_loss_first": result["loss_first"] if result else None,
        "final_loss_last": result["loss_last"] if result else None,
        "boundary": ("harness reads the disk; teacher only sees prompts; "
                     "brain trains on the mix"),
    }


REVIEW_PROMPT = ("You are a senior code reviewer. Review this code from "
                 "a security toolkit. List concrete findings: bugs, "
                 "security issues, design concerns -- each with severity "
                 "(HIGH/MED/LOW). If the code is solid, say what makes "
                 "it solid. Be concise and specific.\n\nCODE:\n{chunk}")


def review_dir(root, teacher_model, max_files=8, max_chunks_per_file=1,
               base="http://127.0.0.1:11434", progress=True):
    """Send code to the teacher for review. The harness reads the disk;
    the teacher only ever sees the chunk in its prompt."""
    reviews = []
    files_seen = 0
    for path in iter_source_files(root):
        if files_seen >= max_files:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text.strip()) < 200:
            continue
        files_seen += 1
        chunks = list(chunk_text(text))[:max_chunks_per_file]
        for chunk in chunks:
            prompt = REVIEW_PROMPT.format(chunk=chunk)
            try:
                result = lb.draft(prompt, model=teacher_model, base=base)
                review = result.get("response", "").strip()
            except Exception as exc:  # noqa: BLE001
                if progress:
                    print("  review error:", str(exc)[:80], flush=True)
                continue
            if review:
                reviews.append({"file": str(path), "review": review})
                if progress:
                    print("  reviewed %s (%d chars)"
                          % (path.name, len(review)), flush=True)
    return reviews

# -------------------------------------------------------------- selftest

def run_selftest():
    checks = []
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fixture = ("import os\n"
                   "def run(cmd):\n"
                   "    return os.system(cmd)  # dangerous pattern\n"
                   "def safe(cmd):\n"
                   "    allowed = {'ls', 'date'}\n"
                   "    return os.system(cmd) if cmd in allowed else -1\n")
        (Path(tmp) / "fixture.py").write_text(fixture, encoding="utf-8")

        lessons = harvest_lessons(tmp, "dolphin3:8b", lessons_target=2,
                                  progress=False)
        checks.append(("teacher produced lessons from the fixture",
                       len(lessons) >= 1))

        corpus = build_mixed_corpus(tmp, lessons)
        checks.append(("mixed corpus includes bulk + lessons",
                       len(corpus) > len(fixture)
                       and b"teacher lesson" in corpus))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": DS_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="distill42", description="Teacher farm: dirs -> lessons -> brain")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("harvest", help="generate teacher lessons")
    p.add_argument("--root", required=True)
    p.add_argument("--teacher", default="dolphin3:8b")
    p.add_argument("--lessons", type=int, default=20)
    p.add_argument("--out", required=True)

    p = subs.add_parser("train", help="train brain on mixed corpus")
    p.add_argument("--root", required=True)
    p.add_argument("--lessons-file")
    p.add_argument("--config", default="mx330")
    p.add_argument("--steps", type=int, default=300)

    p = subs.add_parser("farm", help="harvest + train loop")
    p.add_argument("--root", required=True)
    p.add_argument("--teacher", default="dolphin3:8b")
    p.add_argument("--lessons", type=int, default=50)
    p.add_argument("--hours", type=float, default=None)
    p.add_argument("--config", default="mx330")
    p.add_argument("--steps", type=int, default=300)

    p = subs.add_parser("review", help="teacher reviews a directory")
    p.add_argument("--root", required=True)
    p.add_argument("--teacher", default="dolphin3:8b")
    p.add_argument("--max-files", type=int, default=8)
    p.add_argument("--out")

    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    if args.command == "review":
        reviews = review_dir(args.root, args.teacher,
                             max_files=args.max_files)
        result = {
            "schema": DS_SCHEMA,
            "tool": "teacher-review",
            "teacher": args.teacher,
            "root": args.root,
            "files_reviewed": len(reviews),
            "reviews": reviews,
        }
        if args.out:
            Path(args.out).write_text(
                json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN

    if args.command == "self-test":
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL

    try:
        if args.command == "harvest":
            lessons = harvest_lessons(args.root, args.teacher,
                                      args.lessons, progress=True)
            Path(args.out).write_text(
                json.dumps(lessons, indent=2), encoding="utf-8")
            print(json.dumps({"lessons": len(lessons),
                              "written_to": args.out}))
            return EXIT_CLEAN
        if args.command == "train":
            lessons = []
            if args.lessons_file:
                lessons = json.loads(
                    Path(args.lessons_file).read_text(encoding="utf-8"))
            corpus = build_mixed_corpus(args.root, lessons)
            result = brain.train_torch(corpus, config=args.config,
                                       steps=args.steps)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN
        if args.command == "farm":
            result = farm(args.root, args.teacher, hours=args.hours,
                          lessons_target=args.lessons, config=args.config,
                          steps=args.steps)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN
    except (DsError, OSError) as exc:
        print("distill42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL
    return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
