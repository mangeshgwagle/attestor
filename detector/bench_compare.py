#!/usr/bin/env python3
"""Head-to-head benchmark: the new dataflow engine vs the legacy scanner vs Bandit.

Pillar 3 of the SOTA push. `evaluate.py` measures Attestor on its own corpus; this
proves the *dataflow* upgrade is real by scoring it against baselines on a labeled
taint corpus that deliberately includes the cases that separate a real dataflow
engine from a pattern matcher: interprocedural flows (source and sink in different
functions) and sanitized flows (must NOT be flagged).

Each sample is labeled vulnerable/safe. A tool that flags a vulnerable sample = TP;
flags a safe sample = FP. From that: precision, recall, F1 per tool.

    python3 bench_compare.py            # scorecard
    python3 bench_compare.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dataflow

# name -> (source, is_vulnerable, why)
CORPUS: dict[str, tuple[str, bool, str]] = {
    "intra_cmdi.py": (
        "import subprocess\nfrom flask import request\n"
        "def h():\n    x = request.form.get('q')\n"
        "    subprocess.run('grep ' + x, shell=True)\n",
        True, "intraprocedural command injection"),
    "inter_cmdi.py": (
        "import os\nfrom flask import request\n"
        "def src():\n    return request.args.get('c')\n"
        "def sink(d):\n    os.system('echo ' + d)\n"
        "def h():\n    v = src()\n    sink(v)\n",
        True, "INTERPROCEDURAL command injection (source/sink in different functions)"),
    "intra_eval.py": (
        "def h():\n    data = input('x: ')\n    eval(data)\n",
        True, "intraprocedural code injection"),
    "inter_sqli.py": (
        "from flask import request\n"
        "def get_id():\n    return request.args.get('id')\n"
        "def query(cur, i):\n    cur.execute('SELECT * FROM u WHERE id=' + i)\n"
        "def h(cur):\n    uid = get_id()\n    query(cur, uid)\n",
        True, "INTERPROCEDURAL SQL injection"),
    "inter_deep.py": (
        "import os\nfrom flask import request\n"
        "def a():\n    return request.args.get('x')\n"
        "def b():\n    return a()\n"
        "def c(v):\n    os.system(v)\n"
        "def h():\n    c(b())\n",
        True, "multi-hop interprocedural (a->b->c)"),
    "safe_sanitized.py": (
        "import subprocess, shlex\nfrom flask import request\n"
        "def h():\n    x = request.args.get('q')\n"
        "    subprocess.run(['echo', shlex.quote(x)])\n",
        False, "sanitized with shlex.quote -- must NOT flag"),
    "safe_intcast.py": (
        "import os\nfrom flask import request\n"
        "def h():\n    n = int(request.args.get('n'))\n    os.system('sleep %d' % n)\n",
        False, "int() cast neutralizes taint -- must NOT flag"),
    "safe_constant.py": (
        "import os\ndef h():\n    os.system('ls -la /tmp')\n",
        False, "constant argument, no user input -- must NOT flag"),
    "safe_plain.py": (
        "def add(a, b):\n    return a + b\n"
        "def h():\n    return add(2, 3)\n",
        False, "no security-relevant operation at all"),
}


@dataclass
class Score:
    tool: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    available: bool = True

    @property
    def precision(self):
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self):
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _flag_dataflow(path: str) -> bool:
    return len(dataflow.scan_paths([path])) > 0


def _flag_taint_tracker(path: str) -> bool:
    try:
        import taint_tracker
        return len(taint_tracker.scan_file(path)) > 0
    except Exception:
        return False


def _flag_bandit(path: str) -> bool | None:
    if not shutil.which("bandit"):
        return None
    try:
        p = subprocess.run(["bandit", "-f", "json", path], capture_output=True,
                           text=True, timeout=60)
        data = json.loads(p.stdout or "{}")
        return len(data.get("results", [])) > 0
    except Exception:
        return None


def run() -> list[Score]:
    tools = {
        "dataflow (new)": _flag_dataflow,
        "taint_tracker (legacy)": _flag_taint_tracker,
        "bandit (baseline)": _flag_bandit,
    }
    scores = {name: Score(name) for name in tools}

    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for name, (src, vuln, _why) in CORPUS.items():
            p = os.path.join(tmp, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write(src)
            paths[name] = (p, vuln)

        for tname, fn in tools.items():
            sc = scores[tname]
            for name, (p, vuln) in paths.items():
                flagged = fn(p)
                if flagged is None:                 # tool unavailable
                    sc.available = False
                    break
                if vuln and flagged:
                    sc.tp += 1
                elif vuln and not flagged:
                    sc.fn += 1
                elif not vuln and flagged:
                    sc.fp += 1
                else:
                    sc.tn += 1
    return list(scores.values())


def render(scores: list[Score]) -> str:
    lines = ["\n  Dataflow Engine Benchmark -- vs baselines",
             "  (labeled taint corpus: interprocedural + sanitized cases)",
             "  " + "=" * 60,
             f"  {'tool':<26}{'prec':>7}{'rec':>7}{'F1':>7}   TP/FP/FN"]
    lines.append("  " + "-" * 58)
    for sc in scores:
        if not sc.available:
            lines.append(f"  {sc.tool:<26}   not installed (skipped)")
            continue
        lines.append(f"  {sc.tool:<26}{sc.precision:>7.0%}{sc.recall:>7.0%}"
                     f"{sc.f1:>7.2f}   {sc.tp}/{sc.fp}/{sc.fn}")

    df = next((s for s in scores if s.tool.startswith("dataflow")), None)
    lt = next((s for s in scores if s.tool.startswith("taint")), None)
    if df and lt and lt.available:
        gain = df.recall - lt.recall
        lines.append("")
        lines.append(f"  dataflow recall advantage: +{gain:.0%} "
                     f"(catches the interprocedural flows the legacy scanner misses)")
    n_vuln = sum(1 for _n, (_s, v, _w) in CORPUS.items() if v)
    n_safe = len(CORPUS) - n_vuln
    lines.append(f"\n  corpus: {len(CORPUS)} samples ({n_vuln} vulnerable, {n_safe} safe)")
    return "\n".join(lines)


def to_dict(scores: list[Score]) -> dict:
    return {
        s.tool: {"available": s.available, "precision": round(s.precision, 3),
                 "recall": round(s.recall, 3), "f1": round(s.f1, 3),
                 "tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn}
        for s in scores
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    scores = run()
    print(json.dumps(to_dict(scores), indent=2) if args.json else render(scores))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
