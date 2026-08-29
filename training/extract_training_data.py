#!/usr/bin/env python3
"""Extract instruction-code pairs from the Attestor codebase for fine-tuning."""
import ast
import json
import os
import sys

DETECTOR_DIR = os.path.join(os.path.dirname(__file__), "..", "detector")
OUTPUT = os.path.join(os.path.dirname(__file__), "training_data.jsonl")


def extract_pairs(root_dir):
    pairs = []
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        if "extracted" in dirpath or "__pycache__" in dirpath:
            continue
        for fname in filenames:
            if not fname.endswith(".py") or fname.startswith("test_"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source)
            except SyntaxError:
                skipped += 1
                continue

            mod_doc = ast.get_docstring(tree)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    doc = ast.get_docstring(node)
                    if not doc or len(doc) < 10:
                        continue
                    try:
                        lines = source.splitlines()
                        func_src = "\n".join(lines[node.lineno - 1 : node.end_lineno])
                        if len(func_src) < 30 or len(func_src) > 4000:
                            continue
                        pairs.append({
                            "instruction": "Write a Python function: "
                            + doc.strip().split("\n")[0],
                            "input": "",
                            "output": func_src.strip(),
                        })
                    except Exception:
                        pass

                elif isinstance(node, ast.ClassDef):
                    doc = ast.get_docstring(node)
                    if not doc or len(doc) < 10:
                        continue
                    try:
                        lines = source.splitlines()
                        cls_src = "\n".join(lines[node.lineno - 1 : node.end_lineno])
                        if len(cls_src) < 50 or len(cls_src) > 6000:
                            continue
                        pairs.append({
                            "instruction": "Write a Python class: "
                            + doc.strip().split("\n")[0],
                            "input": "",
                            "output": cls_src.strip(),
                        })
                    except Exception:
                        pass

            # Whole-module pairs for smaller files with good docstrings
            if mod_doc and len(mod_doc) > 20 and len(source) < 8000:
                pairs.append({
                    "instruction": "Write a Python module: "
                    + mod_doc.strip().split("\n")[0],
                    "input": "",
                    "output": source.strip(),
                })

    return pairs, skipped


def main():
    root = os.path.abspath(DETECTOR_DIR)
    print(f"Scanning {root} ...")
    pairs, skipped = extract_pairs(root)
    print(f"Extracted {len(pairs)} pairs, skipped {skipped} files with syntax errors")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for pair in pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")
    print(f"Wrote {OUTPUT}")
    print(f"File size: {os.path.getsize(OUTPUT) / 1024:.0f} KB")


if __name__ == "__main__":
    main()
