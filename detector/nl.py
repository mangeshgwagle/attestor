#!/usr/bin/env python3
"""
nl.py -- a small, HONEST natural-language front-end for Attestor.

You asked for a natural-language -> code path. The real version of that is an LLM,
and it cannot be added here: your API keys don't work and api.anthropic.com is
egress-blocked in this sandbox. So this is NOT that, and it does not pretend to be.

It is the honest, dependency-free approximation: an *intent parser*. It recognizes
a fixed vocabulary of requests and maps them to code Attestor can genuinely produce.
No model, no understanding, no hallucination -- pattern-match in, real code out,
or a plain "I don't know that one." Give it a phrasing or a problem outside its
grammar and it fails loudly instead of inventing an answer.

Three kinds of request it understands:
  - "make a REST API for Book with fields title, author, year (int)"
        -> scaffolds a whole service via codegen. THIS is the genuine win:
           plain English -> Attestor's real generator, no rigid JSON spec needed.
  - "write fibonacci"  (also factorial, palindrome, reverse a string, fizzbuzz,
        gcd, prime, binary search)
        -> returns a vetted snippet from a small CURATED library. This is
           recognition, not reasoning: it only knows a fixed set, and an unknown
           problem (or unknown wording) gets nothing.
  - "review detect.py" / "find bugs in x.py"
        -> runs the detector (both engines on Python).

    python3 nl.py "make a rest api for Book with fields title, author, year (int)"
    python3 nl.py "write fibonacci"
    python3 nl.py "review codegen.py" --out ./svc
"""
from __future__ import annotations

import argparse
import os
import re

import brain as brain_mod
import codegen
import deepscan
import detect

# --------------------------------------------------------------------------- #
# tiny grammar
# --------------------------------------------------------------------------- #
SCAFFOLD_RE = re.compile(
    r"\b(?:generate|make|create|build|scaffold|write)\b.*?\b(?:rest\s+)?"
    r"(?:api|service|crud|backend|endpoint)\b.*?\bfor\s+(?:an?\s+|the\s+)?([A-Za-z_]\w*)",
    re.I)
FIELDS_RE = re.compile(r"\bwith\b(?:\s+fields?)?\s+(.+)$", re.I)
REVIEW_RE = re.compile(r"\b(?:review|scan|check|lint|analy[sz]e|find\s+bugs?\s+in)\b\s+(\S+)", re.I)

TYPE_WORDS = {
    "int": "int", "integer": "int", "number": "int", "count": "int",
    "float": "float", "double": "float", "real": "float", "decimal": "float",
    "bool": "bool", "boolean": "bool", "flag": "bool",
    "str": "str", "string": "str", "text": "str",
}
_STOP_FIELDS = {"and", "a", "an", "the", "with", "fields", "field", "id"}

# --------------------------------------------------------------------------- #
# curated snippet library -- recognition, not reasoning
# --------------------------------------------------------------------------- #
_FIB = '''def fib(n):
    """The nth Fibonacci number (0-indexed): 0, 1, 1, 2, 3, 5, ..."""
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
'''
_FACT = '''def factorial(n):
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result
'''
_PALI = '''def is_palindrome(s):
    letters = [c.lower() for c in s if c.isalnum()]
    return letters == letters[::-1]
'''
_REV = '''def reverse_string(s):
    return s[::-1]
'''
_FIZZ = '''def fizzbuzz(n):
    out = []
    for i in range(1, n + 1):
        if i % 15 == 0:
            out.append("FizzBuzz")
        elif i % 3 == 0:
            out.append("Fizz")
        elif i % 5 == 0:
            out.append("Buzz")
        else:
            out.append(str(i))
    return out
'''
_GCD = '''def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
'''
_PRIME = '''def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True
'''
_BSEARCH = '''def binary_search(arr, target):
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        if arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1
'''
_TWO_SUM = '''def two_sum(nums, target):
    seen = {}
    for i, value in enumerate(nums):
        need = target - value
        if need in seen:
            return [seen[need], i]
        seen[value] = i
    return []
'''
_MERGE_SORTED = '''def merge_sorted_lists(a, b):
    i = 0
    j = 0
    out = []
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            out.append(a[i])
            i += 1
        else:
            out.append(b[j])
            j += 1
    out.extend(a[i:])
    out.extend(b[j:])
    return out
'''
_FLATTEN = '''def flatten(xs):
    out = []
    for item in xs:
        if isinstance(item, list):
            out.extend(flatten(item))
        else:
            out.append(item)
    return out
'''
_ANAGRAM = '''def is_anagram(a, b):
    clean_a = sorted(ch.lower() for ch in a if ch.isalnum())
    clean_b = sorted(ch.lower() for ch in b if ch.isalnum())
    return clean_a == clean_b
'''
_PARENS = '''def valid_parentheses(text):
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in text:
        if ch in pairs.values():
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack
'''
_COUNT_VOWELS = '''def count_vowels(text):
    vowels = set("aeiouAEIOU")
    return sum(1 for ch in text if ch in vowels)
'''
_REMOVE_DUPES = '''def remove_duplicates(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
'''
_SORT_LIST = '''def sort_list(items):
    return sorted(items)
'''
_LRU = '''from collections import OrderedDict


class LRUCache:
    def __init__(self, capacity):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._items = OrderedDict()

    def get(self, key):
        if key not in self._items:
            return -1
        self._items.move_to_end(key)
        return self._items[key]

    def put(self, key, value):
        if key in self._items:
            self._items.move_to_end(key)
        self._items[key] = value
        if len(self._items) > self.capacity:
            self._items.popitem(last=False)
'''
_TRIE = '''class Trie:
    def __init__(self):
        self._root = {}
        self._end = "#"

    def insert(self, word):
        node = self._root
        for ch in word:
            node = node.setdefault(ch, {})
        node[self._end] = True

    def search(self, word):
        node = self._root
        for ch in word:
            if ch not in node:
                return False
            node = node[ch]
        return self._end in node

    def starts_with(self, prefix):
        node = self._root
        for ch in prefix:
            if ch not in node:
                return False
            node = node[ch]
        return True
'''
_STACK = '''class Stack:
    def __init__(self):
        self._items = []

    def push(self, item):
        self._items.append(item)

    def pop(self):
        return self._items.pop()

    def peek(self):
        return self._items[-1] if self._items else None

    def is_empty(self):
        return not self._items
'''
_QUEUE = '''from collections import deque


class Queue:
    def __init__(self):
        self._items = deque()

    def enqueue(self, item):
        self._items.append(item)

    def dequeue(self):
        return self._items.popleft()

    def is_empty(self):
        return not self._items
'''
_DIJKSTRA = '''import heapq


def dijkstra(graph, start):
    distances = {node: float("inf") for node in graph}
    if start not in distances:
        return distances
    distances[start] = 0
    heap = [(0, start)]
    while heap:
        current_distance, node = heapq.heappop(heap)
        if current_distance != distances[node]:
            continue
        for neighbor, weight in graph.get(node, {}).items():
            new_distance = current_distance + weight
            if new_distance < distances.get(neighbor, float("inf")):
                distances[neighbor] = new_distance
                heapq.heappush(heap, (new_distance, neighbor))
    return distances
'''
_TOPO_SORT = '''from collections import deque


def topological_sort(graph):
    indegree = {node: 0 for node in graph}
    for neighbors in graph.values():
        for neighbor in neighbors:
            indegree[neighbor] = indegree.get(neighbor, 0) + 1
    queue = deque(node for node, degree in indegree.items() if degree == 0)
    order = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            indegree[neighbor] -= 1
            if indegree[neighbor] == 0:
                queue.append(neighbor)
    if len(order) != len(indegree):
        raise ValueError("graph has a cycle")
    return order
'''
_MEMOIZE = '''from functools import wraps


def memoize(fn):
    cache = {}

    @wraps(fn)
    def wrapper(*args):
        if args not in cache:
            cache[args] = fn(*args)
        return cache[args]

    return wrapper
'''
_SLUGIFY = '''import re


def slugify(text):
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")
'''
_INVERT_TREE = '''def invert_binary_tree(root):
    if root is None:
        return None
    root.left, root.right = invert_binary_tree(root.right), invert_binary_tree(root.left)
    return root
'''

# (required keywords -- ALL must appear), code, one-line description
SNIPPETS = [
    (("fibonacci",), _FIB, "iterative nth Fibonacci"),
    (("factorial",), _FACT, "iterative factorial"),
    (("palindrome",), _PALI, "case/punctuation-insensitive palindrome check"),
    (("reverse", "string"), _REV, "reverse a string"),
    (("fizzbuzz",), _FIZZ, "classic FizzBuzz for 1..n"),
    (("gcd",), _GCD, "Euclid's greatest common divisor"),
    (("greatest", "common"), _GCD, "Euclid's greatest common divisor"),
    (("prime",), _PRIME, "primality test"),
    (("binary", "search"), _BSEARCH, "binary search -> index or -1"),
    (("two", "sum"), _TWO_SUM, "hash-map two-sum indices"),
    (("merge", "sorted"), _MERGE_SORTED, "linear merge of two sorted lists"),
    (("flatten",), _FLATTEN, "recursive list flattening"),
    (("anagram",), _ANAGRAM, "case-insensitive anagram check"),
    (("valid", "parentheses"), _PARENS, "balanced bracket validation"),
    (("balanced", "parentheses"), _PARENS, "balanced bracket validation"),
    (("count", "vowels"), _COUNT_VOWELS, "vowel counter"),
    (("remove", "duplicates"), _REMOVE_DUPES, "stable duplicate removal"),
    (("sort", "list"), _SORT_LIST, "sorted copy of a list"),
    (("lru", "cache"), _LRU, "LRU cache with OrderedDict"),
    (("trie",), _TRIE, "prefix trie"),
    (("stack",), _STACK, "LIFO stack"),
    (("queue",), _QUEUE, "FIFO queue"),
    (("dijkstra",), _DIJKSTRA, "Dijkstra shortest-path distances"),
    (("shortest", "path"), _DIJKSTRA, "Dijkstra shortest-path distances"),
    (("topological", "sort"), _TOPO_SORT, "topological sort with cycle rejection"),
    (("memoize",), _MEMOIZE, "memoization decorator"),
    (("slugify",), _SLUGIFY, "URL slug generator"),
    (("invert", "binary", "tree"), _INVERT_TREE, "binary tree inversion"),
]


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parse_fields(chunk: str) -> dict:
    fields = {}
    for part in re.split(r",|\sand\s", chunk):
        part = part.strip().rstrip(".")
        if not part:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s*(?:\(([^)]*)\)|:\s*(\w+))?", part)
        if not m:
            continue
        name = m.group(1)
        if name.lower() in _STOP_FIELDS:
            continue
        raw_type = (m.group(2) or m.group(3) or "").strip().lower()
        fields[name] = TYPE_WORDS.get(raw_type, "str")
    return fields


def parse_spec(text: str):
    m = SCAFFOLD_RE.search(text)
    if not m:
        return None
    name = m.group(1)
    name = name[:1].upper() + name[1:]
    fields = {}
    fm = FIELDS_RE.search(text)
    if fm:
        fields = parse_fields(fm.group(1))
    if not fields:
        fields = {"name": "str"}
    return {"resources": [{"name": name, "fields": fields}]}


def match_snippet(text: str):
    low = text.lower()
    for keywords, code, desc in SNIPPETS:
        if all(k in low for k in keywords):
            return code, desc
    return None


def interpret(text: str) -> dict:
    """Map an English request to an intent. Scaffold is tried first (most
    specific), then review, then the snippet library, else 'unknown'."""
    spec = parse_spec(text)
    if spec:
        return {"intent": "scaffold", "spec": spec}
    m = REVIEW_RE.search(text)
    if m:
        return {"intent": "review", "path": m.group(1)}
    snip = match_snippet(text)
    if snip:
        return {"intent": "snippet", "code": snip[0], "desc": snip[1]}
    return {"intent": "unknown"}


# --------------------------------------------------------------------------- #
# acting on an intent
# --------------------------------------------------------------------------- #
def _review(path: str) -> str:
    if not os.path.exists(path):
        return f"can't review '{path}': no such file here."
    findings = detect.scan_file(path)
    if path.endswith(".py"):
        findings += deepscan.scan_path(path)
    if not findings:
        return f"reviewed {path}: 0 findings. clean."
    findings.sort(key=detect.Finding.sort_key)
    out = [f"reviewed {path}: {len(findings)} finding(s):"]
    for f in findings:
        out.append(f"  line {f.line} [{f.severity}] {f.rule}: {f.fix}")
    return "\n".join(out)


def _help_unknown() -> str:
    return "\n".join([
        "I don't recognize that -- and I won't fake it (there's no LLM here).",
        "I only understand a fixed vocabulary:",
        '  - "make a REST API for Book with fields title, author, year (int)"',
        '  - "write fibonacci"  (also: factorial, palindrome, reverse a string,',
        "                         fizzbuzz, gcd, prime, binary search, two sum,",
        "                         merge sorted lists, flatten, parentheses,",
        "                         anagram, LRU cache, trie, stack, queue,",
        "                         dijkstra, topological sort, memoize, slugify)",
        '  - "review <file>"    (runs the detector)',
        "Anything outside this needs a real code-writing model.",
    ])


def _ask_brain(brain, request: str) -> str:
    prompt = ("You are a precise coding assistant. Write code for the following "
              "request. Return only the code, no explanation.\n\nRequest: " + request)
    try:
        answer = brain.generate(prompt)
    except brain_mod.ProviderError as exc:
        return f"(real brain failed: {exc})\n\n" + _help_unknown()
    if isinstance(answer, dict):                # compare mode: one block per provider
        return "\n\n".join(f"----- {name} -----\n{text}"
                           for name, text in answer.items())
    return answer


def run(result: dict, out: str | None = None, brain=None, request: str = "") -> str:
    intent = result["intent"]
    if intent == "unknown" and brain is not None and brain.available():
        # the parser didn't recognize it, but a real LLM is configured -- use it
        return _ask_brain(brain, request)
    if intent == "scaffold":
        spec = result["spec"]
        files = codegen.generate(spec)
        res = spec["resources"][0]
        cols = ", ".join(f"{k}:{v}" for k, v in res["fields"].items())
        lines = [f"understood -> scaffold a service for {res['name']} ({cols})",
                 f"generated {len(files)} files, {codegen.total_lines(files)} lines"]
        if out:
            codegen.write_files(files, out, force=True)
            lines.append(f"written to {out}/   (try: cd {out} && make test)")
        else:
            lines.append("(add --out DIR to write it to disk)")
        return "\n".join(lines)
    if intent == "snippet":
        return (f"understood -> {result['desc']}\n"
                "(retrieved from a curated library: recognition, not reasoning --\n"
                " I only know a fixed set; a novel problem gets nothing)\n\n"
                + result["code"])
    if intent == "review":
        return _review(result["path"])
    return _help_unknown()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("request", nargs="+", help="a plain-English request, in quotes")
    ap.add_argument("--out", help="for a scaffold request, write the service here")
    ap.add_argument("--brain", action="store_true",
                    help="use a real LLM (if GEMINI_API_KEY/OPENAI_API_KEY is set) "
                         "for requests the parser doesn't recognize")
    ap.add_argument("--compare", action="store_true",
                    help="with --brain, ask every configured provider and show all answers")
    args = ap.parse_args(argv)

    text = " ".join(args.request)
    brain = brain_mod.from_env("compare" if args.compare else "fallback") if args.brain else None
    print(run(interpret(text), out=args.out, brain=brain, request=text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
