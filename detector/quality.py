#!/usr/bin/env python3
"""Request-aware behavior checks for Attestor-generated Python.

Static analysis proves code is shaped safely. The crucible proves it imports and
runs. This module adds the missing coder-grade question: does it satisfy the
actual request? For common algorithmic and data-structure prompts we synthesize
small smoke tests and feed failures back through forge/curry.
"""
from __future__ import annotations

import textwrap


_HELPERS = r"""
import inspect
import candidate


def _arity_accepts(fn, n):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return True
    positional = [p for p in sig.parameters.values()
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    required = [p for p in positional if p.default is p.empty]
    has_varargs = any(p.kind is p.VAR_POSITIONAL for p in sig.parameters.values())
    return len(required) <= n and (has_varargs or len(positional) >= n)


def _public_functions():
    out = []
    for name, obj in vars(candidate).items():
        if not name.startswith('_') and inspect.isfunction(obj):
            out.append((name.lower(), obj))
    return out


def _public_classes():
    out = []
    for name, obj in vars(candidate).items():
        if not name.startswith('_') and inspect.isclass(obj) and obj.__module__ == candidate.__name__:
            out.append((name.lower(), obj))
    return out


def _pick_function(keywords, arity=None):
    funcs = _public_functions()
    ranked = []
    for name, fn in funcs:
        score = sum(10 for key in keywords if key in name)
        if arity is not None and _arity_accepts(fn, arity):
            score += 3
        if score:
            ranked.append((score, name, fn))
    if not ranked and arity is not None:
        ranked = [(1, name, fn) for name, fn in funcs if _arity_accepts(fn, arity)]
    if not ranked:
        raise AssertionError('no public function matched ' + ', '.join(keywords))
    ranked.sort(reverse=True)
    return ranked[0][2]


def _pick_class(keywords):
    classes = _public_classes()
    ranked = []
    for name, cls in classes:
        score = sum(10 for key in keywords if key in name)
        if score:
            ranked.append((score, name, cls))
    if not ranked:
        raise AssertionError('no public class matched ' + ', '.join(keywords))
    ranked.sort(reverse=True)
    return ranked[0][2]


def _method(obj, *names):
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    raise AssertionError('missing method: ' + '/'.join(names))


def _as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, (str, bytes, dict)):
        return value
    try:
        return list(value)
    except TypeError:
        return value


def _missing(value):
    return value is None or value == -1 or value is False
"""


def _script(body: str) -> str:
    return _HELPERS + "\n" + textwrap.dedent(body).strip() + "\n"


_CASES = [
    ("merge sorted lists", ("merge", "sorted"), _script("""
        fn = _pick_function(('merge',), 2)
        assert fn([1, 3, 7], [2, 3, 4]) == [1, 2, 3, 3, 4, 7]
        assert fn([], [5]) == [5]
        assert fn([-3, 0], [-2, 9]) == [-3, -2, 0, 9]
    """)),
    ("fibonacci", ("fibonacci",), _script("""
        fn = _pick_function(('fib', 'fibonacci'), 1)
        assert fn(0) == 0
        assert fn(1) == 1
        assert fn(10) == 55
    """)),
    ("fibonacci", ("fib",), _script("""
        fn = _pick_function(('fib', 'fibonacci'), 1)
        assert fn(0) == 0
        assert fn(1) == 1
        assert fn(10) == 55
    """)),
    ("factorial", ("factorial",), _script("""
        fn = _pick_function(('factorial', 'fact'), 1)
        assert fn(0) == 1
        assert fn(1) == 1
        assert fn(6) == 720
    """)),
    ("two sum", ("two", "sum"), _script("""
        fn = _pick_function(('two', 'sum'), 2)
        assert sorted(_as_list(fn([2, 7, 11, 15], 9))) == [0, 1]
        assert sorted(_as_list(fn([3, 2, 4], 6))) == [1, 2]
    """)),
    ("palindrome", ("palindrome",), _script("""
        fn = _pick_function(('palindrome',), 1)
        assert fn('Never odd or even') is True
        assert fn('hello') is False
    """)),
    ("reverse words", ("reverse", "words"), _script("""
        fn = _pick_function(('reverse', 'words'), 1)
        assert fn('a b c') == 'c b a'
        assert fn('single') == 'single'
    """)),
    ("reverse string", ("reverse", "string"), _script("""
        fn = _pick_function(('reverse',), 1)
        assert fn('stressed') == 'desserts'
        assert fn('') == ''
    """)),
    ("fizzbuzz", ("fizzbuzz",), _script("""
        fn = _pick_function(('fizzbuzz',), 1)
        result = _as_list(fn(15))
        assert len(result) >= 15
        assert str(result[0]) == '1'
        assert str(result[1]) == '2'
        assert result[2] == 'Fizz'
        assert str(result[3]) == '4'
        assert result[4] == 'Buzz'
        assert result[14] == 'FizzBuzz'
    """)),
    ("greatest common divisor", ("gcd",), _script("""
        fn = _pick_function(('gcd',), 2)
        assert fn(54, 24) == 6
        assert fn(17, 13) == 1
    """)),
    ("greatest common divisor", ("greatest", "common"), _script("""
        fn = _pick_function(('gcd', 'greatest', 'common'), 2)
        assert fn(54, 24) == 6
        assert fn(17, 13) == 1
    """)),
    ("prime checker", ("prime",), _script("""
        fn = _pick_function(('prime',), 1)
        assert fn(2) is True
        assert fn(17) is True
        assert fn(1) is False
        assert fn(21) is False
    """)),
    ("binary search", ("binary", "search"), _script("""
        fn = _pick_function(('binary', 'search'), 2)
        assert fn([1, 3, 5, 7], 5) == 2
        assert fn([1, 3, 5, 7], 2) in (-1, None)
    """)),
    ("flatten nested list", ("flatten", "nested"), _script("""
        fn = _pick_function(('flatten', 'flat'), 1)
        assert _as_list(fn([1, [2, [3, 4]], [], [5]])) == [1, 2, 3, 4, 5]
        assert _as_list(fn([])) == []
    """)),
    ("anagram checker", ("anagram",), _script("""
        fn = _pick_function(('anagram',), 2)
        assert fn('listen', 'silent') is True
        assert fn('triangle', 'integral') is True
        assert fn('apple', 'papelx') is False
    """)),
    ("valid parentheses", ("valid", "parentheses"), _script("""
        fn = _pick_function(('paren', 'bracket', 'valid', 'balanced'), 1)
        assert fn('([]{})') is True
        assert fn('([)]') is False
        assert fn('(') is False
    """)),
    ("balanced parentheses", ("balanced", "parentheses"), _script("""
        fn = _pick_function(('paren', 'bracket', 'valid', 'balanced'), 1)
        assert fn('([]{})') is True
        assert fn('([)]') is False
        assert fn('(') is False
    """)),
    ("count vowels", ("count", "vowels"), _script("""
        fn = _pick_function(('vowel', 'count'), 1)
        assert fn('Attestor codes') == 4
        assert fn('rhythm') == 0
    """)),
    ("remove duplicates", ("remove", "duplicates"), _script("""
        fn = _pick_function(('duplicate', 'unique'), 1)
        assert _as_list(fn([1, 2, 2, 3, 1])) == [1, 2, 3]
        assert _as_list(fn([])) == []
    """)),
    ("sort list", ("sort", "list"), _script("""
        fn = _pick_function(('sort',), 1)
        assert fn([3, 1, 2]) == [1, 2, 3]
        assert fn([]) == []
    """)),
    ("LRU cache", ("lru", "cache"), _script("""
        cls = _pick_class(('lru', 'cache'))
        cache = cls(2)
        put = _method(cache, 'put', 'set')
        get = _method(cache, 'get')
        put('a', 1)
        put('b', 2)
        assert get('a') == 1
        put('c', 3)
        assert _missing(get('b'))
        assert get('a') == 1
        assert get('c') == 3
    """)),
    ("trie", ("trie",), _script("""
        cls = _pick_class(('trie',))
        trie = cls()
        insert = _method(trie, 'insert', 'add')
        search = _method(trie, 'search', 'contains')
        starts = _method(trie, 'starts_with', 'startswith', 'prefix')
        insert('code')
        insert('coder')
        assert search('code') is True
        assert search('cod') is False
        assert starts('cod') is True
        assert starts('zap') is False
    """)),
    ("stack", ("stack",), _script("""
        cls = _pick_class(('stack',))
        stack = cls()
        push = _method(stack, 'push', 'append')
        pop = _method(stack, 'pop')
        push(1)
        push(2)
        assert pop() == 2
        assert pop() == 1
    """)),
    ("queue", ("queue",), _script("""
        cls = _pick_class(('queue',))
        queue = cls()
        enqueue = _method(queue, 'enqueue', 'push', 'put')
        dequeue = _method(queue, 'dequeue', 'pop', 'get')
        enqueue(1)
        enqueue(2)
        assert dequeue() == 1
        assert dequeue() == 2
    """)),
    ("dijkstra shortest path", ("dijkstra",), _script("""
        fn = _pick_function(('dijkstra', 'shortest', 'path'), 2)
        graph = {
            'a': {'b': 2, 'c': 5},
            'b': {'c': 1},
            'c': {},
        }
        result = fn(graph, 'a')
        assert result['a'] == 0
        assert result['b'] == 2
        assert result['c'] == 3
    """)),
    ("topological sort", ("topological", "sort"), _script("""
        fn = _pick_function(('topological', 'sort'), 1)
        graph = {'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []}
        order = _as_list(fn(graph))
        assert order.index('a') < order.index('b')
        assert order.index('a') < order.index('c')
        assert order.index('b') < order.index('d')
        assert order.index('c') < order.index('d')
    """)),
    ("slugify", ("slugify",), _script("""
        fn = _pick_function(('slug',), 1)
        assert fn('Hello, Attestor 1.4!') == 'hello-attestor-1-4'
        assert fn('  Already nice  ') == 'already-nice'
    """)),
    ("memoize decorator", ("memoize",), _script("""
        fn = _pick_function(('memo',), 1)
        calls = {'n': 0}
        @fn
        def add(a, b):
            calls['n'] += 1
            return a + b
        assert add(2, 3) == 5
        assert add(2, 3) == 5
        assert calls['n'] == 1
    """)),
]


def behavior_check(request: str) -> tuple[str, str]:
    """Return (label, smoke-test snippet) for a request, or ("", "")."""
    low = request.lower()
    for label, words, snippet in _CASES:
        if all(word in low for word in words):
            return label, snippet
    return "", ""


def prompt_addendum(request: str) -> str:
    label, snippet = behavior_check(request)
    if not snippet:
        return ""
    return ("\n\nAttestor will run this behavioral smoke test against your module. "
            "Make it pass exactly while keeping the implementation general:\n"
            "```python\n" + snippet + "```")
