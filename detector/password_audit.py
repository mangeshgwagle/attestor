#!/usr/bin/env python3
"""Password Audit (John-the-Ripper-lite) -- OFFLINE hash auditing.

House contract (offensive lane -- read this):
- OFFLINE ONLY. This audits password hashes you ALREADY POSSESS and are
  authorized to test: your own /etc/shadow, hashes captured in an authorized
  pentest engagement, or a CTF. There is deliberately NO online/network attack
  surface -- it never touches a live login, never brute-forces a service.
- Purpose is a security AUDIT: surface weak/guessable passwords so they can be
  rotated. A cracked hash is a finding ("this account uses a weak password").
- Not wired into the default `attestor check` CLI. Run it deliberately.
- Using this against hashes you are not authorized to test is illegal. Don't.

Supported: raw md5/sha1/sha224/sha256/sha384/sha512, NTLM, and the Unix crypt
families ($1$ md5crypt, $5$ sha256crypt, $6$ sha512crypt) where the platform's
crypt() supports them. Dictionary attack with JtR-style mangling rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field

BANNER = "  [Password Audit] OFFLINE hash auditing -- authorized use only.\n"

# A tiny built-in list so the tool is useful with no external wordlist (CTF/demo).
# For real audits, point --wordlist at rockyou.txt or similar.
BUILTIN_WORDS = [
    "password", "123456", "123456789", "12345678", "12345", "qwerty", "abc123",
    "password1", "admin", "letmein", "welcome", "monkey", "dragon", "master",
    "login", "root", "toor", "changeme", "secret", "hello", "iloveyou",
    "sunshine", "princess", "football", "baseball", "superman", "batman",
    "trustno1", "passw0rd", "test", "guest", "user", "administrator",
]


@dataclass
class HashEntry:
    raw: str
    htype: str
    label: str = ""          # optional user:hash label
    cracked: str | None = None


@dataclass
class AuditResult:
    entries: list[HashEntry] = field(default_factory=list)
    tried: int = 0

    @property
    def cracked(self):
        return [e for e in self.entries if e.cracked is not None]


# ---------------------------------------------------------------- identification
def identify_hash(h: str) -> str:
    h = h.strip()
    if h.startswith("$6$"):
        return "sha512crypt"
    if h.startswith("$5$"):
        return "sha256crypt"
    if h.startswith("$1$"):
        return "md5crypt"
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        return "md5_or_ntlm"      # ambiguous -- try both
    if re.fullmatch(r"[0-9a-fA-F]{40}", h):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{56}", h):
        return "sha224"
    if re.fullmatch(r"[0-9a-fA-F]{64}", h):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{96}", h):
        return "sha384"
    if re.fullmatch(r"[0-9a-fA-F]{128}", h):
        return "sha512"
    return "unknown"


# ---------------------------------------------------------------- hashers
def _ntlm(pw: str) -> str | None:
    try:
        return hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
    except (ValueError, TypeError):
        return None            # md4 unavailable (OpenSSL 3 legacy off)


_RAW = {
    "md5": lambda pw: hashlib.md5(pw.encode()).hexdigest(),
    "sha1": lambda pw: hashlib.sha1(pw.encode()).hexdigest(),
    "sha224": lambda pw: hashlib.sha224(pw.encode()).hexdigest(),
    "sha256": lambda pw: hashlib.sha256(pw.encode()).hexdigest(),
    "sha384": lambda pw: hashlib.sha384(pw.encode()).hexdigest(),
    "sha512": lambda pw: hashlib.sha512(pw.encode()).hexdigest(),
}


def _crypt_check(pw: str, full_hash: str) -> bool:
    """Verify a candidate against a Unix crypt() hash ($1$/$5$/$6$)."""
    try:
        import crypt
    except ImportError:
        try:
            from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt
            for scheme in (sha512_crypt, sha256_crypt, md5_crypt):
                try:
                    if scheme.verify(pw, full_hash):
                        return True
                except (ValueError, TypeError):
                    continue
        except ImportError:
            return False
        return False
    salt = "$".join(full_hash.split("$")[:3])   # $id$salt
    try:
        return crypt.crypt(pw, salt) == full_hash
    except (OSError, ValueError):
        return False


def _matches(pw: str, entry: HashEntry) -> bool:
    t = entry.htype
    target = entry.raw.strip().lower()
    if t in _RAW:
        return _RAW[t](pw) == target
    if t == "md5_or_ntlm":
        if _RAW["md5"](pw) == target:
            entry.htype = "md5"
            return True
        n = _ntlm(pw)
        if n and n == target:
            entry.htype = "ntlm"
            return True
        return False
    if t in ("md5crypt", "sha256crypt", "sha512crypt"):
        return _crypt_check(pw, entry.raw.strip())
    if t == "bcrypt":
        try:
            import bcrypt
            return bcrypt.checkpw(pw.encode(), entry.raw.strip().encode())
        except Exception:
            return False
    return False


# ---------------------------------------------------------------- mangling rules
_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})


def mangle(word: str, rules: bool) -> list[str]:
    """JtR-style candidate generation from one base word."""
    cands = [word]
    if not rules:
        return cands
    cands += [word.capitalize(), word.upper(), word[::-1]]
    for suf in ("1", "12", "123", "!", "@", "2023", "2024", "2025", "01", "007"):
        cands.append(word + suf)
        cands.append(word.capitalize() + suf)
    cands.append(word.translate(_LEET))
    cands.append(word.capitalize().translate(_LEET))
    # dedupe, preserve order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ---------------------------------------------------------------- driver
def load_hashes(path: str) -> list[HashEntry]:
    entries = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            label, h = "", line
            if ":" in line and not line.startswith("$"):
                # user:hash  (or shadow-style user:hash:...)
                parts = line.split(":")
                label, h = parts[0], parts[1] if len(parts) > 1 else parts[0]
            entries.append(HashEntry(raw=h, htype=identify_hash(h), label=label))
    return entries


def iter_words(wordlist: str | None):
    if wordlist:
        with open(wordlist, encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.rstrip("\n")
                if w:
                    yield w
    else:
        yield from BUILTIN_WORDS


def audit(entries: list[HashEntry], wordlist: str | None = None,
          rules: bool = True) -> AuditResult:
    result = AuditResult(entries=entries)
    pending = [e for e in entries if e.htype != "unknown"]
    for base in iter_words(wordlist):
        for cand in mangle(base, rules):
            result.tried += 1
            for e in pending:
                if e.cracked is None and _matches(cand, e):
                    e.cracked = cand
        pending = [e for e in pending if e.cracked is None]
        if not pending:
            break
    return result


def render(result: AuditResult) -> str:
    lines = [BANNER,
             f"  Audited {len(result.entries)} hash(es), {len(result.cracked)} WEAK "
             f"(cracked) after {result.tried} candidate(s).",
             "  " + "=" * 58]
    for e in result.entries:
        who = f"{e.label}  " if e.label else ""
        if e.cracked is not None:
            lines.append(f"  [WEAK]   {who}{e.htype}: {e.raw[:24]}...  ->  {e.cracked!r}")
        elif e.htype == "unknown":
            lines.append(f"  [SKIP]   {who}unrecognised hash format")
        else:
            lines.append(f"  [strong] {who}{e.htype}: not cracked with this wordlist")
    if result.cracked:
        lines.append("\n  ACTION: rotate the WEAK passwords above -- they are guessable.")
    return "\n".join(lines)


def to_dict(result: AuditResult) -> dict:
    return {
        "audited": len(result.entries),
        "weak": len(result.cracked),
        "candidates_tried": result.tried,
        "results": [
            {"label": e.label, "type": e.htype, "hash": e.raw,
             "cracked": e.cracked, "weak": e.cracked is not None}
            for e in result.entries
        ],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-password-audit",
        description="OFFLINE password-hash audit (authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--hashes", required=True, help="file of hashes (one per line, or user:hash)")
    ap.add_argument("--wordlist", help="wordlist file (default: small built-in list)")
    ap.add_argument("--no-rules", action="store_true", help="disable mangling rules")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--yes-authorized", action="store_true",
                    help="confirm you are authorized to audit these hashes")
    args = ap.parse_args(argv)

    if not args.yes_authorized:
        sys.stderr.write(BANNER)
        sys.stderr.write("  Refusing to run without --yes-authorized (attest you have permission).\n")
        return 2
    if not os.path.exists(args.hashes):
        sys.stderr.write(f"  error: no such file: {args.hashes}\n")
        return 2

    entries = load_hashes(args.hashes)
    result = audit(entries, wordlist=args.wordlist, rules=not args.no_rules)
    print(json.dumps(to_dict(result), indent=2) if args.json else render(result))
    return 1 if result.cracked else 0


if __name__ == "__main__":
    raise SystemExit(main())
