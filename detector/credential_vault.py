#!/usr/bin/env python3
"""OS-backed credential vault for Attestor 3.0.

Windows uses current-user DPAPI. Other platforms fail closed unless a native
backend is added; Attestor never falls back to plaintext files or environment dumps.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "attestor-credential-vault/3.0"
MAX_VAULT_BYTES = 2 * 1024 * 1024
MAX_SECRET_BYTES = 64 * 1024
NAME_RX = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{1,95}$")
_LOCK = threading.RLock()


class VaultError(RuntimeError):
    pass


class VaultUnavailable(VaultError):
    pass


def status() -> dict:
    return {
        "available": os.name == "nt",
        "backend": "windows-dpapi-current-user" if os.name == "nt" else "unavailable",
        "plaintext_fallback": False,
        "scope": "current OS user" if os.name == "nt" else "none",
    }


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RX.fullmatch(name):
        raise VaultError("credential name is invalid")
    return name


def default_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "Attestor" / "vault-v3.json"


def _dpapi(data: bytes, entropy: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise VaultUnavailable("no native credential vault backend is available")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = (("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte)))

    def blob(value: bytes):
        buffer = ctypes.create_string_buffer(value or b"\0")
        return DATA_BLOB(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, in_buffer = blob(data)
    entropy_blob, entropy_buffer = blob(entropy)
    out_blob = DATA_BLOB()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if decrypt:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                       ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                       wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        ok = fn(ctypes.byref(in_blob), None, ctypes.byref(entropy_blob), None, None,
                flags, ctypes.byref(out_blob))
    else:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
                       ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                       wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        ok = fn(ctypes.byref(in_blob), "Attestor 3.0 credential", ctypes.byref(entropy_blob),
                None, None, flags, ctypes.byref(out_blob))
    _ = in_buffer, entropy_buffer
    if not ok:
        raise VaultError("Windows DPAPI operation failed (%d)" % ctypes.get_last_error())
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))


class CredentialVault:
    def __init__(self, path: str | os.PathLike[str] | None = None,
                 purpose: str = "attestor-3.0"):
        if not status()["available"]:
            raise VaultUnavailable("Attestor requires a native OS credential backend")
        if not isinstance(purpose, str) or not purpose or len(purpose) > 128:
            raise VaultError("vault purpose is invalid")
        self.path = Path(path).expanduser().resolve() if path else default_path().resolve()
        self.purpose = purpose.encode("utf-8")
        self.document = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"schema": SCHEMA, "backend": "windows-dpapi-current-user", "records": {}}
        if not self.path.is_file() or self.path.stat().st_size > MAX_VAULT_BYTES:
            raise VaultError("credential vault is invalid or too large")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultError("credential vault cannot be parsed") from exc
        if value.get("schema") != SCHEMA or value.get("backend") != "windows-dpapi-current-user" \
                or not isinstance(value.get("records"), dict):
            raise VaultError("credential vault schema is invalid")
        return value

    def _entropy(self, name: str) -> bytes:
        return self.purpose + b"\0" + name.encode("utf-8")

    def put(self, name: str, secret: str | bytes) -> None:
        name = _validate_name(name)
        if isinstance(secret, str):
            data = secret.encode("utf-8")
        elif isinstance(secret, bytes):
            data = secret
        else:
            raise VaultError("credential value must be text or bytes")
        if not data or len(data) > MAX_SECRET_BYTES:
            raise VaultError("credential value is empty or too large")
        ciphertext = _dpapi(data, self._entropy(name), decrypt=False)
        with _LOCK:
            self.document["records"][name] = {
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "updated": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "secret_hash_stored": False,
            }
            self.save()

    def get(self, name: str) -> bytes:
        name = _validate_name(name)
        record = self.document["records"].get(name)
        if not isinstance(record, dict) or not isinstance(record.get("ciphertext"), str):
            raise VaultError("credential does not exist")
        try:
            ciphertext = base64.b64decode(record["ciphertext"], validate=True)
        except (ValueError, TypeError) as exc:
            raise VaultError("credential ciphertext is invalid") from exc
        return _dpapi(ciphertext, self._entropy(name), decrypt=True)

    def delete(self, name: str) -> bool:
        name = _validate_name(name)
        with _LOCK:
            existed = self.document["records"].pop(name, None) is not None
            if existed:
                self.save()
            return existed

    def names(self) -> list[str]:
        return sorted(self.document["records"])

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.document, indent=2, sort_keys=True) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=".attestor-vault-", suffix=".tmp",
                                         dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "list", "store", "delete"))
    parser.add_argument("name", nargs="?")
    parser.add_argument("--vault")
    args = parser.parse_args(argv)
    if args.command == "status":
        print(json.dumps(status(), indent=2, sort_keys=True)); return 0
    if not status()["available"]:
        print("Attestor credential vault unavailable; plaintext fallback is disabled."); return 2
    vault = CredentialVault(args.vault)
    if args.command == "list":
        print("\n".join(vault.names())); return 0
    if not args.name:
        parser.error("credential name is required")
    if args.command == "store":
        secret = getpass.getpass("Credential value (input hidden): ")
        vault.put(args.name, secret); print("credential stored in the OS vault"); return 0
    removed = vault.delete(args.name)
    print("credential deleted" if removed else "credential did not exist")
    return 0 if removed else 1


if __name__ == "__main__":
    raise SystemExit(main())
