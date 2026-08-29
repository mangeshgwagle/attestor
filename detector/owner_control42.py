#!/usr/bin/env python3
"""Permission-first Owner Control 4.2 MVP coordinator.

The coordinator performs no plan parsing or computer probing until permission
is the literal boolean ``True``.  It then issues and consumes one exact,
short-lived in-memory capability before dispatching a read-only observation.
Future mutation plans are integrity-bound review artifacts only; this release
contains no mutation executor.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping

# ``python -I detector/owner_control42.py`` omits the script directory from
# ``sys.path``. Seed exactly this resolved detector directory, never the caller's
# working directory or an environment-provided module path.
_DETECTOR_DIRECTORY = Path(__file__).resolve(strict=True).parent
if os.fspath(_DETECTOR_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(_DETECTOR_DIRECTORY))

import control_authorization42 as authorization
import control_inventory42 as inventory
import control_policy42 as policy


VERSION = "4.2"
SCHEMA = "attestor-owner-control/4.2"

_EXECUTION_BASE = {
    "credential_store_accessed": False,
    "file_contents_emitted": False,
    "filesystem_mutated": False,
    "mutation_executed": False,
    "network_accessed": False,
    "persistence_created": False,
    "process_executed": False,
    "shell_invoked": False,
}
_AUTHORITY_BOUNDARIES = {
    "arbitrary_command_authority": False,
    "credential_authority": False,
    "mutation_authority": False,
    "network_authority": False,
    "owner_attestation_is_identity_proof": False,
    "permission_persisted": False,
    "persistence_authority": False,
    "security_disabling_authority": False,
}


def _valid_result_execution(value: Any, *, observation: bool) -> bool:
    expected = set(_EXECUTION_BASE)
    if observation:
        expected.add("files_read_for_hashing")
    if type(value) is not dict or set(value) != expected:
        return False
    if any(value.get(field) is not False for field in _EXECUTION_BASE):
        return False
    return (not observation
            or type(value.get("files_read_for_hashing")) is bool)


class OwnerControlError(ValueError):
    """An Owner Control request, capability, or report failed closed."""


def _denied_authorization() -> dict[str, Any]:
    return {
        "status": "authorization-required",
        "authorized": False,
        "per_run_required": True,
        "permission_retained": False,
        "mutation_authorized": False,
    }


def denied_report() -> dict[str, Any]:
    """Return denial without reading a plan or probing any computer state."""
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": "authorization-required",
        "profile": policy.compiled_profile_document(),
        "action": "none",
        "policy_sha256": policy.POLICY_SHA256,
        "plan_sha256": "",
        "authorization": _denied_authorization(),
        "result": {},
        "coverage": {
            "complete": False,
            "gaps": [
                "owner-control permission was not granted for this invocation"],
        },
        "execution": {
            **_EXECUTION_BASE,
            "computer_probed": False,
            "plan_loaded": False,
        },
        "authority_boundaries": dict(_AUTHORITY_BOUNDARIES),
    }
    return {**body, "report_sha256": policy.digest_json(body)}


def _future_mutation_result(plan: Mapping[str, Any]) -> dict[str, Any]:
    request = plan["request"]
    operations = request["operations"]
    return {
        "schema": "attestor-owner-control-mutation-plan/4.2",
        "version": VERSION,
        "kind": policy.PLAN_FUTURE_MUTATIONS,
        "status": "planned-only",
        "operations": len(operations),
        "operations_sha256": policy.digest_json(operations),
        "executor": "unavailable",
        "mutation_authorized": False,
        "mutation_executed": False,
        "execution": dict(_EXECUTION_BASE),
        "note": (
            "This digest-bound artifact cannot change files, processes, "
            "services, settings, or persistence state."),
    }


def run(
    plan: Mapping[str, Any] | None,
    *,
    permission_confirmed: bool = False,
    registry: authorization.CapabilityRegistry | None = None,
    ttl_seconds: int = 180,
) -> dict[str, Any]:
    """Run one authorized observation or consume one inert plan review.

    ``permission_confirmed=False`` returns before accessing ``plan``.  A
    supplied registry is useful for a UI session and deterministic tests; a
    fresh ephemeral registry is otherwise created for this invocation.
    """
    if type(permission_confirmed) is not bool:
        raise OwnerControlError(
            "permission confirmation must be a literal boolean")
    if not permission_confirmed:
        return denied_report()
    try:
        exact_plan = policy.require_plan(plan)
    except policy.ControlPolicyError as exc:
        raise OwnerControlError("owner-control plan is invalid") from exc
    if registry is None:
        active_registry = authorization.CapabilityRegistry(
            session_id=exact_plan["session_id"])
    elif type(registry) is authorization.CapabilityRegistry:
        active_registry = registry
    else:
        raise OwnerControlError(
            "owner-control registry has an invalid type")
    try:
        capability = active_registry.issue(
            exact_plan,
            confirmed=True,
            ttl_seconds=ttl_seconds,
        )
        audit = active_registry.consume(capability, plan=exact_plan)
    except authorization.ControlAuthorizationError as exc:
        raise OwnerControlError(
            "owner-control authorization failed closed") from exc

    action = exact_plan["action"]
    try:
        if action == policy.PLAN_FUTURE_MUTATIONS:
            result = _future_mutation_result(exact_plan)
            status = "planned-only"
            computer_probed = False
        else:
            result = inventory.execute_observation(exact_plan)
            raw_status = result.get("status")
            status = raw_status if type(raw_status) is str else "inconsistent"
            computer_probed = True
    except inventory.ControlInventoryError as exc:
        raise OwnerControlError(
            "owner-control observation failed closed") from exc

    nested_execution = result.get("execution")
    if not _valid_result_execution(
            nested_execution,
            observation=action != policy.PLAN_FUTURE_MUTATIONS):
        raise OwnerControlError(
            "owner-control result reported a forbidden side effect")
    raw_coverage = result.get("coverage")
    coverage = (
        dict(raw_coverage) if isinstance(raw_coverage, Mapping)
        else {"complete": True, "gaps": []}
    )
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": status,
        "profile": policy.compiled_profile_document(),
        "action": action,
        "policy_sha256": policy.POLICY_SHA256,
        "plan_sha256": exact_plan["plan_sha256"],
        "authorization": audit,
        "result": result,
        "coverage": coverage,
        "execution": {
            **_EXECUTION_BASE,
            "computer_probed": computer_probed,
            "plan_loaded": True,
        },
        "authority_boundaries": dict(_AUTHORITY_BOUNDARIES),
    }
    report = {**body, "report_sha256": policy.digest_json(body)}
    valid, errors = verify_report(report)
    if not valid:
        raise OwnerControlError(
            "owner-control report construction failed: "
            + "; ".join(errors[:3]))
    return report


_REPORT_KEYS = {
    "action", "authority_boundaries", "authorization", "coverage",
    "execution", "plan_sha256", "policy_sha256", "profile",
    "report_sha256", "result", "schema", "status", "version",
}


def verify_report(value: Any) -> tuple[bool, list[str]]:
    """Verify exact report shape, integrity, and no-mutation assertions."""
    try:
        policy.canonical_bytes(value)
    except policy.ControlPolicyError:
        return False, ["owner-control report is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["owner-control report is not an exact object"]
    errors: list[str] = []
    if set(value) != _REPORT_KEYS:
        errors.append("owner-control report keys are invalid")
    if value.get("schema") != SCHEMA or value.get("version") != VERSION:
        errors.append("owner-control report schema or version is invalid")
    if value.get("profile") != policy.compiled_profile_document():
        errors.append("owner-control report profile binding is invalid")
    if value.get("policy_sha256") != policy.POLICY_SHA256:
        errors.append("owner-control report policy binding is invalid")
    if value.get("authority_boundaries") != _AUTHORITY_BOUNDARIES:
        errors.append("owner-control authority boundary is invalid")
    execution = value.get("execution")
    expected_execution_keys = set(_EXECUTION_BASE) | {
        "computer_probed", "plan_loaded"}
    if type(execution) is not dict or set(execution) != expected_execution_keys:
        errors.append("owner-control execution evidence is invalid")
    else:
        if any(execution.get(field) is not False for field in _EXECUTION_BASE):
            errors.append("owner-control reported a forbidden side effect")
        if type(execution.get("computer_probed")) is not bool or type(
                execution.get("plan_loaded")) is not bool:
            errors.append("owner-control probe evidence is invalid")
    status = value.get("status")
    action = value.get("action")
    authorization_value = value.get("authorization")
    if status == "authorization-required":
        if (action != "none"
                or value.get("plan_sha256") != ""
                or authorization_value != _denied_authorization()
                or type(execution) is not dict
                or execution.get("computer_probed") is not False
                or execution.get("plan_loaded") is not False
                or value.get("result") != {}):
            errors.append("owner-control denial evidence is invalid")
    else:
        if type(action) is not str or action not in policy.ALLOWED_ACTIONS:
            errors.append("owner-control report action is invalid")
        plan_digest = value.get("plan_sha256")
        if (type(plan_digest) is not str
                or policy.SHA256_RE.fullmatch(plan_digest) is None):
            errors.append("owner-control report plan digest is invalid")
        valid_audit, audit_errors = authorization.verify_consumption(
            authorization_value)
        if not valid_audit or type(authorization_value) is not dict:
            errors.append(
                "owner-control authorization evidence is invalid: "
                + "; ".join(audit_errors[:2]))
        elif (authorization_value.get("action") != action
                or authorization_value.get("plan_sha256") != plan_digest
                or authorization_value.get("policy_sha256")
                != policy.POLICY_SHA256
                or authorization_value.get("mutation_authorized") is not False):
            errors.append(
                "owner-control authorization evidence does not match the report")
        result = value.get("result")
        if type(result) is not dict:
            errors.append("owner-control result is invalid")
        elif action == policy.PLAN_FUTURE_MUTATIONS:
            if (result.get("status") != "planned-only"
                    or result.get("executor") != "unavailable"
                    or result.get("mutation_authorized") is not False
                    or result.get("mutation_executed") is not False):
                errors.append(
                    "future-mutation plan was not kept inert")
            if not _valid_result_execution(
                    result.get("execution"), observation=False):
                errors.append(
                    "future-mutation execution evidence is invalid")
        elif result.get("kind") != action:
            errors.append("owner-control inventory kind does not match")
        elif not _valid_result_execution(
                result.get("execution"), observation=True):
            errors.append("owner-control nested execution evidence is invalid")
        elif (type(result.get("execution")) is not dict
                or result["execution"].get("mutation_executed") is not False
                or any(result["execution"].get(field) is True for field in (
                    "credential_store_accessed", "filesystem_mutated",
                    "network_accessed", "persistence_created",
                    "process_executed", "shell_invoked"))):
            errors.append("owner-control inventory side-effect evidence is invalid")
    claimed = value.get("report_sha256")
    if type(claimed) is not str or policy.SHA256_RE.fullmatch(claimed) is None:
        errors.append("owner-control report digest is invalid")
    else:
        body = {
            key: item for key, item in value.items()
            if key != "report_sha256"
        }
        try:
            actual = policy.digest_json(body)
        except policy.ControlPolicyError:
            errors.append("owner-control report body is invalid")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("owner-control report digest does not match")
    return not errors, errors


def render_text(report: Mapping[str, Any]) -> str:
    """Render a compact statement that never implies mutation authority."""
    lines = [
        "Attestor 4.2 Owner Control MVP",
        "Status: " + str(report.get("status", "invalid")),
        "Action: " + str(report.get("action", "none")),
        "Mutation executed: false",
        "Network/shell/process/credential/persistence authority: denied",
    ]
    plan_digest = report.get("plan_sha256")
    if isinstance(plan_digest, str) and plan_digest:
        lines.append("Plan SHA-256: " + plan_digest)
    return "\n".join(lines) + "\n"


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OwnerControlError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise OwnerControlError("JSON non-finite numbers are forbidden")


def _json_depth(text: str) -> int:
    depth = maximum = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            maximum = max(maximum, depth)
        elif character in "]}":
            depth -= 1
    return maximum


def _parse_json_object(text: str, label: str) -> dict[str, Any]:
    if type(text) is not str or len(text.encode("utf-8")) > policy.MAX_DOCUMENT_BYTES:
        raise OwnerControlError(f"{label} exceeds its byte boundary")
    if _json_depth(text) > policy.MAX_JSON_DEPTH:
        raise OwnerControlError(f"{label} exceeds its nesting boundary")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except OwnerControlError:
        raise
    except (RecursionError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise OwnerControlError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise OwnerControlError(f"{label} must be one JSON object")
    try:
        return policy.require_json_object(value)
    except policy.ControlPolicyError as exc:
        raise OwnerControlError(f"{label} is outside its boundary") from exc


def _load_plan_file(value: str) -> dict[str, Any]:
    """Read one bounded non-link plan after permission was confirmed."""
    if type(value) is not str or not value or "\x00" in value:
        raise OwnerControlError("plan path is invalid")
    if value.replace("\\", "/").startswith("//"):
        raise OwnerControlError("network plan paths are denied")
    supplied = Path(value).expanduser()
    try:
        path = supplied.resolve(strict=True)
        before = path.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise OwnerControlError("plan file is unavailable") from exc
    attributes = int(getattr(before, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if (stat.S_ISLNK(before.st_mode)
            or bool(attributes & reparse)
            or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or not 1 <= int(before.st_size) <= policy.MAX_DOCUMENT_BYTES):
        raise OwnerControlError("plan file is unsafe or outside its boundary")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OwnerControlError("plan file could not be opened safely") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1)) != 1
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)):
            raise OwnerControlError(
                "plan file identity changed before reading")
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            total += len(block)
            if total > policy.MAX_DOCUMENT_BYTES:
                raise OwnerControlError(
                    "plan file grew beyond its byte boundary")
            chunks.append(block)
    except OSError as exc:
        raise OwnerControlError("plan file could not be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise OwnerControlError("plan file changed while reading") from exc
    before_identity = (
        int(before.st_dev), int(before.st_ino), stat.S_IFMT(before.st_mode),
        int(before.st_size), int(before.st_mtime_ns), int(before.st_ctime_ns),
    )
    after_identity = (
        int(after.st_dev), int(after.st_ino), stat.S_IFMT(after.st_mode),
        int(after.st_size), int(after.st_mtime_ns), int(after.st_ctime_ns),
    )
    opened_identity = (
        int(opened.st_dev), int(opened.st_ino), stat.S_IFMT(opened.st_mode),
        int(opened.st_size), int(opened.st_mtime_ns),
    )
    if (before_identity != after_identity
            or opened_identity != before_identity[:5]
            or total != int(before.st_size)):
        raise OwnerControlError("plan file changed while reading")
    try:
        text = b"".join(chunks).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise OwnerControlError("plan file must be UTF-8 JSON") from exc
    return policy.require_plan(_parse_json_object(text, "plan file"))


def _write_cli(value: Any, output_format: str) -> None:
    if output_format == "json":
        text = json.dumps(
            value, indent=2, sort_keys=True, ensure_ascii=False)
        print(text)
        return
    if isinstance(value, Mapping) and value.get("schema") == SCHEMA:
        print(render_text(value), end="")
        return
    if isinstance(value, Mapping) and value.get("schema") == policy.PLAN_SCHEMA:
        print("Attestor 4.2 Owner Control plan")
        print("Action: " + str(value.get("action", "invalid")))
        print("Plan SHA-256: " + str(value.get("plan_sha256", "")))
        print("Mutation execution allowed: false")
        return
    if isinstance(value, Mapping) and value.get("schema") == policy.POLICY_SCHEMA:
        print("Attestor 4.2 Owner Control policy")
        print("Policy SHA-256: " + str(value.get("policy_sha256", "")))
        print("Mutation executor: unavailable")
        return
    print("Attestor 4.2 Owner Control output is invalid")


def _failure(error: BaseException, output_format: str) -> None:
    error_type = type(error).__name__[:120]
    if output_format == "json":
        print(json.dumps({
            "schema": "attestor-owner-control-cli-failure/4.2",
            "version": VERSION,
            "status": "failed-closed",
            "error_type": error_type,
            "mutation_executed": False,
        }, sort_keys=True))
    else:
        print(
            "Attestor 4.2 Owner Control failed safely: " + error_type,
            file=sys.stderr,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Permission-first, read-only Attestor 4.2 Owner Control MVP. "
            "Mutation plans are inert."),
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser(
        "policy", help="print the immutable Owner Control policy",
        allow_abbrev=False)
    policy_parser.add_argument(
        "--format", choices=("text", "json"), default="json")

    plan_parser = subparsers.add_parser(
        "plan", help="build one exact non-probing control plan",
        allow_abbrev=False)
    plan_parser.add_argument("action", choices=policy.ACTION_ORDER)
    plan_parser.add_argument("--session-id", required=True)
    plan_parser.add_argument(
        "--request-json", required=True,
        help="strict JSON object for the selected exact action")
    plan_parser.add_argument(
        "--format", choices=("text", "json"), default="json")

    run_parser = subparsers.add_parser(
        "run", help=(
            "run a plan; denied by default and does not open the plan until "
            "--permission plus its exact digest are supplied"),
        allow_abbrev=False)
    run_parser.add_argument("plan_file")
    run_parser.add_argument(
        "--permission", action="store_true",
        help="confirm permission for this invocation only")
    run_parser.add_argument(
        "--confirm-plan-sha256", default="",
        help="exact plan_sha256 reviewed by the operator")
    run_parser.add_argument(
        "--ttl-seconds", type=int, default=180)
    run_parser.add_argument(
        "--format", choices=("text", "json"), default="json")
    return parser


def _reject_duplicate_options(
        parser: argparse.ArgumentParser, argv: list[str]) -> None:
    single_use = (
        "--confirm-plan-sha256", "--format", "--permission",
        "--request-json", "--session-id", "--ttl-seconds",
    )
    duplicates = []
    for option in single_use:
        count = sum(
            token == option or token.startswith(option + "=")
            for token in argv
        )
        if count > 1:
            duplicates.append(option)
    if duplicates:
        parser.error(
            "duplicate option(s) are not allowed: " + ", ".join(duplicates))


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    _reject_duplicate_options(parser, raw_argv)
    args = parser.parse_args(raw_argv)
    output_format = args.format
    try:
        if args.command == "policy":
            _write_cli(policy.policy_document(), output_format)
            return 0
        if args.command == "plan":
            request = _parse_json_object(args.request_json, "request JSON")
            selected_plan = policy.create_plan(
                args.action, request, session_id=args.session_id)
            _write_cli(selected_plan, output_format)
            return 0
        if not args.permission:
            if args.confirm_plan_sha256 or args.ttl_seconds != 180:
                raise OwnerControlError(
                    "confirmation and TTL controls require --permission")
            report = run(None, permission_confirmed=False)
            _write_cli(report, output_format)
            return 2
        if (type(args.confirm_plan_sha256) is not str
                or policy.SHA256_RE.fullmatch(
                    args.confirm_plan_sha256) is None):
            raise OwnerControlError(
                "--permission requires the exact --confirm-plan-sha256")
        if not (authorization.MIN_TTL_SECONDS
                <= args.ttl_seconds <= authorization.MAX_TTL_SECONDS):
            raise OwnerControlError("authorization TTL is outside its boundary")
        selected_plan = _load_plan_file(args.plan_file)
        if not hmac.compare_digest(
                selected_plan["plan_sha256"], args.confirm_plan_sha256):
            raise OwnerControlError(
                "confirmed plan digest does not match the plan file")
        report = run(
            selected_plan,
            permission_confirmed=True,
            ttl_seconds=args.ttl_seconds,
        )
        _write_cli(report, output_format)
        return 1 if report.get("status") in {"partial", "inconsistent"} else 0
    except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
        _failure(exc, output_format)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OwnerControlError", "SCHEMA", "VERSION", "denied_report", "render_text",
    "main", "run", "verify_report",
]
