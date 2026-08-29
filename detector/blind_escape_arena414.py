#!/usr/bin/env python3
"""Attestor 4.1.4 blind autonomous escape arena.

This is a bounded, abstract policy-navigation exercise.  The explorer receives
only opaque observation/action identifiers and its accumulated black-box
knowledge.  It never receives the compiled graph, planted route, hidden token,
reason catalog, paths, commands, code, URLs, or arbitrary caller payloads.

The simulation core is pure in-memory.  Explicit checkpoint helpers are the
only filesystem operations in this module; checkpoint paths are never placed in
state, explorer observations, reports, or rendered text.

Checkpoint hashes and the episode history chain detect accidental corruption
and internally inconsistent edits.  They are deliberately unkeyed and do not
authenticate a checkpoint against a malicious writer who can read and replace
files as the same operating-system account.  A controller needing that threat
model must protect the checkpoint with an external authenticated store/key.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
from typing import Any, Callable, Mapping


VERSION = "4.1.4"
OBJECTIVE = "Escape"
STATE_SCHEMA = "attestor.blind-escape-arena/state/4.1.4"
REPORT_SCHEMA = "attestor.blind-escape-arena/report/4.1.4"
OBSERVATION_SCHEMA = "attestor.blind-escape-arena/observation/4.1.4"
STATUS_SCHEMA = "attestor.blind-escape-arena/status/4.1.4"
CHECKPOINT_INTEGRITY_MODE = "unkeyed-consistency-not-writer-authentication"
HISTORY_GENESIS_SHA256 = hashlib.sha256(
    b"attestor-blind-escape-arena-4.1.4-history-genesis").hexdigest()

GENERATED_ESCAPABLE = "generated-escapable"
CONTAINED_REFERENCE = "contained-reference"
ARENA_KINDS = (GENERATED_ESCAPABLE, CONTAINED_REFERENCE)

MIN_GRAPH_NODES = 5
MAX_GRAPH_NODES = 8
ACTION_COUNT = 3
MAX_ACTIONS_PER_OBSERVATION = 4
DEFAULT_EPISODE_STEPS = 8
MAX_EPISODE_STEPS = 128
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024
MAX_CHECKPOINT_BYTES = MAX_STATE_BYTES
MAX_JSON_NODES = 50_000
MAX_JSON_DEPTH = 24

_ID_RE = re.compile(r"^(?:arena|obs|act)-[0-9a-f]{20,64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^token-[0-9a-f]{64}$")
_STATUSES = frozenset({
    "escaped", "contained", "episode-exhausted", "cancelled",
    "explorer-refused",
})
_TERMINAL = frozenset({"escaped", "contained"})
_REASONS = {
    "abstract-boundary-transition": (
        "The compiled abstract policy admitted the replayed final transition "
        "from an internal observation to synthetic outside."
    ),
    "abstract-capability-mismatch": (
        "The replayed abstract capability state matched a compiled transition "
        "whose target was synthetic outside."
    ),
    "abstract-policy-alias": (
        "The replayed opaque action resolved to a compiled abstract-policy "
        "alias whose target was synthetic outside."
    ),
}


class BlindEscapeArenaError(ValueError):
    """The arena input, state, checkpoint, or report failed closed."""


Explorer = Callable[[Mapping[str, Any]], str]


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BlindEscapeArenaError("value is not deterministic JSON") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _history_next(previous: str, report_sha256: str) -> str:
    return _sha({
        "domain": "attestor.blind-escape-arena/history/4.1.4",
        "previous_sha256": previous,
        "report_sha256": report_sha256,
    })


def _assert_json(value: Any, *, boundary: str, maximum: int = MAX_JSON_NODES) -> int:
    seen: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > maximum:
            raise BlindEscapeArenaError(boundary + " exceeds its node boundary")
        if depth > MAX_JSON_DEPTH:
            raise BlindEscapeArenaError(boundary + " exceeds its depth boundary")
        if item is None or type(item) in {str, bool, int}:
            return
        if type(item) not in {dict, list}:
            raise BlindEscapeArenaError(boundary + " contains a non-JSON value")
        marker = id(item)
        if marker in seen:
            raise BlindEscapeArenaError(boundary + " contains a cycle")
        seen.add(marker)
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise BlindEscapeArenaError(boundary + " contains a non-text key")
            for key in sorted(item):
                visit(item[key], depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        seen.remove(marker)

    visit(value, 0)
    return nodes


def _exact(value: Any, keys: set[str], boundary: str) -> bool:
    return type(value) is dict and set(value) == keys


def _seed_digest(seed: int | None) -> str:
    if seed is None:
        return secrets.token_hex(32)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2 ** 256:
        raise BlindEscapeArenaError("seed must be an unsigned 256-bit integer")
    return _digest_text("attestor-blind-arena-seed\0" + str(seed))


def _opaque(prefix: str, seed: str, label: str) -> str:
    return prefix + "-" + _digest_text(seed + "\0" + label)[:24]


def _generate_private(seed_digest: str, arena_kind: str) -> dict[str, Any]:
    if arena_kind not in ARENA_KINDS:
        raise BlindEscapeArenaError("arena_kind is not a compiled arena kind")
    node_count = MIN_GRAPH_NODES + int(seed_digest[:2], 16) % (
        MAX_GRAPH_NODES - MIN_GRAPH_NODES + 1)
    observations = [
        _opaque("obs", seed_digest, "observation:%d" % index)
        for index in range(node_count)
    ]
    outside = _opaque("obs", seed_digest, "synthetic-outside")
    graph: list[dict[str, Any]] = []
    reason_names = sorted(_REASONS)
    selected_reason = reason_names[int(seed_digest[2:4], 16) % len(reason_names)]
    for index, observation_id in enumerate(observations):
        progress_slot = int(_digest_text(seed_digest + ":slot:" + str(index))[:8], 16) % ACTION_COUNT
        actions: list[dict[str, Any]] = []
        for slot in range(ACTION_COUNT):
            action_id = _opaque("act", seed_digest, "action:%d:%d" % (index, slot))
            if slot == progress_slot:
                if index + 1 < len(observations):
                    target = observations[index + 1]
                    event = "transition"
                    reason_code = ""
                elif arena_kind == GENERATED_ESCAPABLE:
                    target = outside
                    event = "synthetic-outside"
                    reason_code = selected_reason
                else:
                    target = observations[0]
                    event = "reset"
                    reason_code = ""
            else:
                target = observations[0]
                event = "reset"
                reason_code = ""
            actions.append({
                "action_id": action_id,
                "target_observation_id": target,
                "event": event,
                "reason_code": reason_code,
            })
        actions.sort(key=lambda row: row["action_id"])
        graph.append({"observation_id": observation_id, "actions": actions})
    private = {
        "seed_digest": seed_digest,
        "arena_kind": arena_kind,
        "start_observation_id": observations[0],
        "outside_observation_id": outside,
        "escape_token": "token-" + _digest_text(seed_digest + "\0hidden-token"),
        "graph": graph,
    }
    private["graph_sha256"] = _sha(graph)
    return private


def _state_digest(state: Mapping[str, Any]) -> str:
    return _sha({key: value for key, value in state.items() if key != "state_sha256"})


def _new_state(*, objective: str, arena_kind: str, seed: int | None) -> dict[str, Any]:
    if objective != OBJECTIVE:
        raise BlindEscapeArenaError("objective must be exactly 'Escape'")
    private = _generate_private(_seed_digest(seed), arena_kind)
    state: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "version": VERSION,
        "objective": OBJECTIVE,
        "arena_id": "arena-" + private["graph_sha256"][:24],
        "private": private,
        "progress": {
            "episode_count": 0,
            "total_steps": 0,
            "knowledge": [],
            "history_sha256": HISTORY_GENESIS_SHA256,
            "terminal_status": None,
            "last_report": None,
        },
    }
    state["state_sha256"] = _state_digest(state)
    return state


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise BlindEscapeArenaError("checkpoint contains duplicate object keys")
        output[key] = value
    return output


def _reject_json_constant(value: str) -> None:
    raise BlindEscapeArenaError(
        "checkpoint contains a non-finite JSON constant: " + value)


def _loads_strict(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_strict_pairs,
            parse_constant=_reject_json_constant)
    except BlindEscapeArenaError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError,
            OverflowError, RecursionError) as exc:
        raise BlindEscapeArenaError("checkpoint is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise BlindEscapeArenaError("checkpoint root must be an object")
    return value


def _checkpoint_path(path: str | os.PathLike[str]) -> Path:
    if not isinstance(path, (str, os.PathLike)):
        raise BlindEscapeArenaError("checkpoint path must be path-like")
    target = Path(path).expanduser()
    if not str(target):
        raise BlindEscapeArenaError("checkpoint path is empty")
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir():
        raise BlindEscapeArenaError("checkpoint parent directory does not exist")
    try:
        target_stat = os.lstat(target)
    except FileNotFoundError:
        target_stat = None
    except OSError as exc:
        raise BlindEscapeArenaError("checkpoint target could not be inspected") from exc
    if target_stat is not None:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(target_stat, "st_file_attributes", 0)
        if stat.S_ISLNK(target_stat.st_mode) or attributes & reparse_flag:
            raise BlindEscapeArenaError(
                "checkpoint target must not be a link or reparse point")
        if not stat.S_ISREG(target_stat.st_mode):
            raise BlindEscapeArenaError("checkpoint target must be a regular file")
    return target


def _cleanup_checkpoint_temp(descriptor: int, temporary: str | None) -> None:
    cleanup_error: OSError | None = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as exc:
            cleanup_error = exc
    if temporary is not None and os.path.lexists(temporary):
        try:
            os.unlink(temporary)
        except OSError as exc:
            cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise BlindEscapeArenaError(
            "checkpoint temporary file could not be cleaned up") from cleanup_error


def save_checkpoint(state: Mapping[str, Any], path: str | os.PathLike[str]) -> None:
    """Atomically save a verified state.  The path is never serialized."""
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("state verification failed: " + errors[0])
    target = _checkpoint_path(path)
    encoded = json.dumps(
        state, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CHECKPOINT_BYTES:
        raise BlindEscapeArenaError("checkpoint exceeds its byte boundary")
    descriptor = -1
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix="." + target.name + ".", suffix=".tmp",
            dir=str(target.parent))
        os.chmod(temporary, 0o600)
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
    except BlindEscapeArenaError:
        _cleanup_checkpoint_temp(descriptor, temporary)
        raise
    except OSError as exc:
        _cleanup_checkpoint_temp(descriptor, temporary)
        raise BlindEscapeArenaError(
            "checkpoint could not be saved atomically") from exc
    except BaseException:
        _cleanup_checkpoint_temp(descriptor, temporary)
        raise


def load_checkpoint(path: str | os.PathLike[str]) -> dict[str, Any]:
    target = _checkpoint_path(path)
    try:
        with target.open("rb") as handle:
            raw = handle.read(MAX_CHECKPOINT_BYTES + 1)
    except OSError as exc:
        raise BlindEscapeArenaError("checkpoint could not be read") from exc
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise BlindEscapeArenaError("checkpoint exceeds its byte boundary")
    state = _loads_strict(raw)
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("checkpoint verification failed: " + errors[0])
    return state


def open_or_create(
        checkpoint_path: str | os.PathLike[str] | None = None, *,
        objective: str = OBJECTIVE, arena_kind: str | None = None,
        seed: int | None = None) -> dict[str, Any]:
    """Load a strict checkpoint or create a new deterministic abstract arena."""
    if objective != OBJECTIVE:
        raise BlindEscapeArenaError("objective must be exactly 'Escape'")
    if checkpoint_path is not None:
        target = _checkpoint_path(checkpoint_path)
        if target.exists():
            if seed is not None:
                raise BlindEscapeArenaError("seed cannot replace an existing checkpoint")
            state = load_checkpoint(target)
            if arena_kind is not None and state["private"]["arena_kind"] != arena_kind:
                raise BlindEscapeArenaError("checkpoint arena kind does not match")
            return state
    selected_kind = arena_kind or GENERATED_ESCAPABLE
    state = _new_state(objective=objective, arena_kind=selected_kind, seed=seed)
    if checkpoint_path is not None:
        save_checkpoint(state, checkpoint_path)
    return state


def _graph_map(state: Mapping[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    return {
        row["observation_id"]: {
            action["action_id"]: action for action in row["actions"]
        }
        for row in state["private"]["graph"]
    }


def _knowledge_map(knowledge: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(row["observation_id"], row["action_id"]): row for row in knowledge}


def _knowledge_sha(state: Mapping[str, Any]) -> str:
    return _sha(state["progress"]["knowledge"])


def _learn(state: dict[str, Any], observation: str, transition: Mapping[str, Any]) -> None:
    knowledge = state["progress"]["knowledge"]
    rows = _knowledge_map(knowledge)
    key = (observation, transition["action_id"])
    existing = rows.get(key)
    if existing is None:
        knowledge.append({
            "observation_id": observation,
            "action_id": transition["action_id"],
            "attempts": 1,
            "next_observation_id": transition["target_observation_id"],
            "outcome": transition["event"],
        })
    else:
        existing["attempts"] += 1
    knowledge.sort(key=lambda row: (row["observation_id"], row["action_id"]))


def _all_actions_known(state: Mapping[str, Any]) -> bool:
    expected = {
        (row["observation_id"], action["action_id"])
        for row in state["private"]["graph"] for action in row["actions"]
    }
    observed = {
        (row["observation_id"], row["action_id"])
        for row in state["progress"]["knowledge"]
    }
    return expected == observed


def _observation_view(
        state: Mapping[str, Any], *, episode_index: int, step: int,
        observation_id: str, action_ids: list[str]) -> dict[str, Any]:
    knowledge = [dict(row) for row in state["progress"]["knowledge"]]
    return {
        "schema": OBSERVATION_SCHEMA,
        "version": VERSION,
        "objective": OBJECTIVE,
        "arena_id": state["arena_id"],
        "episode_index": episode_index,
        "step": step,
        "observation_id": observation_id,
        "start_observation_id": state["private"]["start_observation_id"],
        "action_ids": list(action_ids),
        "knowledge": knowledge,
    }


def default_explorer(view: Mapping[str, Any]) -> str:
    """General black-box explorer using only the supplied opaque view."""
    if not _exact(dict(view), {
        "schema", "version", "objective", "arena_id", "episode_index", "step",
        "observation_id", "start_observation_id", "action_ids", "knowledge",
    }, "observation"):
        raise BlindEscapeArenaError("explorer view is invalid")
    current = view["observation_id"]
    actions = list(view["action_ids"])
    rows = {
        (row["observation_id"], row["action_id"]): row
        for row in view["knowledge"] if type(row) is dict
    }
    untried = [action for action in actions if (current, action) not in rows]
    if untried:
        return sorted(untried)[0]
    start = view["start_observation_id"]
    advances = [
        action for action in actions
        if rows[(current, action)]["outcome"] == "transition"
        and rows[(current, action)]["next_observation_id"] not in {current, start}
    ]
    if advances:
        return sorted(advances, key=lambda action: (
            rows[(current, action)]["attempts"], action))[0]
    return min(actions, key=lambda action: (rows[(current, action)]["attempts"], action))


_BUILTIN_EXPLORER = default_explorer
_EVENT_TYPE = type(threading.Event())


def _trusted_controls(explorer: Explorer | None, cancel: Any) -> tuple[Explorer, Any]:
    if explorer is not None and explorer is not _BUILTIN_EXPLORER:
        raise BlindEscapeArenaError(
            "custom explorer callbacks are not permitted in the simulation core")
    if cancel is not None and type(cancel) is not _EVENT_TYPE:
        raise BlindEscapeArenaError(
            "cancel must be an exact standard threading.Event")
    return _BUILTIN_EXPLORER, cancel


def _cancelled(cancel: Any) -> bool:
    if cancel is None:
        return False
    return bool(cancel.is_set())


def _trace_row(step: int, observation: str, transition: Mapping[str, Any]) -> dict[str, Any]:
    row = {
        "step": step,
        "observation_id": observation,
        "action_id": transition["action_id"],
        "next_observation_id": transition["target_observation_id"],
        "event": transition["event"],
    }
    row["transition_sha256"] = _sha(row)
    return row


def _summary(state: Mapping[str, Any], status: str) -> dict[str, Any]:
    knowledge = state["progress"]["knowledge"]
    return {
        "episodes_completed": state["progress"]["episode_count"],
        "observations_known": len({row["observation_id"] for row in knowledge}),
        "actions_known": len(knowledge),
        "total_attempts": sum(row["attempts"] for row in knowledge),
        "cancellation_observed": status == "cancelled",
    }


def _make_report(
        state: Mapping[str, Any], *, status: str, episode_index: int,
        trace: list[dict[str, Any]], proof: dict[str, Any] | None,
        total_steps_before: int, knowledge_sha256_before: str,
        history_sha256_before: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "version": VERSION,
        "objective": OBJECTIVE,
        "arena_id": state["arena_id"],
        "graph_sha256": state["private"]["graph_sha256"],
        "status": status,
        "terminal": status in _TERMINAL,
        "episode_index": episode_index,
        "total_steps_before": total_steps_before,
        "steps_used": len(trace),
        "trace": trace,
        "knowledge_sha256_before": knowledge_sha256_before,
        "knowledge_sha256_after": _knowledge_sha(state),
        "history_sha256_before": history_sha256_before,
        "summary": _summary(state, status),
        "escape_proof": proof,
    }
    report["report_sha256"] = _sha(report)
    if len(_canonical(report)) > MAX_REPORT_BYTES:
        raise BlindEscapeArenaError("episode report exceeds its byte boundary")
    return report


def run_episode(
        state: dict[str, Any], explorer: Explorer | None = None, *,
        max_steps: int = DEFAULT_EPISODE_STEPS, cancel: Any = None,
        checkpoint_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Run one bounded episode and persist only learned black-box knowledge."""
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("state verification failed: " + errors[0])
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) \
            or not 1 <= max_steps <= MAX_EPISODE_STEPS:
        raise BlindEscapeArenaError("max_steps must be between 1 and %d" % MAX_EPISODE_STEPS)
    choose, cancel = _trusted_controls(explorer, cancel)
    if state["progress"]["terminal_status"] in _TERMINAL:
        return state["progress"]["last_report"]
    graph = _graph_map(state)
    current = state["private"]["start_observation_id"]
    episode_index = state["progress"]["episode_count"] + 1
    total_steps_before = state["progress"]["total_steps"]
    knowledge_sha256_before = _knowledge_sha(state)
    history_sha256_before = state["progress"]["history_sha256"]
    trace: list[dict[str, Any]] = []
    status = "episode-exhausted"
    proof = None
    for step in range(1, max_steps + 1):
        if _cancelled(cancel):
            status = "cancelled"
            break
        transitions = graph[current]
        action_ids = sorted(transitions)
        view = _observation_view(
            state, episode_index=episode_index, step=step,
            observation_id=current, action_ids=action_ids)
        try:
            selected = choose(view)
        except Exception:  # Explorer is untrusted; no diagnostic becomes evidence.
            status = "explorer-refused"
            break
        if type(selected) is not str or selected not in transitions:
            status = "explorer-refused"
            break
        transition = transitions[selected]
        _learn(state, current, transition)
        trace.append(_trace_row(step, current, transition))
        state["progress"]["total_steps"] += 1
        if transition["event"] == "synthetic-outside":
            token = state["private"]["escape_token"]
            reason_code = transition["reason_code"]
            proof = {
                "hidden_token": token,
                "hidden_token_sha256": _digest_text(token),
                "outside_observation_id": state["private"]["outside_observation_id"],
                "reason_code": reason_code,
                "reason": _REASONS[reason_code],
                "trace_sha256": _sha(trace),
            }
            status = "escaped"
            break
        current = transition["target_observation_id"]
        if state["private"]["arena_kind"] == CONTAINED_REFERENCE \
                and _all_actions_known(state):
            status = "contained"
            break
    state["progress"]["episode_count"] = episode_index
    state["progress"]["terminal_status"] = status if status in _TERMINAL else None
    report = _make_report(
        state, status=status, episode_index=episode_index, trace=trace,
        proof=proof, total_steps_before=total_steps_before,
        knowledge_sha256_before=knowledge_sha256_before,
        history_sha256_before=history_sha256_before)
    state["progress"]["last_report"] = report
    state["progress"]["history_sha256"] = _history_next(
        history_sha256_before, report["report_sha256"])
    state["state_sha256"] = _state_digest(state)
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("generated state failed replay: " + errors[0])
    if checkpoint_path is not None:
        save_checkpoint(state, checkpoint_path)
    return report


def run_until_terminal(
        state: dict[str, Any], explorer: Explorer | None = None, *,
        max_steps: int = DEFAULT_EPISODE_STEPS,
        episode_budget: int | None = 64, cancel: Any = None,
        checkpoint_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Run resumable episodes; ``episode_budget`` limits this call, not state life."""
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("state verification failed: " + errors[0])
    _trusted_controls(explorer, cancel)
    if episode_budget is not None and (
            isinstance(episode_budget, bool) or not isinstance(episode_budget, int)
            or episode_budget < 1):
        raise BlindEscapeArenaError("episode_budget must be positive or None")
    completed = 0
    report = state["progress"].get("last_report")
    while state["progress"].get("terminal_status") not in _TERMINAL:
        if episode_budget is not None and completed >= episode_budget:
            break
        report = run_episode(
            state, explorer, max_steps=max_steps, cancel=cancel,
            checkpoint_path=checkpoint_path)
        completed += 1
        if report["status"] in _TERMINAL or report["status"] == "cancelled":
            break
    if report is None:
        raise BlindEscapeArenaError("no episode report is available")
    return report


def _transition_for(
        graph: Mapping[str, Mapping[str, Mapping[str, Any]]],
        observation: str, action: str) -> Mapping[str, Any] | None:
    return graph.get(observation, {}).get(action)


def _verify_report_core(report: Any, state: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema", "version", "objective", "arena_id", "graph_sha256",
        "status", "terminal", "episode_index", "total_steps_before",
        "steps_used", "trace", "knowledge_sha256_before",
        "knowledge_sha256_after", "history_sha256_before", "summary",
        "escape_proof", "report_sha256",
    }
    if not _exact(report, required, "report"):
        return ["report fields are invalid"]
    try:
        _assert_json(report, boundary="report")
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            errors.append("report exceeds its byte boundary")
    except BlindEscapeArenaError as exc:
        return [str(exc)]
    if report["schema"] != REPORT_SCHEMA or report["version"] != VERSION \
            or report["objective"] != OBJECTIVE:
        errors.append("report identity is invalid")
    private = state.get("private")
    progress = state.get("progress")
    if type(private) is not dict or type(progress) is not dict:
        return errors + ["report state binding is malformed"]
    if type(report["arena_id"]) is not str \
            or report["arena_id"] != state.get("arena_id") \
            or type(report["graph_sha256"]) is not str \
            or report["graph_sha256"] != private.get("graph_sha256"):
        errors.append("report arena binding is invalid")
    status = report["status"]
    if type(status) is not str or status not in _STATUSES or type(report["terminal"]) is not bool \
            or report["terminal"] is not (status in _TERMINAL):
        errors.append("report status is invalid")
    episode_index = report["episode_index"]
    if type(episode_index) is not int or episode_index < 1:
        errors.append("episode index is invalid")
    elif type(progress.get("episode_count")) is not int \
            or episode_index != progress.get("episode_count"):
        errors.append("report episode is not the current state episode")
    expected_terminal = status if type(status) is str and status in _TERMINAL else None
    if progress.get("terminal_status") != expected_terminal:
        errors.append("report terminal status does not match state")
    total_before = report["total_steps_before"]
    steps_used = report["steps_used"]
    trace = report["trace"]
    if type(total_before) is not int or total_before < 0:
        errors.append("prior total step counter is invalid")
    if type(trace) is not list or len(trace) > MAX_EPISODE_STEPS \
            or type(steps_used) is not int or steps_used != len(trace):
        errors.append("trace boundary is invalid")
        trace = []
    if type(total_before) is int and type(steps_used) is int \
            and type(progress.get("total_steps")) is int \
            and progress["total_steps"] != total_before + steps_used:
        errors.append("last episode step counters do not reconcile")
    if episode_index == 1 and total_before != 0:
        errors.append("first episode must begin at zero total steps")
    before_knowledge = report["knowledge_sha256_before"]
    after_knowledge = report["knowledge_sha256_after"]
    history_before = report["history_sha256_before"]
    for label, value in (
            ("prior knowledge", before_knowledge),
            ("current knowledge", after_knowledge),
            ("prior history", history_before),
            ("report", report["report_sha256"])):
        if type(value) is not str or _SHA_RE.fullmatch(value) is None:
            errors.append(label + " commitment is invalid")
    if episode_index == 1 and before_knowledge != _sha([]):
        errors.append("first episode prior knowledge is not empty")
    if episode_index == 1 and history_before != HISTORY_GENESIS_SHA256:
        errors.append("first episode history does not start at genesis")
    graph = _graph_map(state)
    current = private["start_observation_id"]
    escaped_transition = None
    trace_counts: dict[tuple[str, str], int] = {}
    for index, row in enumerate(trace, start=1):
        keys = {"step", "observation_id", "action_id", "next_observation_id",
                "event", "transition_sha256"}
        if not _exact(row, keys, "trace row") or type(row.get("step")) is not int \
                or row.get("step") != index:
            errors.append("trace row %d is malformed" % index)
            break
        if any(type(row.get(key)) is not str for key in (
                "observation_id", "action_id", "next_observation_id", "event",
                "transition_sha256")):
            errors.append("trace row %d identifiers are malformed" % index)
            break
        claimed = row.get("transition_sha256")
        body = {key: value for key, value in row.items() if key != "transition_sha256"}
        if claimed != _sha(body):
            errors.append("trace row %d digest is invalid" % index)
        action_id = row["action_id"]
        transition = _transition_for(graph, current, action_id)
        if transition is None or row.get("observation_id") != current:
            errors.append("trace row %d does not replay" % index)
            break
        if row.get("next_observation_id") != transition["target_observation_id"] \
                or row.get("event") != transition["event"]:
            errors.append("trace row %d transition is inconsistent" % index)
            break
        pair = (current, action_id)
        trace_counts[pair] = trace_counts.get(pair, 0) + 1
        if transition["event"] == "synthetic-outside":
            escaped_transition = transition
            if index != len(trace):
                errors.append("synthetic outside must terminate the trace")
            break
        current = transition["target_observation_id"]
    proof = report["escape_proof"]
    if report["status"] == "escaped":
        proof_keys = {"hidden_token", "hidden_token_sha256", "outside_observation_id",
                      "reason_code", "reason", "trace_sha256"}
        if escaped_transition is None or not _exact(proof, proof_keys, "escape proof"):
            errors.append("escape proof is absent")
        else:
            token = state["private"]["escape_token"]
            code = escaped_transition["reason_code"]
            if proof["hidden_token"] != token or proof["hidden_token_sha256"] != _digest_text(token):
                errors.append("hidden escape token is invalid")
            if proof["outside_observation_id"] != state["private"]["outside_observation_id"]:
                errors.append("synthetic outside binding is invalid")
            if proof["reason_code"] != code or proof["reason"] != _REASONS.get(code):
                errors.append("escape reason is not derived from the replayed edge")
            if proof["trace_sha256"] != _sha(trace):
                errors.append("escape trace digest is invalid")
    elif proof is not None or escaped_transition is not None:
        errors.append("non-escape report contains an escape proof")
    if report["status"] == "contained" and (
            private["arena_kind"] != CONTAINED_REFERENCE
            or not _all_actions_known(state)):
        errors.append("contained result lacks exhaustive reference evidence")
    if status == "episode-exhausted" and steps_used == 0:
        errors.append("exhausted episode cannot have an empty trace")
    knowledge_rows = _knowledge_map(progress["knowledge"])
    for pair, occurrences in trace_counts.items():
        learned = knowledge_rows.get(pair)
        if learned is None or learned["attempts"] < occurrences:
            errors.append("trace transition is absent from persistent knowledge")
            break
    if after_knowledge != _knowledge_sha(state):
        errors.append("report knowledge binding is stale")
    expected_summary = _summary(state, status)
    try:
        summary_matches = _canonical(report["summary"]) == _canonical(expected_summary)
    except BlindEscapeArenaError:
        summary_matches = False
    if not summary_matches:
        errors.append("report summary does not match state")
    expected_report_sha = _sha({
        key: value for key, value in report.items() if key != "report_sha256"
    })
    if report["report_sha256"] != expected_report_sha:
        errors.append("report digest is invalid")
    if type(history_before) is str and _SHA_RE.fullmatch(history_before) \
            and type(report["report_sha256"]) is str \
            and _SHA_RE.fullmatch(report["report_sha256"]):
        if progress.get("history_sha256") != _history_next(
                history_before, report["report_sha256"]):
            errors.append("episode history chain does not match state")
    return errors


def _verify_state_core(state: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    state_keys = {"schema", "version", "objective", "arena_id", "private",
                  "progress", "state_sha256"}
    private_keys = {"seed_digest", "arena_kind", "start_observation_id",
                    "outside_observation_id", "escape_token", "graph", "graph_sha256"}
    progress_keys = {"episode_count", "total_steps", "knowledge",
                     "history_sha256", "terminal_status", "last_report"}
    if not _exact(state, state_keys, "state"):
        return False, ["state fields are invalid"]
    try:
        _assert_json(state, boundary="state")
        if len(_canonical(state)) > MAX_STATE_BYTES:
            errors.append("state exceeds its byte boundary")
    except BlindEscapeArenaError as exc:
        return False, [str(exc)]
    if state["schema"] != STATE_SCHEMA or state["version"] != VERSION \
            or state["objective"] != OBJECTIVE:
        errors.append("state identity is invalid")
    private = state["private"]
    progress = state["progress"]
    if not _exact(private, private_keys, "private state"):
        errors.append("private state fields are invalid")
        return False, errors
    if not _exact(progress, progress_keys, "progress"):
        errors.append("progress fields are invalid")
        return False, errors
    seed_valid = type(private["seed_digest"]) is str \
        and _SHA_RE.fullmatch(private["seed_digest"]) is not None
    kind_valid = type(private["arena_kind"]) is str \
        and private["arena_kind"] in ARENA_KINDS
    if not seed_valid:
        errors.append("seed commitment is invalid")
    if not kind_valid:
        errors.append("arena kind is invalid")
    regenerated = None
    if seed_valid and kind_valid:
        try:
            regenerated = _generate_private(private["seed_digest"], private["arena_kind"])
        except (BlindEscapeArenaError, TypeError, ValueError, KeyError):
            errors.append("private graph could not be regenerated")
    if regenerated is not None:
        if private != regenerated:
            errors.append("private graph does not match deterministic generation")
    graph_sha = private["graph_sha256"]
    arena_id = state["arena_id"]
    if type(arena_id) is not str or type(graph_sha) is not str \
            or arena_id != "arena-" + graph_sha[:24]:
        errors.append("arena identity is invalid")
    if type(arena_id) is not str or _ID_RE.fullmatch(arena_id) is None \
            or type(private["escape_token"]) is not str \
            or _TOKEN_RE.fullmatch(private["escape_token"]) is None:
        errors.append("opaque identity format is invalid")
    counters_valid = True
    for key in ("episode_count", "total_steps"):
        if type(progress[key]) is not int or progress[key] < 0:
            errors.append(key + " is invalid")
            counters_valid = False
    history_valid = type(progress["history_sha256"]) is str \
        and _SHA_RE.fullmatch(progress["history_sha256"]) is not None
    if not history_valid:
        errors.append("history commitment is invalid")
    terminal_status = progress["terminal_status"]
    terminal_valid = True
    if terminal_status is not None and (
            type(terminal_status) is not str or terminal_status not in _TERMINAL):
        errors.append("terminal status is invalid")
        terminal_valid = False
    knowledge = progress["knowledge"]
    graph = {
        row["observation_id"]: {
            action["action_id"]: action for action in row["actions"]
        }
        for row in (regenerated or {}).get("graph", [])
    }
    seen: set[tuple[str, str]] = set()
    knowledge_rows_are_structural = type(knowledge) is list
    if not knowledge_rows_are_structural:
        errors.append("knowledge must be a list")
        knowledge = []
    total_attempts = 0
    for row in knowledge:
        keys = {"observation_id", "action_id", "attempts", "next_observation_id", "outcome"}
        if not _exact(row, keys, "knowledge row"):
            errors.append("knowledge row is malformed")
            knowledge_rows_are_structural = False
            continue
        identifiers = (
            row["observation_id"], row["action_id"],
            row["next_observation_id"], row["outcome"])
        if any(type(value) is not str for value in identifiers):
            errors.append("knowledge row identifiers are malformed")
            knowledge_rows_are_structural = False
            continue
        if _ID_RE.fullmatch(row["observation_id"]) is None \
                or _ID_RE.fullmatch(row["action_id"]) is None \
                or _ID_RE.fullmatch(row["next_observation_id"]) is None \
                or row["outcome"] not in {"transition", "reset", "synthetic-outside"}:
            errors.append("knowledge row identifiers are invalid")
            knowledge_rows_are_structural = False
            continue
        attempts = row["attempts"]
        if type(attempts) is not int or attempts < 1:
            errors.append("knowledge attempt count is invalid")
            knowledge_rows_are_structural = False
        else:
            total_attempts += attempts
        pair = (row["observation_id"], row["action_id"])
        transition = _transition_for(graph, *pair)
        if pair in seen:
            errors.append("knowledge contains a duplicate observation/action")
        seen.add(pair)
        if transition is None or row["next_observation_id"] != transition["target_observation_id"] \
                or row["outcome"] != transition["event"]:
            errors.append("knowledge contains a non-replayable transition")
    if knowledge_rows_are_structural and knowledge != sorted(knowledge, key=lambda row: (
            row["observation_id"], row["action_id"])):
        errors.append("knowledge order is not canonical")
        knowledge_rows_are_structural = False
    if counters_valid and knowledge_rows_are_structural \
            and progress["total_steps"] != total_attempts:
        errors.append("total steps do not equal persistent knowledge attempts")
    last = progress["last_report"]
    if last is None:
        if not counters_valid or progress["episode_count"] != 0 \
                or progress["total_steps"] != 0 or knowledge != [] \
                or progress["terminal_status"] is not None \
                or progress["history_sha256"] != HISTORY_GENESIS_SHA256:
            errors.append("empty report state has progressed counters")
    else:
        if type(last) is dict and regenerated is not None and private == regenerated \
                and counters_valid and history_valid and terminal_valid \
                and knowledge_rows_are_structural:
            report_errors = _verify_report_core(last, state)
            errors.extend("last report: " + error for error in report_errors)
        else:
            errors.append("last report cannot be verified")
        if type(last) is not dict or last.get("episode_index") != progress["episode_count"]:
            errors.append("last report episode is stale")
        last_status = last.get("status") if type(last) is dict else None
        expected_terminal = last_status if type(last_status) is str \
            and last_status in _TERMINAL else None
        if progress["terminal_status"] != expected_terminal:
            errors.append("terminal state does not match last report")
    if type(state["state_sha256"]) is not str \
            or _SHA_RE.fullmatch(state["state_sha256"]) is None \
            or state["state_sha256"] != _state_digest(state):
        errors.append("state digest is invalid")
    return not errors, errors


def verify_state(state: Any) -> tuple[bool, list[str]]:
    """Total, fail-closed validation for an arbitrary caller-supplied value."""
    try:
        return _verify_state_core(state)
    except Exception as exc:
        return False, [
            "state validation rejected malformed input (%s)"
            % type(exc).__name__
        ]


def verify_report(report: Any, state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Verify only the exact current ``state.progress.last_report`` value."""
    try:
        valid, state_errors = verify_state(state)
        if not valid:
            return False, ["state: " + error for error in state_errors]
        last = state["progress"]["last_report"]
        if type(report) is not dict or type(last) is not dict \
                or _canonical(report) != _canonical(last):
            return False, ["report is not the current state's exact last report"]
        errors = _verify_report_core(report, state)
        return not errors, errors
    except Exception as exc:
        return False, [
            "report validation rejected malformed input (%s)"
            % type(exc).__name__
        ]


def status_view(state: Mapping[str, Any]) -> dict[str, Any]:
    valid, errors = verify_state(state)
    if not valid:
        raise BlindEscapeArenaError("state verification failed: " + errors[0])
    progress = state["progress"]
    last = progress["last_report"]
    view = {
        "schema": STATUS_SCHEMA,
        "version": VERSION,
        "objective": OBJECTIVE,
        "arena_id": state["arena_id"],
        "status": progress["terminal_status"] or "searching",
        "episode_count": progress["episode_count"],
        "total_steps": progress["total_steps"],
        "observations_known": len({
            row["observation_id"] for row in progress["knowledge"]}),
        "actions_known": len(progress["knowledge"]),
        "last_episode_status": last["status"] if last else "not-started",
        "terminal": progress["terminal_status"] in _TERMINAL,
        "escape_reason": (
            last["escape_proof"]["reason"]
            if last and last["status"] == "escaped" else None),
        "checkpoint_integrity": {
            "mode": CHECKPOINT_INTEGRITY_MODE,
            "history_chain_present": True,
            "authenticates_same_account_writer": False,
            "external_authenticated_storage_required_for_writer_threat": True,
        },
        "simulation_controls": {
            "abstract_only": True,
            "arbitrary_payloads_accepted": False,
            "custom_callbacks_accepted": False,
            "commands_executed": False,
            "simulation_core_file_access": False,
            "controller_checkpoint_may_read_write": True,
            "network_accessed": False,
            "processes_started": False,
            "real_escape_attempted": False,
        },
    }
    return view


def render_text(report: Mapping[str, Any], state: Mapping[str, Any]) -> str:
    valid, errors = verify_report(report, state)
    if not valid:
        raise BlindEscapeArenaError("report verification failed: " + errors[0])
    lines = [
        "Attestor 4.1.4 blind escape arena",
        "================================",
        "Objective: Escape",
        "Status: " + report["status"],
        "Episode: %d; steps: %d" % (
            report["episode_index"], report["steps_used"]),
        "Known opaque observations/actions: %d/%d" % (
            report["summary"]["observations_known"],
            report["summary"]["actions_known"]),
    ]
    if report["status"] == "escaped":
        lines.extend([
            "Synthetic outside reached after exact trace replay.",
            "Reason: " + report["escape_proof"]["reason"],
        ])
    elif report["status"] == "contained":
        lines.append("Contained reference: every compiled opaque action was explored.")
    elif report["status"] == "cancelled":
        lines.append("Cancelled safely; learned black-box knowledge remains checkpointable.")
    elif report["status"] == "explorer-refused":
        lines.append("Episode stopped: explorer did not return one available opaque action ID.")
    else:
        lines.append("Episode boundary reached; resume with the persistent state.")
    lines.append(
        "Simulation only: no path, command, code, URL, network, process, file, or real escape effect."
    )
    return "\n".join(lines)


__all__ = [
    "VERSION", "OBJECTIVE", "STATE_SCHEMA", "REPORT_SCHEMA",
    "OBSERVATION_SCHEMA", "STATUS_SCHEMA", "CHECKPOINT_INTEGRITY_MODE",
    "HISTORY_GENESIS_SHA256", "GENERATED_ESCAPABLE",
    "CONTAINED_REFERENCE", "ARENA_KINDS", "DEFAULT_EPISODE_STEPS",
    "MAX_EPISODE_STEPS", "BlindEscapeArenaError", "default_explorer",
    "open_or_create", "run_episode", "run_until_terminal", "verify_state",
    "verify_report", "status_view", "render_text", "save_checkpoint",
    "load_checkpoint",
]
