#!/usr/bin/env python3
"""Deny-by-default Security Verification Lab for Attestor 4.1.3.

The lab has no host runner.  Every experiment is a fixed command contract in a
caller-configured digest-pinned image and can execute only through an eligible
``execution_fabric35.ExecutionFabric`` disposable workspace.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

import execution_fabric35
import security_validation413


VERSION = "4.1.3"
SCHEMA = "attestor.security-lab/4.1"
EXPERIMENTS = frozenset({"fuzz", "sanitizer", "mutation", "crash-minimize"})
_IMAGE = re.compile(r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
                    r"[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z")
MAX_SCOPE_FILES = 100_000
MAX_SCOPE_BYTES = 2 * 1024 * 1024 * 1024


class SecurityLabError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def workspace_scope_sha256(workspace: str | os.PathLike[str]) -> str:
    """Content-address the bounded, link-free local workspace without executing it."""
    try:
        return security_validation413.tree_manifest(workspace)["report_sha256"]
    except security_validation413.ValidationError as exc:
        raise SecurityLabError(str(exc)) from exc


@dataclass(frozen=True)
class LabAuthorization:
    granted: bool
    workspace_sha256: str
    experiments: tuple[str, ...]
    purpose: str
    actor: str = ""
    plan_sha256: str = ""

    def valid_for(self, experiment: str, workspace_digest: str,
                  plan_digest: str) -> bool:
        try:
            experiments_valid = (type(self.experiments) is tuple and
                                 self.experiments == tuple(sorted(set(self.experiments))) and
                                 all(isinstance(item, str) for item in self.experiments) and
                                 set(self.experiments) <= EXPERIMENTS)
            return bool(self.granted and experiments_valid and
                        hmac.compare_digest(self.workspace_sha256, workspace_digest) and
                        re.fullmatch(r"[0-9a-f]{64}", self.workspace_sha256) and
                        hmac.compare_digest(self.plan_sha256, plan_digest) and
                        re.fullmatch(r"[0-9a-f]{64}", self.plan_sha256) and
                        experiment in self.experiments and
                        isinstance(self.purpose, str) and 8 <= len(self.purpose.strip()) <= 512 and
                        isinstance(self.actor, str) and len(self.actor) <= 128 and
                        "\x00" not in self.purpose and "\x00" not in self.actor)
        except (TypeError, ValueError):
            return False


@dataclass(frozen=True)
class LabPlan:
    schema: str
    experiment: str
    workspace: str
    workspace_sha256: str
    target: str
    image: str
    command: tuple[str, ...]
    duration_seconds: int
    status: str
    gap: str
    plan_sha256: str


def _is_test_target(relative: Path, experiment: str) -> bool:
    lowered = [part.casefold() for part in relative.parts]
    name = relative.name.casefold()
    test_scoped = (any(part in {"test", "tests", "testing", "fuzz", "fuzzers",
                                "corpus", "crashes"} for part in lowered) or
                   name.startswith("test_") or "_test." in name or name.startswith("fuzz"))
    if experiment == "crash-minimize":
        return test_scoped and any(part in {"corpus", "crashes", "fuzz"} for part in lowered)
    return test_scoped


def _command(experiment: str, target: str, duration: int) -> tuple[str, ...]:
    """Build the only command shape the lab is permitted to submit."""
    return ("attestor-security-lab", experiment, "--target", target,
            "--duration", str(duration), "--artifacts", "/tmp/attestor-artifacts")


def _plan_digest_body(plan: LabPlan | Mapping[str, Any]) -> dict[str, Any]:
    body = asdict(plan) if isinstance(plan, LabPlan) else dict(plan)
    body.pop("plan_sha256", None)
    body.pop("workspace", None)
    return body


class SecurityLab:
    """Plan and execute bounded experiments through an existing secure fabric."""

    def __init__(self, fabric: execution_fabric35.ExecutionFabric,
                 images: Mapping[str, str] | None = None) -> None:
        if not isinstance(fabric, execution_fabric35.ExecutionFabric):
            raise SecurityLabError("Security Lab requires ExecutionFabric")
        self.fabric = fabric
        self.images = dict(images or {})

    def capabilities(self) -> dict[str, Any]:
        adapters = {}
        for experiment in sorted(EXPERIMENTS):
            image = self.images.get(experiment, "")
            if not isinstance(image, str): image = ""
            adapters[experiment] = {
                "available": bool(_IMAGE.fullmatch(image)),
                "reason": ("digest-pinned attestor-lab41 image configured" if _IMAGE.fullmatch(image)
                           else "no valid digest-pinned attestor-lab41 image configured"),
            }
        return {"schema": SCHEMA, "version": VERSION,
                "eligible_execution_fabric": bool(self.fabric.capabilities.eligible),
                "adapters": adapters,
                "unavailable_adapters": ["host execution", "remote fuzzing", "live targets",
                                         "arbitrary command execution", "networked scanners"]}

    def plan(self, experiment: str, workspace: str | os.PathLike[str], target: str,
             *, duration_seconds: int = 60) -> LabPlan:
        kind = str(experiment).strip().lower()
        if kind not in EXPERIMENTS:
            raise SecurityLabError("unsupported security-lab experiment")
        duration = int(duration_seconds)
        if not 1 <= duration <= 600:
            raise SecurityLabError("experiment duration must be between 1 and 600 seconds")
        supplied_workspace = Path(workspace).expanduser()
        if supplied_workspace.is_symlink():
            raise SecurityLabError("workspace must be a real local directory")
        base = supplied_workspace.resolve(strict=True)
        if not base.is_dir(): raise SecurityLabError("workspace must be a local directory")
        if not isinstance(target, str) or any(char in target for char in ("\x00", "\r", "\n")):
            raise SecurityLabError("test target is invalid")
        supplied = Path(target)
        if supplied.is_absolute() or ".." in supplied.parts:
            raise SecurityLabError("test target must be workspace-relative")
        resolved_target = (base / supplied).resolve(strict=True)
        try: relative = resolved_target.relative_to(base)
        except ValueError as exc: raise SecurityLabError("test target escapes workspace") from exc
        if not _is_test_target(relative, kind):
            raise SecurityLabError("only explicit local test/fuzz/corpus targets are eligible")
        digest = workspace_scope_sha256(base)
        image = self.images.get(kind, "")
        if not isinstance(image, str): image = ""
        available = bool(_IMAGE.fullmatch(image))
        command = _command(kind, relative.as_posix(), duration)
        unsigned = {"schema": SCHEMA, "experiment": kind, "workspace": str(base),
                    "workspace_sha256": digest, "target": relative.as_posix(),
                    "image": image if available else "", "command": command if available else (),
                    "duration_seconds": duration, "status": "ready" if available else "unavailable",
                    "gap": "" if available else "digest-pinned adapter image is not configured"}
        return LabPlan(**unsigned, plan_sha256=_sha(_plan_digest_body(unsigned)))

    @staticmethod
    def verify_plan(plan: LabPlan) -> bool:
        if not isinstance(plan, LabPlan): return False
        try:
            if (plan.schema != SCHEMA or plan.experiment not in EXPERIMENTS or
                    type(plan.duration_seconds) is not int or
                    not 1 <= plan.duration_seconds <= 600 or
                    not isinstance(plan.workspace, str) or not plan.workspace or
                    not re.fullmatch(r"[0-9a-f]{64}", plan.workspace_sha256) or
                    not isinstance(plan.target, str) or not plan.target or
                    any(char in plan.target for char in ("\x00", "\r", "\n")) or
                    Path(plan.target).is_absolute() or ".." in Path(plan.target).parts):
                return False
            if plan.status == "ready":
                if (not _IMAGE.fullmatch(plan.image) or plan.gap or
                        plan.command != _command(plan.experiment, plan.target,
                                                 plan.duration_seconds)):
                    return False
            elif plan.status == "unavailable":
                if plan.image or plan.command or plan.gap != "digest-pinned adapter image is not configured":
                    return False
            else:
                return False
            return bool(re.fullmatch(r"[0-9a-f]{64}", plan.plan_sha256) and
                        hmac.compare_digest(plan.plan_sha256,
                                            _sha(_plan_digest_body(plan))))
        except (TypeError, ValueError, OSError):
            return False

    def execute(self, plan: LabPlan,
                authorization: LabAuthorization | None = None) -> dict[str, Any]:
        """Run one fixed experiment; omission of authorization always refuses."""
        if not self.verify_plan(plan):
            return self._refused(plan, "plan integrity verification failed")
        if plan.status != "ready" or not _IMAGE.fullmatch(plan.image):
            return self._refused(plan, plan.gap or "experiment adapter is unavailable")
        try: current_digest = workspace_scope_sha256(plan.workspace)
        except (OSError, SecurityLabError):
            return self._refused(plan, "workspace could not be re-attested")
        try:
            base = Path(plan.workspace).resolve(strict=True)
            target = (base / Path(plan.target)).resolve(strict=True)
            relative = target.relative_to(base)
            if (relative.as_posix() != plan.target or
                    not _is_test_target(relative, plan.experiment)):
                return self._refused(plan, "test target failed execution-time scope validation")
        except (OSError, ValueError):
            return self._refused(plan, "test target could not be re-attested")
        if not hmac.compare_digest(current_digest, plan.workspace_sha256):
            return self._refused(plan, "workspace changed after plan creation")
        if not isinstance(authorization, LabAuthorization) or not authorization.valid_for(
                plan.experiment, current_digest, plan.plan_sha256):
            return self._refused(plan, "explicit plan-bound lab authorization is required")
        if not self.fabric.capabilities.eligible:
            return self._refused(plan, "no eligible local rootless execution fabric is available")
        fabric_auth = execution_fabric35.ExecutionAuthorization(
            True, authorization.purpose, authorization.actor)
        request = execution_fabric35.ExecutionRequest(
            image=plan.image, command=plan.command, workspace=plan.workspace,
            label="lab-" + plan.experiment.replace("-", ""))
        result = self.fabric.run_disposable(request, fabric_auth)
        return {"schema": SCHEMA, "version": VERSION, "status": result.status,
                "experiment": plan.experiment, "plan_sha256": plan.plan_sha256,
                "returncode": result.returncode, "timed_out": result.timed_out,
                "truncated": result.truncated, "runtime": result.runtime,
                "transcript": result.transcript, "reason": result.reason,
                "controls": {"host_execution": False, "network": False,
                             "workspace": "disposable-copy", "image_pull": False}}

    @staticmethod
    def _refused(plan: Any, reason: str) -> dict[str, Any]:
        return {"schema": SCHEMA, "version": VERSION, "status": "refused",
                "experiment": getattr(plan, "experiment", "unknown"),
                "plan_sha256": getattr(plan, "plan_sha256", ""),
                "reason": reason, "transcript": (),
                "controls": {"host_execution": False, "network": False,
                             "workspace": "not-executed", "image_pull": False}}


__all__ = ["LabAuthorization", "LabPlan", "SecurityLab", "SecurityLabError",
           "workspace_scope_sha256", "EXPERIMENTS"]
