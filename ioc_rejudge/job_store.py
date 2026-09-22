"""Durable, file-backed lifecycle state for IOC rejudge jobs."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

from ioc_rejudge.files import atomic_write_text


PENDING = "pending"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"

_TERMINAL_STATES = frozenset({SUCCEEDED, FAILED, CANCELLED})
_VALID_STATES = frozenset({PENDING, RUNNING}) | _TERMINAL_STATES


class JobStoreError(Exception):
    """Base class for job-store failures."""


class InvalidJobIdError(JobStoreError, ValueError):
    """Raised when a job id could produce an unsafe or ambiguous path."""


class JobNotFoundError(JobStoreError, KeyError):
    """Raised when a job does not exist."""


class InvalidTargetStateError(JobStoreError, ValueError):
    """Raised for a target id or lifecycle state the store cannot use."""


class CorruptJobFileError(JobStoreError, ValueError):
    """Raised when an existing job file is malformed or not an object."""


def _validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not job_id:
        raise InvalidJobIdError("job id must be a non-empty string")
    if "/" in job_id or "\\" in job_id:
        raise InvalidJobIdError("job id must not contain slashes or backslashes")
    if job_id in {".", ".."}:
        raise InvalidJobIdError("job id must not be a relative path component")
    return job_id


def _validate_target_id(target_id: str) -> str:
    if not isinstance(target_id, str) or not target_id:
        raise InvalidTargetStateError("target id must be a non-empty string")
    if "/" in target_id or "\\" in target_id:
        raise InvalidTargetStateError(
            "target id must not contain slashes or backslashes"
        )
    if target_id in {".", ".."}:
        raise InvalidTargetStateError("target id must not be a relative path component")
    return target_id


class JobStore:
    """One deterministic JSON document per job under *root*.

    The public methods intentionally avoid exposing file names. On every load,
    targets stranded in the ``running`` state are returned to ``pending`` so a
    later run can resume safely after a process interruption.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, job_id: str) -> Path:
        return self.root / f"{_validate_job_id(job_id)}.json"

    def _read(self, job_id: str) -> dict[str, Any]:
        path = self._path(job_id)
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise JobNotFoundError(job_id) from exc
        except OSError as exc:
            raise JobStoreError(f"cannot read job {job_id!r}: {exc}") from exc
        try:
            document = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CorruptJobFileError(f"job {job_id!r} contains malformed JSON") from exc
        if not isinstance(document, dict):
            raise CorruptJobFileError(f"job {job_id!r} must contain a JSON object")
        return document

    def _write(self, document: dict[str, Any]) -> None:
        path = self.root / f"{document['id']}.json"
        payload = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)
        atomic_write_text(path, payload + "\n")

    def _mutate(self, job_id: str, mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        document = self._read(job_id)
        mutate(document)
        self._write(document)
        return document

    @staticmethod
    def _targets_view(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(document.get("targets", {}))

    def create(
        self,
        job_id: str,
        targets: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_job_id(job_id)
        if not isinstance(targets, list):
            raise InvalidTargetStateError("targets must be a list")
        normalized_targets: dict[str, dict[str, Any]] = {}
        for target_id in targets:
            _validate_target_id(target_id)
            if target_id not in normalized_targets:
                normalized_targets[target_id] = {"state": PENDING}
        if metadata is not None and not isinstance(metadata, dict):
            raise JobStoreError("metadata must be an object when provided")
        document = {
            "id": job_id,
            "targets": normalized_targets,
            "metadata": copy.deepcopy(metadata) if metadata is not None else {},
        }
        self._write(document)
        return copy.deepcopy(document)

    def load(self, job_id: str) -> dict[str, Any]:
        _validate_job_id(job_id)
        document = self._read(job_id)
        changed = False
        for target in document.get("targets", {}).values():
            if isinstance(target, dict) and target.get("state") == RUNNING:
                target["state"] = PENDING
                changed = True
        if changed:
            self._write(document)
        return copy.deepcopy(document)

    def transition(
        self,
        job_id: str,
        target_id: str,
        state: str,
        result: Any = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        _validate_job_id(job_id)
        _validate_target_id(target_id)
        if state not in _VALID_STATES:
            raise InvalidTargetStateError(f"unknown target state {state!r}")

        def mutate(document: dict[str, Any]) -> None:
            targets = document.get("targets")
            if not isinstance(targets, dict) or target_id not in targets:
                raise InvalidTargetStateError(
                    f"target {target_id!r} does not exist in job {job_id!r}"
                )
            target = targets[target_id]
            if not isinstance(target, dict):
                raise CorruptJobFileError(f"target {target_id!r} is malformed")
            target["state"] = state
            if state == SUCCEEDED:
                target["result"] = result
                target.pop("error", None)
            elif state == FAILED:
                target["error"] = str(error) if error is not None else "execution failed"
                target.pop("result", None)
            else:
                target.pop("result", None)
                target.pop("error", None)

        return self._mutate(job_id, mutate)

    def cancel(self, job_id: str) -> dict[str, Any]:
        def mutate(document: dict[str, Any]) -> None:
            for target in document.get("targets", {}).values():
                if not isinstance(target, dict) or "state" not in target:
                    raise CorruptJobFileError("target state is malformed")
                if target["state"] not in _TERMINAL_STATES:
                    target["state"] = CANCELLED
                    target.pop("result", None)
                    target.pop("error", None)

        return self._mutate(job_id, mutate)

    def retry_failed(self, job_id: str) -> dict[str, Any]:
        def mutate(document: dict[str, Any]) -> None:
            for target in document.get("targets", {}).values():
                if not isinstance(target, dict) or "state" not in target:
                    raise CorruptJobFileError("target state is malformed")
                if target["state"] == FAILED:
                    target["state"] = PENDING
                    target.pop("result", None)
                    target.pop("error", None)

        return self._mutate(job_id, mutate)

    def pending_targets(self, job_id: str) -> list[str]:
        document = self.load(job_id)
        targets = document.get("targets", {})
        return sorted(
            target_id
            for target_id, target in targets.items()
            if isinstance(target, dict) and target.get("state") == PENDING
        )
