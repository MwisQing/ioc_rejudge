"""Unified file-backed job queue storage for CLI and UI runners.

Storage layout per job::

    <jobs-dir>/<job_id>/
      job.json
      input.txt | input.jsonl
      results.jsonl
      diagnostics.json
      .lock/owner.json
      export/

This module owns only files and state transitions. It does not import
pipeline, provider, credential, or network code.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import shutil
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ioc_rejudge.files import atomic_write_text
from ioc_rejudge.inputs import _target

DEFAULT_JOBS_DIR = Path("jobs")
LEASE_SECONDS = 600
DEFAULT_KEEP = 50

STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"
STATE_CORRUPT = "corrupt"

JOB_STATES = frozenset(
    {
        STATE_QUEUED,
        STATE_RUNNING,
        STATE_SUCCEEDED,
        STATE_FAILED,
        STATE_CANCELLED,
    }
)

_SAFE_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")
_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|access[_-]?key|secret|password|passwd|token|credential|"
    r"authorization|auth[_-]?header|bearer)",
    re.IGNORECASE,
)

_JOB_TOP_KEYS = frozenset(
    {
        "job_id",
        "created_at",
        "updated_at",
        "state",
        "mode",
        "providers",
        "preset",
        "input",
        "cancel_requested",
        "cancel_requested_late",
        "runner",
        "result_summary",
        "error",
        "config_digest",
    }
)
_INPUT_KEYS = frozenset(
    {"source", "input_kind", "valid", "duplicated", "rejected", "errors"}
)
_RUNNER_KEYS = frozenset({"pid", "name", "started_at", "heartbeat_at"})
_INPUT_KINDS = frozenset({"bare", "jsonl"})
_MODES = frozenset({"offline", "online"})
_FINISH_STATES = frozenset({STATE_SUCCEEDED, STATE_FAILED})


class JobsQueueError(Exception):
    """Base class for unified job-queue failures."""


class InvalidJobIdError(JobsQueueError, ValueError):
    """Raised when a job id is empty, unsafe, or path-like."""


class JobNotFoundError(JobsQueueError, KeyError):
    """Raised when a job directory or job.json is missing."""


class InvalidJobStateError(JobsQueueError, ValueError):
    """Raised for illegal transitions or disallowed job.json fields."""


class CorruptJobRecordError(JobsQueueError, ValueError):
    """Raised when job.json is malformed or not an object."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not job_id:
        raise InvalidJobIdError("job id must be a non-empty string")
    if ".." in job_id or "/" in job_id or "\\" in job_id:
        raise InvalidJobIdError(f"job id is invalid: {job_id!r}")
    if not _SAFE_ID_RE.fullmatch(job_id):
        raise InvalidJobIdError(f"job id is invalid: {job_id!r}")
    return job_id


def _parse_iso(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _reject_secret_keys(value: Any, *, path: str = "job") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            child_path = f"{path}.{key_s}"
            if _SECRET_KEY_RE.search(key_s):
                raise InvalidJobStateError(
                    f"disallowed secret-like field {child_path!r}"
                )
            _reject_secret_keys(child, path=child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, path=f"{path}[{index}]")


def _validate_job_document(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise InvalidJobStateError("job document must be an object")
    unknown = set(document) - _JOB_TOP_KEYS
    if unknown:
        raise InvalidJobStateError(
            f"job document contains unknown fields: {sorted(unknown)}"
        )
    _reject_secret_keys(document)

    state = document.get("state")
    if state not in JOB_STATES:
        raise InvalidJobStateError(f"unknown job state {state!r}")

    mode = document.get("mode")
    if mode not in _MODES:
        raise InvalidJobStateError(f"unknown job mode {mode!r}")

    providers = document.get("providers")
    if not isinstance(providers, list) or not all(
        isinstance(item, str) for item in providers
    ):
        raise InvalidJobStateError("providers must be a list of strings")

    preset = document.get("preset")
    if not isinstance(preset, str):
        raise InvalidJobStateError("preset must be a string")

    input_block = document.get("input")
    if not isinstance(input_block, dict):
        raise InvalidJobStateError("input must be an object")
    unknown_input = set(input_block) - _INPUT_KEYS
    if unknown_input:
        raise InvalidJobStateError(
            f"input contains unknown fields: {sorted(unknown_input)}"
        )
    if input_block.get("input_kind") not in _INPUT_KINDS:
        raise InvalidJobStateError(
            f"unknown input_kind {input_block.get('input_kind')!r}"
        )
    for count_key in ("valid", "duplicated", "rejected"):
        if not isinstance(input_block.get(count_key), int):
            raise InvalidJobStateError(f"input.{count_key} must be an int")
    errors = input_block.get("errors")
    if not isinstance(errors, list) or not all(isinstance(e, str) for e in errors):
        raise InvalidJobStateError("input.errors must be a list of strings")
    if not isinstance(input_block.get("source"), str):
        raise InvalidJobStateError("input.source must be a string")

    if "runner" in document and document["runner"] is not None:
        runner = document["runner"]
        if not isinstance(runner, dict):
            raise InvalidJobStateError("runner must be an object")
        unknown_runner = set(runner) - _RUNNER_KEYS
        if unknown_runner:
            raise InvalidJobStateError(
                f"runner contains unknown fields: {sorted(unknown_runner)}"
            )

    if "result_summary" in document and document["result_summary"] is not None:
        if not isinstance(document["result_summary"], dict):
            raise InvalidJobStateError("result_summary must be an object")

    if "error" in document and document["error"] is not None:
        if not isinstance(document["error"], str):
            raise InvalidJobStateError("error must be a string or null")

    if "cancel_requested" in document and not isinstance(
        document["cancel_requested"], bool
    ):
        raise InvalidJobStateError("cancel_requested must be a bool")
    if "cancel_requested_late" in document and not isinstance(
        document["cancel_requested_late"], bool
    ):
        raise InvalidJobStateError("cancel_requested_late must be a bool")

    return document


def _count_bare_input(content: str) -> tuple[int, int, int, list[str]]:
    """Match workbench bare-row semantics via inputs._target."""
    valid = 0
    duplicated = 0
    rejected = 0
    errors: list[str] = []
    seen: set[str] = set()
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        target = _target(stripped)
        if target is None:
            rejected += 1
            errors.append(f"line {line_no}: invalid IOC {stripped!r}")
            continue
        if target.normalized in seen:
            duplicated += 1
            continue
        seen.add(target.normalized)
        valid += 1
    return valid, duplicated, rejected, errors


def _count_jsonl_input(content: str) -> tuple[int, int, int, list[str]]:
    rows = 0
    for line in content.splitlines():
        if line.strip():
            rows += 1
    return rows, 0, 0, []


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
    except OSError:
        return total
    return total


class UnifiedJobQueue:
    """File-backed unified job queue under *root* (default ``jobs/``)."""

    def __init__(self, root: str | Path = DEFAULT_JOBS_DIR):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # --- path helpers -------------------------------------------------

    def _job_dir(self, job_id: str) -> Path:
        return self.root / _validate_job_id(job_id)

    def _job_path(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "job.json"

    def _lock_dir(self, job_id: str) -> Path:
        return self._job_dir(job_id) / ".lock"

    # --- serialization ------------------------------------------------

    def _read_job_raw(self, job_id: str) -> dict[str, Any]:
        path = self._job_path(job_id)
        try:
            raw = self._read_text_with_retry(path)
        except FileNotFoundError as exc:
            raise JobNotFoundError(job_id) from exc
        except OSError as exc:
            raise JobsQueueError(f"cannot read job {job_id!r}: {exc}") from exc
        try:
            document = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CorruptJobRecordError(
                f"job {job_id!r} contains malformed JSON"
            ) from exc
        if not isinstance(document, dict):
            raise CorruptJobRecordError(f"job {job_id!r} must contain a JSON object")
        return document

    @staticmethod
    def _read_text_with_retry(
        path: Path, *, attempts: int = 3, delay: float = 0.06
    ) -> str:
        """Read a small JSON file, tolerating brief Windows handle contention.

        Antivirus or indexer software can hold a freshly replaced file for a
        few milliseconds; a missing file is never retried (that is a real
        JobNotFoundError), while transient permission/sharing failures are.
        """
        last: OSError | None = None
        for attempt in range(max(1, attempts)):
            try:
                return path.read_text(encoding="utf-8")
            except FileNotFoundError:
                raise
            except OSError as exc:
                last = exc
                if attempt + 1 < attempts:
                    time.sleep(delay)
        assert last is not None
        raise last

    def _write_job(self, document: dict[str, Any]) -> None:
        validated = _validate_job_document(document)
        job_id = validated.get("job_id")
        if not isinstance(job_id, str):
            raise InvalidJobStateError("job_id is required")
        _validate_job_id(job_id)
        path = self._job_path(job_id)
        payload = json.dumps(validated, ensure_ascii=False, sort_keys=True, indent=2)
        last_exc: OSError | None = None
        for attempt in range(4):
            try:
                atomic_write_text(path, payload + "\n")
                return
            except OSError as exc:
                # Concurrent status polls read job.json without sharing
                # delete; on Windows os.replace is briefly denied until the
                # reader closes. Each failed attempt removes its own temp
                # file, so retrying the whole write is clean.
                last_exc = exc
                time.sleep(0.02 * (attempt + 1))
        raise JobsQueueError(f"cannot write job {job_id!r}: {last_exc}") from last_exc

    def _load_for_list(self, job_id: str) -> dict[str, Any]:
        try:
            return copy.deepcopy(self._read_job_raw(job_id))
        except (CorruptJobRecordError, JobsQueueError, OSError, ValueError):
            return {"job_id": job_id, "state": STATE_CORRUPT}

    # --- directory lock -----------------------------------------------

    def _owner_is_stale(self, lock_dir: Path, *, stale_after: float) -> bool:
        """Return True when a lock directory is safe to steal.

        A missing or unreadable ``owner.json`` is common in the brief window
        between ``mkdir(.lock)`` and writing the owner file. Treat that as
        stale only when the lock directory itself is older than *stale_after*,
        so concurrent claimers cannot steal a live lock mid-acquire.
        """
        owner_path = lock_dir / "owner.json"
        try:
            raw = owner_path.read_text(encoding="utf-8")
            owner = json.loads(raw)
        except (OSError, TypeError, ValueError):
            try:
                mtime = lock_dir.stat().st_mtime
            except OSError:
                return True
            return (time.time() - mtime) >= stale_after
        if not isinstance(owner, dict):
            try:
                mtime = lock_dir.stat().st_mtime
            except OSError:
                return True
            return (time.time() - mtime) >= stale_after
        acquired = _parse_iso(owner.get("acquired_at"))
        if acquired is None:
            try:
                mtime = lock_dir.stat().st_mtime
            except OSError:
                return True
            return (time.time() - mtime) >= stale_after
        age = (datetime.now(timezone.utc) - acquired).total_seconds()
        return age >= stale_after

    def _remove_lock_dir(self, lock_dir: Path) -> None:
        owner_path = lock_dir / "owner.json"
        try:
            owner_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            lock_dir.rmdir()
        except OSError:
            # Non-empty or racing; fall back to full tree removal for orphans.
            try:
                shutil.rmtree(lock_dir, ignore_errors=True)
            except OSError:
                pass

    @contextmanager
    def _job_lock(
        self,
        job_id: str,
        timeout: float = 5.0,
        *,
        stale_after: float | None = None,
    ) -> Iterator[None]:
        """Acquire ``<job>/.lock`` via atomic mkdir; write owner.json."""
        _validate_job_id(job_id)
        lock_dir = self._lock_dir(job_id)
        job_dir = self._job_dir(job_id)
        if not job_dir.is_dir():
            raise JobNotFoundError(job_id)

        stale_limit = float(LEASE_SECONDS if stale_after is None else stale_after)
        deadline = time.monotonic() + max(0.0, timeout)
        acquired = False
        while not acquired:
            try:
                os.mkdir(lock_dir)
                acquired = True
            except FileExistsError:
                if self._owner_is_stale(lock_dir, stale_after=stale_limit):
                    self._remove_lock_dir(lock_dir)
                    continue
                if time.monotonic() >= deadline:
                    raise JobsQueueError(
                        f"timed out acquiring lock for job {job_id!r}"
                    )
                time.sleep(0.05)
            except OSError as exc:
                raise JobsQueueError(
                    f"cannot acquire lock for job {job_id!r}: {exc}"
                ) from exc

        owner = {
            "pid": os.getpid(),
            "name": f"job_queue:{os.getpid()}",
            "acquired_at": _utc_now(),
        }
        try:
            owner_path = lock_dir / "owner.json"
            owner_path.write_text(
                json.dumps(owner, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            yield
        finally:
            self._remove_lock_dir(lock_dir)

    # --- public API ---------------------------------------------------

    def create_job(
        self,
        input_text: str,
        *,
        input_kind: str,
        mode: str,
        providers: list[str],
        preset: str,
        source: str,
    ) -> dict[str, Any]:
        if not isinstance(input_text, str):
            raise InvalidJobStateError("input_text must be a string")
        if input_kind not in _INPUT_KINDS:
            raise InvalidJobStateError(f"unknown input_kind {input_kind!r}")
        if mode not in _MODES:
            raise InvalidJobStateError(f"unknown mode {mode!r}")
        if not isinstance(providers, list) or not all(
            isinstance(p, str) for p in providers
        ):
            raise InvalidJobStateError("providers must be a list of strings")
        if not isinstance(preset, str):
            raise InvalidJobStateError("preset must be a string")
        if not isinstance(source, str):
            raise InvalidJobStateError("source must be a string")

        if input_kind == "bare":
            valid, duplicated, rejected, errors = _count_bare_input(input_text)
            input_name = "input.txt"
        else:
            valid, duplicated, rejected, errors = _count_jsonl_input(input_text)
            input_name = "input.jsonl"

        now = _utc_now()
        # jq-YYYYMMDD-HHMMSS-<hex8>
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        job_id = f"jq-{stamp}-{secrets.token_hex(4)}"
        _validate_job_id(job_id)

        job_dir = self._job_dir(job_id)
        job_dir.mkdir(parents=True, exist_ok=False)
        (job_dir / "export").mkdir(exist_ok=True)

        document: dict[str, Any] = {
            "job_id": job_id,
            "created_at": now,
            "updated_at": now,
            "state": STATE_QUEUED,
            "mode": mode,
            "providers": list(providers),
            "preset": preset,
            "input": {
                "source": source,
                "input_kind": input_kind,
                "valid": valid,
                "duplicated": duplicated,
                "rejected": rejected,
                "errors": list(errors),
            },
            "cancel_requested": False,
        }
        # Optional fields (runner/result_summary/error/config_digest/
        # cancel_requested_late) are omitted until first written by their
        # owning transitions; the validator accepts their absence.

        try:
            atomic_write_text(job_dir / input_name, input_text)
            self._write_job(document)
        except Exception:
            shutil.rmtree(job_dir, ignore_errors=True)
            raise
        return copy.deepcopy(document)

    def get(self, job_id: str) -> dict[str, Any]:
        _validate_job_id(job_id)
        if not self._job_dir(job_id).is_dir():
            raise JobNotFoundError(job_id)
        return copy.deepcopy(self._read_job_raw(job_id))

    def list_jobs(self, *, state: str | None = None) -> list[dict[str, Any]]:
        if state is not None and state not in JOB_STATES and state != STATE_CORRUPT:
            raise InvalidJobStateError(f"unknown job state filter {state!r}")

        items: list[dict[str, Any]] = []
        try:
            children = sorted(self.root.iterdir(), key=lambda p: p.name)
        except OSError:
            return []

        for child in children:
            if not child.is_dir() or child.name.startswith("."):
                continue
            try:
                _validate_job_id(child.name)
            except InvalidJobIdError:
                continue
            doc = self._load_for_list(child.name)
            if state is not None:
                if doc.get("state") == STATE_CORRUPT:
                    # Surface corrupt rows even when filtering; callers can ignore.
                    items.append(doc)
                    continue
                if doc.get("state") != state:
                    continue
            items.append(doc)

        # created_at descending; corrupt entries last, stable by id
        valid = [i for i in items if i.get("state") != STATE_CORRUPT]
        corrupt = [i for i in items if i.get("state") == STATE_CORRUPT]
        valid.sort(
            key=lambda i: (
                i.get("created_at") if isinstance(i.get("created_at"), str) else "",
                i.get("job_id", ""),
            ),
            reverse=True,
        )
        return valid + corrupt

    def claim(
        self,
        job_id: str,
        *,
        runner_name: str,
        pid: int | None,
    ) -> dict[str, Any] | None:
        if not isinstance(runner_name, str) or not runner_name:
            raise InvalidJobStateError("runner_name must be a non-empty string")
        if pid is not None and not isinstance(pid, int):
            raise InvalidJobStateError("pid must be an int or None")

        with self._job_lock(job_id):
            document = self._read_job_raw(job_id)
            if document.get("state") != STATE_QUEUED:
                return None
            now = _utc_now()
            document["state"] = STATE_RUNNING
            document["updated_at"] = now
            document["runner"] = {
                "pid": pid if pid is not None else os.getpid(),
                "name": runner_name,
                "started_at": now,
                "heartbeat_at": now,
            }
            document["cancel_requested"] = bool(document.get("cancel_requested", False))
            self._write_job(document)
            return copy.deepcopy(document)

    def heartbeat(self, job_id: str) -> None:
        with self._job_lock(job_id):
            document = self._read_job_raw(job_id)
            if document.get("state") != STATE_RUNNING:
                raise InvalidJobStateError(
                    f"heartbeat requires running state, got {document.get('state')!r}"
                )
            now = _utc_now()
            runner = document.get("runner")
            if not isinstance(runner, dict):
                runner = {
                    "pid": os.getpid(),
                    "name": "unknown",
                    "started_at": now,
                    "heartbeat_at": now,
                }
            else:
                runner = dict(runner)
                runner["heartbeat_at"] = now
            document["runner"] = runner
            document["updated_at"] = now
            self._write_job(document)

    def request_cancel(self, job_id: str) -> dict[str, str]:
        with self._job_lock(job_id):
            document = self._read_job_raw(job_id)
            state = document.get("state")
            now = _utc_now()
            if state == STATE_QUEUED:
                document["state"] = STATE_CANCELLED
                document["updated_at"] = now
                document["cancel_requested"] = False
                self._write_job(document)
                return {"action": "cancelled"}
            if state == STATE_RUNNING:
                document["cancel_requested"] = True
                document["updated_at"] = now
                self._write_job(document)
                return {"action": "requested"}
            raise InvalidJobStateError(
                f"cannot cancel job in state {state!r}"
            )

    def finish(
        self,
        job_id: str,
        *,
        state: str,
        result_summary: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        if state not in _FINISH_STATES:
            raise InvalidJobStateError(
                f"finish state must be succeeded or failed, got {state!r}"
            )
        if result_summary is not None and not isinstance(result_summary, dict):
            raise InvalidJobStateError("result_summary must be an object or null")
        if error is not None and not isinstance(error, str):
            raise InvalidJobStateError("error must be a string or null")

        with self._job_lock(job_id):
            document = self._read_job_raw(job_id)
            if document.get("state") != STATE_RUNNING:
                raise InvalidJobStateError(
                    f"finish requires running state, got {document.get('state')!r}"
                )
            now = _utc_now()
            document["state"] = state
            document["updated_at"] = now
            if result_summary is not None:
                document["result_summary"] = copy.deepcopy(result_summary)
            if error is not None:
                document["error"] = error
            elif state == STATE_FAILED and "error" not in document:
                document["error"] = "execution failed"
            if document.get("cancel_requested"):
                document["cancel_requested_late"] = True
            self._write_job(document)
            return copy.deepcopy(document)

    def mark_cancelled(
        self, job_id: str, *, note: str | None = None
    ) -> dict[str, Any]:
        """Claim-holder transition: running → cancelled (pre-start cancel flag).

        Used by the offline runner after a successful claim when
        ``cancel_requested`` is already set, so the job never starts work.
        """
        if note is not None and not isinstance(note, str):
            raise InvalidJobStateError("note must be a string or null")

        with self._job_lock(job_id):
            document = self._read_job_raw(job_id)
            if document.get("state") != STATE_RUNNING:
                raise InvalidJobStateError(
                    f"mark_cancelled requires running state, got {document.get('state')!r}"
                )
            now = _utc_now()
            document["state"] = STATE_CANCELLED
            document["updated_at"] = now
            document["cancel_requested"] = False
            if note is not None:
                document["error"] = note
            self._write_job(document)
            return copy.deepcopy(document)

    def append_results(self, job_id: str, rows: list[dict[str, Any]]) -> None:
        _validate_job_id(job_id)
        if not isinstance(rows, list):
            raise InvalidJobStateError("rows must be a list")
        job_dir = self._job_dir(job_id)
        if not job_dir.is_dir():
            raise JobNotFoundError(job_id)
        # Ensure the job record exists and is parseable.
        self._read_job_raw(job_id)
        path = job_dir / "results.jsonl"
        lines: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                raise InvalidJobStateError("each result row must be an object")
            _reject_secret_keys(row, path="result_row")
            lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
        if not lines:
            return
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def write_diagnostics(self, job_id: str, payload: dict[str, Any]) -> None:
        _validate_job_id(job_id)
        if not isinstance(payload, dict):
            raise InvalidJobStateError("diagnostics payload must be an object")
        _reject_secret_keys(payload, path="diagnostics")
        job_dir = self._job_dir(job_id)
        if not job_dir.is_dir():
            raise JobNotFoundError(job_id)
        self._read_job_raw(job_id)
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        atomic_write_text(job_dir / "diagnostics.json", text)

    def recover_stale(
        self, *, lease_seconds: int = LEASE_SECONDS
    ) -> list[dict[str, Any]]:
        if not isinstance(lease_seconds, int) or lease_seconds < 0:
            raise InvalidJobStateError("lease_seconds must be a non-negative int")

        recovered: list[dict[str, Any]] = []
        try:
            children = list(self.root.iterdir())
        except OSError:
            return recovered

        now = datetime.now(timezone.utc)
        for child in children:
            if not child.is_dir() or child.name.startswith("."):
                continue
            try:
                job_id = _validate_job_id(child.name)
            except InvalidJobIdError:
                continue

            lock_dir = child / ".lock"
            document: dict[str, Any] | None
            try:
                document = self._read_job_raw(job_id)
            except (CorruptJobRecordError, JobNotFoundError, JobsQueueError):
                document = None

            # Expire running jobs whose heartbeat is past the lease.
            if (
                document is not None
                and document.get("state") == STATE_RUNNING
            ):
                runner = document.get("runner") if isinstance(document.get("runner"), dict) else {}
                heartbeat = _parse_iso(
                    runner.get("heartbeat_at") if isinstance(runner, dict) else None
                )
                expired = False
                if heartbeat is None:
                    expired = True
                else:
                    age = (now - heartbeat).total_seconds()
                    expired = age >= lease_seconds
                if expired:
                    try:
                        with self._job_lock(job_id):
                            current = self._read_job_raw(job_id)
                            if current.get("state") != STATE_RUNNING:
                                pass
                            else:
                                runner2 = (
                                    current.get("runner")
                                    if isinstance(current.get("runner"), dict)
                                    else {}
                                )
                                hb2 = _parse_iso(
                                    runner2.get("heartbeat_at")
                                    if isinstance(runner2, dict)
                                    else None
                                )
                                still_expired = hb2 is None or (
                                    now - hb2
                                ).total_seconds() >= lease_seconds
                                if still_expired:
                                    current["state"] = STATE_FAILED
                                    current["error"] = "runner lease expired"
                                    current["updated_at"] = _utc_now()
                                    self._write_job(current)
                                    recovered.append(copy.deepcopy(current))
                    except (JobsQueueError, CorruptJobRecordError, JobNotFoundError):
                        pass

            # Drop orphan .lock directories (holder crashed after release window).
            if lock_dir.exists():
                try:
                    # If we can acquire briefly, lock was free of live holder path;
                    # stale owner cleanup happens inside _job_lock.
                    if self._owner_is_stale(lock_dir, stale_after=float(lease_seconds)):
                        self._remove_lock_dir(lock_dir)
                except OSError:
                    pass

        return recovered

    def prune(
        self, *, keep: int = DEFAULT_KEEP, dry_run: bool = True
    ) -> dict[str, Any]:
        if not isinstance(keep, int) or keep < 0:
            raise InvalidJobStateError("keep must be a non-negative int")

        entries: list[tuple[str, str, Path, int]] = []
        try:
            children = list(self.root.iterdir())
        except OSError:
            children = []

        for child in children:
            if not child.is_dir() or child.name.startswith("."):
                continue
            try:
                job_id = _validate_job_id(child.name)
            except InvalidJobIdError:
                continue
            try:
                document = self._read_job_raw(job_id)
                created = document.get("created_at")
                created_s = created if isinstance(created, str) else ""
            except (CorruptJobRecordError, JobNotFoundError, JobsQueueError):
                # Corrupt records are excluded from the keep window retention set.
                continue
            size = _dir_size(child)
            entries.append((created_s, job_id, child, size))

        # Oldest first so we remove from the front when over keep.
        entries.sort(key=lambda item: (item[0], item[1]))
        removed_ids: list[str] = []
        freed = 0
        if len(entries) > keep:
            to_remove = entries[: len(entries) - keep]
            for _created, job_id, path, size in to_remove:
                removed_ids.append(job_id)
                freed += size
                if not dry_run:
                    shutil.rmtree(path, ignore_errors=True)

        kept = len(entries) - len(removed_ids)
        return {
            "kept": kept,
            "removed": removed_ids,
            "freed_bytes": freed,
        }
