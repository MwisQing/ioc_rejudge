"""Execution loop over durable job-store targets."""

from __future__ import annotations

from typing import Any, Callable

from ioc_rejudge.job_store import FAILED, PENDING, RUNNING, SUCCEEDED, JobStore


class JobRunnerError(Exception):
    """Base class for job-runner failures."""


class InvalidExecuteResultError(JobRunnerError, TypeError):
    """Raised when a callback does not return a JSON-compatible object."""


class JobCancelled(JobRunnerError):
    """Raised when cancel_check requests a stop before the next target."""


def _validate_result(result: Any) -> Any:
    # json.dumps is the strict, meaningful test for the required JSON-object
    # contract. Dictionaries, arrays, strings, numbers, booleans, and null pass;
    # arbitrary executable or non-serializable values fail.
    import json

    try:
        json.dumps(result, allow_nan=False, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise InvalidExecuteResultError("execute must return a JSON-compatible object") from exc
    return result


class JobRunner:
    """Run pending targets and persist each transition individually."""

    def __init__(self, store: JobStore):
        self.store = store

    def run(
        self,
        job_id: str,
        execute: Callable[[str], Any],
        resume: bool = True,
        retry_failed: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        if not callable(execute):
            raise InvalidExecuteResultError("execute must be callable")
        if not resume:
            raise InvalidExecuteResultError("resume must be enabled")
        if retry_failed:
            self.store.retry_failed(job_id)
        # Loading normalizes any process-interrupted running targets to pending.
        document = self.store.load(job_id)
        targets = document.get("targets", {})

        for target_id in sorted(targets):
            target = targets[target_id]
            if not isinstance(target, dict) or "state" not in target:
                raise InvalidExecuteResultError("job contains malformed target state")
            if target["state"] == SUCCEEDED:
                continue
            if target["state"] != PENDING:
                continue
            if cancel_check is not None and cancel_check():
                raise JobCancelled(f"cancelled before target {target_id!r}")
            self.store.transition(job_id, target_id, RUNNING)
            try:
                result = execute(target_id)
            except Exception as exc:
                self.store.transition(
                    job_id,
                    target_id,
                    FAILED,
                    error=f"{type(exc).__name__}: {exc}",
                )
            else:
                try:
                    validated = _validate_result(result)
                except InvalidExecuteResultError as exc:
                    self.store.transition(
                        job_id,
                        target_id,
                        FAILED,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    raise
                self.store.transition(job_id, target_id, SUCCEEDED, result=validated)
        return self.store.load(job_id)
