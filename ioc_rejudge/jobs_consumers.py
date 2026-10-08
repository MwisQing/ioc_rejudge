"""Shared consumers for unified job-queue results.

Provides explain, human review overlay, and baseline diff over
``<jobs-dir>/<job_id>/`` storage. Review labels are append-only in
``review.jsonl`` and never rewrite system conclusions in ``results.jsonl``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ioc_rejudge.diff import compare_verdicts
from ioc_rejudge.explanations import explain_verdict
from ioc_rejudge.job_queue import (
    JobNotFoundError,
    JobsQueueError,
    UnifiedJobQueue,
)
from ioc_rejudge.review_queue import append_label, load_labels

# Must stay in lockstep with review_queue.label_review_queue's canonical
# decision vocabulary so overlay records remain valid toolchain-wide.
ALLOWED_REVIEW_LABELS = frozenset(
    {
        "approved",
        "rejected",
        "pending",
    }
)

REVIEW_FILENAME = "review.jsonl"
RESULTS_FILENAME = "results.jsonl"


class JobsConsumerError(Exception):
    """Consumer failure mapped to a jobs CLI exit code (default 3)."""

    def __init__(self, message: str, *, exit_code: int = 3) -> None:
        super().__init__(message)
        self.exit_code = int(exit_code)
        self.message = str(message)


class JobsConsumerUsageError(JobsConsumerError):
    """Invalid arguments (CLI exit 2)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=2)


def _as_jobs_dir(jobs_dir: str | Path) -> Path:
    return Path(jobs_dir)


def _queue(jobs_dir: str | Path) -> UnifiedJobQueue:
    return UnifiedJobQueue(_as_jobs_dir(jobs_dir))


def _load_job(jobs_dir: str | Path, job_id: str) -> dict[str, Any]:
    queue = _queue(jobs_dir)
    try:
        return queue.get(job_id)
    except JobNotFoundError as exc:
        raise JobsConsumerError(f"job not found: {job_id}", exit_code=3) from exc
    except JobsQueueError as exc:
        raise JobsConsumerError(str(exc), exit_code=3) from exc


def _job_dir(jobs_dir: str | Path, job_id: str) -> Path:
    return _as_jobs_dir(jobs_dir) / job_id


def _review_path(jobs_dir: str | Path, job_id: str) -> Path:
    return _job_dir(jobs_dir, job_id) / REVIEW_FILENAME


def _result_id_for(job_id: str, index: int, row: dict[str, Any]) -> str:
    """Return the stable result id for *row*.

    Prefer an embedded ``result_id`` field. Otherwise derive a read-only id
    ``{job_id}-{ordinal:06d}`` from the 1-based position among valid rows.
    """
    embedded = row.get("result_id")
    if isinstance(embedded, str) and embedded.strip():
        return embedded.strip()
    return f"{job_id}-{index + 1:06d}"


def read_result_rows(
    jobs_dir: str | Path, job_id: str
) -> tuple[list[dict[str, Any]], int]:
    """Parse ``results.jsonl`` for *job_id*.

    Returns ``(rows, skipped)``. Non-empty lines that fail JSON decode or do
    not yield a dict are skipped and counted. Blank lines are ignored.
    Missing files yield ``([], 0)``.
    """
    path = _job_dir(jobs_dir, job_id) / RESULTS_FILENAME
    if not path.is_file():
        return [], 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], 0

    rows: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            skipped += 1
    return rows, skipped


def _find_row(
    rows: list[dict[str, Any]], job_id: str, result_id: str
) -> tuple[int, dict[str, Any], str] | None:
    """Locate a row by *result_id*.

    1. Exact match on embedded ``result_id``.
    2. Derived id only for rows that lack a usable embedded field.
    """
    target = str(result_id).strip()
    if not target:
        return None

    for index, row in enumerate(rows):
        embedded = row.get("result_id")
        if isinstance(embedded, str) and embedded.strip() and embedded.strip() == target:
            return index, row, embedded.strip()

    for index, row in enumerate(rows):
        embedded = row.get("result_id")
        if isinstance(embedded, str) and embedded.strip():
            continue
        derived = f"{job_id}-{index + 1:06d}"
        if derived == target:
            return index, row, derived
    return None


def _latest_review_for_ioc(
    jobs_dir: str | Path, job_id: str, ioc: str
) -> dict[str, Any] | None:
    labels = load_labels(_review_path(jobs_dir, job_id))
    entry = labels.get(str(ioc))
    if not entry:
        return None
    label = entry.get("label") or ""
    if not label and not entry.get("reviewed_at"):
        # reopen cleared the overlay
        return {
            "label": "",
            "note": entry.get("note", ""),
            "reviewer": entry.get("reviewer", ""),
            "reviewed_at": entry.get("reviewed_at", ""),
        }
    return {
        "label": entry.get("label", ""),
        "note": entry.get("note", ""),
        "reviewer": entry.get("reviewer", ""),
        "reviewed_at": entry.get("reviewed_at", ""),
    }


def explain_result(
    jobs_dir: str | Path,
    job_id: str,
    *,
    result_id: str,
) -> dict[str, Any]:
    """Locate one result row and return ``explain_verdict`` plus metadata.

    Attaches the latest human review overlay summary when present. Never
    mutates system conclusion fields.
    """
    if not isinstance(result_id, str) or not result_id.strip():
        raise JobsConsumerUsageError("result_id is required")

    _load_job(jobs_dir, job_id)
    rows, skipped = read_result_rows(jobs_dir, job_id)
    found = _find_row(rows, job_id, result_id)
    if found is None:
        raise JobsConsumerError(
            f"result not found: {result_id}",
            exit_code=3,
        )
    _index, row, resolved_id = found
    explanation = explain_verdict(row)
    explanation["result_id"] = resolved_id
    explanation["job_id"] = job_id
    if skipped:
        explanation["skipped"] = skipped

    ioc = explanation.get("ioc") or row.get("ioc")
    if ioc is not None:
        review = _latest_review_for_ioc(jobs_dir, job_id, str(ioc))
        if review is not None and (
            review.get("label") or review.get("reviewed_at") or review.get("note")
        ):
            explanation["review"] = review
    return explanation


def append_review(
    jobs_dir: str | Path,
    job_id: str,
    *,
    ioc: str,
    label: str,
    note: str = "",
    reviewer: str = "",
) -> dict[str, Any]:
    """Append one analyst label to ``<job>/review.jsonl`` (append-only).

    Returns the latest overlay summary for *ioc*. Duplicate same-label
    submissions are idempotent (both append; neither raises).
    """
    _load_job(jobs_dir, job_id)

    if not isinstance(ioc, str) or not ioc.strip():
        raise JobsConsumerUsageError("ioc is required")
    if not isinstance(label, str) or not label.strip():
        raise JobsConsumerUsageError("label is required")
    safe_label = label.strip()
    if safe_label not in ALLOWED_REVIEW_LABELS:
        allowed = ", ".join(sorted(ALLOWED_REVIEW_LABELS))
        raise JobsConsumerUsageError(
            f"invalid label {safe_label!r}; allowed: {allowed}"
        )
    if not isinstance(note, str):
        raise JobsConsumerUsageError("note must be a string")
    if not isinstance(reviewer, str):
        raise JobsConsumerUsageError("reviewer must be a string")

    safe_ioc = ioc.strip()
    path = _review_path(jobs_dir, job_id)
    append_label(
        path,
        safe_ioc,
        label=safe_label,
        note=note,
        reviewer=reviewer,
    )
    latest = _latest_review_for_ioc(jobs_dir, job_id, safe_ioc) or {
        "label": safe_label,
        "note": note,
        "reviewer": reviewer,
        "reviewed_at": "",
    }
    return {
        "ok": True,
        "job_id": job_id,
        "ioc": safe_ioc,
        "label": latest.get("label", safe_label),
        "note": latest.get("note", note),
        "reviewer": latest.get("reviewer", reviewer),
        "reviewed_at": latest.get("reviewed_at", ""),
    }


def review_overlay(jobs_dir: str | Path, job_id: str) -> list[dict[str, Any]]:
    """Return the collapsed per-IOC human overlay for *job_id*."""
    _load_job(jobs_dir, job_id)
    labels = load_labels(_review_path(jobs_dir, job_id))
    items: list[dict[str, Any]] = []
    for ioc in sorted(labels.keys()):
        entry = labels[ioc]
        items.append(
            {
                "ioc": ioc,
                "label": entry.get("label", ""),
                "note": entry.get("note", ""),
                "reviewer": entry.get("reviewer", ""),
                "reviewed_at": entry.get("reviewed_at", ""),
            }
        )
    return items


def diff_jobs(
    jobs_dir: str | Path,
    job_id: str,
    baseline_job_id: str,
) -> dict[str, Any]:
    """Compare two succeeded jobs via ``compare_verdicts`` (no disk write)."""
    if not isinstance(baseline_job_id, str) or not baseline_job_id.strip():
        raise JobsConsumerUsageError("baseline_job_id is required")

    current = _load_job(jobs_dir, job_id)
    baseline = _load_job(jobs_dir, baseline_job_id.strip())

    current_state = str(current.get("state") or "")
    baseline_state = str(baseline.get("state") or "")
    if current_state != "succeeded" or baseline_state != "succeeded":
        raise JobsConsumerError(
            (
                "both jobs must be succeeded before diff "
                f"(job state={current_state}, baseline state={baseline_state})"
            ),
            exit_code=3,
        )

    current_rows, current_skipped = read_result_rows(jobs_dir, job_id)
    baseline_rows, baseline_skipped = read_result_rows(
        jobs_dir, baseline_job_id.strip()
    )
    report = compare_verdicts(baseline_rows, current_rows)
    payload: dict[str, Any] = {
        "job_id": job_id,
        "baseline_job_id": baseline_job_id.strip(),
        "available": True,
        "diff": report,
    }
    if current_skipped or baseline_skipped:
        payload["skipped"] = {
            "current": current_skipped,
            "baseline": baseline_skipped,
        }
    return payload
