"""Tests for job-queue explain / review overlay / baseline diff consumers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ioc_rejudge.job_queue import UnifiedJobQueue
from ioc_rejudge.jobs_consumers import (
    JobsConsumerError,
    JobsConsumerUsageError,
    append_review,
    diff_jobs,
    explain_result,
    read_result_rows,
    review_overlay,
)
from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS


def _queue(tmp_path: Path) -> UnifiedJobQueue:
    return UnifiedJobQueue(tmp_path / "jobs")


def _seed_succeeded(
    queue: UnifiedJobQueue,
    rows: list[dict],
    *,
    text: str = "alpha.invalid\nbeta.invalid\n",
) -> str:
    job = queue.create_job(
        text,
        input_kind="bare",
        mode="offline",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test",
    )
    job_id = job["job_id"]
    assert queue.claim(job_id, runner_name="test", pid=1) is not None
    queue.append_results(job_id, rows)
    queue.finish(
        job_id,
        state="succeeded",
        result_summary={"rows": len(rows), "conclusions": {}},
    )
    return job_id


def _sample_rows() -> list[dict]:
    return [
        {
            "ioc": "alpha.invalid",
            "conclusion": "误报",
            "route": "A",
            "disposition": "allow",
            "reason": "synthetic-a",
        },
        {
            "ioc": "beta.invalid",
            "conclusion": "待复核",
            "route": "B",
            "disposition": "review",
            "reason": "synthetic-b",
        },
    ]


def test_read_result_rows_skips_bad_json(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job_id = _seed_succeeded(queue, _sample_rows()[:1])
    path = queue.root / job_id / "results.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
        handle.write(
            json.dumps(
                {
                    "ioc": "gamma.invalid",
                    "conclusion": "灰",
                    "route": "C",
                    "disposition": "monitor",
                },
                ensure_ascii=False,
            )
            + "\n"
        )

    rows, skipped = read_result_rows(queue.root, job_id)
    assert skipped == 1
    assert len(rows) == 2
    assert rows[1]["ioc"] == "gamma.invalid"


def test_explain_result_by_derived_result_id(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    rows = _sample_rows()
    job_id = _seed_succeeded(queue, rows)
    second_id = f"{job_id}-000002"

    payload = explain_result(queue.root, job_id, result_id=second_id)
    assert payload["result_id"] == second_id
    assert payload["ioc"] == "beta.invalid"
    assert payload["conclusion"] == "待复核"
    assert "evidence_fingerprint" in payload
    assert payload.get("reason") == "synthetic-b"


def test_explain_result_prefers_embedded_result_id(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    rows = [
        {
            "ioc": "alpha.invalid",
            "conclusion": "误报",
            "reason": "a",
            "result_id": "custom-rid-alpha",
        },
        {
            "ioc": "beta.invalid",
            "conclusion": "灰",
            "reason": "b",
            "result_id": "custom-rid-beta",
        },
    ]
    job_id = _seed_succeeded(queue, rows)
    payload = explain_result(queue.root, job_id, result_id="custom-rid-beta")
    assert payload["ioc"] == "beta.invalid"
    assert payload["result_id"] == "custom-rid-beta"
    # Derived id must not steal a row that carries its own result_id.
    with pytest.raises(JobsConsumerError) as excinfo:
        explain_result(queue.root, job_id, result_id=f"{job_id}-000002")
    assert excinfo.value.exit_code == 3


def test_explain_result_missing_id_raises(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job_id = _seed_succeeded(queue, _sample_rows())
    with pytest.raises(JobsConsumerError) as excinfo:
        explain_result(queue.root, job_id, result_id=f"{job_id}-009999")
    assert excinfo.value.exit_code == 3


def test_append_review_idempotent_and_overlay_on_explain(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    rows = _sample_rows()
    job_id = _seed_succeeded(queue, rows)
    results_path = queue.root / job_id / "results.jsonl"
    before = results_path.read_bytes()

    first = append_review(
        queue.root,
        job_id,
        ioc="alpha.invalid",
        label="approved",
        note="first-pass",
        reviewer="analyst-a",
    )
    assert first["label"] == "approved"
    assert first["ioc"] == "alpha.invalid"

    second = append_review(
        queue.root,
        job_id,
        ioc="alpha.invalid",
        label="approved",
        note="second-pass",
        reviewer="analyst-a",
    )
    assert second["label"] == "approved"
    assert second["note"] == "second-pass"

    review_path = queue.root / job_id / "review.jsonl"
    assert review_path.is_file()
    records = [
        json.loads(line)
        for line in review_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 2
    assert all(r.get("label") == "approved" for r in records)
    assert results_path.read_bytes() == before

    overlay = review_overlay(queue.root, job_id)
    assert any(item.get("ioc") == "alpha.invalid" for item in overlay)
    match = next(item for item in overlay if item.get("ioc") == "alpha.invalid")
    assert match["label"] == "approved"
    assert match["note"] == "second-pass"

    explained = explain_result(
        queue.root, job_id, result_id=f"{job_id}-000001"
    )
    review = explained.get("review")
    assert isinstance(review, dict)
    assert review.get("label") == "approved"
    assert review.get("note") == "second-pass"
    # System conclusion unchanged.
    assert explained["conclusion"] == "误报"


def test_append_review_rejects_invalid_label(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job_id = _seed_succeeded(queue, _sample_rows())
    with pytest.raises(JobsConsumerUsageError) as excinfo:
        append_review(
            queue.root,
            job_id,
            ioc="alpha.invalid",
            label="not-a-real-label",
        )
    assert excinfo.value.exit_code == 2


def test_diff_jobs_reports_transitions(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    before_rows = [
        {
            "ioc": "alpha.invalid",
            "conclusion": "存活有效",
            "disposition": "block",
            "reason": "old",
        },
        {
            "ioc": "beta.invalid",
            "conclusion": "误报",
            "disposition": "allow",
            "reason": "old-b",
        },
    ]
    after_rows = [
        {
            "ioc": "alpha.invalid",
            "conclusion": "误报",
            "disposition": "allow",
            "reason": "new",
        },
        {
            "ioc": "beta.invalid",
            "conclusion": "误报",
            "disposition": "allow",
            "reason": "old-b",
            "review_suggestion": "必看",
        },
    ]
    baseline_id = _seed_succeeded(
        queue, before_rows, text="alpha.invalid\nbeta.invalid\n"
    )
    current_id = _seed_succeeded(
        queue, after_rows, text="alpha.invalid\nbeta.invalid\n"
    )

    report = diff_jobs(queue.root, current_id, baseline_id)
    assert report["job_id"] == current_id
    assert report["baseline_job_id"] == baseline_id
    body = report["diff"]
    assert body["operations"] == 2
    assert any(item["ioc"] == "alpha.invalid" for item in body["changed"])
    assert "operational_changes" in body
    assert isinstance(body["operational_changes"], list)
    assert any(item["ioc"] == "beta.invalid" for item in body["operational_changes"])
    assert len(body["black_to_white"]) == 1


def test_diff_jobs_rejects_non_succeeded_baseline(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    current_id = _seed_succeeded(queue, _sample_rows())
    queued = queue.create_job(
        "queued.invalid\n",
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="standard",
        source="test",
    )
    with pytest.raises(JobsConsumerError) as excinfo:
        diff_jobs(queue.root, current_id, queued["job_id"])
    assert excinfo.value.exit_code == 3
    assert "succeeded" in str(excinfo.value).lower() or "queued" in str(
        excinfo.value
    ).lower()


def test_explain_missing_job_raises(tmp_path: Path) -> None:
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    with pytest.raises(JobsConsumerError) as excinfo:
        explain_result(jobs_dir, "jq-missing-00000001", result_id="x-000001")
    assert excinfo.value.exit_code == 3
