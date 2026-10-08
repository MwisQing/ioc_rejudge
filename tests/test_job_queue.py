"""Tests for the unified job queue storage module."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ioc_rejudge.job_queue import (
    DEFAULT_KEEP,
    LEASE_SECONDS,
    CorruptJobRecordError,
    InvalidJobIdError,
    InvalidJobStateError,
    JobNotFoundError,
    JobsQueueError,
    UnifiedJobQueue,
)


BARE_SAMPLE = """\
# comment line
1.2.3.4
example.com
1.2.3.4
not a valid!!!
"""


def _queue(tmp_path: Path) -> UnifiedJobQueue:
    return UnifiedJobQueue(tmp_path / "jobs")


def _make_running(queue: UnifiedJobQueue, *, heartbeat_at: str | None = None) -> dict:
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    claimed = queue.claim(job["job_id"], runner_name="runner-a", pid=12345)
    assert claimed is not None
    if heartbeat_at is not None:
        path = queue.root / claimed["job_id"] / "job.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["runner"]["heartbeat_at"] = heartbeat_at
        doc["updated_at"] = heartbeat_at
        path.write_text(
            json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return queue.get(claimed["job_id"])
    return claimed


def test_create_job_bare_counts_and_persists(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info", "fdark"],
        preset="default",
        source="paste",
    )
    assert job["state"] == "queued"
    assert job["job_id"].startswith("jq-")
    assert job["input"]["input_kind"] == "bare"
    assert job["input"]["valid"] == 2
    assert job["input"]["duplicated"] == 1
    assert job["input"]["rejected"] == 1
    assert job["input"]["source"] == "paste"
    assert any("invalid" in err for err in job["input"]["errors"])
    job_dir = queue.root / job["job_id"]
    assert (job_dir / "input.txt").read_text(encoding="utf-8") == BARE_SAMPLE
    assert (job_dir / "job.json").is_file()
    loaded = queue.get(job["job_id"])
    assert loaded["job_id"] == job["job_id"]
    assert loaded["state"] == "queued"


def test_create_job_jsonl_counts_lines(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    text = '{"ioc":"1.2.3.4"}\n{"ioc":"example.com"}\n'
    job = queue.create_job(
        text,
        input_kind="jsonl",
        mode="online",
        providers=["ioc_info"],
        preset="fast",
        source="upload",
    )
    assert job["input"]["input_kind"] == "jsonl"
    assert job["input"]["valid"] == 2
    assert job["input"]["duplicated"] == 0
    assert job["input"]["rejected"] == 0
    assert (queue.root / job["job_id"] / "input.jsonl").read_text(encoding="utf-8") == text


def test_concurrent_claim_exactly_one_wins(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    results: list[dict | None] = [None, None]
    barrier = threading.Barrier(2)

    def worker(index: int) -> None:
        barrier.wait(timeout=5)
        results[index] = queue.claim(
            job["job_id"], runner_name=f"runner-{index}", pid=1000 + index
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    winners = [r for r in results if r is not None]
    losers = [r for r in results if r is None]
    assert len(winners) == 1
    assert len(losers) == 1
    winner = winners[0]
    assert winner["state"] == "running"
    assert winner["runner"]["name"] in {"runner-0", "runner-1"}
    assert winner["runner"]["pid"] in {1000, 1001}
    assert winner["runner"]["started_at"]
    assert winner["runner"]["heartbeat_at"]
    assert queue.get(job["job_id"])["state"] == "running"


def test_request_cancel_queued_and_running(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    queued = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    running = _make_running(queue)

    q_result = queue.request_cancel(queued["job_id"])
    assert q_result["action"] == "cancelled"
    assert queue.get(queued["job_id"])["state"] == "cancelled"

    r_result = queue.request_cancel(running["job_id"])
    assert r_result["action"] == "requested"
    doc = queue.get(running["job_id"])
    assert doc["state"] == "running"
    assert doc["cancel_requested"] is True


def test_recover_stale_expires_old_heartbeat_only(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    now = datetime.now(timezone.utc)
    stale_ts = (now - timedelta(minutes=11)).isoformat()
    fresh_ts = (now - timedelta(minutes=1)).isoformat()

    stale = _make_running(queue, heartbeat_at=stale_ts)
    fresh = _make_running(queue, heartbeat_at=fresh_ts)
    queued = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )

    recovered = queue.recover_stale(lease_seconds=LEASE_SECONDS)
    assert any(item["job_id"] == stale["job_id"] for item in recovered)
    stale_doc = queue.get(stale["job_id"])
    assert stale_doc["state"] == "failed"
    assert stale_doc["error"] == "runner lease expired"
    assert stale_doc["updated_at"]

    assert queue.get(fresh["job_id"])["state"] == "running"
    assert queue.get(queued["job_id"])["state"] == "queued"

    again = queue.recover_stale(lease_seconds=LEASE_SECONDS)
    assert again == []
    assert queue.get(stale["job_id"])["state"] == "failed"


def test_recover_stale_cleans_orphan_lock(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    lock_dir = queue.root / job["job_id"] / ".lock"
    lock_dir.mkdir()
    (lock_dir / "owner.json").write_text(
        json.dumps(
            {
                "pid": 1,
                "name": "dead",
                "acquired_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    recovered = queue.recover_stale()
    assert lock_dir.exists() is False
    assert queue.get(job["job_id"])["state"] == "queued"
    assert recovered == [] or all(r.get("job_id") != job["job_id"] for r in recovered)


def test_list_jobs_orders_and_surfaces_corrupt(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    first = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="a",
    )
    time.sleep(0.02)
    second = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="b",
    )
    bad_id = "jq-corrupt-test-00000001"
    bad_dir = queue.root / bad_id
    bad_dir.mkdir(parents=True)
    (bad_dir / "job.json").write_text("{not-json", encoding="utf-8")

    listed = queue.list_jobs()
    ids = [item["job_id"] for item in listed]
    assert second["job_id"] in ids
    assert first["job_id"] in ids
    assert bad_id in ids
    # newest first among valid records; corrupt still present
    valid_order = [item for item in listed if item.get("state") != "corrupt"]
    assert valid_order[0]["job_id"] == second["job_id"]
    corrupt = [item for item in listed if item.get("state") == "corrupt"]
    assert len(corrupt) == 1
    assert corrupt[0]["job_id"] == bad_id

    filtered = queue.list_jobs(state="queued")
    assert all(item["state"] in {"queued", "corrupt"} or item["state"] == "queued" for item in filtered)
    assert all(
        item["state"] == "queued" for item in filtered if item["job_id"] != bad_id
    )


def test_prune_dry_run_and_apply(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job_ids: list[str] = []
    for i in range(60):
        job = queue.create_job(
            BARE_SAMPLE,
            input_kind="bare",
            mode="offline",
            providers=["ioc_info"],
            preset="default",
            source=f"n{i}",
        )
        # Force deterministic created_at ordering (oldest first).
        path = queue.root / job["job_id"] / "job.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        stamp = (base + timedelta(seconds=i)).isoformat()
        doc["created_at"] = stamp
        doc["updated_at"] = stamp
        path.write_text(
            json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        job_ids.append(job["job_id"])

    bad_id = "jq-bad-prune-00000001"
    bad_dir = queue.root / bad_id
    bad_dir.mkdir(parents=True)
    (bad_dir / "job.json").write_text("{broken", encoding="utf-8")

    dry = queue.prune(keep=DEFAULT_KEEP, dry_run=True)
    assert dry["kept"] == 50
    assert len(dry["removed"]) == 10
    assert dry["freed_bytes"] > 0
    # dry_run must not delete
    assert len([p for p in queue.root.iterdir() if p.is_dir()]) == 61

    applied = queue.prune(keep=DEFAULT_KEEP, dry_run=False)
    assert applied["kept"] == 50
    assert len(applied["removed"]) == 10
    remaining = sorted(
        [p.name for p in queue.root.iterdir() if p.is_dir() and p.name != bad_id]
    )
    # newest 50 survive (indices 10..59)
    expected = sorted(job_ids[10:])
    assert sorted(remaining) == expected
    assert bad_dir.exists()  # corrupt not auto-removed by prune keep window of valid?


def test_whitelist_rejects_secret_keys(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    path = queue.root / job["job_id"] / "job.json"
    before = path.read_text(encoding="utf-8")

    with pytest.raises((InvalidJobStateError, ValueError)):
        queue._write_job(  # intentional internal write path
            {
                **job,
                "api_key": "secret-value",
            }
        )
    assert path.read_text(encoding="utf-8") == before

    with pytest.raises((InvalidJobStateError, ValueError)):
        queue.finish(
            job["job_id"],
            state="succeeded",
            result_summary={"api_key": "nope"},
        )


def test_finish_requires_running(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    with pytest.raises(InvalidJobStateError):
        queue.finish(job["job_id"], state="succeeded")

    claimed = queue.claim(job["job_id"], runner_name="r", pid=1)
    assert claimed is not None
    done = queue.finish(
        job["job_id"],
        state="succeeded",
        result_summary={"rows": 2},
    )
    assert done["state"] == "succeeded"
    assert done["result_summary"] == {"rows": 2}

    with pytest.raises(InvalidJobStateError):
        queue.finish(job["job_id"], state="failed", error="again")


def test_finish_failed_and_cancel_late_flag(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    running = _make_running(queue)
    queue.request_cancel(running["job_id"])
    done = queue.finish(running["job_id"], state="failed", error="boom")
    assert done["state"] == "failed"
    assert done["error"] == "boom"
    assert done.get("cancel_requested_late") is True


def test_heartbeat_updates_timestamp(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    running = _make_running(queue)
    old = running["runner"]["heartbeat_at"]
    time.sleep(0.02)
    queue.heartbeat(running["job_id"])
    updated = queue.get(running["job_id"])
    assert updated["runner"]["heartbeat_at"] >= old


def test_append_results_and_diagnostics(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    running = _make_running(queue)
    queue.append_results(
        running["job_id"],
        [{"ioc": "1.2.3.4", "conclusion": "unknown"}],
    )
    queue.append_results(
        running["job_id"],
        [{"ioc": "example.com", "conclusion": "benign"}],
    )
    results_path = queue.root / running["job_id"] / "results.jsonl"
    lines = [ln for ln in results_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2

    queue.write_diagnostics(running["job_id"], {"cache_hit": 1, "cache_miss": 1})
    diag = json.loads(
        (queue.root / running["job_id"] / "diagnostics.json").read_text(encoding="utf-8")
    )
    assert diag == {"cache_hit": 1, "cache_miss": 1}
    queue.write_diagnostics(running["job_id"], {"cache_hit": 2})
    diag2 = json.loads(
        (queue.root / running["job_id"] / "diagnostics.json").read_text(encoding="utf-8")
    )
    assert diag2 == {"cache_hit": 2}


def test_get_not_found_and_corrupt(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    with pytest.raises(JobNotFoundError):
        queue.get("jq-missing-00000000")
    with pytest.raises(InvalidJobIdError):
        queue.get("../escape")
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    path = queue.root / job["job_id"] / "job.json"
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(CorruptJobRecordError):
        queue.get(job["job_id"])


def test_claim_non_queued_returns_none(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = queue.create_job(
        BARE_SAMPLE,
        input_kind="bare",
        mode="offline",
        providers=["ioc_info"],
        preset="default",
        source="test",
    )
    assert queue.claim(job["job_id"], runner_name="a", pid=1) is not None
    assert queue.claim(job["job_id"], runner_name="b", pid=2) is None


def test_exceptions_are_jobs_queue_error_subclasses() -> None:
    assert issubclass(InvalidJobIdError, JobsQueueError)
    assert issubclass(InvalidJobIdError, ValueError)
    assert issubclass(JobNotFoundError, JobsQueueError)
    assert issubclass(JobNotFoundError, KeyError)
    assert issubclass(InvalidJobStateError, JobsQueueError)
    assert issubclass(InvalidJobStateError, ValueError)
    assert issubclass(CorruptJobRecordError, JobsQueueError)
    assert issubclass(CorruptJobRecordError, ValueError)


def test_write_job_retries_brief_replace_denial(tmp_path, monkeypatch):
    """A transient os.replace denial (concurrent reader on Windows) retries."""
    import ioc_rejudge.job_queue as jq_mod

    queue = jq_mod.UnifiedJobQueue(tmp_path / "jobs")
    job = queue.create_job(
        "retry.example.invalid\n",
        input_kind="bare",
        mode="offline",
        providers=[],
        preset="standard",
        source="test",
    )

    real_write = jq_mod.atomic_write_text
    calls = {"n": 0}

    def flaky_write(path, text, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError(5, "拒绝访问。", str(path))
        return real_write(path, text, **kw)

    monkeypatch.setattr(jq_mod, "atomic_write_text", flaky_write)
    claimed = queue.claim(job["job_id"], runner_name="test", pid=None)
    assert claimed is not None
    assert calls["n"] == 2
    assert queue.get(job["job_id"])["state"] == "running"


def test_write_job_persistent_denial_raises_queue_error(tmp_path, monkeypatch):
    """Persistent replace denial surfaces as JobsQueueError, not raw OSError."""
    import pytest as _pytest

    import ioc_rejudge.job_queue as jq_mod

    queue = jq_mod.UnifiedJobQueue(tmp_path / "jobs")
    job = queue.create_job(
        "stuck.example.invalid\n",
        input_kind="bare",
        mode="offline",
        providers=[],
        preset="standard",
        source="test",
    )

    def always_denied(path, text, **kw):
        raise PermissionError(5, "拒绝访问。", str(path))

    monkeypatch.setattr(jq_mod, "atomic_write_text", always_denied)
    with _pytest.raises(jq_mod.JobsQueueError):
        queue.claim(job["job_id"], runner_name="test", pid=None)
    assert queue.get(job["job_id"])["state"] == "queued"
