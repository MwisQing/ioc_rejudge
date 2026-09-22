import json

import pytest

from ioc_rejudge.job_runner import JobCancelled, JobRunner, InvalidExecuteResultError
from ioc_rejudge.job_store import (
    CANCELLED,
    FAILED,
    PENDING,
    RUNNING,
    SUCCEEDED,
    CorruptJobFileError,
    InvalidJobIdError,
    JobNotFoundError,
    JobStore,
)


def test_create_normalizes_and_persists_targets(tmp_path):
    store = JobStore(tmp_path)
    job = store.create("safe-job", ["zeta", "alpha", "zeta"], {"version": 1})

    assert job["targets"] == {"zeta": {"state": PENDING}, "alpha": {"state": PENDING}}
    assert job["metadata"] == {"version": 1}
    assert store.load("safe-job")["targets"] == job["targets"]
    assert (tmp_path / "safe-job.json").exists()


@pytest.mark.parametrize(
    "job_id",
    ["", "a/b", "a\\b", ".", ".."],
)
def test_reject_unsafe_job_ids(tmp_path, job_id):
    store = JobStore(tmp_path)
    with pytest.raises(InvalidJobIdError):
        store.create(job_id, [])


def test_load_returns_not_found(tmp_path):
    store = JobStore(tmp_path)
    with pytest.raises(JobNotFoundError):
        store.load("absent")


def test_transition_success_and_failure_fields(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["one", "two"])
    store.transition("job", "one", SUCCEEDED, result={"ok": True})
    store.transition("job", "two", FAILED, error="boom")

    targets = store.load("job")["targets"]
    assert targets["one"] == {"state": SUCCEEDED, "result": {"ok": True}}
    assert targets["two"] == {"state": FAILED, "error": "boom"}
    assert store.pending_targets("job") == []


def test_load_resets_running_targets(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["one"])
    store.transition("job", "one", RUNNING)
    assert store.load("job")["targets"]["one"]["state"] == PENDING


def test_cancel_and_retry_failed(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["done", "failed", "queued"])
    store.transition("job", "done", SUCCEEDED, result=1)
    store.transition("job", "failed", FAILED, error="old")
    store.transition("job", "queued", PENDING)
    store.cancel("job")

    targets = store.load("job")["targets"]
    assert targets["done"]["state"] == SUCCEEDED
    assert targets["queued"]["state"] == CANCELLED
    assert "error" not in targets["failed"] or targets["failed"]["error"] == "old"

    store.retry_failed("job")
    assert store.load("job")["targets"]["failed"]["state"] == PENDING


def test_pending_targets_sorted(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["z", "m", "a"])
    assert store.pending_targets("job") == ["a", "m", "z"]


def test_runner_executes_marks_and_persists(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["two", "one"])
    runner = JobRunner(store)

    def execute(target_id):
        state = json.loads((tmp_path / "job.json").read_text(encoding="utf-8"))[
            "targets"
        ][target_id]["state"]
        assert state == RUNNING
        return {"target": target_id}

    runner.run("job", execute)
    assert store.load("job")["targets"] == {
        "one": {"state": SUCCEEDED, "result": {"target": "one"}},
        "two": {"state": SUCCEEDED, "result": {"target": "two"}},
    }


def test_runner_skips_succeeded_and_resumes_pending_after_crash(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["first", "second"])
    store.transition("job", "first", SUCCEEDED, result="kept")
    store.transition("job", "second", RUNNING)

    calls = []
    JobRunner(store).run("job", calls.append)

    assert calls == ["second"]
    assert store.load("job")["targets"]["first"]["state"] == SUCCEEDED
    assert store.load("job")["targets"]["second"]["state"] == SUCCEEDED


def test_runner_failure_is_saved_and_retry_succeeds(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["target"])
    calls = []

    def execute(target_id):
        calls.append(target_id)
        if len(calls) == 1:
            raise RuntimeError("temporary outage")
        return {"attempt": len(calls)}

    JobRunner(store).run("job", execute)
    assert store.load("job")["targets"]["target"]["state"] == FAILED
    assert "RuntimeError: temporary outage" in store.load("job")["targets"]["target"]["error"]

    JobRunner(store).run("job", execute, retry_failed=True)
    assert calls == ["target", "target"]
    assert store.load("job")["targets"]["target"] == {
        "state": SUCCEEDED,
        "result": {"attempt": 2},
    }


def test_runner_stops_before_new_target_on_cancel(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["a", "b", "c"])
    calls = []
    cancel_seen = {"count": 0}

    def execute(target_id):
        calls.append(target_id)
        return target_id

    def cancel_check():
        cancel_seen["count"] += 1
        return len(calls) >= 1

    with pytest.raises(JobCancelled):
        JobRunner(store).run("job", execute, cancel_check=cancel_check)

    assert calls == ["a"]
    targets = store.load("job")["targets"]
    assert targets["a"]["state"] == SUCCEEDED
    assert targets["b"]["state"] == PENDING
    assert targets["c"]["state"] == PENDING


def test_runner_rejects_non_json_callback_result(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", ["one"])
    with pytest.raises(InvalidExecuteResultError, match="JSON-compatible"):
        JobRunner(store).run("job", lambda _target_id: object())
    persisted = json.loads((tmp_path / "job.json").read_text(encoding="utf-8"))
    assert persisted["targets"]["one"]["state"] == FAILED


def test_malformed_job_json_is_rejected(tmp_path):
    store = JobStore(tmp_path)
    store.create("job", [])
    (tmp_path / "job.json").write_text("{not-json", encoding="utf-8")
    with pytest.raises(CorruptJobFileError):
        store.load("job")
    with pytest.raises(CorruptJobFileError):
        JobRunner(store).run("job", lambda _target_id: None)


def test_saved_json_is_deterministic(tmp_path):
    store = JobStore(tmp_path)
    store.create("sort", ["b", "a"])
    store.transition("sort", "b", SUCCEEDED, result={"x": 1, "y": 2})
    raw = (tmp_path / "sort.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    assert list(document) == ["id", "metadata", "targets"]
    assert list(document["targets"]) == ["a", "b"]
