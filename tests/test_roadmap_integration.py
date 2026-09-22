import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from ioc_rejudge.job_store import JobStore
from ioc_rejudge.roadmap_cli import main
from ioc_rejudge.run_history import RunHistory
from ioc_rejudge.workbench import WorkbenchValidationError
from ioc_rejudge.workbench_backend import OfflineWorkbenchAdapter


SNAPSHOT = (
    '{"ioc":"test-malware.invalid","data":[{"key":"test-malware.invalid",'
    '"level":70,"source":["sample-base"],"family":["trojan-downloader"],'
    '"hash":[{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab","level":70,'
    '"time":"2026-07-15 10:00:00"}],"updatetime":"2026-07-20 08:00:00",'
    '"context":"test-malware.invalid associated with trojan activity"}]}\n'
)
RESULT = {
    "ioc": "pending.invalid",
    "conclusion": "待复核",
    "disposition": "review",
    "review_suggestion": "必看",
    "reason": "requires analyst context",
    "hit_evidence": "A=context",
}


def last_json(capsys) -> dict:
    captured = capsys.readouterr()
    return json.loads(captured.out)


def last_error(capsys) -> dict:
    captured = capsys.readouterr()
    return json.loads(captured.err)


def test_job_start_status_resume_retry_and_cancel(tmp_path, capsys):
    input_path = tmp_path / "snapshot.jsonl"
    input_path.write_text(SNAPSHOT, encoding="utf-8")
    job_dir = tmp_path / "jobs"

    assert main(["job", "start", "--input", str(input_path), "--job-dir", str(job_dir), "--offline"]) == 0
    started = last_json(capsys)
    job_id = started["id"]
    assert started["state"] == "succeeded"
    result_path = Path(started["targets"]["run"]["result"]["result_path"])
    assert result_path.is_file()
    assert json.loads(result_path.read_text(encoding="utf-8"))["ioc"] == "test-malware.invalid"

    assert main(["job", "status", job_id, "--job-dir", str(job_dir)]) == 0
    assert last_json(capsys)["state"] == "succeeded"
    assert main(["job", "resume", job_id, "--job-dir", str(job_dir)]) == 0
    assert last_json(capsys)["state"] == "succeeded"

    missing = tmp_path / "missing.jsonl"
    store = JobStore(job_dir)
    store.create(
        "retry-job",
        ["run"],
        {"input_path": str(missing), "pipeline": "legacy_snapshot"},
    )
    assert main(["job", "retry-failed", "retry-job", "--job-dir", str(job_dir)]) == 1
    failed = last_json(capsys)
    assert failed["state"] == "failed"
    missing.write_text(SNAPSHOT, encoding="utf-8")
    assert main(["job", "retry-failed", "retry-job", "--job-dir", str(job_dir)]) == 0
    assert last_json(capsys)["state"] == "succeeded"

    assert main(["job", "cancel", job_id, "--job-dir", str(job_dir)]) == 0
    assert last_json(capsys)["state"] == "succeeded"


def test_job_start_bad_input_is_actionable_and_nonzero(tmp_path, capsys):
    input_path = tmp_path / "bad.jsonl"
    input_path.write_text('{"ioc":"broken.invalid","data":{}}\n', encoding="utf-8")
    assert main(["job", "start", "--input", str(input_path), "--job-dir", str(tmp_path / "jobs")]) == 1
    payload = last_json(capsys)
    assert payload["state"] == "failed"
    assert "no verdicts" in payload["targets"]["run"]["error"]


def test_history_commands_list_get_and_select_baseline(tmp_path, capsys):
    history_dir = tmp_path / "history"
    history = RunHistory(history_dir)
    history.record({"run_id": "old", "created_at": "2026-01-01T00:00:00Z", "count": 1})
    history.record({"run_id": "new", "created_at": "2026-01-02T00:00:00Z", "count": 2})

    assert main(["history", "list", "--history-dir", str(history_dir)]) == 0
    assert [row["run_id"] for row in last_json(capsys)["runs"]] == ["old", "new"]

    assert main(["history", "get", "new", "--history-dir", str(history_dir)]) == 0
    assert last_json(capsys)["count"] == 2

    assert main([
        "history", "baseline", "--history-dir", str(history_dir),
        "--current-run-id", "new",
    ]) == 0
    assert last_json(capsys)["run"]["run_id"] == "old"


def test_review_list_label_reopen_preserves_conclusion(tmp_path, capsys):
    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps(RESULT, ensure_ascii=False) + "\n", encoding="utf-8")
    queue = tmp_path / "queue.jsonl"

    assert main(["review", "list", "--input", str(results), "--queue", str(queue)]) == 0
    listed = last_json(capsys)
    assert listed["summary"]["unreviewed"] == 1
    assert listed["rows"][0]["conclusion"] == "待复核"

    assert main([
        "review", "label", "--queue", str(queue), "--ioc", "pending.invalid",
        "--decision", "approved", "--note", "checked", "--reviewer", "analyst",
    ]) == 0
    assert last_json(capsys)["labelled"]["label"] == "approved"
    assert main(["review", "list", "--input", str(results), "--queue", str(queue)]) == 0
    labelled = last_json(capsys)["rows"][0]
    assert labelled["label"] == "approved"
    assert labelled["conclusion"] == "待复核"

    assert main(["review", "reopen", "--queue", str(queue), "--ioc", "pending.invalid", "--reviewer", "lead"]) == 0
    assert last_json(capsys)["reopened"]["label"] == ""
    assert main(["review", "list", "--input", str(results), "--queue", str(queue)]) == 0
    assert last_json(capsys)["summary"]["unreviewed"] == 1


def test_explain_and_health_are_json_without_network(tmp_path, capsys):
    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps(RESULT, ensure_ascii=False) + "\n", encoding="utf-8")
    assert main(["explain", "--input", str(results), "--ioc", "pending.invalid"]) == 0
    explanation = last_json(capsys)
    assert explanation["conclusion"] == "待复核"
    assert "requires analyst context" in explanation["reason"]

    cache_dir = tmp_path / "health-cache"
    assert main(["health", "--providers", "ioc_info", "--cache-dir", str(cache_dir), "--offline"]) == 0
    health = last_json(capsys)
    assert health["offline"] is True
    assert health["network_access"] == "disabled"
    assert health["providers"]["ioc_info"]["checks"]["transport"] == {"status": "not_probed"}


def _cache_entry(time: str) -> dict:
    return {
        "key": "entry",
        "ioc": "entry.invalid",
        "params": {},
        "fetched_at": time,
        "raw": {"ok": True},
    }


def test_cache_cleanup_dry_run_then_apply(tmp_path, capsys):
    cache_dir = tmp_path / "cache"
    shard = cache_dir / ".cache_provider" / "cache_2020-01-01.jsonl"
    shard.parent.mkdir(parents=True)
    payload = json.dumps(_cache_entry("2020-01-01T00:00:00+00:00"), sort_keys=True) + "\n"
    shard.write_text(payload, encoding="utf-8")

    assert main(["cache", "cleanup", "--cache-dir", str(cache_dir), "--before", "2026-01-01"]) == 0
    dry_run = last_json(capsys)
    assert dry_run["executed"] is False
    assert dry_run["would_delete_files"] == 1
    assert shard.exists()

    assert main([
        "cache", "cleanup", "--cache-dir", str(cache_dir), "--before", "2026-01-01", "--apply",
    ]) == 0
    applied = last_json(capsys)
    assert applied["executed"] is True
    assert applied["deleted_files"] == 1
    assert not shard.exists()


def test_import_csv_and_reject_bad_table(tmp_path, capsys):
    source = tmp_path / "report.csv"
    source.write_text("indicator\nsafe.example.invalid\nsafe.example.invalid\n", encoding="utf-8")
    output = tmp_path / "input.jsonl"
    assert main(["import-table", "--input", str(source), "--column", "indicator", "--output", str(output)]) == 0
    imported = last_json(capsys)
    assert imported["parsed_count"] == 1
    assert imported["duplicate_count"] == 1
    assert output.read_text(encoding="utf-8").splitlines() == [
        '{"data": [], "ioc": "safe.example.invalid"}'
    ]

    bad = tmp_path / "bad.csv"
    bad.write_text("indicator\n=cmd()\n", encoding="utf-8")
    assert main(["import-table", "--input", str(bad), "--column", "indicator", "--output", str(tmp_path / "bad.jsonl")]) == 1
    error = last_error(capsys)
    assert "formula-like" in error["error"]


def test_export_bundle_writes_all_formats_and_protects_inputs(tmp_path, capsys):
    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps(RESULT, ensure_ascii=False) + "\n", encoding="utf-8")
    diagnostics = tmp_path / "diagnostics.json"
    diagnostics.write_text(json.dumps({"processed_count": 1}), encoding="utf-8")
    output_dir = tmp_path / "bundle"

    assert main([
        "export-bundle", "--input", str(results), "--output-dir", str(output_dir),
        "--diagnostics", str(diagnostics), "--base-name", "run",
    ]) == 0
    exported = last_json(capsys)
    assert exported["rows"] == 1
    for name in ("jsonl", "csv", "xlsx", "diagnostics"):
        assert Path(exported["outputs"][name]).is_file()

    assert main([
        "export-bundle", "--input", str(results), "--output-dir", str(tmp_path),
        "--base-name", "results",
    ]) == 1
    assert "protected path" in last_error(capsys)["error"]


def test_workbench_local_offline_happy_path(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")
    staged = adapter.stage_input("snapshot.jsonl", SNAPSHOT)
    started = adapter.start_task(staged["import_id"])
    assert started["state"] == "succeeded"
    assert started["result_count"] == 1

    status = adapter.task_status(started["task_id"])
    assert Path(status["diagnostics_path"]).is_file()
    results = adapter.results(started["task_id"], query="trojan")
    assert results["total"] == 1
    result_id = results["rows"][0]["result_id"]

    explanation = adapter.explanation(started["task_id"], result_id)
    assert explanation["result_id"] == result_id
    reviewed = adapter.submit_review(
        started["task_id"], result_id,
        decision="approved", reason="validated", reviewer="tester",
    )
    assert reviewed["review"] == "approved"
    export = adapter.export(started["task_id"], export_format="jsonl")
    downloaded = adapter.export_file(export["export_id"])
    assert downloaded.is_file()
    assert downloaded.suffix == ".jsonl"


def test_workbench_filtered_result_id_keeps_source_ordinal(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")
    second = SNAPSHOT.replace("test-malware.invalid", "second-malware.invalid")
    staged = adapter.stage_input("snapshot.jsonl", SNAPSHOT + second)
    started = adapter.start_task(staged["import_id"])
    assert started["state"] == "succeeded"

    results = adapter.results(started["task_id"], query="second-malware")
    assert results["total"] == 1
    result_id = results["rows"][0]["result_id"]
    assert result_id.endswith("-000002")

    explanation = adapter.explanation(started["task_id"], result_id)
    assert explanation["ioc"] == "second-malware.invalid"


def test_workbench_provider_issue_filter_matches_failures_and_missing_sources():
    rows = [
        {"ioc": "ok", "provider_statuses": {"whois": "success"}},
        {"ioc": "error", "provider_statuses": {"whois": "error"}},
        {"ioc": "missing", "missing_required_providers": ["icp"]},
        {"ioc": "no-data", "provider_statuses": {"whois": "no_data"}},
    ]
    filtered = OfflineWorkbenchAdapter._filter_rows(
        rows, dispositions=None, query=None, provider_issues=True
    )
    assert [row["ioc"] for row in filtered] == ["error", "missing"]


def test_workbench_background_task_is_observable_and_exposes_safe_diagnostics(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")
    staged = adapter.stage_input("snapshot.jsonl", SNAPSHOT)
    started = adapter.start_task(staged["import_id"], options={"background": True})
    assert started["state"] in {"queued", "running", "succeeded"}

    deadline = time.monotonic() + 10
    status = started
    while status["state"] in {"queued", "running"} and time.monotonic() < deadline:
        time.sleep(0.02)
        status = adapter.task_status(started["task_id"])
    assert status["state"] == "succeeded", status
    diagnostics = adapter.diagnostics(started["task_id"])
    assert diagnostics["available"] is True
    assert "input_path" not in diagnostics

    summary = adapter.summary(started["task_id"])
    assert summary["version"] == "2.8.0"
    assert len(summary["input"]["sha256"]) == 64
    assert summary["execution"]["network"] == "disabled"
    assert "input_path" not in json.dumps(summary, ensure_ascii=False)

    baseline = adapter.start_task(staged["import_id"])
    comparison = adapter.diff(started["task_id"], baseline["task_id"])
    assert comparison["available"] is True
    assert comparison["diff"]["operations"] == 1

    diagnostic_export = adapter.export_artifact(
        started["task_id"], artifact_format="diagnostics"
    )
    assert Path(adapter.export_file(diagnostic_export["export_id"])).suffix == ".json"
    diff_export = adapter.export_artifact(
        started["task_id"],
        artifact_format="diff",
        baseline_task_id=baseline["task_id"],
    )
    assert json.loads(
        adapter.export_file(diff_export["export_id"]).read_text(encoding="utf-8")
    )["available"] is True
    bundle_export = adapter.export_artifact(
        started["task_id"],
        artifact_format="bundle",
        baseline_task_id=baseline["task_id"],
    )
    with zipfile.ZipFile(adapter.export_file(bundle_export["export_id"])) as archive:
        assert set(archive.namelist()) == {
            "results.jsonl", "results.csv", "results.xlsx", "diagnostics.json", "diff.json"
        }


def test_workbench_rejects_provider_mode_and_bad_import(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")
    with pytest.raises(WorkbenchValidationError, match="live providers"):
        adapter.start_task("bad", providers=["ioc_info"])
    with pytest.raises(WorkbenchValidationError, match="not found"):
        adapter.start_task("bad")


def test_module_level_help_and_error_contract():
    help_process = subprocess.run(
        [sys.executable, "-m", "ioc_rejudge", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_process.returncode == 0
    assert "APT IOC Snapshot Rejudgement Tool" in help_process.stdout

    error_process = subprocess.run(
        [sys.executable, "-m", "ioc_rejudge", "explain"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert error_process.returncode == 1
    assert json.loads(error_process.stderr)["available"] is False
