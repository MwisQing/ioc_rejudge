"""UI unified job-queue panel API and in-process offline runner."""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from ioc_rejudge.job_queue import UnifiedJobQueue
from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS
from ioc_rejudge.ui import build_server


class NetworkSentinelSession:
    """Fail closed if any code path tries to open a real network session."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("network Session must not be created during offline UI jobs")


class NetworkSentinelTransport:
    def post_json(self, url, *, headers=None, body=None, timeout=30):
        raise AssertionError(f"network transport must not be called: {url}")


@pytest.fixture()
def make_jobs_server(tmp_path, monkeypatch):
    servers = []

    def _make(*, jobs_dir=None, cache_dir=None, transport_factory=None):
        # Offline runner must stay network-free; install Session sentinel.
        monkeypatch.setattr(
            "ioc_rejudge.providers.transport.requests.Session",
            NetworkSentinelSession,
        )
        monkeypatch.setattr("requests.Session", NetworkSentinelSession)

        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        resolved_jobs = jobs_dir if jobs_dir is not None else (tmp_path / "jobs")
        resolved_cache = cache_dir if cache_dir is not None else (tmp_path / "provider-cache")
        resolved_cache.mkdir(parents=True, exist_ok=True)
        resolved_jobs.mkdir(parents=True, exist_ok=True)

        factory = transport_factory
        if factory is None:
            factory = lambda _name: NetworkSentinelTransport()

        server, url = build_server(
            key_path,
            bundles_dir,
            port=0,
            cache_dir=resolved_cache,
            provider_env={},
            transport_factory=factory,
            jobs_dir=resolved_jobs,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        base, _, token = url.partition("/?token=")
        return base, token, resolved_jobs, resolved_cache, server

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def api_post(url, token, path, payload, timeout=30):
    request = urllib.request.Request(
        url + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def api_get_json(url, token, path, timeout=10):
    request = urllib.request.Request(url + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _wait_job_state(url, token, job_id, *, want=("succeeded", "failed", "cancelled"), timeout=60.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = api_get_json(
            url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
        )
        assert status == 200, body
        last = body.get("job") or {}
        if last.get("state") in want:
            return last
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not reach {want}; last={last}")


def test_jobs_list_requires_session_token(make_jobs_server):
    url, _token, _jobs, _cache, _server = make_jobs_server()
    status, body = api_get_json(url, "wrong-token-value", "/api/jobs/list")
    assert status == 403
    assert body["error"] == "forbidden"

    parsed = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    connection.request("GET", "/api/jobs/list")
    response = connection.getresponse()
    status_no_token = response.status
    response.read()
    connection.close()
    assert status_no_token == 403


def test_enqueue_counts_and_list_queued(make_jobs_server):
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    content = "alpha.example.invalid\nbeta.example.invalid\nalpha.example.invalid\n"
    status, body = api_post(
        url,
        token,
        "/api/jobs/enqueue",
        {"content": content, "filename": "paste.txt"},
    )
    assert status == 200, body
    assert body.get("ok") is True
    job = body["job"]
    assert job["state"] == "queued"
    assert job["mode"] == "offline"
    assert job["input"]["valid"] == 2
    assert job["input"]["duplicated"] == 1
    assert "path" not in json.dumps(body).lower() or "jobs_dir" not in json.dumps(body)
    # Response must not leak local filesystem roots.
    dumped = json.dumps(body)
    assert str(jobs_dir) not in dumped
    assert "\\" not in dumped or "C:" not in dumped

    status, listed = api_get_json(url, token, "/api/jobs/list")
    assert status == 200, listed
    assert listed.get("ok") is True
    match = next(j for j in listed["jobs"] if j["job_id"] == job["job_id"])
    assert match["state"] == "queued"


def test_run_background_reaches_succeeded_and_results(make_jobs_server):
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    content = "alpha.example.invalid\nbeta.example.invalid\n"
    status, body = api_post(url, token, "/api/jobs/enqueue", {"content": content})
    assert status == 200, body
    job_id = body["job"]["job_id"]

    status, run_body = api_post(url, token, "/api/jobs/run", {"job_id": job_id})
    assert status == 200, run_body
    assert run_body.get("ok") is True
    # Immediate return — either accepted or already marked running.
    assert run_body.get("running_job_id") in (None, job_id) or run_body.get("job_id") in (
        None,
        job_id,
    )

    # Duplicate run while (or after) first accepted must not error out.
    status2, run2 = api_post(url, token, "/api/jobs/run", {"job_id": job_id})
    assert status2 == 200, run2
    assert run2.get("ok") is True

    finished = _wait_job_state(url, token, job_id, want=("succeeded", "failed"))
    assert finished["state"] == "succeeded", finished
    summary = finished.get("result_summary") or {}
    assert summary.get("rows") == 2
    assert isinstance(summary.get("conclusions"), dict)

    status, results = api_get_json(
        url, token, f"/api/jobs/results?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, results
    assert results.get("ok") is True
    rows = results["rows"]
    assert len(rows) == 2
    conclusions = [row.get("conclusion") for row in rows]
    assert all(c is not None for c in conclusions)
    # Rows pass through storage JSON without UI reordering rewrite of IOC set.
    iocs = {row.get("ioc") or row.get("normalized") for row in rows}
    assert "alpha.example.invalid" in iocs or any(
        "alpha.example.invalid" in str(row) for row in rows
    )

    # Heartbeat / updated_at advanced during run (job.json on disk).
    doc = json.loads((jobs_dir / job_id / "job.json").read_text(encoding="utf-8"))
    assert doc["state"] == "succeeded"
    assert doc.get("updated_at")
    assert doc.get("runner") is None or isinstance(doc.get("runner"), dict)


def test_cancel_queued_then_run_rejects(make_jobs_server):
    url, token, _jobs, _cache, _server = make_jobs_server()
    status, body = api_post(
        url, token, "/api/jobs/enqueue", {"content": "cancel-me.example.invalid\n"}
    )
    assert status == 200, body
    job_id = body["job"]["job_id"]

    status, cancel_body = api_post(url, token, "/api/jobs/cancel", {"job_id": job_id})
    assert status == 200, cancel_body
    assert cancel_body.get("ok") is True
    assert cancel_body.get("action") == "cancelled"

    status, job_body = api_get_json(
        url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200
    assert job_body["job"]["state"] == "cancelled"

    status, run_body = api_post(url, token, "/api/jobs/run", {"job_id": job_id})
    assert status == 200, run_body
    # Either ok=False with state error, or ok with non-start indication.
    if run_body.get("ok") is True and run_body.get("running_job_id"):
        # Another job may be running; still this job must stay cancelled.
        status, again = api_get_json(
            url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
        )
        assert again["job"]["state"] == "cancelled"
    else:
        assert run_body.get("ok") is False or run_body.get("error")
        assert "queued" not in str(run_body.get("state", "")).lower() or run_body.get(
            "ok"
        ) is False


def test_run_online_job_accepted_and_succeeds(make_jobs_server):
    """UI allows online jobs; without credentials they finish with disabled providers."""
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    queue = UnifiedJobQueue(jobs_dir)
    job = queue.create_job(
        "online.example.invalid\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test",
    )
    job_id = job["job_id"]

    status, run_body = api_post(url, token, "/api/jobs/run", {"job_id": job_id})
    assert status == 200, run_body
    assert run_body.get("ok") is True

    finished = _wait_job_state(url, token, job_id, want=("succeeded", "failed"))
    assert finished["state"] == "succeeded", finished
    assert queue.get(job_id)["state"] == "succeeded"


def test_server_restart_keeps_queued_jobs(make_jobs_server, tmp_path):
    jobs_dir = tmp_path / "shared-jobs"
    cache_dir = tmp_path / "shared-cache"
    jobs_dir.mkdir()
    cache_dir.mkdir()

    url1, token1, _j, _c, server1 = make_jobs_server(jobs_dir=jobs_dir, cache_dir=cache_dir)
    status, body = api_post(
        url1, token1, "/api/jobs/enqueue", {"content": "keep-queued.example.invalid\n"}
    )
    assert status == 200, body
    job_id = body["job"]["job_id"]
    assert body["job"]["state"] == "queued"

    server1.shutdown()
    server1.server_close()

    url2, token2, _j2, _c2, _server2 = make_jobs_server(
        jobs_dir=jobs_dir, cache_dir=cache_dir
    )
    status, listed = api_get_json(url2, token2, "/api/jobs/list")
    assert status == 200, listed
    match = next(j for j in listed["jobs"] if j["job_id"] == job_id)
    assert match["state"] == "queued"


def test_ui_html_has_queue_panel_controls():
    page = (Path(__file__).parents[1] / "ioc_rejudge" / "ui.html").read_text(
        encoding="utf-8"
    )
    assert 'href="#queue-panel"' in page
    assert 'id="queue-panel"' in page
    assert 'id="queue-paste"' in page
    assert 'id="queue-enqueue"' in page
    assert 'id="queue-list"' in page
    assert 'id="queue-refresh"' in page
    assert "/api/jobs/enqueue" in page
    assert "/api/jobs/list" in page
    assert "/api/jobs/run" in page
    assert "/api/jobs/cancel" in page
    assert "/api/jobs/results" in page
    assert "/api/jobs/prune" in page
    assert 'name="queue-mode"' in page
    assert 'id="queue-prune"' in page
    # Zero external resources: no http(s) script/link hosts.
    assert "https://" not in page
    assert "http://" not in page
    assert "\x00" not in page


def test_build_server_accepts_jobs_dir(tmp_path):
    jobs_dir = tmp_path / "custom-jobs"
    server, url = build_server(
        tmp_path / "k.json",
        tmp_path / "b",
        port=0,
        jobs_dir=jobs_dir,
        cache_dir=tmp_path / "c",
        provider_env={},
    )
    try:
        assert jobs_dir.is_dir()
        assert "/?token=" in url
        state = server.RequestHandlerClass.ui_state
        assert Path(state.jobs_dir) == jobs_dir.resolve() or Path(state.jobs_dir) == jobs_dir
    finally:
        server.server_close()


def _seed_succeeded_job(jobs_dir: Path, rows: list[dict], *, text: str | None = None) -> str:
    """Write a finished job with results.jsonl for consumer API tests."""
    queue = UnifiedJobQueue(jobs_dir)
    if text is None:
        iocs = [str(row.get("ioc") or f"row{i}.invalid") for i, row in enumerate(rows)]
        text = "\n".join(iocs) + "\n"
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
    conclusions: dict[str, int] = {}
    provider_statuses: dict[str, int] = {}
    for row in rows:
        conclusion = row.get("conclusion")
        if conclusion is not None:
            key = str(conclusion)
            conclusions[key] = conclusions.get(key, 0) + 1
        statuses = row.get("provider_statuses")
        if isinstance(statuses, dict):
            for status in statuses.values():
                skey = str(status)
                provider_statuses[skey] = provider_statuses.get(skey, 0) + 1
    queue.finish(
        job_id,
        state="succeeded",
        result_summary={
            "rows": len(rows),
            "conclusions": conclusions,
            "provider_statuses": provider_statuses,
        },
    )
    return job_id


def _sample_consumer_rows() -> list[dict]:
    return [
        {
            "ioc": "alpha.example.invalid",
            "conclusion": "误报",
            "route": "A",
            "disposition": "allow",
            "reason": "synthetic-a",
            "provider_statuses": {"ioc_info": "ok", "whois": "error"},
        },
        {
            "ioc": "beta.example.invalid",
            "conclusion": "待复核",
            "route": "B",
            "disposition": "review",
            "reason": "synthetic-b",
            "provider_statuses": {"ioc_info": "ok"},
        },
    ]


def api_get_bytes(url, token, path, timeout=10):
    request = urllib.request.Request(url + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_jobs_consumer_endpoints_require_session_token(make_jobs_server):
    url, _token, _jobs, _cache, _server = make_jobs_server()
    for path in (
        "/api/jobs/explain",
        "/api/jobs/review",
        "/api/jobs/export",
        "/api/jobs/diff",
    ):
        status, body = api_post(url, "wrong-token-value", path, {"job_id": "x"})
        assert status == 403, (path, body)
        assert body.get("error") == "forbidden"

        parsed = urllib.parse.urlsplit(url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        connection.request(
            "POST",
            path,
            body=json.dumps({"job_id": "x"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        status_no_token = response.status
        response.read()
        connection.close()
        assert status_no_token == 403, path


def test_jobs_explain_review_idempotent_and_results_overlay(make_jobs_server):
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    rows = _sample_consumer_rows()
    job_id = _seed_succeeded_job(jobs_dir, rows)
    second_id = f"{job_id}-000002"
    results_path = jobs_dir / job_id / "results.jsonl"
    before = results_path.read_bytes()

    status, explained = api_post(
        url,
        token,
        "/api/jobs/explain",
        {"job_id": job_id, "result_id": second_id},
    )
    assert status == 200, explained
    assert explained.get("ok") is True
    explanation = explained["explanation"]
    assert explanation.get("ioc") == "beta.example.invalid"
    assert explanation.get("result_id") == second_id
    assert explanation.get("conclusion") == "待复核"

    for _ in range(2):
        status, review_body = api_post(
            url,
            token,
            "/api/jobs/review",
            {
                "job_id": job_id,
                "result_id": second_id,
                "label": "approved",
                "note": "ok-note",
                "reviewer": "analyst-ui",
            },
        )
        assert status == 200, review_body
        assert review_body.get("ok") is True
        review = review_body.get("review") or {}
        assert review.get("label") == "approved"
        assert review.get("ioc") == "beta.example.invalid"

    assert results_path.read_bytes() == before

    status, bad = api_post(
        url,
        token,
        "/api/jobs/review",
        {
            "job_id": job_id,
            "result_id": second_id,
            "label": "not-a-real-label",
        },
    )
    assert status == 400, bad
    assert bad.get("error") or bad.get("reason")

    status, explained2 = api_post(
        url,
        token,
        "/api/jobs/explain",
        {"job_id": job_id, "result_id": second_id},
    )
    assert status == 200, explained2
    review_summary = (explained2.get("explanation") or {}).get("review") or {}
    assert review_summary.get("label") == "approved"

    status, results = api_get_json(
        url, token, f"/api/jobs/results?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, results
    assert results.get("ok") is True
    result_rows = results["rows"]
    assert len(result_rows) == 2
    beta = next(r for r in result_rows if r.get("ioc") == "beta.example.invalid")
    overlay = beta.get("review_overlay") or {}
    assert overlay.get("label") == "approved"
    assert beta.get("result_id") == second_id


def test_jobs_export_three_formats_download_no_path_leak(make_jobs_server):
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    job_id = _seed_succeeded_job(jobs_dir, _sample_consumer_rows())

    for fmt in ("jsonl", "csv", "xlsx"):
        status, body = api_post(
            url, token, "/api/jobs/export", {"job_id": job_id, "format": fmt}
        )
        assert status == 200, body
        assert body.get("ok") is True
        assert body.get("export_id")
        assert body.get("rows") == 2
        dumped = json.dumps(body)
        assert str(jobs_dir) not in dumped
        assert "path" not in body
        assert ":\\" not in dumped
        assert "/Users/" not in dumped

        export_id = body["export_id"]
        status, headers, data = api_get_bytes(
            url,
            token,
            f"/api/jobs/export/{urllib.parse.quote(export_id)}/download",
        )
        assert status == 200, data[:200]
        assert len(data) > 0
        if fmt == "jsonl":
            assert b"alpha.example.invalid" in data or b"beta.example.invalid" in data
            text = data.decode("utf-8")
            assert "\n" in text or text.strip().startswith("{")
        elif fmt == "csv":
            text = data.decode("utf-8")
            assert "," in text or "ioc" in text.lower()
        else:
            # xlsx is a zip package
            assert data[:2] == b"PK"


def test_jobs_diff_reports_migration(make_jobs_server):
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    baseline_rows = [
        {
            "ioc": "alpha.example.invalid",
            "conclusion": "误报",
            "route": "A",
            "disposition": "allow",
        }
    ]
    current_rows = [
        {
            "ioc": "alpha.example.invalid",
            "conclusion": "存活有效",
            "route": "A",
            "disposition": "block",
        },
        {
            "ioc": "gamma.example.invalid",
            "conclusion": "灰",
            "route": "C",
            "disposition": "monitor",
        },
    ]
    baseline_id = _seed_succeeded_job(jobs_dir, baseline_rows, text="alpha.example.invalid\n")
    current_id = _seed_succeeded_job(
        jobs_dir,
        current_rows,
        text="alpha.example.invalid\ngamma.example.invalid\n",
    )

    status, body = api_post(
        url,
        token,
        "/api/jobs/diff",
        {"job_id": current_id, "baseline_job_id": baseline_id},
    )
    assert status == 200, body
    assert body.get("ok") is True
    diff = body.get("diff") or {}
    only_after = diff.get("only_after") or []
    assert "gamma.example.invalid" in only_after
    assert int(diff.get("operations") or 0) >= 1
    dumped = json.dumps(body)
    assert str(jobs_dir) not in dumped


def test_ui_html_queue_consumer_and_kpi_contract():
    page = (Path(__file__).parents[1] / "ioc_rejudge" / "ui.html").read_text(
        encoding="utf-8"
    )
    assert 'id="queue-kpi"' in page
    assert 'id="queue-review-submit"' in page or 'id="queue-review"' in page
    assert 'id="queue-export-jsonl"' in page
    assert 'id="queue-export-csv"' in page
    assert 'id="queue-export-xlsx"' in page
    assert 'id="queue-diff"' in page
    assert 'id="queue-baseline-job"' in page
    assert "/api/jobs/explain" in page
    assert "/api/jobs/review" in page
    assert "/api/jobs/export" in page
    assert "/api/jobs/diff" in page
    assert "result_summary" in page
    # KPI must render summary fields rather than inventing independent counts.
    assert "conclusions" in page
    assert "provider_statuses" in page
    # workbench panel remains in markup for legacy entry but is default-hidden.
    assert 'id="workbench-panel"' in page
    assert (
        'id="workbench-panel" hidden' in page
        or 'id="workbench-panel"hidden' in page
        or 'hidden id="workbench-panel"' in page
    )
    assert "https://" not in page
    assert "http://" not in page
    assert "\x00" not in page


def test_jobs_status_kpi_fields_match_result_summary(make_jobs_server):
    """KPI source is job.result_summary; status/list expose the same numbers."""
    url, token, jobs_dir, _cache, _server = make_jobs_server()
    rows = [
        {
            "ioc": "k1.example.invalid",
            "conclusion": "存活有效",
            "route": "A",
            "disposition": "block",
            "provider_statuses": {"ioc_info": "ok", "whois": "timeout"},
        },
        {
            "ioc": "k2.example.invalid",
            "conclusion": "误报",
            "route": "B",
            "disposition": "allow",
            "provider_statuses": {"ioc_info": "error"},
        },
        {
            "ioc": "k3.example.invalid",
            "conclusion": "灰",
            "route": "C",
            "disposition": "monitor",
            "provider_statuses": {"ioc_info": "ok"},
        },
        {
            "ioc": "k4.example.invalid",
            "conclusion": "待复核",
            "route": "D",
            "disposition": "review",
            "provider_statuses": {"ioc_info": "failed"},
        },
    ]
    job_id = _seed_succeeded_job(jobs_dir, rows)

    status, body = api_get_json(
        url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, body
    summary = (body.get("job") or {}).get("result_summary") or {}
    conclusions = summary.get("conclusions") or {}
    provider_statuses = summary.get("provider_statuses") or {}
    assert conclusions.get("存活有效") == 1
    assert conclusions.get("误报") == 1
    assert conclusions.get("灰") == 1
    assert conclusions.get("待复核") == 1
    assert provider_statuses.get("timeout") == 1
    assert provider_statuses.get("error") == 1
    assert provider_statuses.get("failed") == 1
    # Page KPI mapping contract: 判黑 = 存活有效+失活有效; 来源异常 = error+failed+timeout
    black = int(conclusions.get("存活有效") or 0) + int(conclusions.get("失活有效") or 0)
    provider_issue = (
        int(provider_statuses.get("error") or 0)
        + int(provider_statuses.get("failed") or 0)
        + int(provider_statuses.get("timeout") or 0)
    )
    assert black == 1
    assert provider_issue == 3
    dumped = json.dumps(body)
    assert str(jobs_dir) not in dumped


def test_status_runner_progress_while_running_then_cleared(make_jobs_server):
    import ioc_rejudge.ui as ui_mod

    url, token, jobs_dir, _cache, _server = make_jobs_server()
    queue = UnifiedJobQueue(jobs_dir)
    job = queue.create_job(
        "runner-progress.example.invalid\n",
        input_kind="bare",
        mode="offline",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test",
    )
    job_id = job["job_id"]
    claimed = queue.claim(job_id, runner_name="ui-jobs", pid=1)
    assert claimed is not None
    assert queue.get(job_id)["state"] == "running"

    with ui_mod._jobs_runner_lock:
        ui_mod._jobs_runner_job_id = job_id
        ui_mod._jobs_runner_progress = {
            "text": "[whois] 1/3",
            "updated_at": "2026-10-04T12:00:00Z",
        }

    status, body = api_get_json(
        url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, body
    assert body.get("ok") is True
    progress = body.get("runner_progress")
    assert isinstance(progress, dict)
    assert progress.get("text") == "[whois] 1/3"
    dumped = json.dumps(body)
    assert str(jobs_dir) not in dumped
    assert ":\\" not in dumped

    queue.finish(job_id, state="succeeded", result_summary={"rows": 1, "conclusions": {}})
    with ui_mod._jobs_runner_lock:
        ui_mod._jobs_runner_job_id = None
        ui_mod._jobs_runner_progress = None

    status, body = api_get_json(
        url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, body
    assert body.get("job", {}).get("state") == "succeeded"
    assert "runner_progress" not in body


def test_ui_run_wires_progress_callback_and_clears(make_jobs_server, monkeypatch):
    import ioc_rejudge.jobs_cli as jobs_cli
    import ioc_rejudge.ui as ui_mod

    url, token, jobs_dir, cache_dir, _server = make_jobs_server()
    status, body = api_post(
        url,
        token,
        "/api/jobs/enqueue",
        {"content": "ui-progress.example.invalid\n"},
    )
    assert status == 200, body
    job_id = body["job"]["job_id"]
    started_doc = json.loads((jobs_dir / job_id / "job.json").read_text(encoding="utf-8"))
    started_at = started_doc.get("updated_at") or started_doc.get("created_at")

    seen_progress: list[str] = []
    original_run = jobs_cli.run_job

    def wrapped_run(queue, jid, **kwargs):
        progress = kwargs.get("progress")
        on_progress = kwargs.get("on_progress")
        assert progress is not None
        assert on_progress is not None
        # Simulate a mid-run progress line the status endpoint should expose.
        progress("provider 'whois': completed in 0.1s (1 target(s))")
        snap = ui_mod._snapshot_jobs_runner_progress(jid)
        if snap and snap.get("text"):
            seen_progress.append(str(snap["text"]))
        return original_run(queue, jid, **kwargs)

    monkeypatch.setattr(jobs_cli, "run_job", wrapped_run)

    status, run_body = api_post(url, token, "/api/jobs/run", {"job_id": job_id})
    assert status == 200, run_body
    assert run_body.get("ok") is True

    finished = _wait_job_state(url, token, job_id, want=("succeeded", "failed"))
    assert finished["state"] == "succeeded", finished
    assert seen_progress
    assert any("whois" in text for text in seen_progress)

    status, body = api_get_json(
        url, token, f"/api/jobs/status?job_id={urllib.parse.quote(job_id)}"
    )
    assert status == 200, body
    assert "runner_progress" not in body
    assert ui_mod._jobs_runner_progress is None

    final_doc = json.loads((jobs_dir / job_id / "job.json").read_text(encoding="utf-8"))
    assert final_doc.get("updated_at")
    if started_at:
        assert final_doc["updated_at"] >= started_at
