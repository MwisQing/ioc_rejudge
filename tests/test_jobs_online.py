"""Online jobs runner, shared result cache, and UI prune/enqueue mode."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

from ioc_rejudge.job_queue import DEFAULT_KEEP, UnifiedJobQueue
from ioc_rejudge.jobs_cli import run_job
from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS, build_providers
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.ui import build_server


ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "JOBS_ONLINE_SECRET_7f3a"

IOC_A = "online-alpha.example.invalid"
IOC_B = "online-beta.example.invalid"
IOC_CACHE = "cache-hit.example.invalid"


class ScriptedTransport:
    def __init__(self, *, get=None, post=None):
        self.get_callback = get
        self.post_callback = post
        self.calls: list[dict] = []
        self.lock = threading.Lock()

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        with self.lock:
            self.calls.append({"method": "GET", "url": url, "params": params})
        if self.get_callback is None:
            raise AssertionError(f"unexpected GET {url}")
        return self.get_callback(url, params)

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        with self.lock:
            self.calls.append({"method": "POST", "url": url, "body": body})
        if self.post_callback is None:
            raise AssertionError(f"unexpected POST {url}")
        return self.post_callback(url, body)


def _empty_ok_post(url, body):
    params = body.get("params") if isinstance(body, dict) else None
    if not isinstance(params, list):
        params = []
    return {"status": 10000, "data": {ioc: {"level": "unknown", "data": []} for ioc in params}}


def _empty_ioc_post(url, body):
    params = body.get("params") if isinstance(body, dict) else None
    if not isinstance(params, list):
        params = []
    return {"data": {ioc: [] for ioc in params}}


def _empty_get(url, params):
    return {"status": "ok", "data": [], "total": 0, "code": 200, "resultObject": {}}


def _canned_transports() -> dict[str, ScriptedTransport]:
    return {
        "k01_compromise": ScriptedTransport(post=_empty_ok_post),
        "ioc_info": ScriptedTransport(post=_empty_ioc_post),
        "fdark": ScriptedTransport(get=_empty_get),
        "whois": ScriptedTransport(get=_empty_get),
        "pdns": ScriptedTransport(get=_empty_get),
        "icp": ScriptedTransport(get=_empty_get),
    }


def _set_sentinel_credentials(monkeypatch) -> None:
    values = {
        "IOC_INFO_API_KEY": f"{SENTINEL}-ioc",
        "IOC_INFO_URL": "https://ioc-info.invalid/api/v1/ioc/info",
        "K01_COMPROMISE_API_KEY": f"{SENTINEL}-k01",
        "K01_COMPROMISE_URL": "https://k01.invalid",
        "FDP_ACCESS": f"{SENTINEL}-fdp-access",
        "FDP_SECRET": f"{SENTINEL}-fdp-secret",
        "FDARK_URL": "https://fdark.invalid/api/v1/fdark/abstract",
        "WHOIS_ACCESS": f"{SENTINEL}-whois-access",
        "WHOIS_SECRET": f"{SENTINEL}-whois-secret",
        "WHOIS_URL": "https://whois.invalid/v3/whois/detail",
        "PDNS_ACCESS": f"{SENTINEL}-pdns-access",
        "PDNS_SECRET": f"{SENTINEL}-pdns-secret",
        "PDNS_URL": "https://pdns.invalid/api/v1/passivedns/flint/rrset",
        "ICP_UC": f"{SENTINEL}-icp-uc",
        "ICP_KEY": f"{SENTINEL}-icp-key",
        "ICP_URL": "https://icp.invalid/v2/open-api/icp-info",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _clear_credentials(monkeypatch) -> None:
    for name in (
        "IOC_INFO_API_KEY",
        "K01_COMPROMISE_API_KEY",
        "FDP_ACCESS",
        "FDP_SECRET",
        "WHOIS_ACCESS",
        "WHOIS_SECRET",
        "PDNS_ACCESS",
        "PDNS_SECRET",
        "ICP_UC",
        "ICP_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def _forbid_real_network(monkeypatch) -> None:
    def forbid(*_a, **_k):
        raise AssertionError("real network access is forbidden in jobs online tests")

    monkeypatch.setattr(requests.Session, "get", forbid)
    monkeypatch.setattr(requests.Session, "post", forbid)


def _patch_build_providers_transport(monkeypatch, transports) -> None:
    original = build_providers

    def wrapped(*args, **kwargs):
        kwargs = dict(kwargs)
        kwargs["transport_factory"] = transports
        return original(*args, **kwargs)

    monkeypatch.setattr(
        "ioc_rejudge.providers.factory.build_providers", wrapped
    )


def _scan_for_sentinel(root: Path) -> list[str]:
    hits: list[str] = []
    if not root.exists():
        return hits
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SENTINEL in text:
            hits.append(str(path))
    return hits


def _queue(tmp_path: Path) -> UnifiedJobQueue:
    return UnifiedJobQueue(tmp_path / "jobs")


def test_online_run_with_injected_transport_and_sentinel_zero_match(
    tmp_path, monkeypatch
):
    _forbid_real_network(monkeypatch)
    _set_sentinel_credentials(monkeypatch)
    transports = _canned_transports()
    _patch_build_providers_transport(monkeypatch, transports)

    queue = _queue(tmp_path)
    cache_dir = tmp_path / "provider-cache"
    run_dir = tmp_path / "run-audit"
    cache_dir.mkdir()
    job = queue.create_job(
        f"{IOC_A}\n{IOC_B}\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test",
    )
    result = run_job(
        queue,
        job["job_id"],
        cache_dir=cache_dir,
        runner_name="test-online",
        pid=os.getpid(),
        credentials_path=None,
        run_dir=run_dir,
    )
    assert result.get("ok") is True, result
    assert result.get("state") == "succeeded"

    job_dir = queue.root / job["job_id"]
    rows = [
        json.loads(line)
        for line in (job_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 2
    assert all(row.get("conclusion") is not None for row in rows)

    hits = _scan_for_sentinel(queue.root)
    assert hits == [], f"sentinel leaked into jobs files: {hits}"
    if run_dir.exists():
        audit_hits = _scan_for_sentinel(run_dir)
        assert audit_hits == [], f"sentinel leaked into run audit: {audit_hits}"


def test_online_without_credentials_completes_all_disabled(tmp_path, monkeypatch):
    _forbid_real_network(monkeypatch)
    _clear_credentials(monkeypatch)

    queue = _queue(tmp_path)
    cache_dir = tmp_path / "provider-cache"
    cache_dir.mkdir()
    job = queue.create_job(
        f"{IOC_A}\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test",
    )
    result = run_job(
        queue,
        job["job_id"],
        cache_dir=cache_dir,
        runner_name="test-online-no-cred",
        pid=os.getpid(),
        credentials_path=None,
    )
    assert result.get("ok") is True, result
    assert result.get("state") == "succeeded"

    job_dir = queue.root / job["job_id"]
    rows = [
        json.loads(line)
        for line in (job_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    statuses = rows[0].get("provider_statuses") or {}
    assert statuses, rows[0]
    assert all(str(v) == "disabled" for v in statuses.values()), statuses


def _extend_result_cache_valid_until(cache_dir: Path, *, days: int = 7) -> None:
    """Stretch valid_until so a second run in the same test can hit the cache."""
    root = cache_dir / ".cache_adjudication_results"
    if not root.is_dir():
        return
    bound = (datetime.now(timezone.utc) + timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )
    for path in root.glob("cache_*.jsonl"):
        lines: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            row["valid_until"] = bound
            lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_bare_result_cache_second_run_hits(tmp_path, monkeypatch):
    """Shared AdjudicationResultCache: seed via first bare run, second job hits."""
    _forbid_real_network(monkeypatch)
    _set_sentinel_credentials(monkeypatch)
    transports = _canned_transports()
    _patch_build_providers_transport(monkeypatch, transports)

    queue = _queue(tmp_path)
    cache_dir = tmp_path / "provider-cache"
    cache_dir.mkdir()

    first = queue.create_job(
        f"{IOC_CACHE}\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test-1",
    )
    r1 = run_job(
        queue,
        first["job_id"],
        cache_dir=cache_dir,
        runner_name="test-cache-1",
        pid=os.getpid(),
    )
    assert r1.get("ok") is True, r1
    rows1 = [
        json.loads(line)
        for line in (queue.root / first["job_id"] / "results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert rows1 and rows1[0].get("conclusion") is not None
    shards = list((cache_dir / ".cache_adjudication_results").glob("cache_*.jsonl"))
    assert shards, "first run must populate adjudication result cache"
    # Empty-intel rows get a near-immediate valid_until; stretch for the hit check.
    _extend_result_cache_valid_until(cache_dir)

    call_counts_before = {
        name: len(t.calls) for name, t in transports.items()
    }

    second = queue.create_job(
        f"{IOC_CACHE}\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="test-2",
    )
    r2 = run_job(
        queue,
        second["job_id"],
        cache_dir=cache_dir,
        runner_name="test-cache-2",
        pid=os.getpid(),
    )
    assert r2.get("ok") is True, r2
    diag2 = json.loads(
        (queue.root / second["job_id"] / "diagnostics.json").read_text(encoding="utf-8")
    )
    rows2 = [
        json.loads(line)
        for line in (queue.root / second["job_id"] / "results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert diag2.get("result_cache_hit", 0) >= 1, diag2
    assert rows2[0].get("conclusion") == rows1[0].get("conclusion")
    # Provider network calls should not grow on a full result-cache hit.
    for name, transport in transports.items():
        assert len(transport.calls) == call_counts_before[name], name


def test_preset_refresh_bypasses_result_cache(tmp_path, monkeypatch):
    _forbid_real_network(monkeypatch)
    _clear_credentials(monkeypatch)

    queue = _queue(tmp_path)
    cache_dir = tmp_path / "provider-cache"
    cache_dir.mkdir()

    seed = queue.create_job(
        f"{IOC_CACHE}\n",
        input_kind="bare",
        mode="offline",
        providers=list(DEFAULT_PROVIDERS),
        preset="standard",
        source="seed",
    )
    assert run_job(
        queue, seed["job_id"], cache_dir=cache_dir, runner_name="seed", pid=os.getpid()
    ).get("ok") is True

    # online + refresh: result cache bypass (same as CLI --refresh)
    _set_sentinel_credentials(monkeypatch)
    transports = _canned_transports()
    _patch_build_providers_transport(monkeypatch, transports)
    refreshed = queue.create_job(
        f"{IOC_CACHE}\n",
        input_kind="bare",
        mode="online",
        providers=list(DEFAULT_PROVIDERS),
        preset="refresh",
        source="refresh",
    )
    r = run_job(
        queue,
        refreshed["job_id"],
        cache_dir=cache_dir,
        runner_name="refresh-run",
        pid=os.getpid(),
        credentials_path=None,
    )
    assert r.get("ok") is True, r
    diag = json.loads(
        (queue.root / refreshed["job_id"] / "diagnostics.json").read_text(
            encoding="utf-8"
        )
    )
    assert diag.get("result_cache_hit", 0) == 0, diag


def test_offline_refresh_fails_fast(tmp_path, monkeypatch):
    _forbid_real_network(monkeypatch)
    _clear_credentials(monkeypatch)
    queue = _queue(tmp_path)
    cache_dir = tmp_path / "provider-cache"
    cache_dir.mkdir()
    job = queue.create_job(
        f"{IOC_A}\n",
        input_kind="bare",
        mode="offline",
        providers=list(DEFAULT_PROVIDERS),
        preset="refresh",
        source="bad",
    )
    result = run_job(
        queue,
        job["job_id"],
        cache_dir=cache_dir,
        runner_name="offline-refresh",
        pid=os.getpid(),
    )
    assert result.get("ok") is False
    assert result.get("state") == "failed"
    err = str(result.get("error") or "").lower()
    assert "offline" in err and "refresh" in err


# --- UI API: enqueue mode + prune -------------------------------------------


class NetworkSentinelSession:
    def __init__(self, *args, **kwargs):
        raise AssertionError("network Session must not be created during UI jobs tests")


class NetworkSentinelTransport:
    def post_json(self, url, *, headers=None, body=None, timeout=30):
        raise AssertionError(f"network transport must not be called: {url}")

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        raise AssertionError(f"network transport must not be called: {url}")


@pytest.fixture()
def make_online_ui(tmp_path, monkeypatch):
    servers = []

    def _make(*, jobs_dir=None, cache_dir=None, credentials_path=None):
        monkeypatch.setattr(
            "ioc_rejudge.providers.transport.requests.Session",
            NetworkSentinelSession,
        )
        monkeypatch.setattr("requests.Session", NetworkSentinelSession)
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        resolved_jobs = jobs_dir if jobs_dir is not None else (tmp_path / "jobs-ui")
        resolved_cache = (
            cache_dir if cache_dir is not None else (tmp_path / "provider-cache-ui")
        )
        resolved_jobs.mkdir(parents=True, exist_ok=True)
        resolved_cache.mkdir(parents=True, exist_ok=True)
        server, url = build_server(
            key_path,
            bundles_dir,
            port=0,
            cache_dir=resolved_cache,
            provider_env={},
            credentials_path=credentials_path,
            transport_factory=lambda _name: NetworkSentinelTransport(),
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


def _api_post(url, token, path, payload, timeout=30):
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


def test_ui_enqueue_mode_online_and_invalid(make_online_ui):
    url, token, _jobs, _cache, _server = make_online_ui()
    status, body = _api_post(
        url,
        token,
        "/api/jobs/enqueue",
        {"content": f"{IOC_A}\n", "mode": "online"},
    )
    assert status == 200, body
    assert body.get("ok") is True
    assert body["job"]["mode"] == "online"
    assert body["job"]["state"] == "queued"

    status_bad, body_bad = _api_post(
        url,
        token,
        "/api/jobs/enqueue",
        {"content": f"{IOC_A}\n", "mode": "live"},
    )
    assert status_bad in {400, 422}
    assert body_bad.get("ok") is not True
    assert "error" in body_bad


def test_ui_prune_dry_run_and_apply_skips_running(make_online_ui, tmp_path):
    url, token, jobs_dir, _cache, _server = make_online_ui()
    queue = UnifiedJobQueue(jobs_dir)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ids: list[str] = []
    for i in range(3):
        job = queue.create_job(
            f"n{i}.example.invalid\n",
            input_kind="bare",
            mode="offline",
            providers=["ioc_info"],
            preset="standard",
            source=f"n{i}",
        )
        path = queue.root / job["job_id"] / "job.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        stamp = (base + timedelta(seconds=i)).isoformat()
        doc["created_at"] = stamp
        doc["updated_at"] = stamp
        doc["state"] = "succeeded"
        path.write_text(
            json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        ids.append(job["job_id"])

    # Oldest would fall outside keep=2, but mark it running → must be retained.
    running_path = queue.root / ids[0] / "job.json"
    running_doc = json.loads(running_path.read_text(encoding="utf-8"))
    running_doc["state"] = "running"
    running_doc["runner"] = {
        "pid": 1,
        "name": "hold",
        "started_at": base.isoformat(),
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
    }
    running_path.write_text(
        json.dumps(running_doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    status, dry = _api_post(url, token, "/api/jobs/prune", {"keep": 2})
    assert status == 200, dry
    assert dry.get("ok") is True
    assert dry.get("dry_run") is True
    # Only terminal overflow candidates; running oldest is protected.
    assert ids[0] not in (dry.get("removed") or [])
    assert dry.get("kept") >= 2

    status, applied = _api_post(
        url, token, "/api/jobs/prune", {"keep": 2, "apply": True}
    )
    assert status == 200, applied
    assert applied.get("ok") is True
    assert applied.get("dry_run") is False
    assert ids[0] not in (applied.get("removed") or [])
    assert (queue.root / ids[0]).is_dir()
    assert "kept" in applied
    assert "removed" in applied
    assert "freed_bytes" in applied
    # running + newest within keep window remain; at least the protected running stays
    remaining = [
        p.name
        for p in queue.root.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    ]
    assert ids[0] in remaining
    assert len(remaining) >= 2


def test_ui_html_exposes_mode_creds_and_prune_controls():
    page = (ROOT / "ioc_rejudge" / "ui.html").read_text(encoding="utf-8")
    assert 'name="queue-mode"' in page or "queue-mode" in page
    assert "online" in page
    assert "offline" in page
    assert "queue-prune" in page or "/api/jobs/prune" in page
    assert "ioc_info_enabled" in page or "凭据" in page
    assert "online 后续提供" not in page
