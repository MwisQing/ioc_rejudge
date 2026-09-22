"""End-to-end tests for the local share assistant UI server.

Each test starts a real loopback HTTP server on an ephemeral port and talks
to it with urllib/http.client, exactly like the browser page does.
"""

import http.client
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ioc_rejudge import share as share_module
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.ui import LOOKUP_READ_TIMEOUT_SECONDS, build_server, resolve_ui_credentials_path

PASSPHRASE = "test-passphrase"
SHORT_PASSPHRASE = "short"
LOOKUP_IOC = "lookup.example.invalid"
LOOKUP_RESPONSE = {
    "data": {
        LOOKUP_IOC: [
            {
                "comment": "sandbox",
                "url": "https://lookup.example.invalid/a",
            }
        ]
    }
}


class CountingFakeTransport:
    """Injected IOC Info transport that records post_json calls."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self._index = 0

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "body": body,
                "timeout": timeout,
            }
        )
        if self._index >= len(self.responses):
            raise AssertionError("FakeTransport has no remaining responses")
        value = self.responses[self._index]
        self._index += 1
        if isinstance(value, Exception):
            raise value
        return value


def sample_row():
    return {
        "ioc": "evil.example.invalid",
        "data": [
            {
                "url": "https://alice:secret-password@evil.example.invalid/login?token=secret-value",
                "ip": "10.8.8.8",
                "md5": "0123456789abcdef0123456789abcdef",
                "submitter": "张三",
                "comment": "evil.example.invalid contacted 10.8.8.8",
                "api_token": "secret-value",
            }
        ],
    }


def sample_content():
    return json.dumps(sample_row(), ensure_ascii=False) + "\n"


@pytest.fixture()
def make_server(tmp_path):
    servers = []

    def _make(
        max_bundles=20,
        port=0,
        cache_dir=None,
        provider_env=None,
        transport_factory=None,
        credentials_path=None,
    ):
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        resolved_cache = cache_dir if cache_dir is not None else (tmp_path / "provider-cache")
        server, url = build_server(
            key_path,
            bundles_dir,
            port=port,
            max_bundles=max_bundles,
            cache_dir=resolved_cache,
            provider_env=provider_env if provider_env is not None else {},
            transport_factory=transport_factory,
            credentials_path=credentials_path,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        base, _, token = url.partition("/?token=")
        return base, token, key_path, bundles_dir

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def ui(make_server):
    return make_server()


def _lookup_server(make_server, tmp_path, transport, *, provider_env=None):
    cache_dir = tmp_path / "lookup-cache"
    env = (
        {"IOC_INFO_API_KEY": "test-ioc-info-key"}
        if provider_env is None
        else provider_env
    )
    return make_server(
        cache_dir=cache_dir,
        provider_env=env,
        transport_factory=lambda _name: transport,
    )


def api_post(url, token, path, payload, headers=None, timeout=10):
    request = urllib.request.Request(
        url + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    request.add_header("Authorization", "Bearer " + token)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def api_get(url, token, path="/"):
    request = urllib.request.Request(url + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def raw_post(url, path, *, host=None, origin=None, token=None):
    """Low-level POST that can forge Host/Origin exactly as an attacker would."""
    parsed = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    headers = {}
    if host is not None:
        headers["Host"] = host
    if origin is not None:
        headers["Origin"] = origin
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    connection.request("POST", path, body=b"{}", headers=headers)
    response = connection.getresponse()
    status = response.status
    response.read()
    connection.close()
    return status


def unlock(url, token):
    status, body = api_post(url, token, "/api/key", {"passphrase": PASSPHRASE, "generate": True})
    assert status == 200, body
    return body["key_id"]


def create(url, token, payload):
    status, body = api_post(url, token, "/api/create", payload)
    assert status == 200, body
    return body


def cloud_response_rows(text, bundle_id):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row["bundle_id"] = bundle_id
        row["ai_note"] = "reviewed by cloud model"
        rows.append(json.dumps(row, ensure_ascii=False))
    return "\n".join(rows) + "\n"


def test_api_requires_session_token(ui):
    url, _token, _key, _bundles = ui
    status, body = api_post(url, "wrong-token-value", "/api/status", {})
    assert status == 403
    assert body["error"] == "forbidden"

    parsed = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    connection.request("POST", "/api/status", body=b"{}")
    response = connection.getresponse()
    assert response.status == 403
    response.read()
    connection.close()


def test_get_page_requires_session_token(ui):
    url, token, _key, _bundles = ui
    status, _headers, _body = api_get(url, "not-the-token")
    assert status == 403


def test_rejects_foreign_host_and_origin(ui):
    url, token, _key, _bundles = ui
    assert raw_post(url, "/api/status", host="evil.example", token=token) == 403
    assert raw_post(url, "/api/status", host="127.0.0.1:9999", token=token) == 403
    assert (
        raw_post(
            url,
            "/api/status",
            host=f"127.0.0.1:{urllib.parse.urlsplit(url).port}",
            origin="http://evil.example",
            token=token,
        )
        == 403
    )
    assert raw_post(url, "/api/status", token=token) == 200


def test_get_serves_single_file_page(ui):
    url, token, _key, _bundles = ui
    status, headers, body = api_get(url, token)
    assert status == 200
    assert headers.get("Content-Type") == "text/html; charset=utf-8"
    assert headers.get("Cache-Control") == "no-store"
    text = body.decode("utf-8")
    assert text.lstrip().lower().startswith("<!doctype html>")
    assert "至少 12 个字符" not in text
    assert "本机 key 同目录" in text
    assert "脱敏并复制" in text
    assert "全部展开" in text
    assert "全部合拢" in text
    assert "明文" in text
    assert "勿发给云端" in text
    assert "credentials.local.json" in text
    assert "IOC_INFO_API_KEY" in text
    assert "function renderJsonlViewer" in text or "function renderTree" in text
    assert "function withBusy" in text
    assert "AbortController" in text
    assert 'id="lock-btn"' in text
    assert 'id="lock-flash"' in text
    assert "async function doLock" in text
    assert "已清除本机记住的口令" in text
    assert "当前未解锁，也没有本机记住的口令" in text
    # The page must be fully self-contained: no external references at all.
    assert 'src="http' not in text
    assert "https://cdn" not in text.lower()
    for attribute in re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', text):
        assert attribute == "" or attribute.startswith("#")


def test_key_lifecycle_generate_unlock_lock(ui):
    url, token, key_path, _bundles = ui
    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    assert body["key_exists"] is False
    assert body["unlocked"] is False
    assert body["passphrase_saved"] is False
    assert body["ioc_info_enabled"] is False
    assert body["bundles"] == []

    status, body = api_post(url, token, "/api/lock", {})
    assert status == 200
    assert body["unlocked"] is False
    assert body["was_unlocked"] is False
    assert body["had_saved_passphrase"] is False
    assert body["passphrase_cleared"] is False

    first_key_id = unlock(url, token)
    status, body = api_post(url, token, "/api/status", {})
    assert body["unlocked"] is True
    assert body["key_id"] == first_key_id
    assert body["key_exists"] is True
    assert body["passphrase_saved"] is True
    assert (key_path.parent / "passphrase").is_file()

    status, body = api_post(url, token, "/api/key", {"passphrase": PASSPHRASE, "generate": True})
    assert status == 400
    assert "already exists" in body["error"]

    status, body = api_post(
        url,
        token,
        "/api/key",
        {"passphrase": PASSPHRASE, "generate": True, "force": True},
    )
    assert status == 200
    assert body["key_id"] != first_key_id

    status, body = api_post(url, token, "/api/lock", {})
    assert status == 200
    assert body["unlocked"] is False
    assert body["was_unlocked"] is True
    assert body["had_saved_passphrase"] is True
    assert body["passphrase_cleared"] is True
    status, body = api_post(url, token, "/api/status", {})
    assert body["unlocked"] is False
    assert body["key_id"] is None
    assert body["passphrase_saved"] is False
    assert not (key_path.parent / "passphrase").exists()

    status, body = api_post(url, token, "/api/lock", {})
    assert status == 200
    assert body["unlocked"] is False
    assert body["was_unlocked"] is False
    assert body["had_saved_passphrase"] is False
    assert body["passphrase_cleared"] is False

    status, body = api_post(url, token, "/api/create", {"content": sample_content()})
    assert status == 400
    assert "locked" in body["error"]

    status, body = api_post(url, token, "/api/key", {"passphrase": "wrong-passphrase"})
    assert status == 400
    assert "incorrect" in body["error"]


def test_empty_passphrase_rejected(ui):
    url, token, _key, _bundles = ui
    status, body = api_post(url, token, "/api/key", {"passphrase": "", "generate": True})
    assert status == 400
    assert "passphrase is required" in body["error"]
    status, body = api_post(url, token, "/api/key", {"generate": True})
    assert status == 400
    assert "passphrase is required" in body["error"]


def test_short_passphrase_persists_and_auto_unlocks(make_server):
    url, token, key_path, bundles_dir = make_server()
    status, body = api_post(
        url,
        token,
        "/api/key",
        {"passphrase": SHORT_PASSPHRASE, "generate": True},
    )
    assert status == 200, body
    first_key_id = body["key_id"]
    passphrase_file = key_path.parent / "passphrase"
    assert passphrase_file.is_file()
    assert passphrase_file.read_text(encoding="utf-8") == SHORT_PASSPHRASE
    # POSIX mode bits are meaningful; Windows chmod is best-effort only.
    if os.name != "nt":
        assert passphrase_file.stat().st_mode & 0o077 == 0

    status, body = api_post(url, token, "/api/status", {})
    assert body["unlocked"] is True
    assert body["passphrase_saved"] is True
    assert body["key_id"] == first_key_id

    url2, token2, key_path2, bundles_dir2 = make_server()
    assert key_path2 == key_path
    assert bundles_dir2 == bundles_dir
    status, body = api_post(url2, token2, "/api/status", {})
    assert status == 200
    assert body["unlocked"] is True
    assert body["key_id"] == first_key_id
    assert body["passphrase_saved"] is True

    status, body = api_post(url2, token2, "/api/lock", {})
    assert status == 200
    assert body["unlocked"] is False
    assert not passphrase_file.exists()

    url3, token3, _key3, _bundles3 = make_server()
    status, body = api_post(url3, token3, "/api/status", {})
    assert status == 200
    assert body["unlocked"] is False
    assert body["passphrase_saved"] is False
    assert body["key_id"] is None
    assert not passphrase_file.exists()


def test_create_scan_restore_cloud_response_roundtrip(ui):
    url, token, key_path, bundles_dir = ui
    unlock(url, token)

    created = create(url, token, {"content": sample_content()})
    assert created["rows"] == 1
    assert created["source_findings"] >= 1
    assert "evil.example.invalid" not in created["text"]
    assert "10.8.8.8" not in created["text"]
    assert "ss1:" in created["text"]
    assert "[REDACTED]" in created["text"]

    bundle_dir = bundles_dir / created["bundle_id"]
    assert (bundle_dir / "share.jsonl").is_file()
    assert (bundle_dir / "share.jsonl.manifest.json").is_file()
    assert list(bundle_dir.glob("input-*.jsonl"))

    status, body = api_post(url, token, "/api/status", {})
    assert [item["bundle_id"] for item in body["bundles"]] == [created["bundle_id"]]

    status, body = api_post(url, token, "/api/scan", {"content": created["text"]})
    assert status == 200
    assert body["rows"] == 1
    assert body["finding_count"] == 0

    cloud = cloud_response_rows(created["text"], created["bundle_id"])
    status, body = api_post(url, token, "/api/restore", {"content": cloud})
    assert status == 200, body
    assert body["rows"] == 1
    assert body["matched_bundle_id"] == created["bundle_id"]
    assert "evil.example.invalid" in body["text"]
    assert "10.8.8.8" in body["text"]
    assert "张三" in body["text"]
    # Credential-like values stay permanently redacted even after restore.
    assert "secret-value" not in body["text"]
    assert "secret-password" not in body["text"]
    restored_dir_files = list(bundle_dir.glob("restored-*.jsonl"))
    assert restored_dir_files
    assert list(bundle_dir.glob("cloud-*.jsonl"))


def test_restore_exact_replay_matches_by_sha256(ui):
    url, token, _key, bundles_dir = ui
    unlock(url, token)
    created = create(url, token, {"content": sample_content()})

    status, body = api_post(url, token, "/api/restore", {"content": created["text"]})
    assert status == 200, body
    assert body["matched_bundle_id"] == created["bundle_id"]
    assert "evil.example.invalid" in body["text"]


def test_restore_without_matching_bundle_fails(ui):
    url, token, _key, _bundles = ui
    unlock(url, token)
    status, body = api_post(url, token, "/api/restore", {"content": '{"hello": "world"}\n'})
    assert status == 400
    assert "no matching local bundle" in body["error"]


def test_create_with_input_path_and_names_file(ui, tmp_path):
    url, token, _key, _bundles = ui
    unlock(url, token)
    source = tmp_path / "source.jsonl"
    source.write_text(sample_content(), encoding="utf-8")
    names = tmp_path / "names.txt"
    names.write_text("张三\n", encoding="utf-8")

    created = create(url, token, {"input_path": str(source), "names_path": str(names)})
    assert created["rows"] == 1
    assert "张三" not in created["text"]

    status, _body = api_post(url, token, "/api/scan", {"content": created["text"]})
    assert status == 200


def test_create_requires_content_or_input_path(ui):
    url, token, _key, _bundles = ui
    unlock(url, token)
    status, body = api_post(url, token, "/api/create", {})
    assert status == 400
    assert "content or input_path is required" in body["error"]


def test_strict_failure_propagates_and_cleans_staging(ui, monkeypatch):
    url, token, _key, bundles_dir = ui
    unlock(url, token)

    def fake_scan_value(value):
        return [{"code": "domain", "path": "ioc"}]

    monkeypatch.setattr(share_module, "scan_value", fake_scan_value)
    status, body = api_post(url, token, "/api/create", {"content": sample_content()})
    assert status == 400
    assert "sensitive finding" in body["error"]
    assert not [
        child for child in bundles_dir.iterdir() if re.fullmatch(r"[0-9a-f]{20}", child.name)
    ]
    assert not [child for child in bundles_dir.iterdir() if child.name.startswith(".staging-")]


def test_bundle_retention_keeps_only_newest(make_server):
    """max_bundles limits recent-history display; older bundles stay recoverable."""
    url, token, _key, bundles_dir = make_server(max_bundles=2)
    unlock(url, token)
    first = create(url, token, {"content": sample_content()})
    second = create(url, token, {"content": '{"ioc": "second.example.invalid"}\n'})
    third = create(url, token, {"content": '{"ioc": "third.example.invalid"}\n'})

    remaining = {
        child.name
        for child in bundles_dir.iterdir()
        if child.is_dir() and not child.name.startswith(".")
    }
    assert remaining == {first["bundle_id"], second["bundle_id"], third["bundle_id"]}
    assert (bundles_dir / first["bundle_id"] / "share.jsonl.manifest.json").is_file()

    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    listed = [item["bundle_id"] for item in body["bundles"]]
    assert listed == [third["bundle_id"], second["bundle_id"]]
    assert body["bundle_history_limit"] == 2
    assert body["bundle_total"] == 3


def test_scan_reports_residual_findings(ui):
    url, token, _key, _bundles = ui
    status, body = api_post(url, token, "/api/scan", {"content": sample_content()})
    assert status == 200
    assert body["finding_count"] >= 1
    assert "domain" in body["finding_counts"]


def test_unknown_api_endpoint_returns_404(ui):
    url, token, _key, _bundles = ui
    status, body = api_post(url, token, "/api/unknown", {})
    assert status == 404
    assert body["error"] == "unknown api endpoint"


def test_occupied_port_falls_back_to_ephemeral(make_server):
    first_url, _token, _key, _bundles = make_server()
    taken_port = urllib.parse.urlsplit(first_url).port
    fallback_url, _second_token, _key2, _bundles2 = make_server(port=taken_port)
    fallback_port = urllib.parse.urlsplit(fallback_url).port
    # Address reuse is refused so two UI servers can never share one port.
    assert fallback_port != taken_port


def test_lookup_cache_miss_then_hit(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)

    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["live_fetches"] == 1
    assert body["cache_hits"] == 0
    assert body["rows"] == 1
    assert len(transport.calls) == 1
    assert transport.calls[0]["timeout"] == LOOKUP_READ_TIMEOUT_SECONDS
    first_row = json.loads(body["text"].splitlines()[0])
    assert first_row["ioc"] == LOOKUP_IOC
    assert first_row["source"] == "live"
    assert first_row["status"] == "success"
    assert first_row["data"]
    assert first_row["data"][0]["comment"] == "sandbox"

    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["cache_hits"] == 1
    assert body["live_fetches"] == 0
    assert len(transport.calls) == 1
    second_row = json.loads(body["text"].splitlines()[0])
    assert second_row["source"] == "cache"
    assert second_row["status"] == "success"


def test_lookup_empty_live_result_does_not_retry(make_server, tmp_path):
    transport = CountingFakeTransport([{"data": {LOOKUP_IOC: []}}])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)
    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert len(transport.calls) == 1
    row = json.loads(body["text"].splitlines()[0])
    assert row["status"] == "no_data"
    assert row["source"] == "live"


def test_lookup_does_not_require_unlock(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)

    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    assert body["unlocked"] is False

    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["live_fetches"] == 1
    assert body["rows"] == 1


def test_resolve_ui_credentials_path_prefers_explicit_then_local_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_ui_credentials_path(None) is None
    local = tmp_path / "credentials.local.json"
    local.write_text("{}", encoding="utf-8")
    assert resolve_ui_credentials_path(None).resolve() == local.resolve()
    explicit = tmp_path / "other.json"
    assert resolve_ui_credentials_path(str(explicit)) == explicit


def test_status_reports_ioc_info_enabled_with_injected_key(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)
    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    assert body["ioc_info_enabled"] is True


def test_lookup_disabled_without_credentials(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(
        make_server,
        tmp_path,
        transport,
        provider_env={},
    )

    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 400, body
    assert "disabled" in body["error"].lower() or "credential" in body["error"].lower()
    assert len(transport.calls) == 0


def test_lookup_cache_hit_without_credentials(make_server, tmp_path):
    warm = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, warm)
    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["live_fetches"] == 1
    assert len(warm.calls) == 1

    cold = CountingFakeTransport([LOOKUP_RESPONSE])
    url2, token2, _key2, _bundles2 = _lookup_server(
        make_server,
        tmp_path,
        cold,
        provider_env={},
    )
    status, body = api_post(
        url2,
        token2,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["cache_hits"] == 1
    assert body["live_fetches"] == 0
    assert len(cold.calls) == 0
    row = json.loads(body["text"].splitlines()[0])
    assert row["source"] == "cache"
    assert row["status"] == "success"


def test_lookup_rejected_invalid_line(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)

    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\nnot a valid!!!\n"},
    )
    assert status == 200, body
    assert body["rejected"] >= 1
    assert body["live_fetches"] == 1
    assert len(transport.calls) == 1
    rows = [json.loads(line) for line in body["text"].splitlines() if line.strip()]
    assert any(row.get("status") == "error" and row.get("source") == "none" for row in rows)
    assert any(row.get("ioc") == LOOKUP_IOC and row.get("status") == "success" for row in rows)


def test_lookup_jsonl_can_create(make_server, tmp_path):
    transport = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)

    unlock(url, token)
    status, lookup_body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, lookup_body
    assert lookup_body["text"].strip()

    status, create_body = api_post(
        url,
        token,
        "/api/create",
        {"content": lookup_body["text"]},
    )
    assert status == 200, create_body
    assert create_body["rows"] >= 1
    assert create_body["bundle_id"]
    assert "ss1:" in create_body["text"]

    # Page copy for the lookup -> sanitize/copy workflow must stay present.
    page_status, _headers, page_body = api_get(url, token)
    assert page_status == 200
    page_text = page_body.decode("utf-8")
    assert "脱敏并复制" in page_text
    assert "勿发给云端" in page_text
    assert "不要只刷新网页" in page_text


def _age_ioc_info_cache(cache_dir, *, days=10):
    root = Path(cache_dir) / ".cache_ioc_info"
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    for path in root.glob("*.jsonl"):
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            row["fetched_at"] = old
            rows.append(json.dumps(row, ensure_ascii=False))
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_lookup_falls_back_to_stale_cache_when_live_fails(make_server, tmp_path):
    warm = CountingFakeTransport([LOOKUP_RESPONSE])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, warm)
    status, body = api_post(
        url,
        token,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert body["live_fetches"] == 1
    _age_ioc_info_cache(tmp_path / "lookup-cache")

    cold = CountingFakeTransport(
        [TransportError("timeout", "Request timed out for lookup")]
    )
    url2, token2, _key2, _bundles2 = _lookup_server(make_server, tmp_path, cold)
    status, body = api_post(
        url2,
        token2,
        "/api/lookup",
        {"content": LOOKUP_IOC + "\n"},
    )
    assert status == 200, body
    assert len(cold.calls) == 1
    row = json.loads(body["text"].splitlines()[0])
    assert row["source"] == "cache"
    assert row["status"] == "success"
    assert row["data"]


def test_lookup_does_not_block_status(make_server, tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class BlockingTransport(CountingFakeTransport):
        def post_json(self, url, *, headers=None, body=None, timeout=30):
            self.calls.append({"url": url, "timeout": timeout})
            entered.set()
            assert release.wait(timeout=5)
            return LOOKUP_RESPONSE

    transport = BlockingTransport([])
    url, token, _key, _bundles = _lookup_server(make_server, tmp_path, transport)
    result = {}

    def _lookup():
        result["lookup"] = api_post(
            url,
            token,
            "/api/lookup",
            {"content": LOOKUP_IOC + "\n"},
            timeout=8,
        )

    worker = threading.Thread(target=_lookup)
    worker.start()
    assert entered.wait(timeout=5)
    status, body = api_post(url, token, "/api/status", {}, timeout=2)
    assert status == 200, body
    assert "unlocked" in body
    release.set()
    worker.join(timeout=8)
    assert result.get("lookup") is not None
    lookup_status, lookup_body = result["lookup"]
    assert lookup_status == 200, lookup_body
