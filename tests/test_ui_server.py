"""End-to-end tests for the local share assistant UI server.

Each test starts a real loopback HTTP server on an ephemeral port and talks
to it with urllib/http.client, exactly like the browser page does.
"""

import http.client
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from ioc_rejudge import share as share_module
from ioc_rejudge.ui import build_server

PASSPHRASE = "test-passphrase"


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

    def _make(max_bundles=20, port=0):
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        server, url = build_server(key_path, bundles_dir, port=port, max_bundles=max_bundles)
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


def api_post(url, token, path, payload, headers=None):
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
        with urllib.request.urlopen(request, timeout=10) as response:
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
    # The page must be fully self-contained: no external references at all.
    for attribute in re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', text):
        assert attribute == "" or attribute.startswith("#")


def test_key_lifecycle_generate_unlock_lock(ui):
    url, token, key_path, _bundles = ui
    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    assert body["key_exists"] is False
    assert body["unlocked"] is False
    assert body["bundles"] == []

    first_key_id = unlock(url, token)
    status, body = api_post(url, token, "/api/status", {})
    assert body["unlocked"] is True
    assert body["key_id"] == first_key_id
    assert body["key_exists"] is True

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
    status, body = api_post(url, token, "/api/status", {})
    assert body["unlocked"] is False
    assert body["key_id"] is None

    status, body = api_post(url, token, "/api/create", {"content": sample_content()})
    assert status == 400
    assert "locked" in body["error"]

    status, body = api_post(url, token, "/api/key", {"passphrase": "wrong-passphrase"})
    assert status == 400
    assert "incorrect" in body["error"]


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
    url, token, _key, bundles_dir = make_server(max_bundles=2)
    unlock(url, token)
    first = create(url, token, {"content": sample_content()})
    second = create(url, token, {"content": '{"ioc": "second.example.invalid"}\n'})
    third = create(url, token, {"content": '{"ioc": "third.example.invalid"}\n'})

    remaining = {child.name for child in bundles_dir.iterdir()}
    assert remaining == {second["bundle_id"], third["bundle_id"]}
    assert first["bundle_id"] not in remaining


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
