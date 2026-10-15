"""Server routing for the new/legacy UI version switch.

The local share assistant serves the redesigned page at ``/`` and the
restored legacy page at ``/?ui=legacy``.  These tests lock the routing
contract: default stays new, ``ui`` is a strict whitelist, invalid or
missing legacy file falls back to new (never 500), auth runs before file
selection, the legacy-workbench marker only injects into the new page, and
both pages remain single-file with no external references.
"""

import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ioc_rejudge import ui as ui_module
from ioc_rejudge.ui import build_server

NEW_MARKER = 'id="theme-toggle"'
LEGACY_MARKER = "（旧版）"
VERSION_TOGGLE = 'id="ui-version-toggle"'


def _get(url: str, token: str, path: str):
    request = urllib.request.Request(url + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def _is_new(body: bytes) -> bool:
    text = body.decode("utf-8")
    return NEW_MARKER in text and LEGACY_MARKER not in text


def _is_legacy(body: bytes) -> bool:
    text = body.decode("utf-8")
    return LEGACY_MARKER in text and NEW_MARKER not in text


@pytest.fixture()
def make_version_server(tmp_path):
    servers = []

    def _make(*, legacy_workbench=False):
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        server, url = build_server(
            key_path,
            bundles_dir,
            port=0,
            max_bundles=20,
            cache_dir=tmp_path / "provider-cache",
            provider_env={},
            workbench_dir=tmp_path / "workbench",
            jobs_dir=tmp_path / "jobs",
            legacy_workbench=legacy_workbench,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        base, _, token = url.partition("/?token=")
        return base, token

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def test_default_serves_new_page(make_version_server):
    base, token = make_version_server()
    status, headers, body = _get(base, token, "/")
    assert status == 200
    assert headers.get("Content-Type") == "text/html; charset=utf-8"
    assert headers.get("Cache-Control") == "no-store"
    assert _is_new(body)
    assert VERSION_TOGGLE in body.decode("utf-8")


def test_ui_legacy_serves_old_page(make_version_server):
    base, token = make_version_server()
    status, headers, body = _get(base, token, "/?ui=legacy")
    assert status == 200
    assert headers.get("Cache-Control") == "no-store"
    assert _is_legacy(body)
    assert VERSION_TOGGLE in body.decode("utf-8")


def test_ui_new_serves_new_page(make_version_server):
    base, token = make_version_server()
    status, _headers, body = _get(base, token, "/?ui=new")
    assert status == 200
    assert _is_new(body)


def test_ui_invalid_falls_back_to_new(make_version_server):
    base, token = make_version_server()
    for path in ("/?ui=bogus", "/?ui="):
        status, _headers, body = _get(base, token, path)
        assert status == 200
        assert _is_new(body)


def test_legacy_missing_falls_back_to_new_no_500(make_version_server, tmp_path, monkeypatch):
    # Point the legacy page at a missing file before the server is built.
    monkeypatch.setattr(ui_module, "_LEGACY_PAGE_FILE", tmp_path / "does-not-exist.html")
    base, token = make_version_server()
    status, _headers, body = _get(base, token, "/?ui=legacy")
    assert status == 200
    assert _is_new(body)


def test_page_requires_token_before_file_selection(make_version_server):
    base, _token = make_version_server()
    # No token at all: auth must reject before any page file is chosen.
    request = urllib.request.Request(base + "/?ui=legacy")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 403


def test_both_pages_single_file_no_external(make_version_server):
    base, token = make_version_server()
    for path in ("/", "/?ui=legacy"):
        _status, _headers, body = _get(base, token, path)
        text = body.decode("utf-8")
        lowered = text.lower()
        assert lowered.count("<script") == 1, path
        assert "src=" not in lowered, path
        assert "http://" not in lowered, path
        assert "https://" not in lowered, path
        assert "@import" not in lowered, path


def test_legacy_workbench_marker_only_on_new(make_version_server):
    base, token = make_version_server(legacy_workbench=True)
    _status, _headers, new_body = _get(base, token, "/")
    _status, _headers, legacy_body = _get(base, token, "/?ui=legacy")
    assert b"window.__LEGACY_WORKBENCH__=true;" in new_body
    assert b"window.__LEGACY_WORKBENCH__=true;" not in legacy_body
