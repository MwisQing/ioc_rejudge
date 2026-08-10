"""Go batch transport adapter tests without external network access."""

import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from ioc_rejudge.providers.go_transport import (
    BatchRequest,
    GoBatchTransport,
    default_executable,
)


class _LocalHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    active = 0
    peak = 0
    starts = []

    def log_message(self, format, *args):
        return

    def _begin(self):
        with self.lock:
            type(self).active += 1
            type(self).peak = max(type(self).peak, type(self).active)
            type(self).starts.append(time.monotonic())

    def _end(self):
        with self.lock:
            type(self).active -= 1

    def _send_json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self._begin()
        try:
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/status":
                self._send_json(503, {"ignored": True})
                return
            if parsed.path == "/invalid-json":
                body = b"not-json"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            delay = float(query.get("delay", ["0"])[0])
            if delay:
                time.sleep(delay)
            self._send_json(200, {"id": query.get("id", [""])[0]})
        finally:
            self._end()

    def do_POST(self):
        self._begin()
        try:
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size))
            self._send_json(200, {"received": payload})
        finally:
            self._end()


@pytest.fixture
def local_http_server():
    _LocalHandler.active = 0
    _LocalHandler.peak = 0
    _LocalHandler.starts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _LocalHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_default_executable_is_bundled_binary():
    path = default_executable()
    assert path.name in {"provider_http", "provider_http.exe"}
    assert path.parent.name == "bin"


def test_missing_worker_fails_before_spawning(tmp_path):
    transport = GoBatchTransport(tmp_path / "missing.exe")
    assert transport.available is False
    with pytest.raises(RuntimeError, match="not found"):
        list(transport.iter_batch([], workers=1, rate_per_second=1))


def test_adapter_reads_success_and_safe_error_rows(tmp_path):
    worker = tmp_path / "fake_worker.py"
    worker.write_text(
        """#!/usr/bin/env python3
import json, sys
for line in sys.stdin:
    row = json.loads(line)
    if row["id"] == "ok":
        print(json.dumps({"id": "ok", "ok": True, "payload": {"value": 1}}), flush=True)
    else:
        print(json.dumps({"id": row["id"], "ok": False, "error_kind": "http", "message": "HTTP 503 for https://api.invalid", "status_code": 503}), flush=True)
""",
        encoding="utf-8",
    )
    if not hasattr(Path, "chmod"):
        pytest.skip("chmod unavailable")
    worker.chmod(0o755)
    transport = GoBatchTransport(worker)
    requests = [
        BatchRequest("ok", "GET", "https://api.invalid/ok"),
        BatchRequest("bad", "GET", "https://api.invalid/bad"),
    ]

    if Path(default_executable()).suffix == ".exe":
        pytest.skip("script executable adapter probe is POSIX-only")
    results = list(transport.iter_batch(requests, workers=2, rate_per_second=10))
    assert results[0].payload == {"value": 1}
    assert results[1].error.kind == "http"
    assert results[1].error.status_code == 503


def test_bundled_worker_executes_get_post_concurrently_and_streams_large_batch(
    local_http_server,
):
    base_url, handler = local_http_server
    transport = GoBatchTransport()
    assert transport.available
    requests = [
        BatchRequest(
            str(index),
            "GET",
            f"{base_url}/ok",
            params={"id": index, "delay": 0.02},
            timeout=2,
        )
        for index in range(120)
    ]
    requests.append(
        BatchRequest("post", "POST", f"{base_url}/post", body={"value": 7})
    )

    results = list(
        transport.iter_batch(requests, workers=6, rate_per_second=1000)
    )

    assert len(results) == 121
    by_id = {result.id: result for result in results}
    assert by_id["0"].payload == {"id": "0"}
    assert by_id["post"].payload == {"received": {"value": 7}}
    assert 1 < handler.peak <= 6


def test_bundled_worker_rate_limits_request_starts(local_http_server):
    base_url, handler = local_http_server
    transport = GoBatchTransport()
    requests = [
        BatchRequest(str(index), "GET", f"{base_url}/ok", timeout=2)
        for index in range(4)
    ]

    results = list(transport.iter_batch(requests, workers=4, rate_per_second=10))

    assert all(result.error is None for result in results)
    starts = sorted(handler.starts)
    assert len(starts) == 4
    assert starts[-1] - starts[0] >= 0.25


def test_bundled_worker_classifies_errors_without_exposing_secrets(local_http_server):
    base_url, _ = local_http_server
    secret = "sentinel-query-and-header-secret"
    transport = GoBatchTransport()
    requests = [
        BatchRequest(
            "http", "GET", f"{base_url}/status?token={secret}",
            headers={"Authorization": secret},
        ),
        BatchRequest("json", "GET", f"{base_url}/invalid-json?key={secret}"),
        BatchRequest("timeout", "GET", f"{base_url}/ok?delay=0.2&key={secret}", timeout=0.03),
    ]

    results = list(transport.iter_batch(requests, workers=3, rate_per_second=1000))
    by_id = {result.id: result for result in results}

    assert by_id["http"].error.kind == "http"
    assert by_id["http"].error.status_code == 503
    assert by_id["json"].error.kind == "json_decode"
    assert by_id["timeout"].error.kind == "timeout"
    assert secret not in " \n".join(str(result.error) for result in results)
