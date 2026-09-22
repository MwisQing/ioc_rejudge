import http.client
import json
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from ioc_rejudge.ui import build_server
from ioc_rejudge.workbench import WorkbenchAdapter


def jsonl_row(ioc="evil.example.invalid"):
    return {
        "ioc": ioc,
        "data": [{"url": f"https://{ioc}/login"}],
    }


def jsonl_content(*rows):
    values = rows or [jsonl_row()]
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in values)


@pytest.fixture()
def make_server(tmp_path):
    servers = []

    def _make(workbench_adapter=None):
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        workbench_dir = tmp_path / "workbench"
        server, url = build_server(
            key_path,
            bundles_dir,
            port=0,
            cache_dir=tmp_path / "provider-cache",
            provider_env={},
            workbench_adapter=workbench_adapter,
            workbench_dir=workbench_dir,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        parsed = urlsplit(url)
        token = parsed.query.removeprefix("token=")
        return (
            f"http://{parsed.netloc}",
            token,
            Path(workbench_dir),
        )

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def request(
    base,
    path,
    *,
    method="GET",
    payload=None,
    token=None,
    host=None,
    origin=None,
    timeout=5,
):
    parsed = urlsplit(base)
    port = parsed.port or 80
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if origin is not None:
        headers["Origin"] = origin
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        connection.putrequest(method, path, skip_host=True)
        if host is None:
            host = parsed.netloc
        if host != "":
            connection.putheader("Host", host)
        for name, value in headers.items():
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders()
        if body is not None:
            connection.send(body)
        response = connection.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def json_request(base, path, *, method="POST", payload=None, **kwargs):
    status, headers, data = request(
        base,
        path,
        method=method,
        payload=payload,
        **kwargs,
    )
    return status, json.loads(data.decode("utf-8"))


class RecordingWorkbenchAdapter(WorkbenchAdapter):
    def __init__(self, workbench_dir):
        self._dir = Path(workbench_dir)
        self.calls = []
        self.outside_export = None

    @property
    def workbench_dir(self):
        return self._dir

    def _record(self, operation, *args, **kwargs):
        self.calls.append((operation, args, kwargs))

    def stage_input(self, filename, content):
        self._record("stage_input", filename, content)
        return {
            "import_id": "import-1",
            "filename": "input.jsonl",
            "path": str(self._dir / "staging" / "import-1" / "input.jsonl"),
            "size": 32,
            "rows": 1,
        }

    def start_task(self, import_id, *, providers=None, options=None):
        self._record("start_task", import_id, providers=providers, options=options)
        return {"task_id": "task-1", "import_id": import_id, "state": "queued"}

    def task_status(self, task_id):
        self._record("task_status", task_id)
        return {"task_id": task_id, "state": "running"}

    def cancel_task(self, task_id):
        self._record("cancel_task", task_id)
        return {"task_id": task_id, "state": "cancelling"}

    def results(
        self,
        task_id,
        *,
        dispositions=None,
        query=None,
        provider_issues=None,
        offset=0,
        limit=100,
    ):
        kwargs = {
            "dispositions": dispositions,
            "query": query,
            "offset": offset,
            "limit": limit,
        }
        if provider_issues is not None:
            kwargs["provider_issues"] = provider_issues
        self._record("results", task_id, **kwargs)
        return {
            "task_id": task_id,
            "total": 1,
            "offset": offset,
            "limit": limit,
            "rows": [{"result_id": "result-1", "ioc": "evil.example.invalid"}],
        }

    def explanation(self, task_id, result_id):
        self._record("explanation", task_id, result_id)
        return {
            "task_id": task_id,
            "result_id": result_id,
            "explanation": "provider evidence",
        }

    def submit_review(
        self,
        task_id,
        result_id,
        *,
        decision,
        reason="",
        reviewer="",
    ):
        self._record(
            "submit_review",
            task_id,
            result_id,
            decision=decision,
            reason=reason,
            reviewer=reviewer,
        )
        return {"result_id": result_id, "review": decision}

    def export(
        self,
        task_id,
        *,
        dispositions=None,
        query=None,
        provider_issues=None,
        export_format="jsonl",
    ):
        kwargs = {
            "dispositions": dispositions,
            "query": query,
            "export_format": export_format,
        }
        if provider_issues is not None:
            kwargs["provider_issues"] = provider_issues
        self._record("export", task_id, **kwargs)
        export_id = "export-1"
        path = self._dir / "exports" / f"{export_id}.{export_format}"
        return {
            "export_id": export_id,
            "task_id": task_id,
            "format": export_format,
            "path": str(path),
        }

    def export_file(self, export_id):
        self._record("export_file", export_id)
        if self.outside_export is not None:
            return self.outside_export
        return self._dir / "exports" / f"{export_id}.jsonl"

    def diagnostics(self, task_id):
        self._record("diagnostics", task_id)
        return {"task_id": task_id, "available": True, "processed_count": 1}

    def diff(self, task_id, baseline_task_id):
        self._record("diff", task_id, baseline_task_id)
        return {
            "task_id": task_id,
            "baseline_task_id": baseline_task_id,
            "available": True,
            "diff": {"operations": 1, "changed": []},
        }

    def summary(self, task_id):
        self._record("summary", task_id)
        return {
            "task_id": task_id,
            "version": "2.8.0",
            "input_path": str(self._dir / "secret.jsonl"),
            "api_token": "do-not-return",
            "task": {"diagnostics_path": str(self._dir / "diagnostics.json")},
        }

    def export_artifact(
        self,
        task_id,
        *,
        artifact_format,
        dispositions=None,
        query=None,
        provider_issues=None,
        baseline_task_id=None,
    ):
        kwargs = {
            "artifact_format": artifact_format,
            "dispositions": dispositions,
            "query": query,
            "baseline_task_id": baseline_task_id,
        }
        if provider_issues is not None:
            kwargs["provider_issues"] = provider_issues
        self._record("export_artifact", task_id, **kwargs)
        return {
            "export_id": "export-artifact-1",
            "filename": "export-artifact-1.zip",
            "format": artifact_format,
            "rows": 1,
        }


def test_local_adapter_stages_and_validates_jsonl_safely(make_server):
    base, token, workbench_dir = make_server()

    status, body = json_request(
        base,
        "/api/workbench/import",
        payload={"filename": "../outside.jsonl", "content": jsonl_content()},
        token=token,
    )
    assert status == 200, body
    staged = Path(body["path"]).resolve()
    assert body["import_id"]
    assert body["filename"] == "outside.jsonl"
    assert body["rows"] == 1
    assert body["size"] == len(jsonl_content().encode("utf-8"))
    assert staged.parent.parent.parent == workbench_dir.resolve()
    assert staged.read_text(encoding="utf-8") == jsonl_content()

    status, body = json_request(
        base,
        "/api/workbench/import",
        payload={"filename": "bad.jsonl", "content": "[1]\n"},
        token=token,
    )
    assert status == 400
    assert body["available"] is False
    assert "JSONL" in body["error"]
    assert staged.parent.parent.parent == workbench_dir.resolve()


def test_default_local_backend_persists_structured_task_state(make_server):
    base, token, _workbench_dir = make_server()

    status, body = json_request(
        base,
        "/api/workbench/import",
        payload={"filename": "input.jsonl", "content": jsonl_content()},
        token=token,
    )
    assert status == 200, body
    status, body = json_request(
        base,
        "/api/workbench/task",
        payload={"import_id": body["import_id"]},
        token=token,
    )
    assert status == 200
    assert body["state"] == "failed"


def test_fake_adapter_task_status_and_cancel(make_server):
    adapter = RecordingWorkbenchAdapter(Path("/tmp/unused"))
    base, token, _workbench_dir = make_server(adapter)

    status, body = json_request(
        base,
        "/api/workbench/task",
        payload={
            "import_id": "import-1",
            "providers": ["provider-a"],
            "options": {"dry_run": True},
        },
        token=token,
    )
    assert status == 200, body
    assert body == {"task_id": "task-1", "import_id": "import-1", "state": "queued"}

    status, body = json_request(
        base,
        "/api/workbench/task/task-1",
        method="GET",
        token=token,
    )
    assert status == 200, body
    assert body == {"task_id": "task-1", "state": "running"}

    status, body = json_request(
        base,
        "/api/workbench/cancel",
        payload={"task_id": "task-1"},
        token=token,
    )
    assert status == 200, body
    assert body == {"task_id": "task-1", "state": "cancelling"}
    assert adapter.calls[0] == (
        "start_task",
        ("import-1",),
        {"providers": ["provider-a"], "options": {"dry_run": True}},
    )
    assert adapter.calls[1] == ("task_status", ("task-1",), {})
    assert adapter.calls[2] == ("cancel_task", ("task-1",), {})


def test_fake_adapter_results_explanation_review_and_export(make_server, tmp_path):
    adapter = RecordingWorkbenchAdapter(tmp_path / "fake-root")
    base, token, workbench_dir = make_server(adapter)
    adapter._dir = workbench_dir
    export_dir = workbench_dir / "exports"
    export_dir.mkdir(parents=True)
    export_file = export_dir / "export-1.jsonl"
    export_file.write_bytes(b'{"result_id":"result-1"}\n')

    filters = {
        "task_id": "task-1",
        "dispositions": ["malicious"],
        "query": "evil",
        "offset": 10,
        "limit": 50,
    }
    status, body = json_request(
        base,
        "/api/workbench/results",
        payload=filters,
        token=token,
    )
    assert status == 200, body
    assert body["rows"][0]["result_id"] == "result-1"

    status, body = json_request(
        base,
        "/api/workbench/explanation",
        payload={"task_id": "task-1", "result_id": "result-1"},
        token=token,
    )
    assert status == 200, body
    assert body["explanation"] == "provider evidence"

    status, body = json_request(
        base,
        "/api/workbench/review",
        payload={
            "task_id": "task-1",
            "result_id": "result-1",
            "decision": "confirmed",
            "reason": " evidence ",
            "reviewer": "tester",
        },
        token=token,
    )
    assert status == 200, body
    assert body["review"] == "confirmed"

    status, body = json_request(
        base,
        "/api/workbench/export",
        payload={"task_id": "task-1", "dispositions": ["malicious"], "format": "jsonl"},
        token=token,
    )
    assert status == 200, body
    assert body["export_id"] == "export-1"

    status, headers, data = request(
        base,
        "/api/workbench/export/export-1/download",
        token=token,
    )
    assert status == 200
    assert headers["Content-Type"] == "application/x-ndjson; charset=utf-8"
    assert headers["Content-Disposition"] == 'attachment; filename="export-1.jsonl"'
    assert data == b'{"result_id":"result-1"}\n'

    assert adapter.calls[0] == (
        "results",
        ("task-1",),
        {
            "dispositions": ["malicious"],
            "query": "evil",
            "offset": 10,
            "limit": 50,
        },
    )
    assert adapter.calls[1] == (
        "explanation",
        ("task-1", "result-1"),
        {},
    )
    assert adapter.calls[2] == (
        "submit_review",
        ("task-1", "result-1"),
        {
            "decision": "confirmed",
            "reason": " evidence ",
            "reviewer": "tester",
        },
    )
    assert adapter.calls[3] == (
        "export",
        ("task-1",),
        {
            "dispositions": ["malicious"],
            "query": None,
            "export_format": "jsonl",
        },
    )
    assert adapter.calls[4] == ("export_file", ("export-1",), {})


def test_workbench_provider_issue_filter_is_structured_and_optional(make_server, tmp_path):
    adapter = RecordingWorkbenchAdapter(tmp_path / "fake-root")
    base, token, _workbench_dir = make_server(adapter)

    status, body = json_request(
        base,
        "/api/workbench/results",
        payload={"task_id": "task-1", "provider_issues": True},
        token=token,
    )
    assert status == 200, body
    assert adapter.calls[-1] == (
        "results",
        ("task-1",),
        {
            "dispositions": None,
            "query": None,
            "offset": 0,
            "limit": 100,
            "provider_issues": True,
        },
    )

    status, body = json_request(
        base,
        "/api/workbench/export",
        payload={"task_id": "task-1", "format": "jsonl", "provider_issues": True},
        token=token,
    )
    assert status == 200, body
    assert adapter.calls[-1] == (
        "export",
        ("task-1",),
        {
            "dispositions": None,
            "query": None,
            "export_format": "jsonl",
            "provider_issues": True,
        },
    )

    status, body = json_request(
        base,
        "/api/workbench/results",
        payload={"task_id": "task-1", "provider_issues": "yes"},
        token=token,
    )
    assert status == 400
    assert "provider_issues" in body["error"]


def test_export_download_rejects_adapter_path_outside_workbench(
    make_server,
    tmp_path,
):
    adapter = RecordingWorkbenchAdapter(tmp_path / "fake-root")
    outside = tmp_path / "outside.jsonl"
    outside.write_text("secret\n", encoding="utf-8")
    adapter.outside_export = outside
    base, token, _workbench_dir = make_server(adapter)

    status, body = json_request(
        base,
        "/api/workbench/export/outside-id/download",
        method="GET",
        token=token,
    )
    assert status == 400
    assert body["error"] == "export file is outside the workbench directory"
    assert outside.read_text(encoding="utf-8") == "secret\n"


def test_workbench_diagnostics_and_diff_routes(make_server):
    adapter = RecordingWorkbenchAdapter(Path("/tmp/unused"))
    base, token, _workbench_dir = make_server(adapter)

    status, body = json_request(
        base,
        "/api/workbench/diagnostics",
        payload={"task_id": "task-1"},
        token=token,
    )
    assert status == 200, body
    assert body["available"] is True

    status, body = json_request(
        base,
        "/api/workbench/diff",
        payload={"task_id": "task-2", "baseline_task_id": "task-1"},
        token=token,
    )
    assert status == 200, body
    assert body["diff"]["operations"] == 1
    assert adapter.calls == [
        ("diagnostics", ("task-1",), {}),
        ("diff", ("task-2", "task-1"), {}),
    ]


def test_workbench_summary_and_artifact_routes_are_safe(make_server):
    adapter = RecordingWorkbenchAdapter(Path("/tmp/unused"))
    base, token, _workbench_dir = make_server(adapter)

    status, body = json_request(
        base,
        "/api/workbench/task/task-1/summary",
        method="GET",
        token=token,
    )
    assert status == 200, body
    assert body["version"] == "2.8.0"
    assert "input_path" not in json.dumps(body)
    assert "diagnostics_path" not in json.dumps(body)
    assert "do-not-return" not in json.dumps(body)

    status, body = json_request(
        base,
        "/api/workbench/export",
        payload={
            "task_id": "task-2",
            "format": "bundle",
            "baseline_task_id": "task-1",
        },
        token=token,
    )
    assert status == 200, body
    assert body["export_id"] == "export-artifact-1"
    assert adapter.calls[-1] == (
        "export_artifact",
        ("task-2",),
        {
            "artifact_format": "bundle",
            "dispositions": None,
            "query": None,
            "baseline_task_id": "task-1",
        },
    )


def test_workbench_task_paths_are_not_returned_to_browser(make_server):
    class PathLeakingAdapter(RecordingWorkbenchAdapter):
        def start_task(self, import_id, *, providers=None, options=None):
            result = super().start_task(import_id, providers=providers, options=options)
            result["result_path"] = str(self._dir / "tasks" / "task-1" / "results.jsonl")
            result["diagnostics_path"] = str(self._dir / "tasks" / "task-1" / "diagnostics.json")
            return result

        def task_status(self, task_id):
            result = super().task_status(task_id)
            result["result_path"] = str(self._dir / "tasks" / task_id / "results.jsonl")
            result["diagnostics_path"] = str(self._dir / "tasks" / task_id / "diagnostics.json")
            return result

        def diagnostics(self, task_id):
            return {
                "task_id": task_id,
                "available": True,
                "input_path": str(self._dir / "tasks" / task_id / "input.jsonl"),
                "diagnostics_path": str(self._dir / "tasks" / task_id / "diagnostics.json"),
            }

    adapter = PathLeakingAdapter(Path("/tmp/unused"))
    base, token, _workbench_dir = make_server(adapter)
    status, body = json_request(
        base,
        "/api/workbench/task",
        payload={"import_id": "import-1"},
        token=token,
    )
    assert status == 200, body
    assert "result_path" not in body
    assert "diagnostics_path" not in body

    status, body = json_request(
        base,
        "/api/workbench/diagnostics",
        payload={"task_id": "task-1"},
        token=token,
    )
    assert status == 200, body
    assert "input_path" not in body
    assert "diagnostics_path" not in body

    status, body = json_request(
        base,
        "/api/workbench/task/task-1",
        method="GET",
        token=token,
    )
    assert status == 200, body
    assert "result_path" not in body
    assert "diagnostics_path" not in body


def test_session_token_and_host_origin_are_required(make_server):
    base, token, _workbench_dir = make_server()
    host = urlsplit(base).netloc

    status, body = json_request(base, "/api/status")
    assert status == 403
    assert body == {"error": "forbidden"}

    status, body = json_request(base, "/api/status", token="wrong-token")
    assert status == 403

    status, body = json_request(base, "/api/status?token=" + token)
    assert status == 200, body
    assert body["workbench"] == {
        "configured": True,
        "backend_available": True,
    }

    status, body = json_request(base, "/api/status", token=token, host="evil.example.invalid")
    assert status == 403

    status, body = json_request(
        base,
        "/api/status",
        token=token,
        origin="https://" + host,
    )
    assert status == 403

    status, body = json_request(
        base,
        "/api/status",
        token=token,
        origin="http://evil.example.invalid",
    )
    assert status == 403

    status, body = json_request(
        base,
        "/api/status",
        token=token,
        origin=base,
    )
    assert status == 200, body
    assert host.endswith(str(urlsplit(base).port))


def test_workbench_path_traversal_ids_are_rejected(make_server):
    adapter = RecordingWorkbenchAdapter(Path("/tmp/unused"))
    base, token, _workbench_dir = make_server(adapter)

    for path in (
        "/api/workbench/task/..%2Foutside",
        "/api/workbench/task/..",
        "/api/workbench/export/..%2Foutside/download",
        "/api/workbench/export/..%2F..%2Foutside/download",
    ):
        status, body = json_request(base, path, method="GET", token=token)
        assert status == 400, path
        assert "invalid" in body["error"]
    assert adapter.calls == []
