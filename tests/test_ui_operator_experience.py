import csv
import importlib.util
import json
from pathlib import Path
import types

from ioc_rejudge.export import export_csv, export_jsonl
from ioc_rejudge.jobs_cli import _result_summary
from ioc_rejudge.providers.base import ProgressEvent
import ioc_rejudge.jobs_cli as jobs_cli
import ioc_rejudge.ui as ui

ROOT = Path(__file__).parents[1]
UI_PATH = ROOT / "ioc_rejudge" / "ui.html"


def page_text():
    return UI_PATH.read_text(encoding="utf-8")


def _verdict(ioc="example.invalid"):
    return {
        "ioc": ioc,
        "conclusion": "存活有效",
        "reason": "中文结论",
        "latest_material_activity_time": "2026-03-20 17:10:41",
        "latest_intel_update_time": "2026-04-01 09:02:03",
    }


def test_csv_bom_and_date_fields_stay_literal(tmp_path):
    path = tmp_path / "out.csv"
    export_csv([_verdict()], str(path))
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["conclusion"] == "存活有效"
    assert rows[0]["latest_material_activity_time"] == "'2026-03-20 17:10:41"
    assert rows[0]["latest_intel_update_time"] == "'2026-04-01 09:02:03"


def test_jsonl_has_no_bom(tmp_path):
    path = tmp_path / "out.jsonl"
    export_jsonl([_verdict()], str(path))
    assert not path.read_bytes().startswith(b"\xef\xbb\xbf")


def test_result_summary_keeps_provider_names():
    summary = _result_summary([
        {"conclusion": "存活有效", "provider_statuses": {"ioc_info": "ok", "whois": "timeout"}},
        {"conclusion": "误报", "provider_statuses": {"ioc_info": "error"}},
    ])
    assert summary["provider_statuses"] == {"ok": 1, "timeout": 1, "error": 1}
    assert summary["provider_details"] == {
        "ioc_info": "error",
        "whois": "timeout",
    }


def test_ui_job_run_prints_permanent_stderr_log(capsys, monkeypatch, tmp_path):
    calls = []
    summary = {
        "rows": 1,
        "provider_details": {"ioc_info": "ok", "whois": "timeout"},
    }

    class FakeQueue:
        def get(self, _job_id):
            return {"job_id": "job-run", "mode": "online", "result_summary": summary}

        def finish(self, job_id, **_kwargs):
            calls.append(("finish", job_id))

    def fake_run_job(queue, job_id, **kwargs):
        assert job_id == "job-run"
        assert callable(kwargs["on_progress"])
        kwargs["on_progress"](ProgressEvent("ioc_info", 1, 1, "done"))
        return {"ok": True}

    monkeypatch.setattr(jobs_cli, "run_job", fake_run_job)
    ui._ui_runner_logs.clear()
    state = types.SimpleNamespace(
        cache_dir=tmp_path,
        transport_factory=None,
        credentials_path=Path("credentials.local.json"),
        provider_env=None,
        job_queue=FakeQueue(),
    )
    ui._jobs_runner_entry(state, "job-run")
    captured = capsys.readouterr()
    assert "研判开始：模式 联网研判，凭据文件 已加载" in captured.err
    assert "来源完成：ioc_info" in captured.err
    assert "研判结束：异常来源 whois" in captured.err
    log = ui._ui_runner_logs.get("job-run", [])
    assert len(log) == 3
    assert all(entry["text"] for entry in log)
    snapshot = ui._snapshot_jobs_runner_progress("job-run")
    assert snapshot is not None and len(snapshot.get("log", [])) == 3
    ui._ui_runner_logs.clear()


def test_page_keeps_operator_mode_and_mode_labels():
    page = page_text()
    assert "联网研判</label>" in page
    assert "只用本机缓存</label>" in page
    assert "id=\"queue-mode-offline\" value=\"offline\" checked" not in page
    assert "queueState.iocInfoEnabled ? 'online' : 'offline'" in page
    assert "将调用外部 API" in page
    assert "不会发起网络请求" in page
    assert "mode === 'online' ? '联网' : '只用缓存'" in page


def test_page_shows_provider_names_and_run_log():
    page = page_text()
    assert "summary.provider_details" in page
    assert "abnormalProviders" in page
    assert "name + '=' + providerDetails[name]" in page
    assert "queue-run-log" in page
    ui_py = (ROOT / "ioc_rejudge" / "ui.py").read_text(encoding="utf-8")
    assert "来源完成：" in ui_py


def test_page_uses_local_minutes_and_raw_json():
    page = page_text()
    assert "function queueLocalTime(value)" in page
    assert "pad(date.getHours()) + ':' + pad(date.getMinutes())" in page
    assert "renderJsonlViewer($('queue-explain-viewer'), JSON.stringify(explanation))" in page


def test_page_json_defaults_and_single_toggle():
    page = page_text()
    assert "JSON_COLLAPSED_KEYS" in page
    assert "'result_id'" in page
    assert "'job_id'" in page
    assert "'evidence_fingerprint'" in page
    assert "renderTree(item.value, null, false)" in page
    assert "全部收起" in page
    assert "全部展开" in page
    assert "cardsHost.addEventListener('toggle', updateJsonToggle, true)" in page
    assert "transition: height 180ms ease" in page
    assert "prefers-reduced-motion: reduce" in page


def test_page_collapsed_key_branch_does_not_recurse():
    page = page_text()
    start = page.index("function renderTree(")
    end = page.index("\nfunction setAllOpen", start)
    function_text = page[start:end]
    branch_start = function_text.index("if (key != null && JSON_COLLAPSED_KEYS.has(")
    branch_end = function_text.index("if (value !== null && typeof value === 'object')", branch_start)
    branch = function_text[branch_start:branch_end]
    assert "details.open = false" in branch
    assert "body.appendChild(renderTree(value, null, false));" in branch
    assert "body.appendChild(renderTree(value, key, false));" not in branch
    assert "body.appendChild(renderTree(value[childKey], childKey" not in branch
    assert "setAllOpen(cardsHost, shouldOpen);" in page


def test_page_queue_visual_contract():
    page = page_text()
    assert "#queue-panel #queue-enqueue" in page
    assert "minmax(84px, 1fr)" in page
    assert '"PingFang SC", "Microsoft YaHei"' in page
    assert "prefers-reduced-motion: reduce" in page


def test_page_stays_single_file_without_external_resources():
    page = page_text()
    assert page.lower().count("<script") == 1
    assert "src=" not in page.lower()
    assert "@import" not in page
    for tag in ("<link", "<script", "<style"):
        start = 0
        while True:
            start = page.lower().find(tag, start)
            if start < 0:
                break
            end = page.find(">", start)
            assert "http://" not in page[start:end].lower()
            assert "https://" not in page[start:end].lower()
            start = end


def test_cache_index_message_prints_before_warmup():
    page = (ROOT / "ioc_rejudge" / "ui.py").read_text(encoding="utf-8")
    assert page.index("正在加载 IOC Info 缓存索引，缓存大时会等一会儿。") < page.index("_warmup_lookup_cache(state)\n", page.index("def build_server"))


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_start_script_detects_existing_server(tmp_path, monkeypatch, capsys):
    module = _load_script("start-server")
    record = {"pid": 1234, "port": 8731, "start_time": "2026-10-09T00:00:00+08:00"}
    (tmp_path / ".server.pid").write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_process_alive", lambda _pid: True)
    monkeypatch.setattr(module, "_process_is_server", lambda _pid: True)
    assert module.start() == 0
    assert "服务已在运行：http://127.0.0.1:8731" in capsys.readouterr().out


def test_start_record_has_only_pid_port_and_start_time(tmp_path, monkeypatch, capsys):
    module = _load_script("start-server")
    calls = []
    class FakeProcess:
        pid = 4321
        def __init__(self):
            lines = iter(["ioc rejudge share ui: http://127.0.0.1:8731/?token=hidden\n"])
            self.stdout = types.SimpleNamespace(readline=lambda: next(lines, ""), close=lambda: None)
            self.stderr = types.SimpleNamespace(readline=lambda: "", close=lambda: None)
        def wait(self):
            calls.append("wait")
            return 0
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_preferred_python", lambda _root: Path("python"))
    monkeypatch.setattr(module, "_check_dependencies", lambda _python: True)
    popen_calls = []
    def fake_popen(args, *_args, **_kwargs):
        popen_calls.append(args)
        return FakeProcess()
    fake_subprocess = types.SimpleNamespace(
        PIPE="PIPE",
        Popen=fake_popen,
    )
    monkeypatch.setattr(module, "subprocess", fake_subprocess)
    assert module.start() == 0
    output = capsys.readouterr().out
    assert "服务已启动：http://127.0.0.1:8731/?token=hidden" in output
    assert popen_calls[0][-2:] == ["--cache-dir", ".\\provider-cache"]
    record = json.loads((tmp_path / ".server.pid").read_text(encoding="utf-8"))
    assert set(record) == {"pid", "port", "start_time"}
    assert record["pid"] == 4321
    assert record["port"] == 8731


def test_stop_script_failed_command_line_lookup_does_not_kill(tmp_path, monkeypatch, capsys):
    module = _load_script("stop-server")
    record = {"pid": 1234, "port": 8731, "start_time": "2026-10-09T00:00:00+08:00"}
    (tmp_path / ".server.pid").write_text(json.dumps(record), encoding="utf-8")
    killed = []
    os_killed = []
    lookup_calls = []
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_process_alive", lambda _pid: True)
    monkeypatch.setattr(module.os, "kill", lambda pid, _signal: os_killed.append(pid))
    monkeypatch.setattr(module.os, "name", "nt")

    def failed_lookup(*args, **kwargs):
        lookup_calls.append(args)
        return types.SimpleNamespace(returncode=1, stdout="", stderr="lookup failed")

    monkeypatch.setattr(module.subprocess, "run", failed_lookup)
    monkeypatch.setattr(module, "_stop_process", lambda pid: killed.append(pid))
    assert module._process_is_server(1234, record) is False
    assert module.stop() == 0
    assert "已经停了" in capsys.readouterr().out
    assert lookup_calls
    assert killed == []
    assert os_killed == []
    assert not (tmp_path / ".server.pid").exists()


def test_stop_script_verifies_identity_before_kill(tmp_path, monkeypatch, capsys):
    module = _load_script("stop-server")
    record = {"pid": 1234, "port": 8731, "start_time": "2026-10-09T00:00:00+08:00"}
    (tmp_path / ".server.pid").write_text(json.dumps(record), encoding="utf-8")
    killed = []
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_process_alive", lambda _pid: True)
    monkeypatch.setattr(module, "_process_is_server", lambda _pid, _record: False)
    monkeypatch.setattr(module, "_stop_process", lambda pid: killed.append(pid))
    assert module.stop() == 0
    assert "已经停了" in capsys.readouterr().out
    assert killed == []
    assert not (tmp_path / ".server.pid").exists()


def test_stop_script_stops_matching_record(tmp_path, monkeypatch, capsys):
    module = _load_script("stop-server")
    record = {"pid": 1234, "port": 8731, "start_time": "2026-10-09T00:00:00+08:00"}
    (tmp_path / ".server.pid").write_text(json.dumps(record), encoding="utf-8")
    killed = []
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_process_alive", lambda _pid: True)
    monkeypatch.setattr(module, "_process_is_server", lambda _pid, _record: True)
    monkeypatch.setattr(module, "_stop_process", lambda pid: killed.append(pid))
    assert module.stop() == 0
    assert killed == [1234]
    assert "已经停了" in capsys.readouterr().out


def test_stop_script_says_already_stopped_for_missing_record(tmp_path, monkeypatch, capsys):
    module = _load_script("stop-server")
    killed = []
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_stop_process", lambda pid: killed.append(pid))
    assert module.stop() == 0
    assert "已经停了" in capsys.readouterr().out
    assert killed == []


def test_bat_files_and_gitignore_contract():
    assert "start-server.py" in (ROOT / "start-server.bat").read_text(encoding="utf-8")
    assert "stop-server.py" in (ROOT / "stop-server.bat").read_text(encoding="utf-8")
    assert ".server.pid" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_readme_startup_contract():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "start-server.bat" in readme
    assert "python start-server.py" in readme
