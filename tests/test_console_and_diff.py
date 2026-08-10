"""Console visibility and baseline diff behaviors of the CLI."""
import json
import sys

import pytest

from ioc_rejudge.cli import main
from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import ProviderStatus
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.factory import ResultCacheSettings


class _StubProvider:
    def __init__(self, name, result=None, error=None):
        self.name = name
        self._result = result
        self._error = error

    def supports(self, target):
        return True

    def collect(self, targets, context):
        if self._error:
            raise self._error
        return self._result(targets)


def _no_data_result(name):
    def build(targets):
        return ProviderResult(
            name=name,
            statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
        )
    return build


def _write_sidecar(path, ioc="a.invalid"):
    observation = {
        "ioc": ioc,
        "kind": "ioc_info_record",
        "status": "success",
        "scope": "domain",
        "fetched_at": "2026-07-25T10:00:00",
        "observed_at": "2026-07-25T10:00:00",
        "payload": {"key": ioc},
    }
    path.write_text(json.dumps(observation) + "\n", encoding="utf-8")
    return path


def test_cli_prints_provider_summary_and_disabled_warning(tmp_path, monkeypatch, capsys):
    for variable in ("WHOIS_ACCESS", "WHOIS_SECRET", "FDP_ACCESS", "FDP_SECRET"):
        monkeypatch.delenv(variable, raising=False)
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--providers", "whois",
            "--cache-dir", str(tmp_path / "cache"),
            "--jsonl", str(output),
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Providers: whois [disabled]" in captured.out
    assert "WARNING: provider 'whois' disabled: missing required credentials" in captured.err


def test_cli_prints_sidecar_marker_and_provider_status_summary(tmp_path, monkeypatch, capsys):
    sidecar = _write_sidecar(tmp_path / "side.jsonl")
    output = tmp_path / "result.jsonl"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--provider-data", f"side={sidecar}",
            "--jsonl", str(output),
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Providers: side (sidecar)" in captured.out
    assert "Provider status:" in captured.out
    assert "side: success=1" in captured.out


def test_cli_warns_rejected_input_lines(tmp_path, monkeypatch, capsys):
    source = tmp_path / "iocs.txt"
    source.write_text("a.invalid\nbad_domain._x\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input", str(source),
            "--offline",
            "--jsonl", str(output),
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "WARNING: 1 input line(s) rejected" in captured.err
    assert "invalid IOC" in captured.err
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["ioc"] for row in rows] == ["a.invalid"]


def test_unified_pipeline_reports_progress_and_durations():
    bundle = read_input_bundle(None, ["a.invalid"])
    messages = []

    result = run_unified_pipeline(
        bundle,
        [
            _StubProvider("ok", result=_no_data_result("ok")),
            _StubProvider("broken", error=RuntimeError("boom")),
        ],
        Config(),
        ProviderContext(offline=True),
        progress=messages.append,
    )

    assert any(m.startswith("provider 'ok': completed in ") for m in messages)
    assert any(m.startswith("provider 'broken': failed after ") for m in messages)
    metrics = result.diagnostics.to_dict()["provider_metrics"]
    assert metrics["ok"]["duration_seconds"] >= 0.0
    assert metrics["broken"]["duration_seconds"] >= 0.0
    assert result.diagnostics.providers["ok"].no_data == 1
    assert result.diagnostics.provider_errors["broken"] == ["boom"]


def test_unified_pipeline_progress_callback_errors_do_not_break_run():
    bundle = read_input_bundle(None, ["a.invalid"])

    def bad_progress(message):
        raise RuntimeError("progress boom")

    result = run_unified_pipeline(
        bundle,
        [_StubProvider("ok", result=_no_data_result("ok"))],
        Config(),
        ProviderContext(offline=True),
        progress=bad_progress,
    )

    assert [row["conclusion"] for row in result.verdicts] == ["待复核"]
    assert result.diagnostics.providers["ok"].no_data == 1
    assert "ok" not in result.diagnostics.provider_errors


def test_cli_prints_progress_and_total_time(tmp_path, monkeypatch, capsys):
    sidecar = _write_sidecar(tmp_path / "side.jsonl")
    output = tmp_path / "result.jsonl"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--provider-data", f"side={sidecar}",
            "--jsonl", str(output),
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "provider 'side': completed in " in captured.err
    assert "Total time: " in captured.out


def test_cli_second_run_reuses_same_result_cache_without_collecting(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "result.jsonl"
    cache_dir = tmp_path / "persistent-cache"
    provider = _StubProvider("stable", result=_no_data_result("stable"))
    calls = []
    original_collect = provider.collect

    def counted_collect(targets, context):
        calls.append([target.normalized for target in targets])
        return original_collect(targets, context)

    provider.collect = counted_collect
    monkeypatch.setattr(
        "ioc_rejudge.cli.build_providers", lambda *args, **kwargs: [provider]
    )
    monkeypatch.setattr(
        "ioc_rejudge.cli.load_result_cache_settings",
        lambda path: ResultCacheSettings(),
    )

    argv = [
        "ioc_rejudge",
        "--ioc", "cache-reuse.invalid",
        "--providers", "whois",
        "--cache-dir", str(cache_dir),
        "--jsonl", str(output),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    main()
    first_output = capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", argv)
    main()
    second_output = capsys.readouterr().out

    assert calls == [["cache-reuse.invalid"]]
    assert f"Cache root: {cache_dir.resolve()}" in first_output
    assert "Adjudication result cache: hit=0 miss=1 (missing=1)" in first_output
    assert "Adjudication result cache: hit=1 miss=0" in second_output


def test_cli_interrupt_explains_partial_cache_reuse(tmp_path, monkeypatch, capsys):
    cache_dir = tmp_path / "persistent-cache"
    monkeypatch.setattr(
        "ioc_rejudge.cli.build_providers", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        "ioc_rejudge.cli.run_unified_pipeline",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "interrupt.invalid",
            "--providers", "whois",
            "--cache-dir", str(cache_dir),
            "--jsonl", str(tmp_path / "result.jsonl"),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 130
    captured = capsys.readouterr()
    assert "Provider responses already written to the cache remain reusable" in captured.err
    assert "incomplete adjudication results are not cached" in captured.err


def test_cli_diff_baseline_writes_report_and_summary(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps({"ioc": "a.invalid", "conclusion": "误报"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--diff-baseline", str(baseline),
            "--jsonl", str(output),
        ],
    )

    main()

    diff_path = tmp_path / "result_diff.json"
    assert diff_path.is_file()
    report = json.loads(diff_path.read_text(encoding="utf-8"))
    assert report["transitions"] == {"误报->待复核": 1}
    assert len(report["to_review"]) == 1
    assert report["black_to_white"] == []
    captured = capsys.readouterr()
    assert "Diff report written to " in captured.out
    assert "changed=1" in captured.out
    assert "to_review=1" in captured.out


def test_cli_diff_output_custom_path(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps({"ioc": "a.invalid", "conclusion": "待复核"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.jsonl"
    custom = tmp_path / "custom" / "migration.json"
    custom.parent.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--diff-baseline", str(baseline),
            "--diff-output", str(custom),
            "--jsonl", str(output),
        ],
    )

    main()

    assert custom.is_file()
    assert not (tmp_path / "result_diff.json").exists()
    report = json.loads(custom.read_text(encoding="utf-8"))
    assert report["transitions"] == {"待复核->待复核": 1}
    assert report["changed"] == []


@pytest.mark.parametrize(
    "content",
    [None, '{"ioc": "a.invalid"}', "not json"],
    ids=["missing-file", "missing-conclusion", "bad-json"],
)
def test_cli_diff_baseline_rejects_bad_file(tmp_path, monkeypatch, capsys, content):
    baseline = tmp_path / "baseline.jsonl"
    if content is not None:
        baseline.write_text(content + "\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--diff-baseline", str(baseline),
            "--jsonl", str(output),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    assert "diff baseline" in capsys.readouterr().err
    assert not output.exists()


def test_cli_diff_output_requires_baseline(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "a.invalid",
            "--offline",
            "--diff-output", str(tmp_path / "diff.json"),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    assert "--diff-output requires --diff-baseline" in capsys.readouterr().err


def test_cli_diff_baseline_works_with_legacy_snapshot(tmp_path, monkeypatch):
    snapshot = tmp_path / "snapshot.jsonl"
    snapshot.write_text(
        json.dumps({
            "ioc": "legacy.invalid",
            "data": [{
                "key": "legacy.invalid",
                "host": "legacy.invalid",
                "level": 30,
                "source": ["spider"],
            }],
        }) + "\n",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps({"ioc": "legacy.invalid", "conclusion": "误报"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input", str(snapshot),
            "--diff-baseline", str(baseline),
            "--jsonl", str(output),
        ],
    )

    main()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["ioc"] for row in rows] == ["legacy.invalid"]
    report = json.loads((tmp_path / "result_diff.json").read_text(encoding="utf-8"))
    assert sum(report["transitions"].values()) == 1
    assert report["only_before"] == []
    assert report["only_after"] == []
