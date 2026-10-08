"""Tests for the lightweight ``judge`` CLI adapter."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ioc_rejudge import quick_cli


ROOT = Path(__file__).resolve().parents[1]


def _run_module(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ioc_rejudge", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_judge_help_lists_core_options():
    result = _run_module("judge", "--help")
    assert result.returncode == 0
    text = result.stdout.lower()
    assert "usage:" in text
    assert "--stdin" in text
    assert "--file" in text
    assert "--preset" in text
    assert "ioc" in text


def test_judge_routes_from_package_main_subprocess(tmp_path):
    """``python -m ioc_rejudge judge`` must hit the adapter, not the bare CLI."""
    out = tmp_path / "result.jsonl"
    result = _run_module(
        "judge",
        "route-check.invalid",
        "--offline",
        "--jsonl",
        str(out),
        "--diagnostics",
        str(tmp_path / "diag.json"),
    )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == ["route-check.invalid"]


def test_main_module_source_routes_judge():
    source = (ROOT / "ioc_rejudge" / "__main__.py").read_text(encoding="utf-8")
    assert 'sys.argv[1] == "judge"' in source
    assert "quick_cli" in source


def test_positional_iocs_preserve_order_and_dedupe_via_main_cli(
    monkeypatch, tmp_path
):
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    code = quick_cli.main(
        [
            "b.invalid",
            "a.invalid",
            "b.invalid",
            "--offline",
            "--jsonl",
            str(tmp_path / "out.jsonl"),
        ]
    )

    assert code == 0
    assert len(captured) == 1
    argv = captured[0]
    # Adapter hands off once to the main CLI with stable --ioc order.
    iocs = [argv[i + 1] for i, part in enumerate(argv) if part == "--ioc"]
    assert iocs == ["b.invalid", "a.invalid", "b.invalid"]
    assert "--offline" in argv


def test_stdin_skips_blank_and_comment_lines(monkeypatch, tmp_path):
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO("# note\n\nfirst.invalid\n  \nsecond.invalid\n"),
    )

    code = quick_cli.main(["--stdin", "--offline", "--jsonl", str(tmp_path / "o.jsonl")])

    assert code == 0
    assert len(captured) == 1
    iocs = [
        captured[0][i + 1]
        for i, part in enumerate(captured[0])
        if part == "--ioc"
    ]
    assert iocs == ["first.invalid", "second.invalid"]


def test_stdin_empty_or_comments_only_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("# only comment\n\n"))

    code = quick_cli.main(["--stdin"])

    assert code != 0
    err = capsys.readouterr().err
    assert "stdin" in err.lower() or "no ioc" in err.lower() or "empty" in err.lower()


def test_stdin_empty_stream_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    code = quick_cli.main(["--stdin", "--offline"])

    assert code != 0
    err = capsys.readouterr().err
    assert err


def test_missing_input_source_returns_nonzero(capsys):
    code = quick_cli.main([])

    assert code != 0
    err = capsys.readouterr().err
    assert "stdin" in err.lower() or "file" in err.lower() or "ioc" in err.lower()


def test_unknown_preset_argparse_error_does_not_call_cli(monkeypatch):
    called = {"n": 0}

    def fake_cli_main() -> None:
        called["n"] += 1
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    with pytest.raises(SystemExit) as exc:
        quick_cli.main(["a.invalid", "--preset", "turbo"])

    assert exc.value.code == 2
    assert called["n"] == 0


def test_preset_refresh_maps_to_refresh_flag(monkeypatch):
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    code = quick_cli.main(["a.invalid", "--preset", "refresh"])

    assert code == 0
    assert "--refresh" in captured[0]
    assert "--offline" not in captured[0]


def test_preset_fast_and_standard_do_not_force_refresh(monkeypatch):
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    assert quick_cli.main(["a.invalid", "--preset", "fast"]) == 0
    assert "--refresh" not in captured[-1]

    assert quick_cli.main(["a.invalid", "--preset", "standard"]) == 0
    assert "--refresh" not in captured[-1]


def test_file_and_positional_keep_stable_order(monkeypatch, tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text(
        "# header\nfile-one.invalid\n\nfile-two.invalid\n",
        encoding="utf-8",
    )
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    code = quick_cli.main(
        ["pos.invalid", "--file", str(ioc_file), "--offline"]
    )

    assert code == 0
    iocs = [
        captured[0][i + 1]
        for i, part in enumerate(captured[0])
        if part == "--ioc"
    ]
    assert iocs == ["pos.invalid", "file-one.invalid", "file-two.invalid"]


def test_combined_positional_stdin_file_order(monkeypatch, tmp_path):
    ioc_file = tmp_path / "more.txt"
    ioc_file.write_text("from-file.invalid\n", encoding="utf-8")
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)
    monkeypatch.setattr(sys, "stdin", io.StringIO("from-stdin.invalid\n"))

    code = quick_cli.main(
        ["from-pos.invalid", "--stdin", "--file", str(ioc_file), "--offline"]
    )

    assert code == 0
    iocs = [
        captured[0][i + 1]
        for i, part in enumerate(captured[0])
        if part == "--ioc"
    ]
    assert iocs == [
        "from-pos.invalid",
        "from-stdin.invalid",
        "from-file.invalid",
    ]


def test_adapter_json_summary_on_stderr(monkeypatch, capsys):
    def fake_cli_main() -> None:
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    code = quick_cli.main(["a.invalid", "--offline", "--json"])

    assert code == 0
    err = capsys.readouterr().err.strip()
    payload = json.loads(err.splitlines()[-1])
    assert payload["command"] == "judge"
    assert payload["ioc_count"] == 1
    assert payload["preset"] == "standard"
    assert payload["offline"] is True


def test_passthrough_unknown_main_cli_flags(monkeypatch, tmp_path):
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)
    out = str(tmp_path / "r.jsonl")

    code = quick_cli.main(["a.invalid", "--offline", "--jsonl", out, "--strict"])

    assert code == 0
    assert "--jsonl" in captured[0]
    assert out in captured[0]
    assert "--strict" in captured[0]


def test_end_to_end_offline_judge_subprocess(tmp_path):
    out = tmp_path / "result.jsonl"
    result = _run_module(
        "judge",
        "alpha.invalid",
        "beta.invalid",
        "alpha.invalid",
        "--offline",
        "--jsonl",
        str(out),
        "--diagnostics",
        str(tmp_path / "diag.json"),
    )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == ["alpha.invalid", "beta.invalid"]


def test_small_input_keeps_expanded_ioc_argv(monkeypatch, tmp_path):
    """Below-threshold inputs must still expand as repeated --ioc tokens."""
    captured: list[list[str]] = []

    def fake_cli_main() -> None:
        captured.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    values = ["one.invalid", "two.invalid", "three.invalid"]
    code = quick_cli.main([*values, "--offline", "--jsonl", str(tmp_path / "o.jsonl")])

    assert code == 0
    argv = captured[0]
    assert "--input" not in argv
    iocs = [argv[i + 1] for i, part in enumerate(argv) if part == "--ioc"]
    assert iocs == values


def test_large_input_transfers_via_temp_input_file(monkeypatch, tmp_path):
    """Count threshold (>500) routes values through a single --input path."""
    captured: list[list[str]] = []
    seen_paths: list[str] = []

    def fake_cli_main() -> None:
        argv = list(sys.argv)
        captured.append(argv)
        assert "--input" in argv
        path = argv[argv.index("--input") + 1]
        seen_paths.append(path)
        assert Path(path).is_file()
        body = Path(path).read_text(encoding="utf-8")
        lines = [line for line in body.splitlines() if line.strip()]
        assert lines == values
        assert "--ioc" not in argv
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    # 600 values with intentional duplicates to exercise order preservation.
    values = [f"host-{i % 550}.invalid" for i in range(600)]
    code = quick_cli.main([*values, "--offline", "--jsonl", str(tmp_path / "o.jsonl")])

    assert code == 0
    assert len(captured) == 1
    assert "--input" in captured[0]
    assert "--ioc" not in captured[0]
    # Temp file must be removed after the adapter returns.
    for path in seen_paths:
        assert not Path(path).exists()


def test_large_input_offline_subprocess_verdicts_match_deduped(tmp_path):
    """End-to-end offline run with 600 values yields the deduped IOC set."""
    # Include duplicates so main-CLI dedupe is part of the contract.
    values = [f"bulk-{i % 550}.invalid" for i in range(600)]
    expected = list(dict.fromkeys(values))
    out = tmp_path / "bulk.jsonl"
    result = _run_module(
        "judge",
        *values,
        "--offline",
        "--jsonl",
        str(out),
        "--diagnostics",
        str(tmp_path / "diag.json"),
    )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == expected


def test_large_input_temp_file_cleaned_on_nonzero_exit(monkeypatch, tmp_path):
    """SystemExit(non-zero) still deletes the temp file and forwards the code."""
    seen_paths: list[str] = []

    def fake_cli_main() -> None:
        argv = list(sys.argv)
        assert "--input" in argv
        path = argv[argv.index("--input") + 1]
        seen_paths.append(path)
        assert Path(path).is_file()
        raise SystemExit(3)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    values = [f"fail-{i}.invalid" for i in range(600)]
    code = quick_cli.main([*values, "--offline", "--jsonl", str(tmp_path / "o.jsonl")])

    assert code == 3
    assert seen_paths
    for path in seen_paths:
        assert not Path(path).exists()


def test_adapter_json_includes_transfer_fields_for_large_input(monkeypatch, capsys):
    def fake_cli_main() -> None:
        raise SystemExit(0)

    monkeypatch.setattr("ioc_rejudge.cli.main", fake_cli_main)

    values = [f"json-{i}.invalid" for i in range(600)]
    code = quick_cli.main([*values, "--offline", "--json"])

    assert code == 0
    err = capsys.readouterr().err.strip()
    payload = json.loads(err.splitlines()[-1])
    assert payload["command"] == "judge"
    assert payload["ok"] is True
    assert payload["ioc_count"] == 600
    assert payload["value_count"] == 600
    assert payload["transferred_to_file"] is True
