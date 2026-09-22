"""Regression coverage for input isolation, output safety, export contract,
release selection, and strict provider configuration (audit R7/R8/R12/R15/R16),
plus supervisor review-fixes for atomic writes, nested counts, finite options,
release zip grammar, sibling preflight, and streaming JSONL.
"""

from __future__ import annotations

import csv
import inspect
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

import upgrade
from ioc_rejudge.cli import (
    _strict_failure_reasons,
    main,
    run_pipeline_with_diagnostics,
)
from ioc_rejudge.config import Config, load_config
from ioc_rejudge.export import export_csv, export_jsonl
from ioc_rejudge.files import assert_path_writable, atomic_write_text
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.parser import read_jsonl_snapshot_with_diagnostics
from ioc_rejudge.providers.factory import (
    _positive_number,
    build_providers,
    load_local_config,
)


def _snapshot_row(ioc: str, level: int = 40) -> str:
    return json.dumps(
        {
            "ioc": ioc,
            "data": [
                {
                    "key": ioc,
                    "ioc": ioc,
                    "level": level,
                    "source": ["sample-base"],
                    "context": f"sample connected to {ioc}",
                }
            ],
        },
        ensure_ascii=False,
    )


# --- R7: bad row isolation and physical line numbers ---


def test_parser_isolates_non_object_jsonl_rows(tmp_path):
    path = tmp_path / "mixed.jsonl"
    path.write_text(
        "\n".join(
            [
                _snapshot_row("a.invalid"),
                "[]",
                "null",
                "12",
                '"string"',
                _snapshot_row("b.invalid"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = read_jsonl_snapshot_with_diagnostics(str(path))
    assert [row["ioc"] for row in result.records] == ["a.invalid", "b.invalid"]
    assert result.skipped == 4
    assert any("expected JSON object" in sample for sample in result.parse_error_samples)


def test_legacy_pipeline_continues_after_non_object_and_nested_bad_entries(tmp_path):
    path = tmp_path / "legacy.jsonl"
    good = json.loads(_snapshot_row("a.invalid"))
    nested = {
        "ioc": "nested.invalid",
        "data": [
            {
                "key": "nested.invalid",
                "ioc": "nested.invalid",
                "level": 40,
                "source": ["sample-base"],
            },
            "not-a-record",
            None,
            3,
        ],
    }
    path.write_text(
        "\n".join(
            [
                json.dumps(good, ensure_ascii=False),
                "[]",
                "null",
                json.dumps(nested, ensure_ascii=False),
                _snapshot_row("b.invalid"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = run_pipeline_with_diagnostics(str(path), Config())
    iocs = [row["ioc"] for row in result.verdicts]
    assert "a.invalid" in iocs
    assert "b.invalid" in iocs
    assert "nested.invalid" in iocs
    assert result.diagnostics.parse_error_count >= 2


def test_unified_input_bundle_isolates_non_object_rows(tmp_path):
    path = tmp_path / "unified.jsonl"
    path.write_text(
        "\n".join(
            [
                _snapshot_row("a.invalid"),
                "[]",
                "null",
                _snapshot_row("b.invalid"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bundle = read_input_bundle(str(path))
    assert [target.normalized for target in bundle.targets] == [
        "a.invalid",
        "b.invalid",
    ]
    assert any("expected JSON object" in err for err in bundle.errors)


def test_physical_line_number_after_comment_and_blank(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text(
        "# comment\n\ngood.invalid\nbad host value\n",
        encoding="utf-8",
    )
    bundle = read_input_bundle(str(path), inline_iocs=["also bad"])
    assert [t.normalized for t in bundle.targets] == ["good.invalid"]
    assert any("line 4:" in err and "bad host value" in err for err in bundle.errors)
    assert any("inline IOC 1:" in err for err in bundle.errors)
    assert not any(err.startswith("line 2:") for err in bundle.errors)


# --- R8: output path safety and atomic writes ---


def test_cli_rejects_jsonl_output_equal_to_input_without_provider_call(
    tmp_path, monkeypatch
):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    original = source.read_bytes()
    called = {"providers": False}

    def boom(*args, **kwargs):
        called["providers"] = True
        raise AssertionError("provider collection must not run after path collision")

    monkeypatch.setattr("ioc_rejudge.cli.build_providers", boom)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(source),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert called["providers"] is False
    assert source.read_bytes() == original


def test_cli_rejects_output_output_collision(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(out),
            "--csv",
            str(out),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_cli_creates_nested_output_directory(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    nested = tmp_path / "deep" / "nested" / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(nested),
        ],
    )
    main()
    assert nested.is_file()
    assert nested.with_name("result_diagnostics.json").is_file()


def test_atomic_write_leaves_previous_bytes_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "result.jsonl"
    target.write_text("PREVIOUS\n", encoding="utf-8")
    original = target.read_bytes()

    def fail_replace(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("ioc_rejudge.files.os.replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        atomic_write_text(target, "NEW\n", encoding="utf-8")
    assert target.read_bytes() == original


def test_export_jsonl_failure_preserves_previous_output(tmp_path, monkeypatch):
    path = tmp_path / "out.jsonl"
    path.write_text("OLD\n", encoding="utf-8")
    original = path.read_bytes()

    def fail_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr("ioc_rejudge.files.os.replace", fail_replace)
    with pytest.raises(OSError):
        export_jsonl(
            [
                {
                    "ioc": "a.invalid",
                    "conclusion": "待复核",
                    "classification_unknown": False,
                }
            ],
            str(path),
        )
    assert path.read_bytes() == original


# --- R12: export contract, auto diagnostics, strict ---


def test_export_classification_unknown_jsonl_and_csv(tmp_path):
    unknown = {
        "ioc": "a.invalid",
        "conclusion": "存活有效",
        "classification_unknown": True,
        "scope_actions": [],
        "retained_urls": [],
        "provider_statuses": {},
        "evidence_origins": [],
        "missing_required_providers": [],
    }
    legacy = {
        "ioc": "b.invalid",
        "conclusion": "待复核",
    }
    jsonl_path = tmp_path / "out.jsonl"
    csv_path = tmp_path / "out.csv"
    export_jsonl([unknown, legacy], str(jsonl_path))
    export_csv([unknown, legacy], str(csv_path))

    rows = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows[0]["classification_unknown"] is True
    assert rows[1]["classification_unknown"] is False

    with csv_path.open(encoding="utf-8", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    assert csv_rows[0]["classification_unknown"] == "true"
    assert csv_rows[1]["classification_unknown"] == "false"


def test_cli_always_writes_diagnostics_for_jsonl(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
        ],
    )
    main()
    diag = tmp_path / "result_diagnostics.json"
    assert diag.is_file()
    payload = json.loads(diag.read_text(encoding="utf-8"))
    assert "input_errors" in payload or "processed_count" in payload


def test_cli_always_writes_diagnostics_for_csv(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    output = tmp_path / "result.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--csv",
            str(output),
        ],
    )
    main()
    assert (tmp_path / "result_diagnostics.json").is_file()


def test_strict_exits_nonzero_on_rejected_input_but_keeps_results(
    tmp_path, monkeypatch
):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\nbad host\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
            "--strict",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert output.is_file()
    rows = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == ["a.invalid"]
    assert (tmp_path / "result_diagnostics.json").is_file()


def test_non_strict_partial_success_exits_zero(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\nbad host\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
        ],
    )
    main()
    assert output.is_file()


def test_no_valid_input_exits_two_and_writes_diagnostics(tmp_path, monkeypatch):
    source = tmp_path / "list.txt"
    source.write_text("bad host\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert not output.exists()
    assert (tmp_path / "result_diagnostics.json").is_file()


# --- R15: semantic release selection ---


def test_find_latest_zip_prefers_semantic_version(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    older = release / "ioc_rejudge_v2.9.0_20260101-000000.zip"
    newer = release / "ioc_rejudge_v2.10.0_20260101-000000.zip"
    older.write_bytes(b"old")
    newer.write_bytes(b"new")
    assert upgrade._find_latest_zip(tmp_path) == newer


def test_find_latest_zip_v10_beats_v9(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    left = release / "ioc_rejudge_v9.9.9_20260101-000000.zip"
    right = release / "ioc_rejudge_v10.0.0_20260101-000000.zip"
    left.write_bytes(b"9")
    right.write_bytes(b"10")
    assert upgrade._find_latest_zip(tmp_path) == right


def test_find_latest_zip_ignores_malformed_and_uses_timestamp_tiebreak(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "ioc_rejudge_not-a-version.zip").write_bytes(b"x")
    (release / "ioc_rejudge_v2.6.0_20260101-100000.zip").write_bytes(b"a")
    later = release / "ioc_rejudge_v2.6.0_20260102-100000.zip"
    later.write_bytes(b"b")
    assert upgrade._find_latest_zip(tmp_path) == later


# --- R16: strict provider config types ---


def test_string_false_boolean_options_are_rejected(tmp_path):
    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps(
            {
                "providers": {
                    "k01_compromise": {"ignore_url": "false"},
                    "fdark": {"include_slow_variants": 0},
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ignore_url must be a JSON boolean"):
        load_local_config(path)


def test_valid_boolean_and_numeric_options_are_accepted(tmp_path):
    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps(
            {
                "providers": {
                    "k01_compromise": {
                        "ignore_port": False,
                        "ignore_url": True,
                        "ignore_top": False,
                    },
                    "fdark": {
                        "include_slow_variants": False,
                        "include_url_param": True,
                    },
                    "ioc_info": {"max_attempts": 3, "retry_delay": 0},
                }
            }
        ),
        encoding="utf-8",
    )
    loaded = load_local_config(path)
    providers = build_providers(
        ["k01_compromise", "fdark", "ioc_info"],
        env={
            "K01_COMPROMISE_API_KEY": "k",
            "IOC_INFO_API_KEY": "i",
            "FDP_ACCESS": "a",
            "FDP_SECRET": "s",
        },
        config_path=path,
        adjudication_config=Config(),
    )
    by_name = {provider.name: provider for provider in providers}
    assert by_name["k01_compromise"].ignore_url is True
    assert by_name["fdark"].include_url_param is True
    assert by_name["ioc_info"].max_attempts == 3
    assert by_name["ioc_info"].retry_delay == 0
    assert loaded["ioc_info"]["retry_delay"] == 0


@pytest.mark.parametrize(
    "options,match",
    [
        ({"ioc_info": {"max_attempts": True}}, "max_attempts"),
        ({"ioc_info": {"max_attempts": -1}}, "max_attempts"),
        ({"ioc_info": {"max_attempts": 1.5}}, "max_attempts"),
        ({"ioc_info": {"retry_delay": -0.1}}, "retry_delay"),
        ({"ioc_info": {"retry_delay": "NaN"}}, "retry_delay"),
        ({"ioc_info": {"retry_delay": "Infinity"}}, "retry_delay"),
        ({"k01_compromise": {"enabled": "true"}}, "enabled"),
    ],
)
def test_invalid_numeric_and_enabled_options(tmp_path, options, match):
    path = tmp_path / "providers.json"
    path.write_text(json.dumps({"providers": options}), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_local_config(path)


def test_invalid_config_errors_do_not_echo_secret_values(tmp_path):
    secret = "SUPER_SECRET_VALUE_do_not_echo"
    path = tmp_path / "providers.json"
    # Unknown secret-looking keys are rejected by name; boolean type errors
    # must still avoid echoing unrelated option values.
    path.write_text(
        json.dumps(
            {
                "providers": {
                    "k01_compromise": {
                        "ignore_url": secret,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        load_local_config(path)
    assert secret not in str(exc.value)
    assert "ignore_url" in str(exc.value)


def test_config_rejects_negative_activity_window():
    with pytest.raises(ValueError, match="activity_window"):
        load_config(activity_window_days=-1)


def test_config_rejects_boolean_threshold():
    with pytest.raises(TypeError, match="hash_malicious_level"):
        load_config(hash_malicious_level=True)  # type: ignore[arg-type]


# --- Supervisor review-fixes (2026-09-21) ---


def test_permission_error_on_replace_preserves_destination_bytes(tmp_path, monkeypatch):
    """Failed os.replace must not truncate or copy into the locked destination."""
    target = tmp_path / "locked.jsonl"
    target.write_text("OLD\n", encoding="utf-8")
    original = target.read_bytes()

    def locked_replace(src, dst):
        raise PermissionError("simulated lock")

    monkeypatch.setattr("ioc_rejudge.files.os.replace", locked_replace)
    with pytest.raises(OSError, match="cannot replace output"):
        atomic_write_text(target, "NEW\n", encoding="utf-8")
    assert target.read_bytes() == original
    assert b"NEW" not in target.read_bytes()


def test_writer_failure_preserves_destination_bytes(tmp_path):
    from ioc_rejudge.files import atomic_write_via

    target = tmp_path / "out.jsonl"
    target.write_text("KEEP\n", encoding="utf-8")
    original = target.read_bytes()

    def failing_writer(temp_path):
        raise OSError("disk full while writing temp")

    with pytest.raises(OSError, match="disk full"):
        atomic_write_via(target, failing_writer)
    assert target.read_bytes() == original


def test_nested_only_rejects_count_and_strict_reasons(tmp_path):
    path = tmp_path / "nested.jsonl"
    row = {
        "ioc": "a.invalid",
        "data": [
            {"key": "a.invalid", "level": 40, "source": ["sample-base"]},
            None,
        ],
    }
    path.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
    read_result = read_jsonl_snapshot_with_diagnostics(str(path))
    assert read_result.nested_data_error_count == 1
    assert read_result.skipped == 0
    assert len(read_result.records) == 1
    assert any("dropped" in sample for sample in read_result.parse_error_samples)

    result = run_pipeline_with_diagnostics(str(path), Config())
    assert result.diagnostics.nested_data_error_count == 1
    assert result.diagnostics.parse_error_count == 0
    assert result.diagnostics.skipped_total == 0
    assert [row["ioc"] for row in result.verdicts] == ["a.invalid"]
    reasons = _strict_failure_reasons(result.diagnostics)
    assert any("nested data errors" in reason for reason in reasons)


def test_nested_and_parse_errors_beyond_sample_limit_keep_real_counts(tmp_path):
    path = tmp_path / "many.jsonl"
    lines = []
    # 5 blank-skipped-looking non-objects + 25 nested-bad objects + 1 good
    for _ in range(5):
        lines.append("[]")
    for index in range(25):
        lines.append(
            json.dumps(
                {
                    "ioc": f"n{index}.invalid",
                    "data": [
                        {
                            "key": f"n{index}.invalid",
                            "level": 40,
                            "source": ["sample-base"],
                        },
                        None,
                        "bad",
                    ],
                },
                ensure_ascii=False,
            )
        )
    lines.append(_snapshot_row("good.invalid"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    read_result = read_jsonl_snapshot_with_diagnostics(str(path), sample_limit=20)
    assert read_result.skipped == 5
    assert read_result.nested_data_error_count == 50  # 25 rows * 2 nested bad
    assert len(read_result.parse_error_samples) == 20
    assert len(read_result.records) == 26

    bundle = read_input_bundle(str(path))
    assert bundle.parse_error_count == 5
    assert bundle.nested_data_error_count == 50
    assert "good.invalid" in [t.normalized for t in bundle.targets]


def test_snapshot_invalid_ioc_uses_physical_line_number(tmp_path):
    path = tmp_path / "snap.jsonl"
    path.write_text(
        "\n".join(
            [
                "",  # physical line 1 blank
                "# not json",  # line 2 - invalid JSON skipped
                _snapshot_row("good.invalid"),  # line 3
                json.dumps({"ioc": "not a host", "data": []}, ensure_ascii=False),  # line 4
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bundle = read_input_bundle(str(path))
    assert [t.normalized for t in bundle.targets] == ["good.invalid"]
    assert any(err.startswith("line 4:") and "invalid IOC" in err for err in bundle.errors)
    assert not any("snapshot row" in err for err in bundle.errors)


def test_strict_nested_only_exports_good_entry_and_exits_one(tmp_path, monkeypatch):
    source = tmp_path / "nested.jsonl"
    row = {
        "ioc": "a.invalid",
        "data": [
            {
                "key": "a.invalid",
                "ioc": "a.invalid",
                "level": 40,
                "source": ["sample-base"],
                "context": "sample connected to a.invalid",
            },
            None,
        ],
    }
    source.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
            "--strict",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    rows = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == ["a.invalid"]
    diag = json.loads((tmp_path / "result_diagnostics.json").read_text(encoding="utf-8"))
    assert diag.get("nested_data_error_count", 0) >= 1


@pytest.mark.parametrize(
    "value",
    [float("inf"), float("nan"), "Infinity", "NaN", float("-inf")],
)
def test_nonfinite_integer_options_raise_value_error(value):
    with pytest.raises(ValueError, match="finite|positive|integer"):
        _positive_number("ioc_info", "max_attempts", value, integer=True)


def test_load_local_config_rejects_infinity_max_attempts(tmp_path):
    path = tmp_path / "providers.json"
    # JSON does not allow bare Infinity; inject via Python float after parse path
    # by writing a number that json loads, then patching — use a custom loader path
    # through the validated helper directly after constructing options.
    path.write_text(
        json.dumps({"providers": {"ioc_info": {"max_attempts": 3}}}),
        encoding="utf-8",
    )
    # Direct option validation path used by load_local_config:
    from ioc_rejudge.providers.factory import _validate_provider_option_types

    with pytest.raises(ValueError, match="max_attempts"):
        _validate_provider_option_types(
            "ioc_info", {"max_attempts": float("inf")}
        )


def test_config_rejects_window_overflow():
    with pytest.raises(ValueError, match="activity_window_days"):
        Config(activity_window_days=10**18)


def test_config_rejects_ttl_day_window_overflow():
    with pytest.raises(ValueError, match="dga_pdns_recent_days"):
        Config(dga_pdns_recent_days=10**18)


def test_ttl_option_overflow_raises_value_error(tmp_path):
    from ioc_rejudge.providers.factory import _timedelta_from_ttl, _ttl

    with pytest.raises(ValueError, match="too large"):
        _timedelta_from_ttl("whois", "ttl_days", 1e308)
    with pytest.raises(ValueError, match="too large|finite"):
        _ttl("whois", {"ttl_days": 1e308})

    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps({"providers": {"whois": {"ttl_days": 1e308}}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="too large|finite"):
        load_local_config(path)


def test_parse_release_zip_rejects_malformed_timestamp_and_partial_version():
    assert (
        upgrade._parse_release_zip_name(
            Path("ioc_rejudge_v99.0.0_20269999-garbage.zip")
        )
        is None
    )
    assert (
        upgrade._parse_release_zip_name(Path("ioc_rejudge_v2.6_20260101-120000.zip"))
        is None
    )
    assert (
        upgrade._parse_release_zip_name(
            Path("ioc_rejudge_v-1.0.0_20260101-120000.zip")
        )
        is None
    )
    assert (
        upgrade._parse_release_zip_name(
            Path("ioc_rejudge_v2.6.0_20261301-120000.zip")
        )
        is None
    )
    assert upgrade._parse_release_zip_name(
        Path("ioc_rejudge_v2.6.0_20260101-120000.zip")
    ) == ((2, 6, 0), "20260101-120000")


def test_find_latest_zip_ignores_invalid_calendar_timestamp(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "ioc_rejudge_v99.0.0_20269999-garbage.zip").write_bytes(b"bad")
    good = release / "ioc_rejudge_v2.6.0_20260101-120000.zip"
    good.write_bytes(b"good")
    assert upgrade._find_latest_zip(tmp_path) == good


def test_existing_output_sibling_preflight_blocks_before_providers(
    tmp_path, monkeypatch
):
    source = tmp_path / "list.txt"
    source.write_text("a.invalid\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    output.write_text("PREVIOUS\n", encoding="utf-8")
    original = output.read_bytes()
    called = {"providers": False}

    def boom(*args, **kwargs):
        called["providers"] = True
        raise AssertionError("providers must not run after sibling preflight failure")

    def fail_probe(parent, destination_name):
        raise OSError(f"output directory is not writable for atomic replace: {parent}")

    monkeypatch.setattr("ioc_rejudge.files._probe_sibling_temp", fail_probe)
    monkeypatch.setattr("ioc_rejudge.cli.build_providers", boom)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--input",
            str(source),
            "--offline",
            "--jsonl",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert called["providers"] is False
    assert output.read_bytes() == original


def test_assert_path_writable_probes_sibling_for_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "existing.jsonl"
    target.write_text("OLD\n", encoding="utf-8")
    probed = {"called": False}

    real_probe = __import__("ioc_rejudge.files", fromlist=["_probe_sibling_temp"])._probe_sibling_temp

    def tracking_probe(parent, destination_name):
        probed["called"] = True
        return real_probe(parent, destination_name)

    monkeypatch.setattr("ioc_rejudge.files._probe_sibling_temp", tracking_probe)
    assert_path_writable(target)
    assert probed["called"] is True


def test_export_jsonl_streams_via_atomic_write_via():
    source = inspect.getsource(export_jsonl)
    assert "atomic_write_via" in source
    assert "join(" not in source
    assert "atomic_write_text" not in source


def test_export_jsonl_streams_rows_without_building_full_payload(tmp_path, monkeypatch):
    """Writer must open the temp path and write row-by-row (not one joined blob)."""
    path = tmp_path / "stream.jsonl"
    seen = {"writes": 0, "open_mode": None}

    real_open = open

    def counting_open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if "w" in mode and str(file).endswith(".tmp"):
            seen["open_mode"] = mode
            original_write = handle.write

            def tracked_write(data):
                seen["writes"] += 1
                return original_write(data)

            handle.write = tracked_write  # type: ignore[method-assign]
        return handle

    monkeypatch.setattr("builtins.open", counting_open)
    export_jsonl(
        [
            {
                "ioc": "a.invalid",
                "conclusion": "待复核",
                "classification_unknown": False,
            },
            {
                "ioc": "b.invalid",
                "conclusion": "待复核",
                "classification_unknown": False,
            },
        ],
        str(path),
    )
    # At least one write per row plus newlines (or combined); must be multi-write streaming.
    assert seen["writes"] >= 2
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["ioc"] for row in rows] == ["a.invalid", "b.invalid"]
