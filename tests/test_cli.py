import json
import tempfile
import os
import sys
import pytest
from ioc_rejudge.cli import run_pipeline, run_pipeline_with_diagnostics, main
from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Observation, ProviderStatus
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult


def test_full_pipeline_with_real_data():
    lines = [
        {
            "ioc": "test.com",
            "data": [
                {
                    "key": "test.com",
                    "host": "test.com",
                    "level": 70,
                    "category": "DOMAIN_PORT",
                    "source": ["sample-base"],
                    "context": "Sample connected to test.com C2",
                    "hash": [{"md5": "abc", "level": 70, "time": "2026-03-20 17:10:41"}],
                    "family": ["SilverFox"],
                }
            ],
        },
        {
            "ioc": "normal.com",
            "data": [
                {
                    "key": "normal.com",
                    "host": "normal.com",
                    "level": 30,
                    "source": ["spider"],
                    "official_website": "https://www.google.com",
                }
            ],
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as sf:
        for line in lines:
            sf.write(json.dumps(line, ensure_ascii=False) + "\n")
        sf.flush()

        verdicts = run_pipeline(sf.name, Config())
        assert len(verdicts) == 2
        iocs = {v["ioc"] for v in verdicts}
        assert "test.com" in iocs
        assert "normal.com" in iocs

    os.unlink(sf.name)


def test_legacy_pipeline_skips_invalid_url_and_continues(tmp_path):
    bad_url = "https://bad.invalid:99999/a"
    snapshot = tmp_path / "mixed.jsonl"
    rows = [
        {
            "ioc": bad_url,
            "data": [{
                "key": bad_url,
                "host": bad_url,
                "category": "URL",
                "level": 70,
            }],
        },
        {
            "ioc": "good.invalid",
            "data": [{
                "key": "good.invalid",
                "host": "good.invalid",
                "category": "DOMAIN_PORT",
                "level": 30,
            }],
        },
    ]
    snapshot.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )

    result = run_pipeline_with_diagnostics(str(snapshot), Config())

    assert [row["ioc"] for row in result.verdicts] == ["good.invalid"]
    assert result.diagnostics.invalid_ioc_count == 1
    assert result.diagnostics.skipped_total == 1
    assert any(
        sample.startswith("invalid IOC: https://bad.invalid:99999/a")
        for sample in result.diagnostics.skipped_row_samples
    )


def test_pipeline_populates_excel_review_fields():
    line = {
        "ioc": "review.com",
        "data": [
            {
                "key": "review.com",
                "host": "review.com",
                "level": 70,
                "source": ["sample-base"],
                "alert_name": "APT Alert",
                "add_date": "2026-05-01",
                "update_date": "2026-05-02",
                "campaign": "CampaignX",
                "malicious_family": "SilverFox",
                "malicious_type": ["TROJAN"],
                "submitter": "alice",
                "comment": "sample comment",
                "context": "Sample connected to review.com C2",
                "hash": [
                    {"md5": "low", "level": 10, "time": "2026-04-01 00:00:00"},
                    {"md5": "high", "level": 70, "time": "2026-05-01 00:00:00"},
                ],
            }
        ],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as sf:
        sf.write(json.dumps(line, ensure_ascii=False) + "\n")
        sf.flush()

        verdicts = run_pipeline(sf.name, Config())
        row = verdicts[0]
        assert row["alert_info"] == (
            "alert_name:APT Alert\n"
            "add_date:2026-05-01\n"
            "update_date:2026-05-02\n"
            "campaign:CampaignX\n"
            "malicious_family:SilverFox\n"
            "malicious_type:TROJAN"
        )
        assert row["submitter"] == "alice"
        assert row["comment"] == "sample comment"
        assert row["context"] == "Sample connected to review.com C2"
        assert row["md5"] == "high"
        assert row["md5_list"] == "low,high"

    os.unlink(sf.name)


def test_cli_no_valid_rows_does_not_generate_empty_excel(monkeypatch):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as sf:
        sf.write("not json\n")
        sf.write(json.dumps({"ioc": "missing-data"}, ensure_ascii=False) + "\n")
        sf.flush()
        input_path = sf.name

    xlsx_path = os.path.splitext(input_path)[0] + "_result.xlsx"
    diag_path = os.path.splitext(input_path)[0] + "_diagnostics.json"

    try:
        monkeypatch.setattr(sys, "argv", ["ioc_rejudge", "-i", input_path])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
        assert not os.path.exists(xlsx_path)
        assert os.path.exists(diag_path)
        with open(diag_path, encoding="utf-8") as f:
            diag = json.load(f)
        assert diag["processed_count"] == 0
        assert diag["skipped_total"] == 2
    finally:
        for path in (input_path, xlsx_path, diag_path):
            if os.path.exists(path):
                os.unlink(path)


class _ResultProvider:
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


def test_unified_pipeline_raw_offline_without_facts_is_review_and_stable_order():
    bundle = read_input_bundle(None, ["b.invalid", "a.invalid"])
    result = run_unified_pipeline(bundle, [], Config(), ProviderContext(offline=True))

    assert [row["ioc"] for row in result.verdicts] == ["b.invalid", "a.invalid"]
    assert [row["conclusion"] for row in result.verdicts] == ["待复核", "待复核"]
    assert all(row["route"] == "standard" for row in result.verdicts)
    assert all(row["disposition"] == "review" for row in result.verdicts)


def test_unified_pipeline_provider_exception_isolated_per_batch():
    bundle = read_input_bundle(None, ["a.invalid", "b.invalid"])
    broken = _ResultProvider("broken", error=RuntimeError("boom"))

    result = run_unified_pipeline(
        bundle,
        [broken],
        Config(),
        ProviderContext(offline=True),
    )

    assert len(result.verdicts) == 2
    assert all(row["provider_statuses"]["broken"] == "error" for row in result.verdicts)
    assert result.diagnostics.provider_errors["broken"] == ["boom"]


def test_dga_classification_error_keeps_strong_malicious_standard_closure():
    bundle = read_input_bundle(None, ["evil.invalid"])

    def dga_error(targets):
        return ProviderResult(
            name="k01_compromise",
            statuses={target.normalized: ProviderStatus.ERROR for target in targets},
        )

    def intel_success(targets):
        target = targets[0]
        return ProviderResult(
            name="ioc_info",
            observations=[Observation(
                ioc=target.normalized,
                scope="ioc",
                provider="ioc_info",
                kind="ioc_info_record",
                status=ProviderStatus.SUCCESS,
                observed_at=None,
                payload={
                    "key": target.normalized,
                    "host": target.host,
                    "level": 70,
                    "source": ["sample-base"],
                    "context": f"sample connected to {target.normalized} C2",
                    "hash": [{"md5": "abc", "level": 70, "time": "2026-07-01"}],
                    "family": ["trojan"],
                },
            )],
            statuses={target.normalized: ProviderStatus.SUCCESS},
        )

    result = run_unified_pipeline(
        bundle,
        [
            _ResultProvider("k01_compromise", result=dga_error),
            _ResultProvider("ioc_info", result=intel_success),
        ],
        Config(),
        ProviderContext(offline=True),
    )

    row = result.verdicts[0]
    assert row["route"] == "standard"
    assert row["classification_unknown"] is True
    assert row["conclusion"] in {"存活有效", "失活有效"}
    assert row["disposition"] == "block"


def test_cli_inline_iocs_support_offline_jsonl_and_preserve_order(tmp_path, monkeypatch):
    output = tmp_path / "result.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "b.invalid",
            "--ioc", "a.invalid",
            "--offline",
            "--jsonl", str(output),
        ],
    )

    main()

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["ioc"] for row in rows] == ["b.invalid", "a.invalid"]
    assert all(row["conclusion"] == "待复核" for row in rows)


@pytest.mark.parametrize("value", ["missing_equals", "=missing-name", "bad name=x.jsonl"])
def test_cli_rejects_invalid_provider_data(value, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["ioc_rejudge", "--ioc", "a.invalid", "--provider-data", value],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
