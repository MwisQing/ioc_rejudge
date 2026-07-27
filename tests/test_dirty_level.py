"""Dirty level fields (null / string) must not crash any adjudication path."""
import json

from ioc_rejudge.adjudicator import adjudicate, _has_threat_residue
from ioc_rejudge.cli import run_pipeline_with_diagnostics
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.normalize import merge_records
from ioc_rejudge.observations import Observation, ProviderStatus
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult


_DIRTY_RECORD = {
    "key": "dirty.invalid",
    "host": "dirty.invalid",
    "level": None,
    "source": ["sample-base"],
    "relate_ip_domain": [{"key": "r.invalid", "level": None}],
    "dtree": [
        {"key": "d.invalid", "last": "2026-07-01 00:00:00", "count": 1, "level": "high"},
    ],
    "hash": [{"md5": "m1", "level": None, "time": "2026-07-01 00:00:00"}],
}


def test_merge_records_tolerates_dirty_top_level_level():
    records = [
        dict(_DIRTY_RECORD),
        {"key": "dirty.invalid", "host": "dirty.invalid", "level": "high"},
        {"key": "dirty.invalid", "host": "dirty.invalid", "level": "70"},
    ]

    dossier = merge_records(records)

    assert dossier.ioc == "dirty.invalid"


def test_adjudicate_and_residue_tolerate_dirty_nested_levels():
    config = Config()
    dossier = merge_records([dict(_DIRTY_RECORD)])
    dossier = extract_evidence(dossier, config)

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion is not None
    assert _has_threat_residue(dossier, config) in (True, False)


def test_legacy_pipeline_survives_dirty_level_rows(tmp_path):
    snapshot = tmp_path / "dirty.jsonl"
    rows = [
        {"ioc": "dirty.invalid", "data": [dict(_DIRTY_RECORD)]},
        {"ioc": "clean.invalid", "data": [{
            "key": "clean.invalid",
            "host": "clean.invalid",
            "level": 30,
            "source": ["spider"],
        }]},
    ]
    snapshot.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )

    result = run_pipeline_with_diagnostics(str(snapshot), Config())

    iocs = [row["ioc"] for row in result.verdicts]
    assert "clean.invalid" in iocs
    assert "dirty.invalid" in iocs


class _PayloadProvider:
    name = "ioc_info"

    def __init__(self, payloads):
        self._payloads = payloads

    def supports(self, target):
        return True

    def collect(self, targets, context):
        observations = []
        statuses = {}
        for target in targets:
            payload = self._payloads.get(target.normalized)
            if payload:
                statuses[target.normalized] = ProviderStatus.SUCCESS
                observations.append(Observation(
                    ioc=target.normalized,
                    scope="domain",
                    provider=self.name,
                    kind="ioc_info_record",
                    status=ProviderStatus.SUCCESS,
                    observed_at=None,
                    payload=dict(payload),
                ))
            else:
                statuses[target.normalized] = ProviderStatus.NO_DATA
        return ProviderResult(
            name=self.name,
            observations=observations,
            statuses=statuses,
        )


def test_unified_pipeline_survives_dirty_level_payload():
    bundle = read_input_bundle(None, ["dirty.invalid", "clean.invalid"])
    provider = _PayloadProvider({"dirty.invalid": dict(_DIRTY_RECORD)})

    result = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(offline=True),
    )

    assert [row["ioc"] for row in result.verdicts] == ["dirty.invalid", "clean.invalid"]


def test_unified_serialize_failure_degrades_single_ioc(monkeypatch):
    import ioc_rejudge.pipeline as pipeline_module

    bundle = read_input_bundle(None, ["boom.invalid", "ok.invalid"])
    provider = _PayloadProvider({"boom.invalid": {
        "key": "boom.invalid",
        "host": "boom.invalid",
        "level": 70,
        "source": ["sample-base"],
    }})

    real = pipeline_module._has_threat_residue

    def explode(dossier, config):
        if dossier.ioc == "boom.invalid":
            raise TypeError("synthetic residue failure")
        return real(dossier, config)

    monkeypatch.setattr(pipeline_module, "_has_threat_residue", explode)

    result = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(offline=True),
    )

    rows = {row["ioc"]: row for row in result.verdicts}
    assert set(rows) == {"boom.invalid", "ok.invalid"}
    assert rows["boom.invalid"]["conclusion"] == "待复核"
    assert "boom.invalid" in result.diagnostics.processing_errors
