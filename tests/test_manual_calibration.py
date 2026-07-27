"""Generalized synthetic regressions derived from human calibration reasons."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.config import Config
from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.evidence import extract_evidence, is_malicious_sample
from ioc_rejudge.models import Conclusion, IocDossier, Verdict
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_hash_entry, build_record


_NOW = datetime(2026, 7, 24, 12, 0, 0)
_REASONS_PATH = Path(__file__).parent / "data" / "manual_calibration_reasons.json"
_CASES = json.loads(_REASONS_PATH.read_text(encoding="utf-8"))


@dataclass
class CalibrationOutcome:
    verdict: Verdict
    dossier: IocDossier | None = None
    excluded_samples: list[dict] = field(default_factory=list)


def _time(days_ago: int) -> str:
    return (_NOW - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _standard(record: dict) -> CalibrationOutcome:
    config = Config()
    dossier = extract_evidence(merge_records([record]), config)
    return CalibrationOutcome(adjudicate(dossier, config), dossier)


def _direct_sample(
    ioc: str,
    *,
    family: str,
    days_ago: int,
    context: str,
    source: list[str] | None = None,
) -> CalibrationOutcome:
    return _standard(build_record(
        ioc,
        level=70,
        source=source or ["sample-base"],
        context=context,
        hash_entries=[build_hash_entry(
            md5=f"synthetic-{ioc.split('.')[0]}",
            level=70,
            time=_time(days_ago),
            family=family,
        )],
    ))


def _r001() -> CalibrationOutcome:
    ioc = "analyst-context.invalid"
    return _direct_sample(
        ioc,
        family="Trojan.Loader",
        days_ago=10,
        context=f"Detailed analyst note: malware sample connected to {ioc} C2.",
    )


def _r002() -> CalibrationOutcome:
    ioc = "mining-node.invalid"
    return _direct_sample(
        ioc,
        family="CoinMiner",
        days_ago=20,
        context=f"Malware miner connected to {ioc} for command traffic.",
    )


def _r003() -> CalibrationOutcome:
    ioc = "operator-clue.invalid"
    return _standard(build_record(
        ioc,
        level=20,
        source=["manual"],
        comment="来源：线索群，确认恶意",
        icp_website="ICP-CONFLICT",
    ))


def _r004() -> CalibrationOutcome:
    ioc = "historical-miner.invalid"
    outcome = _direct_sample(
        ioc,
        family="CoinMiner",
        days_ago=1000,
        context=f"Historical malware miner connected to {ioc}; no asset handover observed.",
    )
    return outcome


def _r005() -> CalibrationOutcome:
    verdict = adjudicate_dga(
        "dga-icp.invalid",
        DgaFacts(
            sample_check_complete=True,
            has_current_icp=True,
            provider_statuses={"ioc_info": "no_data", "fdark": "no_data"},
        ),
        now=_NOW,
    )
    return CalibrationOutcome(verdict)


def _r006() -> CalibrationOutcome:
    ioc = "mining-variant.invalid"
    return _direct_sample(
        ioc,
        family="Miner.Downloader",
        days_ago=45,
        context=f"Trojan mining payload contacted {ioc} after execution.",
    )


def _r007() -> CalibrationOutcome:
    ioc = "remote-control.invalid"
    return _direct_sample(
        ioc,
        family="AsyncRAT",
        days_ago=2,
        context=f"AsyncRAT sample used {ioc} as a C2 endpoint.",
    )


def _r013() -> CalibrationOutcome:
    ioc = "icp-conflict.invalid"
    config = Config()
    records = [
        build_record(
            ioc,
            level=20,
            updatetime=_time(120),
            icp_website="ICP-HISTORICAL",
        ),
        build_record(
            ioc,
            level=70,
            source=["manual"],
            context=f"Rootkit sample connected to {ioc} C2.",
            updatetime=_time(2),
            icp_website="",
        ),
    ]
    dossier = extract_evidence(merge_records(records), config)
    dossier.current_icp_check_complete = True
    return CalibrationOutcome(adjudicate(dossier, config), dossier)


def _r016() -> CalibrationOutcome:
    ioc = "expired-phishing.invalid"
    return _standard(build_record(
        ioc,
        level=60,
        context=f"Historical phishing URL intelligence for {ioc}.",
        family=["phishing"],
        whois={"expiresDate": "2020-01-01"},
        relate_url=[
            {"url": f"https://{ioc}/login", "level": 60},
            {"url": f"https://{ioc}/reset", "level": 70},
        ],
    ))


def _r018() -> CalibrationOutcome:
    sample = build_hash_entry(
        family="not-a-virus:AdWare",
        level=90,
        time=_time(1),
    )
    assert is_malicious_sample(sample, Config()) is False
    verdict = adjudicate_dga(
        "dga-whois.invalid",
        DgaFacts(
            sample_check_complete=True,
            whois_expires=_NOW + timedelta(days=90),
            provider_statuses={"ioc_info": "success", "fdark": "no_data"},
        ),
        now=_NOW,
    )
    return CalibrationOutcome(verdict, excluded_samples=[sample])


def _r023() -> CalibrationOutcome:
    return _standard(build_record(
        "public-apt.invalid",
        level=70,
        malicious_type=["APT"],
        private=False,
        confidence=5,
        info_level=3,
        context="Public APT reference: https://reports.invalid/campaign-analysis",
        updatetime="2024-01-01 00:00:00",
    ))


_BUILDERS = {
    "R001": _r001,
    "R002": _r002,
    "R003": _r003,
    "R004": _r004,
    "R005": _r005,
    "R006": _r006,
    "R007": _r007,
    "R013": _r013,
    "R016": _r016,
    "R018": _r018,
    "R023": _r023,
}


def test_calibration_metadata_is_complete_and_synthetic():
    assert len(_CASES) == 11
    assert {case["case_id"] for case in _CASES} == set(_BUILDERS)
    assert all(set(case) == {"case_id", "human_label", "reason", "pattern"} for case in _CASES)
    assert all(".invalid" not in case["reason"] for case in _CASES)


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case["case_id"])
def test_manual_calibration_pattern(case):
    outcome = _BUILDERS[case["case_id"]]()
    verdict = outcome.verdict

    expected = case["human_label"]
    if expected == "black":
        assert verdict.conclusion in {Conclusion.ALIVE_VALID, Conclusion.INACTIVE_VALID}
        assert verdict.disposition == "block"
        assert verdict.route == "standard"
        assert verdict.conclusion.value in verdict.reason
    elif expected == "false_positive":
        assert verdict.conclusion == Conclusion.FALSE_POSITIVE
        assert verdict.disposition == "false_positive"
        assert verdict.route == "dga"
        assert "已确认无关联恶意样本" in verdict.reason
    elif expected == "review":
        assert verdict.conclusion == Conclusion.PENDING_REVIEW
        assert verdict.disposition == "review"
        assert "ICP" in verdict.reason
    elif expected == "gray":
        assert verdict.conclusion == Conclusion.GRAY
        assert verdict.disposition == "gray"
        assert "保留具体URL" in verdict.reason
    else:  # pragma: no cover - metadata schema guard
        pytest.fail(f"unknown human label: {expected}")

    if case["pattern"] == "expired_domain_retain_urls":
        assert len(verdict.retained_urls) == 2
        assert verdict.scope_actions[0]["action"] == "gray"
        assert all(action["action"] == "retain" for action in verdict.scope_actions[1:])
    if case["pattern"] == "dga_not_a_virus_whois":
        assert len(outcome.excluded_samples) == 1
        assert "WHOIS未过期" in verdict.reason
    if case["pattern"] == "structured_public_apt":
        assert outcome.dossier is not None
        assert any(
            evidence.field == "structured_public_apt"
            for evidence in outcome.dossier.evidence_c
        )
        assert "structured_public_apt" in verdict.hit_evidence
