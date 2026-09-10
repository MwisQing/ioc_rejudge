"""Regression coverage for current ICP aggregation and conflicts."""

from datetime import datetime, timedelta

import pytest

from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.config import Config
from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.models import Evidence, EvidenceLevel, EvidenceStrength, IocDossier, Conclusion
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
from ioc_rejudge.pipeline import (
    _apply_current_icp_state,
    _build_dga_facts,
    _has_current_icp,
    run_unified_pipeline,
)
from ioc_rejudge.providers.base import ProviderContext, ProviderResult


NOW = datetime(2026, 7, 23, 12, 0, 0)
_MISSING = object()


def _icp_observation(
    *,
    kind="icp",
    status=ProviderStatus.SUCCESS,
    freshness=Freshness.FRESH,
    current=False,
    registration=_MISSING,
    provider="icp",
):
    payload = {"current": current}
    if registration is not _MISSING:
        payload["registration"] = registration
    return Observation(
        ioc="conflict.invalid",
        scope="domain",
        provider=provider,
        kind=kind,
        status=status,
        freshness=freshness,
        payload=payload,
    )


def _dossier(*, ioc="conflict.invalid"):
    dossier = IocDossier(ioc=ioc, ioc_type="domain")
    dossier.icp_website = "OLD-REGISTRATION"
    dossier.current_icp_conflict = True
    return dossier


def _evidence(
    field,
    *,
    level=EvidenceLevel.A,
    strength=EvidenceStrength.STRONG,
    tags=(),
):
    return Evidence(
        level=level,
        field=field,
        detail=field,
        strength=strength,
        tags=list(tags),
    )


def test_historical_ioc_info_icp_does_not_become_current_state():
    dossier = _dossier()
    observation = _icp_observation(
        kind="ioc_info_record",
        current=True,
        registration="HISTORICAL-ICP",
    )

    assert _has_current_icp([observation], {"icp": ProviderStatus.SUCCESS}) is False
    _apply_current_icp_state(dossier, [observation], {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == "OLD-REGISTRATION"
    assert dossier.current_icp_check_complete is False
    assert dossier.current_icp_conflict is True


def test_typed_positive_sets_trimmed_registration_and_completes():
    dossier = _dossier()
    observation = _icp_observation(
        kind="icp_registration",
        current=True,
        registration="  ICP-CURRENT  ",
    )

    assert _has_current_icp([observation], {"icp": ProviderStatus.SUCCESS}) is True
    _apply_current_icp_state(dossier, [observation], {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == "ICP-CURRENT"
    assert dossier.current_icp_check_complete is True
    assert dossier.current_icp_conflict is False


def test_typed_negative_clears_registration_and_completes():
    dossier = _dossier()
    observation = _icp_observation(kind="icp_record", current=False)

    _apply_current_icp_state(dossier, [observation], {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == ""
    assert dossier.current_icp_check_complete is True
    assert dossier.current_icp_conflict is False


@pytest.mark.parametrize(
    ("status", "freshness"),
    [
        (ProviderStatus.ERROR, Freshness.FRESH),
        (ProviderStatus.DISABLED, Freshness.FRESH),
        (ProviderStatus.SUCCESS, Freshness.UNKNOWN),
        (ProviderStatus.SUCCESS, Freshness.STALE),
    ],
    ids=["error", "disabled", "unknown", "stale"],
)
def test_failed_or_nonfresh_observations_do_not_complete_current_check(status, freshness):
    dossier = _dossier()
    observation = _icp_observation(
        status=status,
        freshness=freshness,
        current=False,
    )

    _apply_current_icp_state(dossier, [observation], {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == "OLD-REGISTRATION"
    assert dossier.current_icp_check_complete is False
    assert dossier.current_icp_conflict is True


@pytest.mark.parametrize("aggregate", [
    ProviderStatus.ERROR, ProviderStatus.DISABLED, ProviderStatus.NO_DATA, None,
])
def test_provider_status_must_also_be_success(aggregate):
    dossier = _dossier()
    observation = _icp_observation(current=False)

    assert _has_current_icp([observation], {"icp": aggregate}) is False
    _apply_current_icp_state(dossier, [observation], {"icp": aggregate})

    assert dossier.icp_website == "OLD-REGISTRATION"
    assert dossier.current_icp_check_complete is False


@pytest.mark.parametrize("registration", ["", "   ", None, 123])
def test_dirty_positive_current_or_registration_is_ignored(registration):
    dossier = _dossier()
    observation = _icp_observation(current=True, registration=registration)

    _apply_current_icp_state(dossier, [observation], {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == "OLD-REGISTRATION"
    assert dossier.current_icp_check_complete is False
    assert dossier.current_icp_conflict is True


@pytest.mark.parametrize(
    "observations",
    [
        [
            _icp_observation(current=True, registration="ICP-CURRENT"),
            _icp_observation(current=False),
        ],
        [
            _icp_observation(current=False),
            _icp_observation(current=True, registration="ICP-CURRENT"),
        ],
    ],
    ids=["positive-then-negative", "negative-then-positive"],
)
def test_positive_and_negative_current_icp_is_order_independent_conflict(observations):
    dossier = _dossier()

    _apply_current_icp_state(dossier, observations, {"icp": ProviderStatus.SUCCESS})

    assert dossier.icp_website == "OLD-REGISTRATION"
    assert dossier.current_icp_check_complete is False
    assert dossier.current_icp_conflict is True


def test_multiple_positive_registrations_choose_deterministically():
    observations = [
        _icp_observation(current=True, registration="ICP-Z"),
        _icp_observation(current=True, registration="ICP-A"),
    ]
    first = _dossier()
    second = _dossier()

    _apply_current_icp_state(first, observations, {"icp": ProviderStatus.SUCCESS})
    _apply_current_icp_state(second, list(reversed(observations)), {"icp": ProviderStatus.SUCCESS})

    assert first.icp_website == second.icp_website == "ICP-A"
    assert first.current_icp_check_complete is True


@pytest.mark.parametrize("signal", ["whois", "pdns"])
def test_dga_conflict_is_wired_and_overrides_whois_and_pdns_white_signals(signal):
    observations = [
        _icp_observation(current=True, registration="ICP-CURRENT"),
        _icp_observation(current=False),
        Observation(
            ioc="conflict.invalid",
            scope="domain",
            provider="whois",
            kind="whois_record",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            observed_at=NOW + timedelta(days=30),
            payload={"expires_at": (NOW + timedelta(days=30)).isoformat()},
        ),
        Observation(
            ioc="conflict.invalid",
            scope="domain",
            provider="pdns",
            kind="pdns_activity",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            observed_at=NOW - timedelta(days=1),
        ),
    ]
    observations = [item for item in observations if item.provider in {"icp", signal}]
    statuses = {
        "ioc_info": ProviderStatus.SUCCESS,
        "fdark": ProviderStatus.SUCCESS,
        "icp": ProviderStatus.SUCCESS,
        "whois": ProviderStatus.SUCCESS,
        "pdns": ProviderStatus.SUCCESS,
    }

    facts, missing = _build_dga_facts(
        observations,
        statuses,
        Config(),
        {"ioc_info": Freshness.FRESH, "fdark": Freshness.FRESH},
    )
    verdict = adjudicate_dga("conflict.invalid", facts, now=NOW)

    assert missing == []
    assert facts.current_icp_conflict is True
    assert facts.has_current_icp is False
    if signal == "whois":
        assert facts.whois_expires > NOW
    else:
        assert facts.pdns_last_seen > NOW - timedelta(days=30)
    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"
    assert "冲突" in verdict.reason


def test_dga_malicious_sample_remains_black_but_conflict_is_reviewable():
    facts = DgaFacts(
        sample_check_complete=True,
        has_malicious_sample=True,
        malicious_sample_times=[NOW],
        current_icp_conflict=True,
        has_current_icp=False,
        whois_expires=NOW + timedelta(days=30),
        pdns_last_seen=NOW,
    )

    verdict = adjudicate_dga("sample-conflict.invalid", facts, now=NOW)

    assert verdict.conclusion == Conclusion.ALIVE_VALID
    assert verdict.disposition == "block"
    assert verdict.review_suggestion == "必看"
    assert "ICP" in verdict.reason
    assert "冲突" in verdict.reason


def test_standard_operator_candidate_with_icp_conflict_requires_review():
    dossier = _dossier()
    dossier.evidence_a = [_evidence("operator_confirmed_malicious_context")]

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"
    assert "ICP" in verdict.reason


def test_standard_false_positive_candidate_with_icp_conflict_requires_review():
    dossier = _dossier()
    dossier.evidence_a = []
    dossier.evidence_e = [
        _evidence(
            "trusted_business",
            level=EvidenceLevel.E,
            strength=EvidenceStrength.STRONG,
            tags=["trusted_business"],
        )
    ]

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"


def test_standard_gray_candidate_with_icp_conflict_requires_review():
    dossier = _dossier()
    dossier.whois = {"expiresDate": "2000-01-01"}
    dossier.retained_urls = ["https://conflict.invalid/path"]
    dossier.evidence_c = [
        _evidence(
            "historical_malicious",
            level=EvidenceLevel.C,
            strength=EvidenceStrength.NORMAL,
            tags=["historical"],
        )
    ]

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"


def test_strong_hash_direct_a_keeps_black_with_icp_conflict_but_requires_review():
    dossier = _dossier()
    dossier.evidence_a = [
        _evidence("hash[deadbeef]", tags=["direct", "hash"]),
    ]
    dossier.evidence_b = [_evidence("hash.time[deadbeef]", level=EvidenceLevel.B)]

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.ALIVE_VALID
    assert verdict.disposition == "block"
    assert verdict.review_suggestion == "必看"
    assert "ICP" in verdict.reason
    assert "恶意" in verdict.reason


@pytest.mark.parametrize("field", ["authoritative_context_keyword", "operator_clue_group"])
def test_authoritative_evidence_keeps_black_with_icp_conflict_but_requires_review(field):
    dossier = _dossier()
    dossier.evidence_a = [_evidence(field)]
    dossier.evidence_b = [_evidence("recent_activity", level=EvidenceLevel.B)]

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.ALIVE_VALID
    assert verdict.disposition == "block"
    assert verdict.review_suggestion == "必看"
    assert "ICP" in verdict.reason
    assert "恶意" in verdict.reason


class _StaticProvider:
    def __init__(self, name, observations=(), status=ProviderStatus.SUCCESS):
        self.name = name
        self.observations = list(observations)
        self.status = status

    def supports(self, target):
        return True

    def collect(self, targets, context):
        return ProviderResult(
            self.name,
            observations=self.observations,
            statuses={target.normalized: self.status for target in targets},
            freshnesses={target.normalized: Freshness.FRESH for target in targets},
        )


@pytest.mark.parametrize("route", ["standard", "dga"])
def test_pipeline_keeps_conflict_decision_stable_in_both_routes(route):
    decisions = []
    observations = [
        _icp_observation(current=True, registration="ICP-CURRENT"),
        _icp_observation(current=False),
    ]
    for ordered in (observations, list(reversed(observations))):
        providers = [
            _StaticProvider("icp", ordered),
            _StaticProvider("fdark", status=ProviderStatus.NO_DATA),
        ]
        if route == "dga":
            providers.extend([
                _StaticProvider("ioc_info", status=ProviderStatus.NO_DATA),
                _StaticProvider("k01_compromise", [Observation(
                    ioc="conflict.invalid", scope="domain", provider="k01_compromise",
                    kind="dga_classification", status=ProviderStatus.SUCCESS,
                    freshness=Freshness.FRESH, payload={"tags": ["dga"]},
                )]),
            ])
        else:
            providers.append(_StaticProvider("ioc_info", [Observation(
                ioc="conflict.invalid", scope="domain", provider="ioc_info",
                kind="ioc_info_record", status=ProviderStatus.SUCCESS,
                freshness=Freshness.FRESH, payload={
                    "key": "conflict.invalid", "level": 70, "source": ["manual"],
                    "context": "conflict.invalid malware communication",
                },
            )]))

        result = run_unified_pipeline(
            read_input_bundle(None, ["conflict.invalid"]), providers,
            Config(), ProviderContext(offline=True), now=NOW,
        )
        row = result.verdicts[0]
        assert row["route"] == route
        assert row["disposition"] == "review"
        assert "ICP" in row["reason"]
        decisions.append((row["conclusion"], row["reason"], row["provider_statuses"]))

    assert decisions[0] == decisions[1]
