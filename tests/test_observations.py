from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from ioc_rejudge.models import (
    Conclusion,
    Evidence,
    EvidenceLevel,
    Verdict,
)
from ioc_rejudge.observations import (
    Disposition,
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
    Route,
)


def _verdict() -> Verdict:
    return Verdict(
        conclusion=Conclusion.ALIVE_VALID,
        malicious_nature="direct malicious",
        activity_status="recently active",
        confidence="high",
        review_suggestion="skip",
        candidate_label=None,
        hit_evidence="A+B",
        forbidden_labels="not false positive",
        reason="direct evidence with recent activity",
    )


def test_gray_is_a_first_class_conclusion():
    assert Conclusion.GRAY.value == "灰"
    assert Conclusion.GRAY != Conclusion.FALSE_POSITIVE


def test_observation_keeps_provenance_scope_and_freshness():
    fetched_at = datetime(2026, 7, 23, 10, 0, 0)
    observed_at = datetime(2026, 7, 23, 0, 0, 0)
    observation = Observation(
        ioc="example.invalid",
        scope="domain",
        provider="whois",
        kind="whois",
        status=ProviderStatus.SUCCESS,
        fetched_at=fetched_at,
        observed_at=observed_at,
        freshness=Freshness.FRESH,
        payload={"expires_at": "2027-01-01"},
        raw_ref="run/whois/example.json",
    )

    assert observation.provider == "whois"
    assert observation.scope == "domain"
    assert observation.status.value == "success"
    assert observation.fetched_at == fetched_at
    assert observation.observed_at == observed_at
    assert observation.payload["expires_at"] == "2027-01-01"


def test_target_keeps_original_and_normalized_values_and_is_frozen():
    target = IocTarget(
        original="HTTPS://Example.INVALID:8443/a",
        normalized="example.invalid:8443/a",
        ioc_type="url",
        host="example.invalid",
        ports=("8443",),
    )

    assert target.original == "HTTPS://Example.INVALID:8443/a"
    assert target.host == "example.invalid"
    assert target.ports == ("8443",)
    with pytest.raises(FrozenInstanceError):
        target.host = "changed.invalid"


def test_provider_route_and_disposition_enum_values_are_stable():
    assert [status.value for status in ProviderStatus] == [
        "success",
        "no_data",
        "error",
        "disabled",
    ]
    assert [freshness.value for freshness in Freshness] == [
        "fresh",
        "stale",
        "unknown",
    ]
    assert Route.DGA.value == "dga"
    assert Route.STANDARD.value == "standard"
    assert Disposition.BLOCK.value == "block"
    assert Disposition.GRAY.value == "gray"
    assert Disposition.FALSE_POSITIVE.value == "false_positive"
    assert Disposition.REVIEW.value == "review"


def test_evidence_and_verdict_extensions_are_optional_and_isolated():
    observed_at = datetime(2026, 7, 23, 9, 30, 0)
    evidence = Evidence(
        EvidenceLevel.A,
        "hash",
        "associated sample",
        provider="ioc_info",
        observed_at=observed_at,
        record_index=2,
    )
    first = _verdict()
    second = _verdict()

    assert evidence.provider == "ioc_info"
    assert evidence.observed_at == observed_at
    assert evidence.record_index == 2
    assert first.route == "standard"
    assert first.disposition == "review"
    assert first.scope_actions == []
    assert first.retained_urls == []
    assert first.provider_statuses == {}
    assert first.evidence_origins == []
    assert first.missing_required_providers == []

    first.scope_actions.append({"scope": "domain", "action": "block"})
    first.provider_statuses["ioc_info"] = "success"
    assert second.scope_actions == []
    assert second.provider_statuses == {}


def test_observation_payload_default_is_not_shared():
    first = Observation(
        ioc="one.invalid",
        scope="domain",
        provider="whois",
        kind="whois",
        status=ProviderStatus.NO_DATA,
    )
    second = Observation(
        ioc="two.invalid",
        scope="domain",
        provider="whois",
        kind="whois",
        status=ProviderStatus.NO_DATA,
    )

    first.payload["marker"] = True
    assert second.payload == {}
