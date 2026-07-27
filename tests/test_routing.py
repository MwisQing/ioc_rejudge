"""Route selection contract tests."""

from dataclasses import FrozenInstanceError

import pytest

from ioc_rejudge.observations import (
    IocTarget,
    Observation,
    ProviderStatus,
    Route,
)
from ioc_rejudge.routing import RouteDecision, select_route


TARGET = IocTarget(
    original="example.invalid",
    normalized="example.invalid",
    ioc_type="domain",
    host="example.invalid",
)


def _classification(tags, status=ProviderStatus.SUCCESS):
    return Observation(
        ioc=TARGET.normalized,
        scope="domain",
        provider="k01_compromise",
        kind="dga_classification",
        status=status,
        payload={"tags": tags},
    )


def test_route_decision_is_frozen():
    decision = RouteDecision(Route.STANDARD)
    with pytest.raises(FrozenInstanceError):
        decision.route = Route.DGA


@pytest.mark.parametrize("tags", [["dga"], ["DGA"], [" dga "]])
def test_successful_exact_dga_only_classification_selects_dga(tags):
    decision = select_route(
        TARGET,
        [_classification(tags)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.DGA
    assert decision.classification_unknown is False


def test_authoritative_clue_forces_standard_over_exact_dga():
    decision = select_route(
        TARGET,
        [_classification(["dga"])],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
        authoritative_clue=True,
    )
    assert decision.route == Route.STANDARD
    assert decision.reason == "authoritative clue-group evidence"


@pytest.mark.parametrize(
    "tags",
    [[], ["dga", "phishing"], ["phishing"], "dga", None],
)
def test_mixed_missing_or_malformed_tags_never_select_dga(tags):
    decision = select_route(
        TARGET,
        [_classification(tags)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is False


def test_non_success_classification_observation_is_ignored():
    decision = select_route(
        TARGET,
        [_classification(["dga"], ProviderStatus.ERROR)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.ERROR,
    )
    assert decision == RouteDecision(
        Route.STANDARD,
        classification_unknown=True,
        reason="dga classification failed",
    )


def test_unconfigured_dga_provider_uses_standard_without_unknown_flag():
    decision = select_route(
        TARGET,
        [],
        dga_provider_configured=False,
        dga_provider_status=None,
    )
    assert decision == RouteDecision(Route.STANDARD)
