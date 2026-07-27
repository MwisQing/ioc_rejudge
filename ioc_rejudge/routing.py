"""Deterministic route selection for IOC adjudication."""

from dataclasses import dataclass

from ioc_rejudge.observations import (
    IocTarget,
    Observation,
    ProviderStatus,
    Route,
)


@dataclass(frozen=True)
class RouteDecision:
    route: Route
    classification_unknown: bool = False
    reason: str = ""


def select_route(
    target: IocTarget,
    observations: list[Observation],
    dga_provider_configured: bool,
    dga_provider_status: ProviderStatus | None,
    *,
    authoritative_clue: bool = False,
) -> RouteDecision:
    """Choose DGA only for a successful, exact DGA-only classification."""
    del target  # Reserved for future target-specific routing policy.

    if authoritative_clue:
        return RouteDecision(
            Route.STANDARD,
            reason="authoritative clue-group evidence",
        )

    tags: set[str] = set()
    for observation in observations:
        if (
            observation.kind != "dga_classification"
            or observation.status != ProviderStatus.SUCCESS
        ):
            continue
        raw_tags = observation.payload.get("tags", [])
        if not isinstance(raw_tags, (list, tuple, set)):
            continue
        tags.update(str(tag).strip().lower() for tag in raw_tags)

    if tags == {"dga"}:
        return RouteDecision(
            Route.DGA,
            reason="reliable dga-only classification",
        )
    if dga_provider_configured and dga_provider_status == ProviderStatus.ERROR:
        return RouteDecision(
            Route.STANDARD,
            classification_unknown=True,
            reason="dga classification failed",
        )
    return RouteDecision(Route.STANDARD)
