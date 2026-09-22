"""Deterministic route selection for IOC adjudication."""

from dataclasses import dataclass

from ioc_rejudge.observations import (
    Freshness,
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
    authoritative_context: bool = False,
) -> RouteDecision:
    """Choose DGA only for a reliable, fresh, exact DGA-only classification.

    Requirements for the DGA route:
    - classification provider is configured
    - aggregate provider status is SUCCESS (success+error is not SUCCESS)
    - at least one target-matching ``dga_classification`` observation is
      SUCCESS with Freshness.FRESH and exact tags ``{dga}``

    Stale or UNKNOWN freshness never enables automatic DGA white/gray.
    UNKNOWN is not treated as trusted success (legacy rows must re-fetch or
    set explicit FRESH). Failed aggregate classification exposes
    ``classification_unknown`` so white/gray candidates stay under review.
    Authoritative clue/context still force the standard route.
    """
    if authoritative_context:
        return RouteDecision(
            Route.STANDARD,
            reason="authoritative context keyword evidence",
        )

    if authoritative_clue:
        return RouteDecision(
            Route.STANDARD,
            reason="authoritative clue-group evidence",
        )

    if not dga_provider_configured:
        return RouteDecision(Route.STANDARD)

    if dga_provider_status != ProviderStatus.SUCCESS:
        if dga_provider_status == ProviderStatus.ERROR:
            return RouteDecision(
                Route.STANDARD,
                classification_unknown=True,
                reason="dga classification failed",
            )
        return RouteDecision(Route.STANDARD)

    tags: set[str] = set()
    saw_untrusted_dga_only = False
    for observation in observations:
        if observation.kind != "dga_classification":
            continue
        if observation.ioc != target.normalized:
            continue
        if observation.status != ProviderStatus.SUCCESS:
            continue
        raw_tags = observation.payload.get("tags", [])
        if not isinstance(raw_tags, (list, tuple, set)):
            continue
        normalized_tags = {
            str(tag).strip().lower() for tag in raw_tags if str(tag).strip()
        }
        if normalized_tags != {"dga"}:
            # Mixed/non-DGA success facts still count as reliable classification
            # content; they simply do not select the DGA route.
            if observation.freshness == Freshness.FRESH:
                tags.update(normalized_tags)
            continue
        if observation.freshness != Freshness.FRESH:
            # Stale/unknown exact-DGA facts cannot unlock automatic DGA white.
            saw_untrusted_dga_only = True
            continue
        tags.update(normalized_tags)

    if tags == {"dga"}:
        return RouteDecision(
            Route.DGA,
            reason="reliable dga-only classification",
        )
    if saw_untrusted_dga_only and not tags:
        return RouteDecision(
            Route.STANDARD,
            classification_unknown=True,
            reason="dga classification freshness untrusted",
        )
    return RouteDecision(Route.STANDARD)
