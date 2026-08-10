"""Provider protocol, context, and result types."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from ioc_rejudge.observations import Freshness, IocTarget, Observation, ProviderStatus


@dataclass(frozen=True)
class ProgressEvent:
    """One per-provider progress update during batch collection.

    done counts targets whose status is already determined; total is the
    number of targets this provider was asked to process. detail is optional
    short human-readable context (for example a cache hit notice).
    """

    provider: str
    done: int
    total: int
    detail: str = ""


@dataclass(frozen=True)
class ProviderContext:
    """Immutable execution context passed to every provider.

    offline: when True, providers must not make network requests.
    refresh: when True, providers should bypass local caches.
    run_dir: writable directory for transient artifacts (cache, logs).
    on_progress: optional sink that receives per-provider ProgressEvent
        updates as targets are processed; progress reporting must never
        affect collection results.
    """

    offline: bool = False
    refresh: bool = False
    run_dir: Path | None = None
    on_progress: Callable[[ProgressEvent], None] | None = None


def report_progress(
    context: ProviderContext,
    provider: str,
    done: int,
    total: int,
    detail: str = "",
) -> None:
    """Emit one progress event when a handler is configured.

    Handler exceptions are swallowed so a broken progress sink can never
    change collection outcomes.
    """
    handler = getattr(context, "on_progress", None)
    if handler is None:
        return
    try:
        handler(ProgressEvent(provider, done, total, detail))
    except Exception:
        pass


@dataclass
class ProviderResult:
    """Result of a provider collection for a batch of targets.

    observations: every sidecar row or provider response, in order.
    statuses: aggregate status per normalized IOC key.
    errors: human-readable error details (bad lines, parse failures).
    cache_hits: count of results served from a local cache (always 0 for sidecar).
    freshnesses: optional per-IOC completeness freshness, including NO_DATA rows.
    """

    name: str
    observations: list[Observation] = field(default_factory=list)
    statuses: dict[str, ProviderStatus] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    cache_hits: int = 0
    freshnesses: dict[str, Freshness] = field(default_factory=dict)


@runtime_checkable
class Provider(Protocol):
    """Structural protocol that every provider must satisfy.

    name: stable short name used in provider_statuses keys.
    supports(target): whether this provider can handle the given IocTarget.
    collect(targets, context): gather observations for a batch of targets.
    """

    name: str

    def supports(self, target: IocTarget) -> bool: ...

    def collect(
        self, targets: list[IocTarget], context: ProviderContext
    ) -> ProviderResult: ...
