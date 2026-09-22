"""Typed primitives for IOC targets and provider observations."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ProviderStatus(str, Enum):
    SUCCESS = "success"
    NO_DATA = "no_data"
    ERROR = "error"
    DISABLED = "disabled"


class Freshness(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class Route(str, Enum):
    DGA = "dga"
    STANDARD = "standard"


class Disposition(str, Enum):
    BLOCK = "block"
    GRAY = "gray"
    FALSE_POSITIVE = "false_positive"
    REVIEW = "review"


@dataclass(frozen=True)
class IocTarget:
    """Unified IOC identity.

    ``normalized`` is the canonical key for dedup, provider status maps,
    observation grouping, result cache, diagnostics, and exports. URL values
    keep their scheme (``https://host/path``) so bare domains, HTTP, and HTTPS
    remain distinct. ``scheme`` is set for URL targets; ``host`` is the
    lowercased host used by host-scoped enrichments (WHOIS/pDNS/ICP).
    """

    original: str
    normalized: str
    ioc_type: str
    host: str
    ports: tuple[str, ...] = ()
    scheme: str = ""

    @property
    def identity(self) -> str:
        """Alias for the canonical key (``normalized``)."""
        return self.normalized


@dataclass(frozen=True)
class Observation:
    ioc: str
    scope: str
    provider: str
    kind: str
    status: ProviderStatus
    fetched_at: datetime | None = None
    observed_at: datetime | None = None
    freshness: Freshness = Freshness.UNKNOWN
    strength: str = "normal"
    payload: dict[str, Any] = field(default_factory=dict)
    raw_ref: str = ""
