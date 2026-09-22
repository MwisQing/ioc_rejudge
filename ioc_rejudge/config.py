"""Configuration parameters for IOC rejudgement."""
from dataclasses import dataclass, field
from datetime import timedelta
from math import isfinite

from ioc_rejudge.rules import RuleConfig, load_rules, _build_defaults


def _require_non_negative_int(name: str, value: object) -> int:
    """Accept only real integers (reject bool, float, NaN/Inf, negatives)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    try:
        as_float = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be finite") from exc
    if not isfinite(as_float):
        raise ValueError(f"{name} must be finite")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _require_day_window(name: str, value: object) -> int:
    """Non-negative day count that fits in a timedelta without overflow."""
    days = _require_non_negative_int(name, value)
    try:
        timedelta(days=days)
    except OverflowError as exc:
        raise ValueError(f"{name} is too large") from exc
    return days


@dataclass
class Config:
    """Configurable parameters. None = use default."""
    activity_window_days: int = 365
    hash_malicious_level: int = 40
    relate_url_malicious_level: int = 40
    historical_malicious_level: int = 40
    high_level_no_a_threshold: int = 70
    dga_pdns_recent_days: int = 30
    provider_workers: int = 5
    rules: RuleConfig = field(default_factory=_build_defaults)

    def __post_init__(self) -> None:
        self.activity_window_days = _require_day_window(
            "activity_window_days", self.activity_window_days
        )
        self.hash_malicious_level = _require_non_negative_int(
            "hash_malicious_level", self.hash_malicious_level
        )
        self.relate_url_malicious_level = _require_non_negative_int(
            "relate_url_malicious_level", self.relate_url_malicious_level
        )
        self.historical_malicious_level = _require_non_negative_int(
            "historical_malicious_level", self.historical_malicious_level
        )
        self.high_level_no_a_threshold = _require_non_negative_int(
            "high_level_no_a_threshold", self.high_level_no_a_threshold
        )
        self.dga_pdns_recent_days = _require_day_window(
            "dga_pdns_recent_days", self.dga_pdns_recent_days
        )
        if isinstance(self.provider_workers, bool) or not isinstance(
            self.provider_workers, int
        ):
            raise TypeError("provider_workers must be an integer")
        if self.provider_workers < 1:
            raise ValueError("provider_workers must be at least 1")


def load_config(
    activity_window_days: int | None = None,
    hash_malicious_level: int | None = None,
    relate_url_malicious_level: int | None = None,
    historical_malicious_level: int | None = None,
    high_level_no_a_threshold: int | None = None,
    dga_pdns_recent_days: int | None = None,
    provider_workers: int | None = None,
    rules_path: str | None = None,
) -> Config:
    """Load config with defaults, overridden by CLI args."""
    rules = load_rules(rules_path)
    return Config(
        activity_window_days=activity_window_days if activity_window_days is not None else 365,
        hash_malicious_level=hash_malicious_level if hash_malicious_level is not None else 40,
        relate_url_malicious_level=relate_url_malicious_level if relate_url_malicious_level is not None else 40,
        historical_malicious_level=historical_malicious_level if historical_malicious_level is not None else 40,
        high_level_no_a_threshold=high_level_no_a_threshold if high_level_no_a_threshold is not None else 70,
        dga_pdns_recent_days=dga_pdns_recent_days if dga_pdns_recent_days is not None else 30,
        provider_workers=provider_workers if provider_workers is not None else 5,
        rules=rules,
    )
