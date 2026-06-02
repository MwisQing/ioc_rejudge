"""Configuration parameters for IOC rejudgement."""
from dataclasses import dataclass, field
from ioc_rejudge.rules import RuleConfig, load_rules, _build_defaults


@dataclass
class Config:
    """Configurable parameters. None = use default."""
    activity_window_days: int = 365
    hash_malicious_level: int = 40
    relate_url_malicious_level: int = 40
    historical_malicious_level: int = 40
    high_level_no_a_threshold: int = 70
    rules: RuleConfig = field(default_factory=_build_defaults)


def load_config(
    activity_window_days: int | None = None,
    hash_malicious_level: int | None = None,
    relate_url_malicious_level: int | None = None,
    historical_malicious_level: int | None = None,
    high_level_no_a_threshold: int | None = None,
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
        rules=rules,
    )
