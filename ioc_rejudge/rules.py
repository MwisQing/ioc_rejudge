"""Lightweight JSON rule configuration for IOC rejudgement."""
import json
from dataclasses import dataclass, field
from pathlib import Path


_BUILT_IN_DEFAULTS: dict = {
    "strong_sources": [
        "sample-base", "zion_sandbox", "cloud_sandbox",
        "vt_contacted", "virustotal", "manual",
    ],
    "weak_sources": [],
    "malicious_indicators": [
        "sample", "c2", "malware", "trojan", "backdoor", "rat",
        "callback", "connect", "dns", "http", "tcp", "download",
        "payload", "sandbox", "virus", "恶意", "样本", "通信",
        "回连", "下载", "沙箱",
    ],
    "strong_malicious_indicators": [
        "trojan", "malware", "backdoor", "rat", "c2", "malicious",
        "spyware", "botnet", "木马", "恶意", "后门", "远控", "间谍", "僵尸",
        "worm", "virus", "exploit", "rootkit", "keylogger", "downloader",
        "dropper", "ransom", "蠕虫", "病毒", "漏洞", "勒索",
    ],
    "context_comment_malicious_indicators": [],
    "authoritative_context_indicators": ["黑产", "扩展", "扩线"],
    "context_comment_historical_indicators": [
        "historical", "history", "曾", "历史", "曾经",
    ],
    "normalization_indicators": [
        "cdn", "cloud", "shared hosting",
        "official", "官网", "备案", "正常业务",
    ],
    "review_indicators": [
        "mixed-family", "shared-hosting", "标签混杂", "家族混杂",
    ],
    "trusted_business_fields": [
        "icp_website", "official_website",
    ],
    "authoritative_clue_indicators": ["线索群"],
    "operator_sources": ["manual", "alliocs_tpd"],
}

_LIST_FIELDS = [
    "strong_sources", "weak_sources", "malicious_indicators",
    "strong_malicious_indicators",
    "context_comment_malicious_indicators", "context_comment_historical_indicators",
    "authoritative_context_indicators",
    "normalization_indicators", "review_indicators", "trusted_business_fields",
    "authoritative_clue_indicators", "operator_sources",
]


@dataclass
class RuleConfig:
    """Rule configuration loaded from JSON or built-in defaults."""
    strong_sources: list[str] = field(default_factory=list)
    weak_sources: list[str] = field(default_factory=list)
    malicious_indicators: list[str] = field(default_factory=list)
    strong_malicious_indicators: list[str] = field(default_factory=list)
    context_comment_malicious_indicators: list[str] = field(default_factory=list)
    authoritative_context_indicators: list[str] = field(default_factory=list)
    context_comment_historical_indicators: list[str] = field(default_factory=list)
    normalization_indicators: list[str] = field(default_factory=list)
    review_indicators: list[str] = field(default_factory=list)
    trusted_business_fields: list[str] = field(default_factory=list)
    authoritative_clue_indicators: list[str] = field(default_factory=list)
    operator_sources: list[str] = field(default_factory=list)


def _build_defaults() -> RuleConfig:
    return RuleConfig(**{k: list(v) for k, v in _BUILT_IN_DEFAULTS.items()})


def _validate_rules(data: dict) -> None:
    """Validate rule config structure. Raises ValueError on bad input."""
    if not isinstance(data, dict):
        raise ValueError("Rule config must be a JSON object")
    for key, value in data.items():
        if key not in _LIST_FIELDS:
            raise ValueError(f"Unknown rule field: {key!r}")
        if not isinstance(value, list):
            raise ValueError(f"Rule field {key!r} must be a list, got {type(value).__name__}")
        for item in value:
            if not isinstance(item, str):
                raise ValueError(
                    f"Rule field {key!r} must contain only strings, "
                    f"got {type(item).__name__}: {item!r}"
                )


def load_rules(filepath: str | None = None) -> RuleConfig:
    """Load rule config from JSON file, merged with defaults.

    If filepath is None, returns built-in defaults.
    Missing keys are filled from defaults.
    """
    defaults = _build_defaults()
    if filepath is None:
        return defaults

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Rule config file not found: {filepath}")

    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in rule config: {e}") from e

    _validate_rules(data)

    merged = {}
    for field_name in _LIST_FIELDS:
        if field_name in data:
            merged[field_name] = data[field_name]
        else:
            merged[field_name] = getattr(defaults, field_name)

    return RuleConfig(**merged)
