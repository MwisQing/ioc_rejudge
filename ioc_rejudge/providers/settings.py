"""Secret-safe runtime settings shared by live providers."""

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class ProviderSettings:
    name: str
    base_url: str
    secrets: dict[str, str] = field(default_factory=dict, repr=False)
    timeout: int = 30
    workers: int = 10
    rate_per_second: int = 20
    ttl: timedelta = timedelta(days=1)
    enabled: bool = True

    def __post_init__(self) -> None:
        self.name = str(self.name).strip()
        self.base_url = str(self.base_url).strip()
        self.secrets = dict(self.secrets)
        if not self.name:
            raise ValueError("provider name must not be empty")
        if not self.base_url:
            raise ValueError("provider base_url must not be empty")
        if self.timeout <= 0:
            raise ValueError("provider timeout must be greater than zero")
        if self.workers <= 0:
            raise ValueError("provider workers must be greater than zero")
        if self.rate_per_second <= 0:
            raise ValueError("provider rate_per_second must be greater than zero")
        if self.ttl < timedelta(0):
            raise ValueError("provider ttl must not be negative")

    def __repr__(self) -> str:
        return (
            f"ProviderSettings(name={self.name!r}, base_url={self.base_url!r}, "
            f"timeout={self.timeout!r}, workers={self.workers!r}, "
            f"rate_per_second={self.rate_per_second!r}, "
            f"ttl={self.ttl!r}, enabled={self.enabled!r})"
        )

    def public_dict(self) -> dict:
        """Return settings metadata suitable for diagnostics and logs."""
        return {
            "name": self.name,
            "base_url": self.base_url,
            "timeout": self.timeout,
            "workers": self.workers,
            "rate_per_second": self.rate_per_second,
            "ttl_seconds": self.ttl.total_seconds(),
            "enabled": self.enabled,
        }
