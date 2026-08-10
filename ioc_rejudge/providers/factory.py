"""Secret-safe live provider selection and construction."""

from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from ioc_rejudge.config import Config
from ioc_rejudge.providers.cache import CacheEntry, JsonlProviderCache
from ioc_rejudge.providers.fdark import FDarkProvider
from ioc_rejudge.providers.go_transport import GoBatchTransport
from ioc_rejudge.providers.icp import ICPProvider
from ioc_rejudge.providers.ioc_info import DEFAULT_URL as IOC_INFO_DEFAULT_URL
from ioc_rejudge.providers.ioc_info import IOCInfoProvider
from ioc_rejudge.providers.k01_compromise import K01CompromiseProvider
from ioc_rejudge.providers.pdns import PDNSProvider
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.providers.whois import WhoisProvider
from ioc_rejudge.result_cache import ResultCacheSettings


DEFAULT_PROVIDERS = (
    "k01_compromise",
    "ioc_info",
    "fdark",
    "whois",
    "pdns",
    "icp",
)
SUPPORTED_PROVIDERS = DEFAULT_PROVIDERS

_DEFAULTS = {
    "k01_compromise": {
        "url": "https://a.ti.qianxin.com",
        "ttl": timedelta(days=7),
    },
    "ioc_info": {
        "url": IOC_INFO_DEFAULT_URL,
        "ttl": timedelta(days=7),
    },
    "fdark": {
        "url": "http://fdp.qianxin-inc.cn/api/v1/fdark/abstract",
        "ttl": timedelta(days=7),
    },
    "whois": {
        "url": "http://fdp.qianxin-inc.cn/v3/whois/detail",
        "ttl": timedelta(days=7),
    },
    "pdns": {
        "url": "https://fdp.qianxin-inc.cn/api/v1/passivedns/flint/rrset",
        "ttl": timedelta(days=7),
    },
    "icp": {
        "url": "https://icp.xuanji.qianxin.com/v2/open-api/icp-info",
        "ttl": timedelta(days=30),
        "workers": 2,
        "rate_per_second": 2,
    },
}

_COMMON_OPTIONS = {
    "enabled",
    "url",
    "base_url",
    "timeout",
    "workers",
    "rate_per_second",
    "ttl_seconds",
    "ttl_hours",
    "ttl_days",
}
_PROVIDER_OPTIONS = {
    "k01_compromise": {"ignore_port", "ignore_url", "ignore_top"},
    "ioc_info": {"max_attempts", "retry_delay"},
    "fdark": {"include_slow_variants", "include_url_param", "query_params"},
    "whois": set(),
    "pdns": set(),
    "icp": set(),
}
_SECRET_KEY_PARTS = (
    "apikey",
    "token",
    "secret",
    "password",
    "authorization",
    "fdpaccess",
    "whoisaccess",
    "pdnsaccess",
)
_CREDENTIAL_KEYS = frozenset({
    "K01_COMPROMISE_API_KEY",
    "IOC_INFO_API_KEY",
    "FDP_ACCESS",
    "FDP_SECRET",
    "WHOIS_ACCESS",
    "WHOIS_SECRET",
    "PDNS_ACCESS",
    "PDNS_SECRET",
    "ICP_UC",
    "ICP_KEY",
})


class _OfflineTransport:
    """Fail closed if a provider violates the offline context contract."""

    @staticmethod
    def _error() -> TransportError:
        return TransportError("offline", "Network access is disabled in offline mode")

    def get_json(self, *args, **kwargs):
        raise self._error()

    def post_json(self, *args, **kwargs):
        raise self._error()


class _AuditedProviderCache(JsonlProviderCache):
    """Mirror cache writes and reads into the current run's raw audit log."""

    def __init__(self, cache_root, run_raw_root, provider_name, ttl):
        super().__init__(cache_root, provider_name, ttl)
        self.audit = JsonlProviderCache(run_raw_root, provider_name, ttl)

    def put(self, ioc, raw, params=None, fetched_at=None) -> CacheEntry:
        entry = super().put(ioc, raw, params, fetched_at=fetched_at)
        self.audit.put(ioc, raw, params, fetched_at=entry.fetched_at)
        return entry

    def get(self, ioc, params=None, *, now=None) -> CacheEntry | None:
        entry = super().get(ioc, params, now=now)
        diagnostics = list(self.diagnostics)
        if entry is not None:
            try:
                self.audit.put(ioc, entry.raw, params, fetched_at=entry.fetched_at)
            except (OSError, TypeError, ValueError) as exc:
                diagnostics.append(f"run audit write failed: {exc}")
        self.diagnostics = diagnostics
        return entry


def parse_provider_names(
    value: str | Iterable[str] | None,
) -> list[str]:
    if value is None:
        names = list(DEFAULT_PROVIDERS)
    elif isinstance(value, str):
        if not value.strip():
            raise ValueError("provider list must not be empty")
        names = [name.strip() for name in value.split(",")]
    else:
        names = [str(name).strip() for name in value]

    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        if not name:
            raise ValueError("provider list must not contain empty names")
        if name not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unknown provider: {name}")
        if name in seen:
            raise ValueError(f"duplicate provider: {name}")
        seen.add(name)
        result.append(name)
    return result


def _normalized_key(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def _contains_secret_key(value: object) -> bool:
    normalized = _normalized_key(value)
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _reject_secrets(value: object, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _contains_secret_key(key):
                raise ValueError(f"secret option is not allowed in local config: {path}.{key}")
            _reject_secrets(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secrets(item, f"{path}[{index}]")


def load_local_config(path: str | Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    source = Path(path)
    try:
        parsed = json.loads(source.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ValueError(f"provider config does not exist: {source}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read provider config {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid provider config JSON at line {exc.lineno}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("provider config top-level must be an object")
    if set(parsed) - {"providers", "result_cache"}:
        raise ValueError("provider config has unknown top-level options")
    result_cache = parsed.get("result_cache", {})
    if not isinstance(result_cache, dict):
        raise ValueError("provider config 'result_cache' must be an object")
    unknown_result_options = set(result_cache) - {
        "enabled", "ttl_seconds", "ttl_hours", "ttl_days"
    }
    if unknown_result_options:
        joined = ", ".join(sorted(unknown_result_options))
        raise ValueError(f"unknown result_cache option: {joined}")
    if "enabled" in result_cache and not isinstance(
        result_cache["enabled"], bool
    ):
        raise ValueError("result_cache enabled must be boolean")
    ttl_options = [
        key
        for key in ("ttl_seconds", "ttl_hours", "ttl_days")
        if key in result_cache
    ]
    if len(ttl_options) > 1:
        raise ValueError("result_cache must set only one TTL option")
    if ttl_options:
        _positive_number(
            "result_cache", ttl_options[0], result_cache[ttl_options[0]], integer=False
        )
    providers = parsed.get("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("provider config 'providers' must be an object")
    _reject_secrets(providers)

    validated: dict[str, dict] = {}
    for name, options in providers.items():
        if name not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unknown provider in config: {name}")
        if not isinstance(options, dict):
            raise ValueError(f"provider options for {name} must be an object")
        unknown = set(options) - _COMMON_OPTIONS - _PROVIDER_OPTIONS[name]
        if unknown:
            joined = ", ".join(sorted(unknown))
            raise ValueError(f"unknown option for provider {name}: {joined}")
        if "url" in options and "base_url" in options:
            raise ValueError(f"provider {name} cannot set both url and base_url")
        if "query_params" in options and not isinstance(options["query_params"], dict):
            raise ValueError(f"provider {name} query_params must be an object")
        validated[name] = dict(options)
    return validated


def load_result_cache_settings(
    path: str | Path | None,
) -> ResultCacheSettings:
    if path is None:
        return ResultCacheSettings()
    source = Path(path)
    try:
        parsed = json.loads(source.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ValueError(f"provider config does not exist: {source}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read provider config {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid provider config JSON at line {exc.lineno}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("provider config top-level must be an object")
    # Reuse the complete validation contract before reading this section.
    load_local_config(source)
    options = parsed.get("result_cache", {})
    enabled = options.get("enabled", True)
    ttl_options = [
        key
        for key in ("ttl_seconds", "ttl_hours", "ttl_days")
        if key in options
    ]
    if not ttl_options:
        ttl = timedelta(days=7)
    else:
        key = ttl_options[0]
        value = _positive_number(
            "result_cache", key, options[key], integer=False
        )
        if key == "ttl_seconds":
            ttl = timedelta(seconds=value)
        elif key == "ttl_hours":
            ttl = timedelta(hours=value)
        else:
            ttl = timedelta(days=value)
    return ResultCacheSettings(enabled=enabled, ttl=ttl)


def load_credentials_file(path: str | Path) -> dict[str, str]:
    """Load only documented credential names from a local JSON object."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"credentials file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"credentials file is not valid JSON: line {exc.lineno}, column {exc.colno}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("credentials file must contain a JSON object")
    unknown = set(payload).difference(_CREDENTIAL_KEYS)
    if unknown:
        raise ValueError(
            "unknown credentials file key(s): " + ", ".join(sorted(unknown))
        )
    credentials: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(value, str):
            raise ValueError(f"credentials file value for {key} must be a string")
        normalized = value.strip()
        if normalized:
            credentials[key] = normalized
    return credentials


def _validate_url(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"provider {name} URL must be a non-empty string")
    url = value.strip()
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"provider {name} URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"provider {name} URL must be absolute HTTP(S)")
    if parsed.username or parsed.password:
        raise ValueError(f"provider {name} URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError(f"provider {name} URL must not contain query or fragment")
    return url.rstrip("/")


def _positive_number(name: str, option: str, value: object, *, integer: bool):
    if isinstance(value, bool):
        raise ValueError(f"provider {name} {option} must be positive")
    try:
        parsed = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"provider {name} {option} must be positive") from exc
    if parsed <= 0:
        raise ValueError(f"provider {name} {option} must be positive")
    return parsed


def _ttl(name: str, options: dict) -> timedelta:
    ttl_options = [key for key in ("ttl_seconds", "ttl_hours", "ttl_days") if key in options]
    if len(ttl_options) > 1:
        raise ValueError(f"provider {name} must set only one TTL option")
    if not ttl_options:
        return _DEFAULTS[name]["ttl"]
    key = ttl_options[0]
    value = _positive_number(name, key, options[key], integer=False)
    if key == "ttl_seconds":
        return timedelta(seconds=value)
    if key == "ttl_hours":
        return timedelta(hours=value)
    return timedelta(days=value)


def _env_value(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    return str(value).strip() if value is not None else ""


def _secrets(name: str, env: Mapping[str, str]) -> dict[str, str]:
    if name == "ioc_info":
        key = _env_value(env, "IOC_INFO_API_KEY")
        return {"Api-Key": key} if key else {}
    if name == "k01_compromise":
        key = _env_value(env, "K01_COMPROMISE_API_KEY")
        return {"Api-Key": key} if key else {}
    if name == "icp":
        uc = _env_value(env, "ICP_UC")
        key = _env_value(env, "ICP_KEY")
        return {"uc": uc, "key": key} if uc and key else {}

    if name == "fdark":
        access = _env_value(env, "FDP_ACCESS")
        secret = _env_value(env, "FDP_SECRET")
    elif name == "whois":
        access = _env_value(env, "WHOIS_ACCESS") or _env_value(env, "FDP_ACCESS")
        secret = _env_value(env, "WHOIS_SECRET") or _env_value(env, "FDP_SECRET")
    else:
        access = _env_value(env, "PDNS_ACCESS") or _env_value(env, "FDP_ACCESS")
        secret = _env_value(env, "PDNS_SECRET") or _env_value(env, "FDP_SECRET")
    if not access or not secret:
        return {}
    return {"fdp-access": access, "fdp-secret": secret}


def _env_url(name: str, env: Mapping[str, str]) -> str:
    variable = {
        "ioc_info": "IOC_INFO_URL",
        "k01_compromise": "K01_COMPROMISE_URL",
        "fdark": "FDARK_URL",
        "whois": "WHOIS_URL",
        "pdns": "PDNS_URL",
        "icp": "ICP_URL",
    }[name]
    return _env_value(env, variable) or _DEFAULTS[name]["url"]


def _cache_for(
    name: str,
    ttl: timedelta,
    cache_dir: Path | None,
    run_dir: Path | None,
):
    run_raw = run_dir / "raw" if run_dir is not None else None
    if cache_dir is not None and run_raw is not None:
        if cache_dir.resolve() == run_raw.resolve():
            return JsonlProviderCache(cache_dir, name, ttl)
        return _AuditedProviderCache(cache_dir, run_raw, name, ttl)
    if cache_dir is not None:
        return JsonlProviderCache(cache_dir, name, ttl)
    if run_raw is not None:
        return JsonlProviderCache(run_raw, name, ttl)
    return None


def _transport(name: str, transport_factory, offline: bool):
    if offline:
        return _OfflineTransport()
    if transport_factory is None:
        return None
    if isinstance(transport_factory, Mapping):
        return transport_factory.get(name)
    return transport_factory(name)


def build_providers(
    names: str | Iterable[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    credentials_path: str | Path | None = None,
    config_path: str | Path | None = None,
    cache_dir: str | Path | None = None,
    run_dir: str | Path | None = None,
    adjudication_config: Config | None = None,
    transport_factory=None,
    offline: bool = False,
) -> list:
    selected = parse_provider_names(names)
    if env is not None and credentials_path is not None:
        raise ValueError("env and credentials_path cannot be used together")
    if credentials_path is not None:
        environment = load_credentials_file(credentials_path)
    else:
        environment = os.environ if env is None else env
    local = load_local_config(config_path)
    core_config = adjudication_config or Config()
    cache_root = Path(cache_dir) if cache_dir is not None else None
    run_root = Path(run_dir) if run_dir is not None else None
    providers = []
    go_transport = GoBatchTransport() if transport_factory is None and not offline else None

    for name in selected:
        options = local.get(name, {})
        configured_enabled = options.get("enabled", True)
        if not isinstance(configured_enabled, bool):
            raise ValueError(f"provider {name} enabled must be boolean")
        url = options.get("url", options.get("base_url", _env_url(name, environment)))
        url = _validate_url(name, url)
        timeout = _positive_number(
            name, "timeout", options.get("timeout", 30), integer=True
        )
        workers = _positive_number(
            name, "workers", options.get("workers", _DEFAULTS[name].get("workers", 10)), integer=True
        )
        rate = _positive_number(
            name,
            "rate_per_second",
            options.get("rate_per_second", _DEFAULTS[name].get("rate_per_second", 20)),
            integer=True,
        )
        ttl = _ttl(name, options)
        secrets = _secrets(name, environment)
        enabled = configured_enabled and (offline or bool(secrets))
        settings = ProviderSettings(
            name=name,
            base_url=url,
            secrets=secrets,
            timeout=timeout,
            workers=workers,
            rate_per_second=rate,
            ttl=ttl,
            enabled=enabled,
        )
        cache = _cache_for(name, ttl, cache_root, run_root)
        transport = _transport(name, transport_factory, offline)

        if name == "ioc_info":
            provider = IOCInfoProvider(
                settings,
                transport=transport,
                cache=cache,
                go_transport=go_transport,
                max_attempts=int(options.get("max_attempts", 10)),
                retry_delay=float(options.get("retry_delay", 0)),
            )
        elif name == "k01_compromise":
            provider = K01CompromiseProvider(
                settings,
                transport=transport,
                cache=cache,
                go_transport=go_transport,
                ignore_port=bool(options.get("ignore_port", False)),
                ignore_url=bool(options.get("ignore_url", False)),
                ignore_top=bool(options.get("ignore_top", False)),
            )
        elif name == "fdark":
            provider = FDarkProvider(
                settings,
                core_config,
                transport=transport,
                cache=cache,
                go_transport=go_transport,
                include_slow_variants=bool(
                    options.get("include_slow_variants", False)
                ),
                include_url_param=bool(options.get("include_url_param", False)),
                query_params=options.get("query_params"),
            )
        elif name == "whois":
            provider = WhoisProvider(
                settings, transport=transport, cache=cache, go_transport=go_transport
            )
        elif name == "icp":
            provider = ICPProvider(
                settings, transport=transport, cache=cache, go_transport=go_transport
            )
        else:
            provider = PDNSProvider(
                settings, transport=transport, cache=cache, go_transport=go_transport
            )

        provider.is_live_provider = True
        if not configured_enabled:
            provider.disabled_reason = "disabled by provider configuration"
        elif not enabled:
            provider.disabled_reason = "missing required credentials"
        else:
            provider.disabled_reason = ""
        providers.append(provider)
    return providers


__all__ = [
    "DEFAULT_PROVIDERS",
    "SUPPORTED_PROVIDERS",
    "build_providers",
    "load_credentials_file",
    "load_local_config",
    "load_result_cache_settings",
    "parse_provider_names",
]
