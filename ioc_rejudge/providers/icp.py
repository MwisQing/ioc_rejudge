"""Opt-in ICP registration provider with cache-first, secret-safe collection."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
import ipaddress
from threading import Lock
import time
from typing import Callable

from ioc_rejudge.observations import Freshness, IocTarget, Observation, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.cache import CacheEntry, JsonlProviderCache
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import RequestsTransport, TransportError


_SUPPORTED_TYPES = {"domain", "url", "domain_port"}
_REDACTED = "[REDACTED]"


def _is_non_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(host)
    return False


def _registration(response: object) -> tuple[str | None, str | None]:
    if not isinstance(response, dict):
        return None, "ICP response must be an object"
    result_object = response.get("resultObject")
    if result_object is not None and not isinstance(result_object, dict):
        return None, "ICP resultObject must be an object"

    def candidate(container: dict, key: str) -> tuple[str | None, str | None]:
        value = container.get(key)
        if value is None:
            return None, None
        if not isinstance(value, str):
            return None, "ICP registration must be a string"
        normalized = value.strip()
        if _REDACTED in normalized:
            return None, "ICP registration contains redacted data"
        return (normalized or None), None

    if isinstance(result_object, dict):
        for key in ("website_icp_num", "icp"):
            value, error = candidate(result_object, key)
            if error or value is not None:
                return value, error

    rows = response.get("rows")
    if rows is not None and not isinstance(rows, list):
        return None, "ICP rows must be a list"
    if isinstance(rows, list) and rows:
        if not isinstance(rows[0], dict):
            return None, "ICP rows[0] must be an object"
        for key in ("website_icp_num", "icp"):
            value, error = candidate(rows[0], key)
            if error or value is not None:
                return value, error
    return "", None


def _redact_secret_values(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            redacted = redacted.replace(secret, _REDACTED)
        return redacted
    if isinstance(value, dict):
        return {
            _redact_secret_values(key, secrets): _redact_secret_values(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_secret_values(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_secret_values(item, secrets) for item in value)
    return value


class _RateLimiter:
    def __init__(self, rate: int, clock: Callable[[], float], sleep: Callable[[float], None]):
        self.interval = 1.0 / max(1, rate)
        self.clock = clock
        self.sleep = sleep
        self.lock = Lock()
        self.next_at = 0.0

    def wait(self) -> None:
        with self.lock:
            now = self.clock()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            self.sleep(delay)


class ICPProvider:
    name = "icp"

    def __init__(
        self,
        settings: ProviderSettings,
        *,
        transport: RequestsTransport | None = None,
        cache: JsonlProviderCache | None = None,
        now_fn: Callable[[], datetime] | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or RequestsTransport()
        self.cache = cache
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep

    def supports(self, target: IocTarget) -> bool:
        return target.ioc_type in _SUPPORTED_TYPES and _is_non_ip_host(target.host)

    def cache_params(self, host: str) -> dict:
        return {"endpoint": self.settings.base_url, "host": host}

    def request_params(self, host: str) -> dict:
        return {
            "uc": self.settings.secrets["uc"],
            "key": self.settings.secrets["key"],
            "dm": host,
        }

    def _safe_error(self, message: object) -> str:
        text = str(message)
        for secret in self.settings.secrets.values():
            if secret:
                text = text.replace(str(secret), "[REDACTED]")
        return text

    def _observation(
        self,
        target: IocTarget,
        registration: str,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> Observation:
        return Observation(
            ioc=target.normalized,
            scope=target.ioc_type,
            provider=self.name,
            kind="icp_registration",
            status=ProviderStatus.SUCCESS,
            fetched_at=fetched_at,
            observed_at=fetched_at,
            freshness=freshness,
            strength="normal",
            payload={"current": bool(registration), "registration": registration},
            raw_ref=raw_ref,
        )

    def _consume(
        self,
        target: IocTarget,
        response: object,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> tuple[ProviderStatus, Observation | None, str | None]:
        registration, error = _registration(response)
        if error:
            return ProviderStatus.ERROR, None, error
        assert registration is not None
        if any(
            isinstance(secret, str) and secret and secret in registration
            for secret in self.settings.secrets.values()
        ):
            return ProviderStatus.ERROR, None, "ICP registration contained a credential value"
        return ProviderStatus.SUCCESS, self._observation(
            target,
            registration,
            fetched_at=fetched_at,
            freshness=freshness,
            raw_ref=raw_ref,
        ), None

    def _store(self, host: str, response: object, fetched_at: datetime) -> tuple[str, str | None]:
        if self.cache is None:
            return f"live:{self.name}", None
        try:
            secrets = tuple(sorted(
                {
                    str(secret)
                    for secret in self.settings.secrets.values()
                    if isinstance(secret, str) and secret
                },
                key=len,
                reverse=True,
            ))
            persisted = _redact_secret_values(response, secrets)
            entry = self.cache.put(host, persisted, self.cache_params(host), fetched_at=fetched_at)
        except (OSError, TypeError, ValueError) as exc:
            return "", f"cache write failed for {host}: {self._safe_error(exc)}"
        return f"cache:{self.name}:{entry.key}", None

    def _stale_observation(self, target: IocTarget, entry: CacheEntry) -> tuple[Observation | None, str | None]:
        status, observation, error = self._consume(
            target,
            entry.raw,
            fetched_at=entry.fetched_at,
            freshness=Freshness.STALE,
            raw_ref=f"cache:{self.name}:{entry.key}",
        )
        return observation, error

    def collect(self, targets: list[IocTarget], context: ProviderContext) -> ProviderResult:
        statuses: dict[str, ProviderStatus] = {}
        observations_by_ioc: dict[str, Observation] = {}
        errors: list[str] = []
        cache_hits = 0
        supported: list[IocTarget] = []
        for target in targets:
            if self.supports(target):
                supported.append(target)
            else:
                statuses[target.normalized] = ProviderStatus.DISABLED
        if not self.settings.enabled:
            for target in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
            return ProviderResult(self.name, [], statuses, errors, cache_hits)
        credentials_ready = bool(self.settings.secrets.get("uc")) and bool(self.settings.secrets.get("key"))
        if not context.offline and not credentials_ready:
            for target in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
            return ProviderResult(self.name, [], statuses, errors, cache_hits)

        groups: dict[str, list[IocTarget]] = {}
        for target in supported:
            groups.setdefault(target.host, []).append(target)
        limiter = _RateLimiter(self.settings.rate_per_second, self.clock, self.sleep)
        live_hosts: list[tuple[str, list[IocTarget], CacheEntry | None]] = []

        for host, host_targets in groups.items():
            entry = None
            if self.cache is not None and not context.refresh:
                entry = self.cache.get(host, self.cache_params(host), now=self.now_fn())
                errors.extend(f"cache: {self._safe_error(item)}" for item in self.cache.diagnostics)
            if entry is not None and (entry.fresh or context.offline):
                status, observation, error = self._consume(
                    host_targets[0],
                    entry.raw,
                    fetched_at=entry.fetched_at,
                    freshness=Freshness.FRESH if entry.fresh else Freshness.STALE,
                    raw_ref=f"cache:{self.name}:{entry.key}",
                )
                for target in host_targets:
                    statuses[target.normalized] = status
                    if observation is not None:
                        observations_by_ioc[target.normalized] = replace(observation, ioc=target.normalized, scope=target.ioc_type)
                cache_hits += len(host_targets)
                if error:
                    errors.append(f"{host}: {self._safe_error(error)}")
                continue
            if context.offline:
                for target in host_targets:
                    statuses[target.normalized] = ProviderStatus.ERROR
                errors.append(f"offline cache miss for {host}")
                continue
            live_hosts.append((host, host_targets, entry if entry is not None and entry.stale else None))

        def fetch(item):
            host, host_targets, stale_entry = item
            try:
                limiter.wait()
                response = self.transport.get_json(
                    self.settings.base_url,
                    params=self.request_params(host),
                    timeout=self.settings.timeout,
                )
                fetched_at = self.now_fn()
                raw_ref, cache_error = self._store(host, response, fetched_at)
                if cache_error:
                    return host, host_targets, ProviderStatus.ERROR, None, cache_error, stale_entry
                status, observation, error = self._consume(
                    host_targets[0], response, fetched_at=fetched_at,
                    freshness=Freshness.FRESH, raw_ref=raw_ref,
                )
                return host, host_targets, status, observation, error, stale_entry
            except TransportError as exc:
                return host, host_targets, ProviderStatus.ERROR, None, self._safe_error(exc), stale_entry
            except Exception as exc:
                return host, host_targets, ProviderStatus.ERROR, None, self._safe_error(exc), stale_entry

        if live_hosts:
            with ThreadPoolExecutor(max_workers=min(self.settings.workers, len(live_hosts))) as executor:
                futures = [executor.submit(fetch, item) for item in live_hosts]
                for future in as_completed(futures):
                    host, host_targets, status, observation, error, stale_entry = future.result()
                    for target in host_targets:
                        statuses[target.normalized] = status
                        if observation is not None:
                            observations_by_ioc[target.normalized] = replace(observation, ioc=target.normalized, scope=target.ioc_type)
                    if error:
                        errors.append(f"{host}: {self._safe_error(error)}")
                    if status == ProviderStatus.ERROR and stale_entry is not None:
                        stale_observation, stale_error = self._stale_observation(host_targets[0], stale_entry)
                        if stale_observation is not None:
                            for target in host_targets:
                                observations_by_ioc[target.normalized] = replace(stale_observation, ioc=target.normalized, scope=target.ioc_type)
                        if stale_error:
                            errors.append(f"{host}: stale cache: {self._safe_error(stale_error)}")

        observations = [observations_by_ioc[target.normalized] for target in targets if target.normalized in observations_by_ioc]
        return ProviderResult(self.name, observations, statuses, errors, cache_hits)


__all__ = ["ICPProvider"]
