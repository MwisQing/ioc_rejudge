"""Passive DNS provider preserving every activity record."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Callable
from urllib.parse import quote

from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
)
from ioc_rejudge.parser import parse_time
from ioc_rejudge.providers.base import (
    ProviderContext,
    ProviderResult,
    report_progress,
)
from ioc_rejudge.providers.cache import CacheEntry, JsonlProviderCache
from ioc_rejudge.providers.go_transport import BatchRequest, GoBatchTransport
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import RequestsTransport, TransportError


_SUPPORTED_TYPES = {"domain", "url", "domain_port"}


def _is_domain_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(host)
    return False


def _activity_time(value: object) -> datetime | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and value.strip().replace(".", "", 1).isdigit()
    ):
        try:
            timestamp = float(value)
            if timestamp < 0:
                return None
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            return datetime.fromtimestamp(timestamp, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    parsed = parse_time(text)
    if parsed is not None:
        return parsed
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _normalized_time(raw: object, parsed: datetime | None) -> object:
    if parsed is not None:
        return parsed.isoformat(sep=" ")
    return "" if raw in (None, "") else raw


class PDNSProvider:
    name = "pdns"

    def __init__(
        self,
        settings: ProviderSettings,
        *,
        transport: RequestsTransport | None = None,
        cache: JsonlProviderCache | None = None,
        go_transport: GoBatchTransport | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or RequestsTransport()
        self.cache = cache
        self.go_transport = go_transport
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    def supports(self, target: IocTarget) -> bool:
        return target.ioc_type in _SUPPORTED_TYPES and _is_domain_host(target.host)

    def endpoint(self, target: IocTarget) -> str:
        return f"{self.settings.base_url.rstrip('/')}/{quote(target.host, safe='')}/"

    def cache_params(self, target: IocTarget) -> dict:
        return {"endpoint": self.endpoint(target), "host": target.host}

    def _cache_ref(self, entry: CacheEntry) -> str:
        return f"cache:{self.name}:{entry.key}"

    @staticmethod
    def _records(response: object) -> tuple[list[dict] | None, str | None]:
        if not isinstance(response, dict):
            return None, "pDNS response must be an object"
        if str(response.get("code")) != "200":
            return None, f"pDNS business code {response.get('code')!r}"
        data = response.get("data", [])
        if not isinstance(data, list):
            return None, "pDNS response data must be a list"
        if any(not isinstance(record, dict) for record in data):
            return None, "pDNS response records must be objects"
        return data, None

    def _observations(
        self,
        target: IocTarget,
        records: list[dict],
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> tuple[list[Observation], list[str]]:
        observations: list[Observation] = []
        diagnostics: list[str] = []
        for index, record in enumerate(records):
            raw_first = record.get("time_first")
            raw_last = record.get("time_last")
            first = _activity_time(raw_first)
            last = _activity_time(raw_last)
            if raw_first not in (None, "") and first is None:
                diagnostics.append(f"record {index}: invalid time_first")
            if raw_last not in (None, "") and last is None:
                diagnostics.append(f"record {index}: invalid time_last")
            observations.append(Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider=self.name,
                kind="pdns_activity",
                status=ProviderStatus.SUCCESS,
                fetched_at=fetched_at,
                observed_at=last,
                freshness=freshness,
                strength="normal",
                payload={
                    "rrtype": record.get("rrtype", ""),
                    "rdata": record.get("rdata", ""),
                    "count": record.get("count", 0),
                    "time_first": _normalized_time(raw_first, first),
                    "time_last": _normalized_time(raw_last, last),
                    "raw_time_first": raw_first,
                    "raw_time_last": raw_last,
                },
                raw_ref=raw_ref,
            ))
        return observations, diagnostics

    def _consume(
        self,
        target: IocTarget,
        response: object,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> tuple[ProviderStatus, list[Observation], list[str]]:
        records, response_error = self._records(response)
        if response_error:
            return ProviderStatus.ERROR, [], [response_error]
        if not records:
            return ProviderStatus.NO_DATA, [], []
        observations, diagnostics = self._observations(
            target,
            records,
            fetched_at=fetched_at,
            freshness=freshness,
            raw_ref=raw_ref,
        )
        return ProviderStatus.SUCCESS, observations, diagnostics

    def _store_response(
        self,
        target: IocTarget,
        response: object,
        fetched_at: datetime,
    ) -> tuple[str, str | None]:
        if self.cache is None:
            return f"live:{self.name}", None
        try:
            entry = self.cache.put(
                target.host,
                response,
                self.cache_params(target),
                fetched_at=fetched_at,
            )
        except (OSError, TypeError, ValueError) as exc:
            return "", f"cache write failed for {target.normalized}: {exc}"
        return self._cache_ref(entry), None

    def _append_stale(
        self,
        target: IocTarget,
        entry: CacheEntry | None,
        observations: list[Observation],
        errors: list[str],
    ) -> None:
        if entry is None:
            return
        _, stale_observations, diagnostics = self._consume(
            target,
            entry.raw,
            fetched_at=entry.fetched_at,
            freshness=Freshness.STALE,
            raw_ref=self._cache_ref(entry),
        )
        observations.extend(stale_observations)
        errors.extend(
            f"{target.normalized}: stale cache: {item}" for item in diagnostics
        )

    def _collect_with_go(
        self,
        supported: list[IocTarget],
        context: ProviderContext,
        statuses: dict[str, ProviderStatus],
        cache_hits: int,
    ) -> ProviderResult:
        assert self.go_transport is not None
        total = len(supported)
        done = 0
        report_progress(context, self.name, done, total)
        observations_by_ioc: dict[str, list[Observation]] = {}
        errors_by_ioc: dict[str, list[str]] = {target.normalized: [] for target in supported}
        jobs: list[BatchRequest] = []
        pending: dict[str, tuple[IocTarget, CacheEntry | None]] = {}
        global_errors: list[str] = []

        for target in supported:
            entry = None
            if self.cache is not None and not context.refresh:
                entry = self.cache.get(
                    target.host, self.cache_params(target), now=self.now_fn()
                )
                global_errors.extend(
                    f"cache: {message}" for message in self.cache.diagnostics
                )
            if entry is not None and entry.fresh:
                status, cached_observations, diagnostics = self._consume(
                    target, entry.raw, fetched_at=entry.fetched_at,
                    freshness=Freshness.FRESH, raw_ref=self._cache_ref(entry),
                )
                statuses[target.normalized] = status
                observations_by_ioc[target.normalized] = cached_observations
                errors_by_ioc[target.normalized].extend(diagnostics)
                cache_hits += 1
                done += 1
                report_progress(context, self.name, done, total)
                continue
            request_id = str(len(jobs))
            pending[request_id] = (
                target, entry if entry is not None and entry.stale else None
            )
            jobs.append(BatchRequest(
                id=request_id, method="GET", url=self.endpoint(target),
                headers=dict(self.settings.secrets),
                timeout=self.settings.timeout,
            ))

        for result in self.go_transport.iter_batch(
            jobs, workers=self.settings.workers,
            rate_per_second=self.settings.rate_per_second,
        ):
            target, stale_entry = pending[result.id]
            target_errors = errors_by_ioc[target.normalized]
            if result.error is not None:
                statuses[target.normalized] = ProviderStatus.ERROR
                target_errors.append(str(result.error))
                stale_observations: list[Observation] = []
                self._append_stale(target, stale_entry, stale_observations, target_errors)
                observations_by_ioc[target.normalized] = stale_observations
            else:
                fetched_at = self.now_fn()
                raw_ref, cache_error = self._store_response(
                    target, result.payload, fetched_at
                )
                if cache_error:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    target_errors.append(cache_error)
                    stale_observations = []
                    self._append_stale(
                        target, stale_entry, stale_observations, target_errors
                    )
                    observations_by_ioc[target.normalized] = stale_observations
                else:
                    status, live_observations, diagnostics = self._consume(
                        target, result.payload, fetched_at=fetched_at,
                        freshness=Freshness.FRESH, raw_ref=raw_ref,
                    )
                    statuses[target.normalized] = status
                    observations_by_ioc[target.normalized] = live_observations
                    target_errors.extend(diagnostics)
            done += 1
            report_progress(context, self.name, done, total)

        observations = [
            observation
            for target in supported
            for observation in observations_by_ioc.get(target.normalized, [])
        ]
        errors = list(global_errors)
        for target in supported:
            errors.extend(
                f"{target.normalized}: {message}"
                for message in errors_by_ioc[target.normalized]
            )
        return ProviderResult(self.name, observations, statuses, errors, cache_hits)

    def collect(
        self,
        targets: list[IocTarget],
        context: ProviderContext,
    ) -> ProviderResult:
        statuses: dict[str, ProviderStatus] = {}
        observations: list[Observation] = []
        errors: list[str] = []
        cache_hits = 0

        supported = [target for target in targets if self.supports(target)]
        for target in targets:
            if target not in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
        if not self.settings.enabled:
            for target in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
            return ProviderResult(self.name, observations, statuses, errors, cache_hits)
        if (
            not context.offline
            and self.go_transport is not None
            and self.go_transport.available
        ):
            return self._collect_with_go(
                supported, context, statuses, cache_hits
            )

        total = len(supported)
        done = 0
        # done counts only targets whose status is already determined.
        report_progress(context, self.name, done, total)
        for target in supported:
            try:
                entry = None
                if self.cache is not None and not context.refresh:
                    entry = self.cache.get(
                        target.host,
                        self.cache_params(target),
                        now=self.now_fn(),
                    )
                    errors.extend(
                        f"cache: {message}" for message in self.cache.diagnostics
                    )

                if entry is not None and (entry.fresh or context.offline):
                    status, cached_observations, diagnostics = self._consume(
                        target,
                        entry.raw,
                        fetched_at=entry.fetched_at,
                        freshness=Freshness.FRESH if entry.fresh else Freshness.STALE,
                        raw_ref=self._cache_ref(entry),
                    )
                    statuses[target.normalized] = status
                    observations.extend(cached_observations)
                    errors.extend(
                        f"{target.normalized}: {item}" for item in diagnostics
                    )
                    cache_hits += 1
                    continue

                if context.offline:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(f"offline cache miss for {target.normalized}")
                    continue

                stale_entry = entry if entry is not None and entry.stale else None
                try:
                    response = self.transport.get_json(
                        self.endpoint(target),
                        headers=dict(self.settings.secrets),
                        timeout=self.settings.timeout,
                    )
                except TransportError as exc:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(f"{target.normalized}: {exc}")
                    self._append_stale(target, stale_entry, observations, errors)
                    continue

                records, response_error = self._records(response)
                if response_error:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(f"{target.normalized}: {response_error}")
                    self._append_stale(target, stale_entry, observations, errors)
                    continue

                fetched_at = self.now_fn()
                raw_ref, cache_error = self._store_response(target, response, fetched_at)
                if cache_error:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(cache_error)
                    self._append_stale(target, stale_entry, observations, errors)
                    continue

                status, live_observations, diagnostics = self._consume(
                    target,
                    response,
                    fetched_at=fetched_at,
                    freshness=Freshness.FRESH,
                    raw_ref=raw_ref,
                )
                statuses[target.normalized] = status
                observations.extend(live_observations)
                errors.extend(f"{target.normalized}: {item}" for item in diagnostics)
            finally:
                # Count after status/observations/errors are settled, including
                # handled continue paths. An unexpected exception propagates
                # without claiming that this target completed.
                if target.normalized in statuses:
                    done += 1
                    report_progress(context, self.name, done, total)

        return ProviderResult(self.name, observations, statuses, errors, cache_hits)


__all__ = ["PDNSProvider"]
