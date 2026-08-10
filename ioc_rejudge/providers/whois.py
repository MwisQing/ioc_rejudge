"""Current WHOIS provider with cache freshness kept separate from domain dates."""

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
_DATE_FIELDS = {
    "created": ("createdDate", "creationDate", "created_at", "created"),
    "updated": ("updatedDate", "updateDate", "lastUpdated", "updated_at"),
    "expires": (
        "expiresDate",
        "expirationDate",
        "expiryDate",
        "expires_at",
        "expiration_date",
    ),
}
_REGISTRANT_FIELDS = (
    "registrantName",
    "registrantOrganization",
    "registrantEmail",
    "registrant",
)


def _is_domain_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(host)
    return False


def _as_values(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _parse_date(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value in (None, ""):
        return None
    text = str(value).strip()
    parsed = parse_time(text)
    if parsed is not None:
        return parsed
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _date_fact(
    data: dict,
    names: tuple[str, ...],
    *,
    earliest: bool = False,
) -> tuple[str, list[object], int]:
    raw_values: list[object] = []
    for name in names:
        if name in data:
            raw_values.extend(_as_values(data.get(name)))
    parsed = [value for value in (_parse_date(item) for item in raw_values) if value]
    if not parsed:
        return "", raw_values, len(raw_values)
    selected = min(parsed, key=_utc_naive) if earliest else max(parsed, key=_utc_naive)
    invalid_count = len(raw_values) - len(parsed)
    return selected.isoformat(sep=" "), raw_values, invalid_count


def _first_value(data: dict, names: tuple[str, ...]) -> object:
    for name in names:
        for value in _as_values(data.get(name)):
            if value not in (None, ""):
                return value
    return ""


class WhoisProvider:
    name = "whois"

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
        return f"{self.settings.base_url.rstrip('/')}/{quote(target.host, safe='')}"

    def cache_params(self, target: IocTarget) -> dict:
        return {
            "endpoint": self.endpoint(target),
            "host": target.host,
            "merge": 0,
        }

    def _cache_ref(self, entry: CacheEntry) -> str:
        return f"cache:{self.name}:{entry.key}"

    @staticmethod
    def _response_data(response: object) -> tuple[dict | None, str | None]:
        if not isinstance(response, dict):
            return None, "WHOIS response must be an object"
        if str(response.get("code")) != "200":
            return None, f"WHOIS business code {response.get('code')!r}"
        data = response.get("data")
        if data in (None, {}):
            return {}, None
        if not isinstance(data, dict):
            return None, "WHOIS response data must be an object"
        return data, None

    @staticmethod
    def _payload(response: dict, data: dict) -> tuple[dict, list[str]]:
        created_at, raw_created, invalid_created = _date_fact(
            data, _DATE_FIELDS["created"], earliest=True
        )
        updated_at, raw_updated, invalid_updated = _date_fact(
            data, _DATE_FIELDS["updated"]
        )
        expires_at, raw_expires, invalid_expires = _date_fact(
            data, _DATE_FIELDS["expires"]
        )
        diagnostics: list[str] = []
        for name, invalid_count in (
            ("created", invalid_created),
            ("updated", invalid_updated),
            ("expires", invalid_expires),
        ):
            if invalid_count:
                diagnostics.append(f"invalid {name} date value(s): {invalid_count}")
        if not raw_expires:
            diagnostics.append("missing expires date")
        elif not expires_at:
            diagnostics.append("invalid expires date")

        raw_dates = {
            key: data[key]
            for names in _DATE_FIELDS.values()
            for key in names
            if key in data
        }
        payload = {
            "created_at": created_at,
            "updated_at": updated_at,
            "expires_at": expires_at,
            "registrant": _first_value(data, _REGISTRANT_FIELDS),
            "response_code": response.get("code"),
            "response_status": response.get("status"),
            "domain_status": data.get("status", []),
            "merge_status": data.get("mergeStatus"),
            "raw_dates": raw_dates,
        }
        return payload, diagnostics

    def _consume(
        self,
        target: IocTarget,
        response: object,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> tuple[ProviderStatus, Observation | None, list[str]]:
        data, response_error = self._response_data(response)
        if response_error:
            return ProviderStatus.ERROR, None, [response_error]
        if not data:
            return ProviderStatus.NO_DATA, None, []
        payload, diagnostics = self._payload(response, data)
        observation = Observation(
            ioc=target.normalized,
            scope=target.ioc_type,
            provider=self.name,
            kind="whois",
            status=ProviderStatus.SUCCESS,
            fetched_at=fetched_at,
            observed_at=fetched_at,
            freshness=freshness,
            strength="normal",
            payload=payload,
            raw_ref=raw_ref,
        )
        return ProviderStatus.SUCCESS, observation, diagnostics

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
        _, observation, diagnostics = self._consume(
            target,
            entry.raw,
            fetched_at=entry.fetched_at,
            freshness=Freshness.STALE,
            raw_ref=self._cache_ref(entry),
        )
        if observation is not None:
            observations.append(observation)
        errors.extend(f"{target.normalized}: stale cache: {item}" for item in diagnostics)

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
        observations_by_ioc: dict[str, Observation] = {}
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
                status, observation, diagnostics = self._consume(
                    target, entry.raw, fetched_at=entry.fetched_at,
                    freshness=Freshness.FRESH, raw_ref=self._cache_ref(entry),
                )
                statuses[target.normalized] = status
                if observation is not None:
                    observations_by_ioc[target.normalized] = observation
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
                headers=dict(self.settings.secrets), params={"merge": 0},
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
                if stale_observations:
                    observations_by_ioc[target.normalized] = stale_observations[0]
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
                    if stale_observations:
                        observations_by_ioc[target.normalized] = stale_observations[0]
                else:
                    status, observation, diagnostics = self._consume(
                        target, result.payload, fetched_at=fetched_at,
                        freshness=Freshness.FRESH, raw_ref=raw_ref,
                    )
                    statuses[target.normalized] = status
                    if observation is not None:
                        observations_by_ioc[target.normalized] = observation
                    target_errors.extend(diagnostics)
            done += 1
            report_progress(context, self.name, done, total)

        observations = [
            observations_by_ioc[target.normalized]
            for target in supported
            if target.normalized in observations_by_ioc
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
                    status, observation, diagnostics = self._consume(
                        target,
                        entry.raw,
                        fetched_at=entry.fetched_at,
                        freshness=Freshness.FRESH if entry.fresh else Freshness.STALE,
                        raw_ref=self._cache_ref(entry),
                    )
                    statuses[target.normalized] = status
                    if observation is not None:
                        observations.append(observation)
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
                        params={"merge": 0},
                        timeout=self.settings.timeout,
                    )
                except TransportError as exc:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(f"{target.normalized}: {exc}")
                    self._append_stale(target, stale_entry, observations, errors)
                    continue

                data, response_error = self._response_data(response)
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

                status, observation, diagnostics = self._consume(
                    target,
                    response,
                    fetched_at=fetched_at,
                    freshness=Freshness.FRESH,
                    raw_ref=raw_ref,
                )
                statuses[target.normalized] = status
                if observation is not None:
                    observations.append(observation)
                errors.extend(f"{target.normalized}: {item}" for item in diagnostics)
            finally:
                # Count after status/observations/errors are settled, including
                # handled continue paths. An unexpected exception propagates
                # without claiming that this target completed.
                if target.normalized in statuses:
                    done += 1
                    report_progress(context, self.name, done, total)

        return ProviderResult(self.name, observations, statuses, errors, cache_hits)


__all__ = ["WhoisProvider"]
