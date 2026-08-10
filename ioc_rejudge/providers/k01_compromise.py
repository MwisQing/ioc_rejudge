"""K01 compromises classification provider."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
)
from ioc_rejudge.providers.base import (
    ProviderContext,
    ProviderResult,
    report_progress,
)
from ioc_rejudge.providers.cache import CacheEntry, JsonlProviderCache
from ioc_rejudge.providers.go_transport import BatchRequest, GoBatchTransport
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import RequestsTransport, TransportError


API_PATH = "/api/v1/k01/compromises"
DEFAULT_BATCH_SIZE = 100
_SUPPORTED_TYPES = {"domain", "url", "domain_port", "ip", "ip_port"}


def build_batch_payload(
    targets: list[IocTarget],
    *,
    ignore_port: bool = False,
    ignore_url: bool = False,
    ignore_top: bool = False,
) -> dict:
    """Build the exact K01 batch request without changing IOC shapes."""

    return {
        "params": [target.original for target in targets],
        "ignore_port": bool(ignore_port),
        "ignore_url": bool(ignore_url),
        "ignore_top": bool(ignore_top),
    }


def _endpoint(base_url: str) -> str:
    split = urlsplit(base_url.rstrip("/"))
    path = split.path.rstrip("/")
    if not path.endswith(API_PATH):
        path += API_PATH
    return urlunsplit((split.scheme, split.netloc, path, "", ""))


def _normalize_tags(value: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(value, list):
        return None, "tags must be a list"
    tags: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            return None, "tags entries must be strings"
        tag = item.strip().lower()
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags, None


def _scope_response_to_target(response: object, target: IocTarget) -> object:
    """Preserve the K01 envelope while isolating one target's response node."""

    if not isinstance(response, dict):
        return response
    data = response.get("data")
    if not isinstance(data, dict):
        return response

    scoped = dict(response)
    if target.original in data:
        scoped["data"] = {target.original: data[target.original]}
    elif target.normalized in data:
        scoped["data"] = {target.original: data[target.normalized]}
    else:
        scoped["data"] = {}
    return scoped


class K01CompromiseProvider:
    """Collect K01 classifications while preserving route-safety semantics."""

    name = "k01_compromise"

    def __init__(
        self,
        settings: ProviderSettings,
        *,
        transport: RequestsTransport | None = None,
        cache: JsonlProviderCache | None = None,
        go_transport: GoBatchTransport | None = None,
        ignore_port: bool = False,
        ignore_url: bool = False,
        ignore_top: bool = False,
        batch_size: int = DEFAULT_BATCH_SIZE,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("K01 batch_size must be a positive integer")
        self.settings = settings
        self.transport = transport or RequestsTransport()
        self.cache = cache
        self.go_transport = go_transport
        self.ignore_port = bool(ignore_port)
        self.ignore_url = bool(ignore_url)
        self.ignore_top = bool(ignore_top)
        self.batch_size = batch_size
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    def supports(self, target: IocTarget) -> bool:
        return target.ioc_type in _SUPPORTED_TYPES

    def cache_params(self, target: IocTarget) -> dict:
        return {
            "endpoint": _endpoint(self.settings.base_url),
            "request_ioc": target.original,
            "ignore_port": self.ignore_port,
            "ignore_url": self.ignore_url,
            "ignore_top": self.ignore_top,
        }

    def _cache_ref(self, entry: CacheEntry) -> str:
        return f"cache:{self.name}:{entry.key}"

    def _safe_error(self, value: object) -> str:
        message = str(value).strip()
        for secret in self.settings.secrets.values():
            if secret:
                message = message.replace(secret, "[REDACTED]")
        return message

    def _response_data(self, response: object) -> tuple[dict | None, str | None]:
        if not isinstance(response, dict):
            return None, "response must be an object"
        if response.get("status") != 10000:
            error = f"K01 business status {response.get('status')!r}"
            message = self._safe_error(response.get("msg", ""))
            if message:
                error += f": {message}"
            return None, error
        data = response.get("data")
        if not isinstance(data, dict):
            return None, "K01 response data must be an object"
        return data, None

    @staticmethod
    def _classification(data: dict, target: IocTarget) -> object:
        if target.original in data:
            return data[target.original]
        return data.get(target.normalized)

    def _parse_target(
        self,
        target: IocTarget,
        response: object,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> tuple[ProviderStatus, Observation | None, str | None]:
        data, response_error = self._response_data(response)
        if response_error:
            return ProviderStatus.ERROR, None, response_error

        classification = self._classification(data or {}, target)
        if classification is None:
            return ProviderStatus.NO_DATA, None, None
        if not isinstance(classification, dict):
            return ProviderStatus.ERROR, None, "classification must be an object"

        hits = classification.get("data")
        if hits in (None, []):
            return ProviderStatus.NO_DATA, None, None
        if not isinstance(hits, list):
            return ProviderStatus.ERROR, None, "classification data must be a list"

        tags: list[str] = []
        seen: set[str] = set()
        for hit_index, hit in enumerate(hits):
            if not isinstance(hit, dict):
                return (
                    ProviderStatus.ERROR,
                    None,
                    f"classification hit {hit_index} must be an object",
                )
            normalized, tag_error = _normalize_tags(hit.get("tags"))
            if tag_error:
                return (
                    ProviderStatus.ERROR,
                    None,
                    f"classification hit {hit_index}: {tag_error}",
                )
            for tag in normalized or []:
                if tag not in seen:
                    seen.add(tag)
                    tags.append(tag)

        observation = Observation(
            ioc=target.normalized,
            scope=target.ioc_type,
            provider=self.name,
            kind="dga_classification",
            status=ProviderStatus.SUCCESS,
            fetched_at=fetched_at,
            observed_at=None,
            freshness=freshness,
            strength="strong",
            payload={
                "tags": tags,
                "source_level": classification.get("level"),
                "hit_count": len(hits),
                "raw_classification": classification,
            },
            raw_ref=raw_ref,
        )
        return ProviderStatus.SUCCESS, observation, None

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
                target.original,
                _scope_response_to_target(response, target),
                self.cache_params(target),
                fetched_at=fetched_at,
            )
        except (OSError, TypeError, ValueError) as exc:
            return "", f"cache write failed for {target.normalized}: {exc}"
        return self._cache_ref(entry), None

    def _consume_batch(
        self,
        batch_number: int,
        batch: list[IocTarget],
        response: object,
        request_error: Exception | None,
        context: ProviderContext,
        statuses: dict[str, ProviderStatus],
        observations: list[Observation],
        errors: list[str],
        done: int,
        total: int,
    ) -> int:
        if request_error is not None:
            message = self._safe_error(request_error)
            errors.append(f"batch {batch_number}: {message}")
            for target in batch:
                statuses[target.normalized] = ProviderStatus.ERROR
                done += 1
                report_progress(context, self.name, done, total)
            return done

        _, response_error = self._response_data(response)
        if response_error:
            errors.append(f"batch {batch_number}: {response_error}")
            for target in batch:
                statuses[target.normalized] = ProviderStatus.ERROR
                done += 1
                report_progress(context, self.name, done, total)
            return done

        fetched_at = self.now_fn()
        for target in batch:
            raw_ref, cache_error = self._store_response(target, response, fetched_at)
            if cache_error:
                statuses[target.normalized] = ProviderStatus.ERROR
                errors.append(cache_error)
            else:
                status, observation, parse_error = self._parse_target(
                    target,
                    response,
                    fetched_at=fetched_at,
                    freshness=Freshness.FRESH,
                    raw_ref=raw_ref,
                )
                statuses[target.normalized] = status
                if observation is not None:
                    observations.append(observation)
                if parse_error:
                    errors.append(f"{target.normalized}: {parse_error}")
            done += 1
            report_progress(context, self.name, done, total)
        return done

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

        total = len(supported)
        pending: list[IocTarget] = []
        for target in supported:
            entry = None
            if self.cache is not None and not context.refresh:
                entry = self.cache.get(
                    target.original,
                    self.cache_params(target),
                    now=self.now_fn(),
                )
                errors.extend(f"cache: {message}" for message in self.cache.diagnostics)
            if entry is None or (not entry.fresh and not context.offline):
                pending.append(target)
                continue

            status, observation, parse_error = self._parse_target(
                target,
                entry.raw,
                fetched_at=entry.fetched_at,
                freshness=Freshness.FRESH if entry.fresh else Freshness.STALE,
                raw_ref=self._cache_ref(entry),
            )
            statuses[target.normalized] = status
            if observation is not None:
                observations.append(observation)
            if parse_error:
                errors.append(f"{target.normalized}: {parse_error}")
            cache_hits += 1

        done = cache_hits
        report_progress(context, self.name, done, total)

        if context.offline:
            for target in pending:
                statuses[target.normalized] = ProviderStatus.ERROR
                errors.append(f"offline cache miss for {target.normalized}")
                done += 1
                report_progress(context, self.name, done, total)
            return ProviderResult(self.name, observations, statuses, errors, cache_hits)

        if pending:
            batches = [
                pending[start : start + self.batch_size]
                for start in range(0, len(pending), self.batch_size)
            ]
            report_progress(
                context,
                self.name,
                done,
                total,
                detail=f"requesting {len(batches)} batch(es)",
            )
            if self.go_transport is not None and self.go_transport.available:
                jobs = [
                    BatchRequest(
                        id=str(index),
                        method="POST",
                        url=_endpoint(self.settings.base_url),
                        headers=dict(self.settings.secrets),
                        body=build_batch_payload(
                            batch,
                            ignore_port=self.ignore_port,
                            ignore_url=self.ignore_url,
                            ignore_top=self.ignore_top,
                        ),
                        timeout=self.settings.timeout,
                    )
                    for index, batch in enumerate(batches)
                ]
                for result in self.go_transport.iter_batch(
                    jobs,
                    workers=self.settings.workers,
                    rate_per_second=self.settings.rate_per_second,
                ):
                    batch_index = int(result.id)
                    done = self._consume_batch(
                        batch_index + 1,
                        batches[batch_index],
                        result.payload,
                        result.error,
                        context,
                        statuses,
                        observations,
                        errors,
                        done,
                        total,
                    )
            else:
                for batch_index, batch in enumerate(batches, 1):
                    response = None
                    request_error: TransportError | None = None
                    try:
                        response = self.transport.post_json(
                            _endpoint(self.settings.base_url),
                            headers=dict(self.settings.secrets),
                            body=build_batch_payload(
                                batch,
                                ignore_port=self.ignore_port,
                                ignore_url=self.ignore_url,
                                ignore_top=self.ignore_top,
                            ),
                            timeout=self.settings.timeout,
                        )
                    except TransportError as exc:
                        request_error = exc
                    done = self._consume_batch(
                        batch_index,
                        batch,
                        response,
                        request_error,
                        context,
                        statuses,
                        observations,
                        errors,
                        done,
                        total,
                    )

        return ProviderResult(self.name, observations, statuses, errors, cache_hits)


__all__ = [
    "API_PATH",
    "DEFAULT_BATCH_SIZE",
    "K01CompromiseProvider",
    "build_batch_payload",
]
