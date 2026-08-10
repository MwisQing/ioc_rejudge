"""F-Dark abstract provider and reviewed IOC query normalization."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
from typing import Callable
from urllib.parse import unquote_plus, urlsplit

from ioc_rejudge.config import Config
from ioc_rejudge.evidence import is_malicious_sample
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


_SUPPORTED_TYPES = {"domain", "url", "domain_port", "ip", "ip_port"}
DEFAULT_QUERY_PARAMS: dict[str, str | int] = {
    "limit": 20,
    "offset": 0,
    "order": "lseen-",
}


def _valid_port(value: str) -> int | None:
    try:
        port = int(value)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _parse_ip_port(value: str) -> tuple[str, int] | None:
    bracketed = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d+)", value)
    if bracketed:
        host, raw_port = bracketed.groups()
    else:
        match = re.fullmatch(r"([^:]+):(\d+)", value)
        if not match:
            return None
        host, raw_port = match.groups()

    port = _valid_port(raw_port)
    if port is None:
        return None

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host, port


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _looks_like_uri(value: str) -> bool:
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        return True
    return "/" in value


def _http_proto_for_scheme(scheme: str) -> str:
    if scheme.lower() == "https":
        return "ssl"
    return "http"


def _default_port_for_scheme(scheme: str) -> int:
    if scheme.lower() == "https":
        return 443
    return 80


def _http_url_query_params(value: str) -> dict[str, str | int] | None:
    raw = value if "://" in value else f"http://{value}"
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None

    params: dict[str, str | int] = {}
    host = parsed.hostname
    if _is_ip(host):
        params["ip"] = host
    else:
        params["domain"] = host
    params["proto"] = _http_proto_for_scheme(scheme)
    if parsed.path:
        params["http_path"] = parsed.path
    return params


def _host_params(host: str) -> dict[str, str]:
    if _is_ip(host):
        return {"ip": host}
    return {"domain": host}


def _append_variant(
    variants: list[tuple[str, dict[str, str | int]]],
    seen: set[tuple[tuple[str, str], ...]],
    name: str,
    params: dict[str, str | int],
) -> None:
    clean = {key: value for key, value in params.items() if value not in ("", None)}
    signature = tuple(sorted((key, str(value)) for key, value in clean.items()))
    if signature in seen:
        return
    seen.add(signature)
    variants.append((name, clean))


def build_query_param_variants(
    target: str,
    *,
    include_url_param: bool = False,
    include_slow_variants: bool = False,
) -> list[tuple[str, dict[str, str | int]]]:
    value = target.strip()
    if not value:
        raise ValueError("target is empty")

    if not _looks_like_uri(value):
        params = build_query_params(value)
        if "dport" in params:
            return [("ip_port", params)]
        if "ip" in params:
            return [("ip", params)]
        return [("domain", params)]

    raw = value if "://" in value else f"http://{value}"
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return [("uri_full", {"uri": value})]

    variants: list[tuple[str, dict[str, str | int]]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    host = parsed.hostname
    host_only = _host_params(host)
    proto = _http_proto_for_scheme(scheme)
    alt_scheme = "https" if scheme == "http" else "http"
    alt_proto = _http_proto_for_scheme(alt_scheme)
    explicit_port = parsed.port
    default_port = _default_port_for_scheme(scheme)
    alt_default_port = _default_port_for_scheme(alt_scheme)
    path = parsed.path or ""
    query = parsed.query or ""
    uri_without_query = raw.split("?", 1)[0]
    uri_no_scheme = raw.split("://", 1)[1] if "://" in raw else raw
    uri_no_scheme_without_query = uri_no_scheme.split("?", 1)[0]
    path_no_slash = path.lstrip("/") if path else ""
    query_part = f"?{query}" if query else ""
    alt_uri = f"{alt_scheme}://{parsed.netloc}{path}{query_part}"
    alt_uri_without_query = f"{alt_scheme}://{parsed.netloc}{path}"

    if not include_slow_variants:
        if path:
            _append_variant(
                variants,
                seen,
                "host_proto_path",
                {**host_only, "proto": proto, "http_path": path},
            )
        else:
            _append_variant(
                variants, seen, "host_proto", {**host_only, "proto": proto}
            )
        return variants

    _append_variant(variants, seen, "uri_full", {"uri": value})
    if uri_without_query != value:
        _append_variant(
            variants, seen, "uri_without_query", {"uri": uri_without_query}
        )
    _append_variant(variants, seen, "uri_alt_scheme", {"uri": alt_uri})
    if alt_uri_without_query != alt_uri:
        _append_variant(
            variants,
            seen,
            "uri_alt_scheme_without_query",
            {"uri": alt_uri_without_query},
        )
    if uri_no_scheme:
        _append_variant(
            variants, seen, "uri_no_scheme", {"uri": uri_no_scheme}
        )
    if uri_no_scheme_without_query and uri_no_scheme_without_query != uri_no_scheme:
        _append_variant(
            variants,
            seen,
            "uri_no_scheme_without_query",
            {"uri": uri_no_scheme_without_query},
        )
    if include_url_param:
        _append_variant(variants, seen, "url_full", {"url": value})
        _append_variant(variants, seen, "url_alt_scheme", {"url": alt_uri})
        if uri_no_scheme:
            _append_variant(
                variants, seen, "url_no_scheme", {"url": uri_no_scheme}
            )
        if uri_without_query != value:
            _append_variant(
                variants,
                seen,
                "url_without_query",
                {"url": uri_without_query},
            )
        if alt_uri_without_query != alt_uri:
            _append_variant(
                variants,
                seen,
                "url_alt_scheme_without_query",
                {"url": alt_uri_without_query},
            )
        if uri_no_scheme_without_query and uri_no_scheme_without_query != uri_no_scheme:
            _append_variant(
                variants,
                seen,
                "url_no_scheme_without_query",
                {"url": uri_no_scheme_without_query},
            )
    _append_variant(variants, seen, "host_only", host_only)
    _append_variant(
        variants, seen, "host_proto", {**host_only, "proto": proto}
    )
    _append_variant(
        variants, seen, "host_alt_proto", {**host_only, "proto": alt_proto}
    )

    if explicit_port is not None:
        _append_variant(
            variants, seen, "host_port", {**host_only, "dport": explicit_port}
        )
    else:
        _append_variant(
            variants,
            seen,
            "host_default_port",
            {**host_only, "dport": default_port},
        )
        _append_variant(
            variants,
            seen,
            "host_alt_default_port",
            {**host_only, "dport": alt_default_port},
        )
    _append_variant(variants, seen, "host_port_zero", {**host_only, "dport": 0})

    if path:
        _append_variant(variants, seen, "path_only", {"http_path": path})
        if path_no_slash:
            _append_variant(
                variants, seen, "path_no_slash", {"http_path": path_no_slash}
            )
        _append_variant(
            variants,
            seen,
            "proto_path_only",
            {"proto": proto, "http_path": path},
        )
        _append_variant(
            variants,
            seen,
            "alt_proto_path_only",
            {"proto": alt_proto, "http_path": path},
        )
        _append_variant(
            variants, seen, "host_path", {**host_only, "http_path": path}
        )
        _append_variant(
            variants,
            seen,
            "host_proto_path",
            {**host_only, "proto": proto, "http_path": path},
        )
        _append_variant(
            variants,
            seen,
            "host_alt_proto_path",
            {**host_only, "proto": alt_proto, "http_path": path},
        )
        _append_variant(
            variants,
            seen,
            "host_port_zero_path",
            {**host_only, "dport": 0, "http_path": path},
        )
        _append_variant(
            variants,
            seen,
            "host_proto_port_zero_path",
            {**host_only, "proto": proto, "dport": 0, "http_path": path},
        )
        _append_variant(
            variants,
            seen,
            "host_alt_proto_port_zero_path",
            {**host_only, "proto": alt_proto, "dport": 0, "http_path": path},
        )
        if explicit_port is not None:
            _append_variant(
                variants,
                seen,
                "host_port_path",
                {**host_only, "dport": explicit_port, "http_path": path},
            )
        else:
            _append_variant(
                variants,
                seen,
                "host_default_port_path",
                {**host_only, "dport": default_port, "http_path": path},
            )
            _append_variant(
                variants,
                seen,
                "host_alt_default_port_path",
                {**host_only, "dport": alt_default_port, "http_path": path},
            )

    if query:
        _append_variant(variants, seen, "query_only", {"http_query": query})
        _append_variant(
            variants,
            seen,
            "proto_query_only",
            {"proto": proto, "http_query": query},
        )
        _append_variant(
            variants,
            seen,
            "host_query",
            {**host_only, "http_query": query},
        )
        _append_variant(
            variants,
            seen,
            "host_proto_query",
            {**host_only, "proto": proto, "http_query": query},
        )

    if path and query:
        _append_variant(
            variants,
            seen,
            "path_query_only",
            {"http_path": path, "http_query": query},
        )
        _append_variant(
            variants,
            seen,
            "proto_path_query_only",
            {"proto": proto, "http_path": path, "http_query": query},
        )
        _append_variant(
            variants,
            seen,
            "host_path_query",
            {**host_only, "http_path": path, "http_query": query},
        )
        _append_variant(
            variants,
            seen,
            "host_proto_path_query",
            {
                **host_only,
                "proto": proto,
                "http_path": path,
                "http_query": query,
            },
        )
        port = explicit_port or default_port
        port_name = (
            "host_port_path_query"
            if explicit_port is not None
            else "host_default_port_path_query"
        )
        _append_variant(
            variants,
            seen,
            port_name,
            {**host_only, "dport": port, "http_path": path, "http_query": query},
        )
        proto_port_name = (
            "host_proto_port_path_query"
            if explicit_port is not None
            else "host_proto_default_port_path_query"
        )
        _append_variant(
            variants,
            seen,
            proto_port_name,
            {
                **host_only,
                "proto": proto,
                "dport": port,
                "http_path": path,
                "http_query": query,
            },
        )

    if query:
        for index, part in enumerate(query.split("&"), start=1):
            if not part:
                continue
            raw_key, _, raw_value = part.partition("=")
            key = unquote_plus(raw_key)
            value_part = unquote_plus(raw_value)
            suffix = re.sub(r"[^A-Za-z0-9_-]+", "_", key) or str(index)
            _append_variant(
                variants, seen, f"query_kv_only_{suffix}", {"http_query_kv": part}
            )
            _append_variant(
                variants, seen, f"query_key_only_{suffix}", {"http_query_k": key}
            )
            _append_variant(
                variants,
                seen,
                f"query_kv_{suffix}",
                {**host_only, "http_query_kv": part},
            )
            _append_variant(
                variants,
                seen,
                f"query_key_{suffix}",
                {**host_only, "http_query_k": key},
            )
            if raw_value != "":
                value_suffix = (
                    re.sub(r"[^A-Za-z0-9_-]+", "_", value_part) or str(index)
                )
                _append_variant(
                    variants,
                    seen,
                    f"query_value_only_{value_suffix}",
                    {"http_query_v": value_part},
                )
                _append_variant(
                    variants,
                    seen,
                    f"query_value_{value_suffix}",
                    {**host_only, "http_query_v": value_part},
                )

    return variants


def build_query_params(target: str) -> dict[str, str | int]:
    value = target.strip()
    if not value:
        raise ValueError("target is empty")
    if _looks_like_uri(value):
        http_params = _http_url_query_params(value)
        if http_params is not None:
            return http_params
        return {"uri": value}
    if _is_ip(value):
        return {"ip": value}
    ip_port = _parse_ip_port(value)
    if ip_port is not None:
        ip, port = ip_port
        return {"ip": ip, "dport": port}
    return {"domain": value}


def build_request_params(
    target: str,
    extra_params: dict[str, str | int] | None = None,
) -> dict[str, str | int]:
    params = build_query_params(target)
    if extra_params:
        params.update(
            {key: value for key, value in extra_params.items() if value not in ("", None)}
        )
    return params


def _sample_time(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and value.strip().replace(".", "", 1).isdigit()
    ):
        try:
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            return datetime.fromtimestamp(timestamp, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return parse_time(str(value)) if value not in (None, "") else None


class FDarkProvider:
    name = "fdark"

    def __init__(
        self,
        settings: ProviderSettings,
        config: Config,
        *,
        transport: RequestsTransport | None = None,
        cache: JsonlProviderCache | None = None,
        include_slow_variants: bool = False,
        include_url_param: bool = False,
        query_params: dict[str, str | int] | None = None,
        go_transport: GoBatchTransport | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.config = config
        self.transport = transport or RequestsTransport()
        self.cache = cache
        self.include_slow_variants = bool(include_slow_variants)
        self.include_url_param = bool(include_url_param)
        self.query_params = dict(DEFAULT_QUERY_PARAMS)
        self.go_transport = go_transport
        if query_params:
            self.query_params.update(
                {
                    key: value
                    for key, value in query_params.items()
                    if value not in ("", None)
                }
            )
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    def supports(self, target: IocTarget) -> bool:
        return target.ioc_type in _SUPPORTED_TYPES

    def query_variants(
        self, target: IocTarget
    ) -> list[tuple[str, dict[str, str | int]]]:
        variants = build_query_param_variants(
            target.original,
            include_url_param=self.include_url_param,
            include_slow_variants=self.include_slow_variants,
        )
        return [
            (
                name,
                {
                    **params,
                    **{
                        key: value
                        for key, value in self.query_params.items()
                        if value not in ("", None)
                    },
                },
            )
            for name, params in variants
        ]

    def cache_params(
        self,
        target: IocTarget,
        strategy: str,
        query_params: dict[str, str | int],
    ) -> dict:
        return {
            "endpoint": self.settings.base_url,
            "request_ioc": target.original,
            "strategy": strategy,
            "query": dict(query_params),
        }

    def _cache_ref(self, entry: CacheEntry) -> str:
        return f"cache:{self.name}:{entry.key}"

    @staticmethod
    def _items(response: object) -> tuple[list[dict] | None, str | None]:
        if not isinstance(response, dict):
            return None, "F-Dark response must be an object"
        if response.get("status") != "ok":
            return None, f"F-Dark business status {response.get('status')!r}"
        data = response.get("data")
        if not isinstance(data, list):
            return None, "F-Dark response data must be a list"
        if any(not isinstance(item, dict) for item in data):
            return None, "F-Dark response items must be objects"
        return data, None

    def _observations(
        self,
        target: IocTarget,
        items: list[dict],
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> list[Observation]:
        observations: list[Observation] = []
        for item in items:
            observations.append(Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider=self.name,
                kind="associated_sample",
                status=ProviderStatus.SUCCESS,
                fetched_at=fetched_at,
                observed_at=_sample_time(item.get("lseen"))
                or _sample_time(item.get("fseen")),
                freshness=freshness,
                strength="strong",
                payload={
                    "hash": item.get("md5")
                    or item.get("sha1")
                    or item.get("sha256")
                    or "",
                    "level": item.get("level", 0),
                    "family": item.get("family", ""),
                    "type": item.get("type", ""),
                    "malicious": is_malicious_sample(item, self.config),
                },
                raw_ref=raw_ref,
            ))
        return observations

    def _store_response(
        self,
        target: IocTarget,
        strategy: str,
        query: dict[str, str | int],
        response: object,
        fetched_at: datetime,
    ) -> tuple[str, str | None]:
        if self.cache is None:
            return f"live:{self.name}:{strategy}", None
        try:
            entry = self.cache.put(
                target.original,
                response,
                self.cache_params(target, strategy, query),
                fetched_at=fetched_at,
            )
        except (OSError, TypeError, ValueError) as exc:
            return "", f"cache write failed for {target.normalized}: {exc}"
        return self._cache_ref(entry), None

    def _complete_target(
        self,
        target: IocTarget,
        target_observations: list[Observation],
        target_errors: list[str],
        target_freshnesses: list[Freshness],
    ) -> tuple[ProviderStatus, list[Observation], list[str], Freshness | None]:
        if target_errors:
            return ProviderStatus.ERROR, target_observations, target_errors, None
        if target_observations:
            status = ProviderStatus.SUCCESS
        else:
            status = ProviderStatus.NO_DATA
        freshness = None
        if target_freshnesses:
            freshness = (
                Freshness.STALE
                if Freshness.STALE in target_freshnesses
                else Freshness.FRESH
            )
        return status, target_observations, [], freshness

    def _collect_with_go(
        self,
        supported: list[IocTarget],
        context: ProviderContext,
        statuses: dict[str, ProviderStatus],
        observations: list[Observation],
        errors: list[str],
        freshnesses: dict[str, Freshness],
    ) -> ProviderResult:
        """Batch live variants through one Go worker, preserving Python semantics."""
        assert self.go_transport is not None
        total = len(supported)
        done = 0
        cache_hits = 0
        report_progress(context, self.name, done, total)
        states: dict[str, dict] = {}
        job_index: dict[str, tuple[str, str, dict[str, str | int]]] = {}
        jobs: list[BatchRequest] = []
        outcomes: dict[str, tuple[ProviderStatus, list[Observation], list[str], Freshness | None]] = {}

        def finish(key: str) -> None:
            nonlocal done
            state = states[key]
            if state["remaining"]:
                return
            outcomes[key] = self._complete_target(
                state["target"],
                state["observations"],
                state["errors"],
                state["freshnesses"],
            )
            done += 1
            report_progress(context, self.name, done, total)

        for target in supported:
            key = target.normalized
            state = {
                "target": target,
                "observations": [],
                "errors": [],
                "freshnesses": [],
                "remaining": 0,
            }
            states[key] = state
            try:
                variants = self.query_variants(target)
            except (TypeError, ValueError) as exc:
                state["errors"].append(f"invalid query: {exc}")
                finish(key)
                continue

            for strategy, query in variants:
                entry = None
                if self.cache is not None and not context.refresh:
                    entry = self.cache.get(
                        target.original,
                        self.cache_params(target, strategy, query),
                        now=self.now_fn(),
                    )
                    errors.extend(f"cache: {message}" for message in self.cache.diagnostics)
                if entry is not None and (entry.fresh or context.offline):
                    response = entry.raw
                    fetched_at = entry.fetched_at
                    freshness = Freshness.FRESH if entry.fresh else Freshness.STALE
                    raw_ref = self._cache_ref(entry)
                    cache_hits += 1
                    items, response_error = self._items(response)
                    if response_error:
                        state["errors"].append(response_error)
                    else:
                        state["freshnesses"].append(freshness)
                        state["observations"].extend(self._observations(
                            target, items or [], fetched_at=fetched_at,
                            freshness=freshness, raw_ref=raw_ref,
                        ))
                    continue
                if context.offline:
                    state["errors"].append(
                        f"offline cache miss for {target.normalized} ({strategy})"
                    )
                    continue
                request_id = str(len(jobs))
                state["remaining"] += 1
                job_index[request_id] = (key, strategy, query)
                jobs.append(BatchRequest(
                    id=request_id,
                    method="GET",
                    url=self.settings.base_url,
                    headers=dict(self.settings.secrets),
                    params=query,
                    timeout=self.settings.timeout,
                ))
            finish(key)

        for result in self.go_transport.iter_batch(
            jobs,
            workers=self.settings.workers,
            rate_per_second=self.settings.rate_per_second,
        ):
            key, strategy, query = job_index[result.id]
            state = states[key]
            target = state["target"]
            state["remaining"] -= 1
            if result.error is not None:
                state["errors"].append(str(result.error))
                finish(key)
                continue
            fetched_at = self.now_fn()
            raw_ref, cache_error = self._store_response(
                target, strategy, query, result.payload, fetched_at
            )
            if cache_error:
                state["errors"].append(cache_error)
                finish(key)
                continue
            items, response_error = self._items(result.payload)
            if response_error:
                state["errors"].append(response_error)
                finish(key)
                continue
            state["freshnesses"].append(Freshness.FRESH)
            state["observations"].extend(self._observations(
                target, items or [], fetched_at=fetched_at,
                freshness=Freshness.FRESH, raw_ref=raw_ref,
            ))
            finish(key)

        for target in supported:
            status, target_observations, target_errors, freshness = outcomes[target.normalized]
            statuses[target.normalized] = status
            observations.extend(target_observations)
            errors.extend(f"{target.normalized}: {message}" for message in target_errors)
            if freshness is not None:
                freshnesses[target.normalized] = freshness
        return ProviderResult(
            self.name, observations, statuses, errors, cache_hits, freshnesses
        )

    def collect(
        self,
        targets: list[IocTarget],
        context: ProviderContext,
    ) -> ProviderResult:
        statuses: dict[str, ProviderStatus] = {}
        observations: list[Observation] = []
        errors: list[str] = []
        cache_hits = 0
        freshnesses: dict[str, Freshness] = {}

        supported = [target for target in targets if self.supports(target)]
        for target in targets:
            if target not in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
        if not self.settings.enabled:
            for target in supported:
                statuses[target.normalized] = ProviderStatus.DISABLED
            return ProviderResult(
                self.name, observations, statuses, errors, cache_hits, freshnesses
            )
        if (
            not context.offline
            and self.go_transport is not None
            and self.go_transport.available
        ):
            return self._collect_with_go(
                supported, context, statuses, observations, errors, freshnesses
            )

        total = len(supported)
        done = 0
        # done counts only targets whose status is already determined.
        report_progress(context, self.name, done, total)
        for target in supported:
            try:
                target_observations: list[Observation] = []
                target_errors: list[str] = []
                target_freshnesses: list[Freshness] = []
                try:
                    variants = self.query_variants(target)
                except (TypeError, ValueError) as exc:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(f"{target.normalized}: invalid query: {exc}")
                    continue

                for strategy, query in variants:
                    entry = None
                    if self.cache is not None and not context.refresh:
                        entry = self.cache.get(
                            target.original,
                            self.cache_params(target, strategy, query),
                            now=self.now_fn(),
                        )
                        errors.extend(
                            f"cache: {message}" for message in self.cache.diagnostics
                        )

                    if entry is not None and (entry.fresh or context.offline):
                        response = entry.raw
                        fetched_at = entry.fetched_at
                        freshness = Freshness.FRESH if entry.fresh else Freshness.STALE
                        raw_ref = self._cache_ref(entry)
                        cache_hits += 1
                    elif context.offline:
                        target_errors.append(
                            f"offline cache miss for {target.normalized} ({strategy})"
                        )
                        continue
                    else:
                        try:
                            response = self.transport.get_json(
                                self.settings.base_url,
                                headers=dict(self.settings.secrets),
                                params=query,
                                timeout=self.settings.timeout,
                            )
                        except TransportError as exc:
                            target_errors.append(str(exc))
                            continue
                        fetched_at = self.now_fn()
                        freshness = Freshness.FRESH
                        raw_ref, cache_error = self._store_response(
                            target, strategy, query, response, fetched_at
                        )
                        if cache_error:
                            target_errors.append(cache_error)
                            continue

                    items, response_error = self._items(response)
                    if response_error:
                        target_errors.append(response_error)
                        continue
                    target_freshnesses.append(freshness)
                    target_observations.extend(self._observations(
                        target,
                        items or [],
                        fetched_at=fetched_at,
                        freshness=freshness,
                        raw_ref=raw_ref,
                    ))

                observations.extend(target_observations)
                if target_errors:
                    statuses[target.normalized] = ProviderStatus.ERROR
                    errors.extend(
                        f"{target.normalized}: {message}" for message in target_errors
                    )
                elif target_observations:
                    statuses[target.normalized] = ProviderStatus.SUCCESS
                else:
                    statuses[target.normalized] = ProviderStatus.NO_DATA
                if not target_errors and target_freshnesses:
                    freshnesses[target.normalized] = (
                        Freshness.STALE
                        if Freshness.STALE in target_freshnesses
                        else Freshness.FRESH
                    )
            finally:
                # Count after status/observations/errors/freshness are settled,
                # including invalid-query continue. Unexpected exceptions
                # propagate without claiming that this target completed.
                if target.normalized in statuses:
                    done += 1
                    report_progress(context, self.name, done, total)

        return ProviderResult(
            self.name, observations, statuses, errors, cache_hits, freshnesses
        )


__all__ = [
    "DEFAULT_QUERY_PARAMS",
    "FDarkProvider",
    "_append_variant",
    "_default_port_for_scheme",
    "_host_params",
    "_http_proto_for_scheme",
    "_http_url_query_params",
    "_is_ip",
    "_looks_like_uri",
    "_parse_ip_port",
    "_valid_port",
    "build_query_param_variants",
    "build_query_params",
    "build_request_params",
]
