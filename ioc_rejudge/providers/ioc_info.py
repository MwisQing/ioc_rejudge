"""IOC Info live provider and legacy command compatibility implementation."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import requests

from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
)
from ioc_rejudge.parser import parse_time
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.cache import CacheEntry, JsonlProviderCache
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import RequestsTransport, TransportError


BATCH_SIZE = 20
MAX_EMPTY_DATA_ATTEMPTS = 10
RETRY_DELAY_SECONDS = 0
DEFAULT_URL = "http://iocproducer01v.tic.shyc3.qianxin-inc.cn/api/v1/ioc/info"
API_URL = DEFAULT_URL
ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = ROOT / "ioc_info_cache"

IOC_FIELD_NAMES = (
    "ioc", "indicator", "domain", "host", "url", "value", "key", "query", "param",
)
DATA_FIELD_NAMES = ("data", "info", "result", "records", "items")
_SUPPORTED_TYPES = {"domain", "url", "domain_port", "ip", "ip_port"}


@dataclass
class QueryResult:
    data_by_ioc: dict[str, object]
    failed_iocs: list[str]
    attempts_by_ioc: dict[str, int]


def has_non_empty_data(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, dict, str, bytes)):
        return len(value) > 0
    return True


def as_result_data(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def extract_ioc_key(record) -> str | None:
    if not isinstance(record, dict):
        return None
    for field in IOC_FIELD_NAMES:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def find_requested_ioc(value, requested_iocs: set[str]) -> str | None:
    if isinstance(value, str):
        return value if value in requested_iocs else None
    if isinstance(value, dict):
        for field in IOC_FIELD_NAMES:
            found = find_requested_ioc(value.get(field), requested_iocs)
            if found:
                return found
        for item in value.values():
            found = find_requested_ioc(item, requested_iocs)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = find_requested_ioc(item, requested_iocs)
            if found:
                return found
    return None


def extract_record_data(record):
    if not isinstance(record, dict):
        return record
    for field in DATA_FIELD_NAMES:
        if field in record:
            return record[field]
    return record


def add_data(target: dict[str, list], ioc: str, value) -> None:
    data = as_result_data(value)
    if not has_non_empty_data(data):
        return
    target.setdefault(ioc, []).extend(data)


def normalize_dict_data(iocs: list[str], data: dict) -> dict[str, list]:
    normalized: dict[str, list] = {}
    for ioc in iocs:
        if ioc in data:
            add_data(normalized, ioc, data[ioc])
    return normalized


def normalize_list_data(iocs: list[str], records: list) -> dict[str, list]:
    normalized: dict[str, list] = {}
    requested_iocs = set(iocs)

    for record in records:
        ioc = extract_ioc_key(record)
        if not ioc:
            ioc = find_requested_ioc(record, requested_iocs)
        if ioc in requested_iocs:
            add_data(normalized, ioc, extract_record_data(record))

    if normalized:
        return normalized
    if len(records) == len(iocs):
        for ioc, value in zip(iocs, records):
            add_data(normalized, ioc, value)
    return normalized


def normalize_payload(requested: list[str], response) -> dict[str, list]:
    payload = response.get("data", response) if isinstance(response, dict) else response
    if isinstance(payload, dict):
        present = normalize_dict_data(requested, payload)
    elif isinstance(payload, list):
        present = normalize_list_data(requested, payload)
    else:
        present = {}
    return {ioc: list(present.get(ioc) or []) for ioc in requested}


def build_payload(targets: list[IocTarget]) -> dict:
    return {"params": [target.original for target in targets]}


def _record_observed_at(record: object) -> datetime | None:
    if not isinstance(record, dict):
        return None
    for field in ("updatetime", "inserttime", "disposaltime", "observed_at"):
        parsed = parse_time(str(record.get(field, "")))
        if parsed is not None:
            return parsed
    return None


class IOCInfoProvider:
    name = "ioc_info"

    def __init__(
        self,
        settings: ProviderSettings,
        *,
        transport: RequestsTransport | None = None,
        cache: JsonlProviderCache | None = None,
        max_attempts: int = MAX_EMPTY_DATA_ATTEMPTS,
        retry_delay: float = RETRY_DELAY_SECONDS,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if max_attempts <= 0:
            raise ValueError("max_attempts must be greater than zero")
        if retry_delay < 0:
            raise ValueError("retry_delay must not be negative")
        self.settings = settings
        self.transport = transport or RequestsTransport()
        self.cache = cache
        self.max_attempts = max_attempts
        self.retry_delay = retry_delay
        self.sleep_fn = sleep_fn
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    def supports(self, target: IocTarget) -> bool:
        return target.ioc_type in _SUPPORTED_TYPES

    def cache_params(self, target: IocTarget) -> dict:
        return {
            "endpoint": self.settings.base_url,
            "request_ioc": target.original,
        }

    def _cache_ref(self, entry: CacheEntry) -> str:
        return f"cache:{self.name}:{entry.key}"

    def _observations(
        self,
        target: IocTarget,
        records: list,
        *,
        fetched_at: datetime,
        freshness: Freshness,
        raw_ref: str,
    ) -> list[Observation]:
        return [
            Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider=self.name,
                kind="ioc_info_record",
                status=ProviderStatus.SUCCESS,
                fetched_at=fetched_at,
                observed_at=_record_observed_at(record),
                freshness=freshness,
                strength="normal",
                payload=dict(record) if isinstance(record, dict) else {"value": record},
                raw_ref=raw_ref,
            )
            for record in records
        ]

    def _consume_cache(
        self,
        target: IocTarget,
        entry: CacheEntry,
    ) -> tuple[ProviderStatus, list[Observation]]:
        records = normalize_payload([target.original], entry.raw)[target.original]
        status = ProviderStatus.SUCCESS if records else ProviderStatus.NO_DATA
        freshness = Freshness.FRESH if entry.fresh else Freshness.STALE
        observations = self._observations(
            target,
            records,
            fetched_at=entry.fetched_at,
            freshness=freshness,
            raw_ref=self._cache_ref(entry),
        )
        return status, observations

    def _store_response(
        self,
        target: IocTarget,
        response,
        fetched_at: datetime,
    ) -> tuple[str, str | None]:
        if self.cache is None:
            return f"live:{self.name}", None
        try:
            entry = self.cache.put(
                target.original,
                response,
                self.cache_params(target),
                fetched_at=fetched_at,
            )
        except (OSError, TypeError, ValueError) as exc:
            return "", f"cache write failed for {target.normalized}: {exc}"
        return self._cache_ref(entry), None

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
            if entry is not None and (entry.fresh or context.offline):
                status, cached_observations = self._consume_cache(target, entry)
                statuses[target.normalized] = status
                freshnesses[target.normalized] = (
                    Freshness.FRESH if entry.fresh else Freshness.STALE
                )
                observations.extend(cached_observations)
                cache_hits += 1
            else:
                pending.append(target)

        if context.offline:
            for target in pending:
                statuses[target.normalized] = ProviderStatus.ERROR
                errors.append(f"offline cache miss for {target.normalized}")
            return ProviderResult(
                self.name, observations, statuses, errors, cache_hits, freshnesses
            )

        for start in range(0, len(pending), BATCH_SIZE):
            retry_targets = pending[start : start + BATCH_SIZE]
            attempt = 0
            while retry_targets and attempt < self.max_attempts:
                attempt += 1
                requested = [target.original for target in retry_targets]
                try:
                    response = self.transport.post_json(
                        self.settings.base_url,
                        headers=dict(self.settings.secrets),
                        body=build_payload(retry_targets),
                        timeout=self.settings.timeout,
                    )
                except TransportError as exc:
                    for target in retry_targets:
                        statuses[target.normalized] = ProviderStatus.ERROR
                    errors.append(str(exc))
                    retry_targets = []
                    break

                fetched_at = self.now_fn()
                normalized = normalize_payload(requested, response)
                empty: list[IocTarget] = []
                for target in retry_targets:
                    records = normalized[target.original]
                    if not records and attempt < self.max_attempts:
                        empty.append(target)
                        continue

                    raw_ref, cache_error = self._store_response(
                        target,
                        response,
                        fetched_at,
                    )
                    if cache_error:
                        statuses[target.normalized] = ProviderStatus.ERROR
                        errors.append(cache_error)
                        continue
                    if records:
                        statuses[target.normalized] = ProviderStatus.SUCCESS
                        observations.extend(self._observations(
                            target,
                            records,
                            fetched_at=fetched_at,
                            freshness=Freshness.FRESH,
                            raw_ref=raw_ref,
                        ))
                    else:
                        statuses[target.normalized] = ProviderStatus.NO_DATA
                    freshnesses[target.normalized] = Freshness.FRESH
                retry_targets = empty
                if retry_targets and self.retry_delay:
                    self.sleep_fn(self.retry_delay)

        return ProviderResult(
            self.name, observations, statuses, errors, cache_hits, freshnesses
        )


# Legacy command helpers retained here so the root script remains a thin re-export.


def load_key(path: Path) -> str:
    key = path.read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError(f"Api-Key file is empty: {path}")
    return key


def load_iocs(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8-sig").strip().splitlines()
    iocs = [line.strip() for line in lines if line.strip()]
    if not iocs:
        raise ValueError(f"IOC file is empty: {path}")
    return iocs


def unique_preserving_order(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def cache_path_for_today() -> Path:
    return CACHE_DIR / f"{date.today().isoformat()}.jsonl"


def query_batch(iocs: list[str], key: str) -> dict[str, list]:
    response = requests.post(
        API_URL,
        headers={"Api-Key": key},
        json={"params": iocs},
        timeout=30,
    )
    response.raise_for_status()
    normalized = normalize_payload(iocs, response.json())
    return {ioc: rows for ioc, rows in normalized.items() if rows}


def split_success_and_empty(
    iocs: list[str],
    data: dict[str, list],
) -> tuple[dict[str, list], list[str]]:
    ready = {}
    empty = []
    for ioc in iocs:
        entries = data.get(ioc)
        if has_non_empty_data(entries):
            ready[ioc] = entries
        else:
            empty.append(ioc)
    return ready, empty


def query_iocs_with_retry(
    iocs: list[str],
    key: str,
    max_attempts: int = MAX_EMPTY_DATA_ATTEMPTS,
    retry_delay: int = RETRY_DELAY_SECONDS,
) -> QueryResult:
    data_by_ioc: dict[str, list] = {}
    attempts_by_ioc = {ioc: 0 for ioc in iocs}
    pending = list(iocs)
    attempt = 0
    while pending and attempt < max_attempts:
        attempt += 1
        for ioc in pending:
            attempts_by_ioc[ioc] += 1
        ready, pending = split_success_and_empty(pending, query_batch(pending, key))
        data_by_ioc.update(ready)
        print(
            f"    attempt {attempt}: requested {len(ready) + len(pending)}, "
            f"got {len(ready)}, still empty {len(pending)}"
        )
        if pending and attempt < max_attempts:
            time.sleep(retry_delay)
    return QueryResult(data_by_ioc, pending, attempts_by_ioc)


def load_cache(path: Path) -> dict[str, list]:
    if not path.exists():
        return {}
    cache = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"skip broken cache line {path}:{line_no}: {exc}")
            continue
        ioc = record.get("ioc") if isinstance(record, dict) else None
        data = record.get("data") if isinstance(record, dict) else None
        if isinstance(ioc, str) and has_non_empty_data(data):
            cache[ioc] = as_result_data(data)
    return cache


def load_recent_cache(days: int = 7) -> dict[str, list]:
    merged: dict[str, list] = {}
    total_files = 0
    for offset in range(days - 1, -1, -1):
        path = CACHE_DIR / f"{(date.today() - timedelta(days=offset)).isoformat()}.jsonl"
        if not path.exists():
            continue
        day_cache = load_cache(path)
        if day_cache:
            total_files += 1
            merged.update(day_cache)
    if total_files:
        print(f"  loaded {total_files} cache file(s) from last {days} days")
    return merged


def write_jsonl(path: Path, records: list[dict]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    temporary.replace(path)


def append_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_cache(path: Path, data_by_ioc: dict[str, object]) -> None:
    write_jsonl(path, [
        {"ioc": ioc, "data": data}
        for ioc, data in data_by_ioc.items()
        if has_non_empty_data(data)
    ])


def build_success_records(
    iocs: list[str],
    data_by_ioc: dict[str, object],
) -> list[dict]:
    return [
        {"ioc": ioc, "data": as_result_data(data_by_ioc[ioc])}
        for ioc in iocs
        if ioc in data_by_ioc and has_non_empty_data(data_by_ioc[ioc])
    ]


def build_failed_records(
    iocs: list[str],
    attempts_by_ioc: dict[str, int],
) -> list[dict]:
    return [{"ioc": ioc, "attempts": attempts_by_ioc.get(ioc, 0)} for ioc in iocs]


def main() -> None:
    cache_file = cache_path_for_today()
    key = load_key(ROOT / "Api-Key.txt")
    input_iocs = load_iocs(ROOT / "ioc.txt")
    unique_iocs = unique_preserving_order(input_iocs)

    CACHE_DIR.mkdir(exist_ok=True)
    cache = load_recent_cache(days=7)
    cache.update(load_cache(cache_file))
    print(f"cache loaded (7 days + today): {len(cache)} IOCs")

    data_by_ioc = {ioc: cache[ioc] for ioc in unique_iocs if ioc in cache}
    query_iocs = [ioc for ioc in unique_iocs if ioc not in data_by_ioc]
    print(
        f"IOCs: {len(input_iocs)} input lines, {len(unique_iocs)} unique, "
        f"{len(data_by_ioc)} cached, {len(query_iocs)} to query"
    )

    failed_iocs: list[str] = []
    attempts_by_ioc = {ioc: 0 for ioc in unique_iocs}
    for start in range(0, len(query_iocs), BATCH_SIZE):
        batch = query_iocs[start : start + BATCH_SIZE]
        batch_num = start // BATCH_SIZE + 1
        print(f"querying batch {batch_num}: {len(batch)} iocs ...")
        try:
            result = query_iocs_with_retry(batch, key)
            data_by_ioc.update(result.data_by_ioc)
            failed_iocs.extend(result.failed_iocs)
            attempts_by_ioc.update(result.attempts_by_ioc)
            records = [
                {"ioc": ioc, "data": data}
                for ioc, data in result.data_by_ioc.items()
                if has_non_empty_data(data)
            ]
            if records:
                append_jsonl(cache_file, records)
        except requests.exceptions.HTTPError as exc:
            failed_iocs.extend(batch)
            print(f"  batch {batch_num} HTTP error: {exc}")
        except Exception as exc:
            failed_iocs.extend(batch)
            print(f"  batch {batch_num} error: {exc}")

    success_records = build_success_records(input_iocs, data_by_ioc)
    failed_records = build_failed_records(
        unique_preserving_order(failed_iocs),
        attempts_by_ioc,
    )
    out_path = ROOT / "ioc_info_result.jsonl"
    failed_path = ROOT / "ioc_info_failed.jsonl"
    write_jsonl(out_path, success_records)
    write_jsonl(failed_path, failed_records)
    print(f"success result lines: {len(success_records)}")
    print(f"failed unique IOCs: {len(failed_records)}")
    print(f"cached -> {cache_file}")
    print(f"result -> {out_path}")
    print(f"failed -> {failed_path}")


__all__ = [
    "API_URL", "BATCH_SIZE", "CACHE_DIR", "DEFAULT_URL",
    "IOCInfoProvider", "MAX_EMPTY_DATA_ATTEMPTS", "QueryResult",
    "RETRY_DELAY_SECONDS", "ROOT", "add_data", "append_jsonl",
    "as_result_data", "build_failed_records", "build_payload",
    "build_success_records", "cache_path_for_today", "extract_ioc_key",
    "extract_record_data", "find_requested_ioc", "has_non_empty_data",
    "load_cache", "load_iocs", "load_key", "load_recent_cache", "main",
    "normalize_dict_data", "normalize_list_data", "normalize_payload",
    "query_batch", "query_iocs_with_retry", "split_success_and_empty",
    "unique_preserving_order", "write_cache", "write_jsonl",
]
