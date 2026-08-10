"""Daily adjudication-result cache for completed IOC verdict rows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class ResultCacheSettings:
    enabled: bool = True
    ttl: timedelta = timedelta(days=7)


@dataclass(frozen=True)
class ResultCacheEntry:
    ioc: str
    fingerprint: str
    fetched_at: datetime
    result: dict[str, Any]
    fresh: bool


class AdjudicationResultCache:
    """Store complete verdict rows in independent daily JSONL shards."""

    _registry_lock = Lock()
    _path_locks: dict[str, Lock] = {}

    def __init__(self, root: str | Path, ttl: timedelta = timedelta(days=7)) -> None:
        if not isinstance(ttl, timedelta) or ttl < timedelta(0):
            raise ValueError("result cache ttl must be a non-negative timedelta")
        self.root = Path(root)
        self.ttl = ttl
        self.cache_dir = self.root / ".cache_adjudication_results"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.diagnostics: list[str] = []
        self._index_lock = Lock()
        self._index_signature: tuple[tuple[str, int, int], ...] | None = None
        self._index: dict[str, tuple[dict[str, Any], datetime]] = {}
        self._cached_iocs: set[str] = set()
        self._index_diagnostics: list[str] = []

    @staticmethod
    def _utc_naive(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None

    @classmethod
    def _lock_for(cls, path: Path) -> Lock:
        resolved = str(path.resolve())
        with cls._registry_lock:
            return cls._path_locks.setdefault(resolved, Lock())

    def _path_for(self, fetched_at: datetime) -> Path:
        day = self._utc_naive(fetched_at).date().isoformat()
        return self.cache_dir / f"cache_{day}.jsonl"

    def _read_paths(self) -> list[Path]:
        return sorted(self.cache_dir.glob("cache_*.jsonl"))

    @staticmethod
    def _paths_signature(paths: list[Path]) -> tuple[tuple[str, int, int], ...]:
        signature = []
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                signature.append((str(path), -1, -1))
            else:
                signature.append((str(path), stat.st_mtime_ns, stat.st_size))
        return tuple(signature)

    @staticmethod
    def key(ioc: str, fingerprint: str) -> str:
        payload = json.dumps(
            {"ioc": str(ioc), "fingerprint": str(fingerprint)},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def put(
        self,
        ioc: str,
        fingerprint: str,
        result: dict[str, Any],
        *,
        fetched_at: datetime | None = None,
    ) -> ResultCacheEntry:
        if not isinstance(result, dict):
            raise TypeError("cached adjudication result must be an object")
        normalized_ioc = str(ioc).strip()
        normalized_fingerprint = str(fingerprint).strip()
        if not normalized_ioc or not normalized_fingerprint:
            raise ValueError("result cache IOC and fingerprint must not be empty")
        stored_result = json.loads(json.dumps(result, ensure_ascii=False))
        if stored_result.get("ioc") != normalized_ioc:
            raise ValueError("cached adjudication result IOC does not match cache key")
        fetched = fetched_at or datetime.now(timezone.utc)
        if not isinstance(fetched, datetime):
            raise TypeError("fetched_at must be a datetime")
        row = {
            "key": self.key(normalized_ioc, normalized_fingerprint),
            "ioc": normalized_ioc,
            "fingerprint": normalized_fingerprint,
            "fetched_at": fetched.isoformat(),
            "result": stored_result,
        }
        path = self._path_for(fetched)
        line = json.dumps(
            row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ) + "\n"
        with self._lock_for(path):
            with path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(line)
                handle.flush()
        with self._index_lock:
            if self._index_signature is not None:
                latest = self._index.get(row["key"])
                if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                    latest[1]
                ):
                    self._index[row["key"]] = (row, fetched)
                self._cached_iocs.add(normalized_ioc)
                self._index_signature = self._paths_signature(self._read_paths())
        return ResultCacheEntry(
            normalized_ioc, normalized_fingerprint, fetched, stored_result, True
        )

    def _ensure_index(self) -> None:
        paths = self._read_paths()
        signature = self._paths_signature(paths)
        if self._index_signature == signature:
            self.diagnostics = list(self._index_diagnostics)
            return
        with self._index_lock:
            paths = self._read_paths()
            signature = self._paths_signature(paths)
            if self._index_signature == signature:
                self.diagnostics = list(self._index_diagnostics)
                return
            index: dict[str, tuple[dict[str, Any], datetime]] = {}
            cached_iocs: set[str] = set()
            diagnostics: list[str] = []
            required = {"key", "ioc", "fingerprint", "fetched_at", "result"}
            for path in paths:
                try:
                    with self._lock_for(path):
                        lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError) as exc:
                    diagnostics.append(f"{path.name}: cache read failed: {exc}")
                    continue
                for line_no, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        diagnostics.append(
                            f"{path.name}: line {line_no}: bad JSON: {exc.msg}"
                        )
                        continue
                    if not isinstance(row, dict) or not required.issubset(row):
                        diagnostics.append(
                            f"{path.name}: line {line_no}: missing required fields"
                        )
                        continue
                    fetched = self._parse_datetime(row.get("fetched_at"))
                    result = row.get("result")
                    if fetched is None or not isinstance(result, dict):
                        diagnostics.append(
                            f"{path.name}: line {line_no}: invalid cached result"
                        )
                        continue
                    ioc = str(row.get("ioc", ""))
                    cached_iocs.add(ioc)
                    key = str(row.get("key", ""))
                    latest = index.get(key)
                    if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                        latest[1]
                    ):
                        index[key] = (row, fetched)
            self._index = index
            self._cached_iocs = cached_iocs
            self._index_diagnostics = diagnostics
            self._index_signature = signature
            self.diagnostics = list(diagnostics)

    def lookup(
        self,
        ioc: str,
        fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> tuple[ResultCacheEntry | None, str]:
        normalized_ioc = str(ioc).strip()
        normalized_fingerprint = str(fingerprint).strip()
        expected_key = self.key(normalized_ioc, normalized_fingerprint)
        self._ensure_index()
        latest = self._index.get(expected_key)
        if latest is None:
            reason = (
                "fingerprint_mismatch"
                if normalized_ioc in self._cached_iocs
                else "missing"
            )
            return None, reason
        row, fetched = latest
        result = row.get("result")
        if row.get("ioc") != normalized_ioc or not isinstance(result, dict) or result.get(
            "ioc"
        ) != normalized_ioc:
            return None, "invalid"
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime):
            raise TypeError("now must be a datetime")
        fresh = self._utc_naive(current) - self._utc_naive(fetched) <= self.ttl
        entry = ResultCacheEntry(
            normalized_ioc,
            normalized_fingerprint,
            fetched,
            dict(result),
            fresh,
        )
        return entry, "hit" if fresh else "stale"

    def get(
        self,
        ioc: str,
        fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> ResultCacheEntry | None:
        entry, _ = self.lookup(ioc, fingerprint, now=now)
        return entry


__all__ = [
    "AdjudicationResultCache",
    "ResultCacheEntry",
    "ResultCacheSettings",
]
