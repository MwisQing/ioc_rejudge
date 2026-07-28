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
        return ResultCacheEntry(
            normalized_ioc, normalized_fingerprint, fetched, stored_result, True
        )

    def get(
        self,
        ioc: str,
        fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> ResultCacheEntry | None:
        self.diagnostics = []
        normalized_ioc = str(ioc).strip()
        normalized_fingerprint = str(fingerprint).strip()
        expected_key = self.key(normalized_ioc, normalized_fingerprint)
        latest: tuple[dict[str, Any], datetime] | None = None
        required = {"key", "ioc", "fingerprint", "fetched_at", "result"}
        for path in sorted(self.cache_dir.glob("cache_*.jsonl")):
            try:
                with self._lock_for(path):
                    lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                self.diagnostics.append(f"{path.name}: cache read failed: {exc}")
                continue
            for line_no, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    self.diagnostics.append(
                        f"{path.name}: line {line_no}: bad JSON: {exc.msg}"
                    )
                    continue
                if not isinstance(row, dict) or not required.issubset(row):
                    self.diagnostics.append(
                        f"{path.name}: line {line_no}: missing required fields"
                    )
                    continue
                fetched = self._parse_datetime(row.get("fetched_at"))
                result = row.get("result")
                if fetched is None or not isinstance(result, dict):
                    self.diagnostics.append(
                        f"{path.name}: line {line_no}: invalid cached result"
                    )
                    continue
                if (
                    row.get("key") == expected_key
                    and row.get("ioc") == normalized_ioc
                    and result.get("ioc") == normalized_ioc
                    and (
                        latest is None
                        or self._utc_naive(fetched) >= self._utc_naive(latest[1])
                    )
                ):
                    latest = (row, fetched)
        if latest is None:
            return None
        row, fetched = latest
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime):
            raise TypeError("now must be a datetime")
        fresh = self._utc_naive(current) - self._utc_naive(fetched) <= self.ttl
        return ResultCacheEntry(
            normalized_ioc,
            normalized_fingerprint,
            fetched,
            dict(row["result"]),
            fresh,
        )


__all__ = [
    "AdjudicationResultCache",
    "ResultCacheEntry",
    "ResultCacheSettings",
]
