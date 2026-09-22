"""Provider-scoped, daily-rotated append-only JSONL response cache."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from threading import Lock
from typing import Any, Sequence

from ioc_rejudge.providers.redaction import REDACTED, redact_secret_values

from ioc_rejudge.normalize import normalize_ioc
from ioc_rejudge.parser import is_fresh, normalize_datetime, parse_time


_PROVIDER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SENSITIVE_KEY_PARTS = (
    "authorization",
    "api-key",
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "cookie",
    "fdp-access",
    "fdp-secret",
)


@dataclass(frozen=True)
class CacheEntry:
    key: str
    ioc: str
    params: dict
    fetched_at: datetime
    raw: Any
    fresh: bool

    @property
    def stale(self) -> bool:
        return not self.fresh


@dataclass(frozen=True)
class _IndexHit:
    path: str
    offset: int
    fetched_at: datetime


class JsonlProviderCache:
    """Append raw provider responses and retrieve the newest matching row."""

    _registry_lock = Lock()
    _path_locks: dict[str, Lock] = {}

    def __init__(
        self,
        root: str | Path,
        provider_name: str,
        ttl: timedelta,
    ) -> None:
        provider_name = str(provider_name).strip()
        if not _PROVIDER_NAME_RE.fullmatch(provider_name):
            raise ValueError(f"invalid provider cache name: {provider_name!r}")
        if not isinstance(ttl, timedelta) or ttl < timedelta(0):
            raise ValueError("cache ttl must be a non-negative timedelta")

        self.root = Path(root)
        self.provider_name = provider_name
        self.ttl = ttl
        self.root.mkdir(parents=True, exist_ok=True)
        self.provider_dir = self.root / f".cache_{provider_name}"
        self.provider_dir.mkdir(parents=True, exist_ok=True)
        self.legacy_path = self.root / f"{provider_name}.jsonl"
        self.path = self._path_for(datetime.now(timezone.utc))
        self.diagnostics: list[str] = []
        self._index_lock = Lock()
        self._index_signature: tuple[tuple[str, int, int], ...] | None = None
        self._index: dict[str, _IndexHit] = {}
        self._index_diagnostics: list[str] = []

    @property
    def errors(self) -> list[str]:
        return self.diagnostics

    def _path_for(self, fetched_at: datetime) -> Path:
        day = self._utc_naive(fetched_at).date().isoformat()
        return self.provider_dir / f"cache_{day}.jsonl"

    @classmethod
    def _lock_for(cls, path: Path) -> Lock:
        resolved = str(path.resolve())
        with cls._registry_lock:
            return cls._path_locks.setdefault(resolved, Lock())

    def _read_paths(self) -> list[Path]:
        paths = sorted(self.provider_dir.glob("cache_*.jsonl"))
        if self.legacy_path.is_file():
            paths.insert(0, self.legacy_path)
        return paths

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
    def _stable_json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=JsonlProviderCache._json_default,
        )

    @staticmethod
    def _json_default(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _normalize_ioc(ioc: str) -> str:
        normalized, _, _ = normalize_ioc(str(ioc))
        if not normalized:
            raise ValueError("cache IOC must not be empty")
        return normalized

    @staticmethod
    def _is_sensitive_key(key: object) -> bool:
        lowered = str(key).strip().lower()
        return any(part in lowered for part in _SENSITIVE_KEY_PARTS)

    @classmethod
    def _redact(cls, value: Any, secret_values: Sequence[str] = ()) -> Any:
        if isinstance(value, dict):
            return {
                str(redact_secret_values(key, secret_values)): (
                    REDACTED
                    if cls._is_sensitive_key(key)
                    else cls._redact(item, secret_values)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item, secret_values) for item in value]
        if isinstance(value, tuple):
            return [cls._redact(item, secret_values) for item in value]
        return redact_secret_values(value, secret_values)

    def key(self, ioc: str, params: dict | None = None) -> str:
        shape = {
            "provider": self.provider_name,
            "ioc": self._normalize_ioc(ioc),
            "params": dict(params or {}),
        }
        return hashlib.sha256(self._stable_json(shape).encode("utf-8")).hexdigest()

    def put(
        self,
        ioc: str,
        raw: Any,
        params: dict | None = None,
        fetched_at: datetime | None = None,
        *,
        secret_values: Sequence[str] = (),
    ) -> CacheEntry:
        normalized = self._normalize_ioc(ioc)
        query_params = dict(params or {})
        fetched = fetched_at if fetched_at is not None else datetime.now(timezone.utc)
        if not isinstance(fetched, datetime) or normalize_datetime(fetched) is None:
            raise TypeError("fetched_at must be a datetime")
        cache_key = self.key(normalized, query_params)
        # Key material uses the original IOC/params; persisted/returned
        # surfaces are sanitized with sensitive-key and configured-value
        # redaction only.
        stored_params = self._redact(query_params, secret_values)
        stored_raw = self._redact(raw, secret_values)
        stored_ioc = str(self._redact(normalized, secret_values))
        row = {
            "key": cache_key,
            "ioc": stored_ioc,
            "params": stored_params,
            "fetched_at": fetched.isoformat(),
            "raw": stored_raw,
        }
        encoded = (self._stable_json(row) + "\n").encode("utf-8")
        path = self._path_for(fetched)
        lock = self._lock_for(path)
        with lock:
            offset = path.stat().st_size if path.is_file() else 0
            with path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
        with self._index_lock:
            if self._index_signature is not None:
                latest = self._index.get(cache_key)
                if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                    latest.fetched_at
                ):
                    self._index[cache_key] = _IndexHit(str(path), offset, fetched)
                self._index_signature = self._paths_signature(self._read_paths())
        self.path = path
        return CacheEntry(
            key=cache_key,
            ioc=stored_ioc,
            params=stored_params,
            fetched_at=fetched,
            raw=stored_raw,
            fresh=True,
        )

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        return parse_time(value)

    @staticmethod
    def _utc_naive(value: datetime) -> datetime:
        normalized = normalize_datetime(value)
        if normalized is None:
            raise ValueError("invalid datetime")
        return normalized

    def _is_fresh(self, fetched_at: datetime, now: datetime) -> bool:
        return is_fresh(fetched_at, now, self.ttl)

    def _read_shard_bytes(self, path: Path) -> bytes:
        with self._lock_for(path):
            return path.read_bytes()

    def _read_row_at(self, path: Path, offset: int) -> dict | None:
        with self._lock_for(path):
            with path.open("rb") as handle:
                handle.seek(offset)
                raw_line = handle.readline()
        if not raw_line.strip():
            return None
        try:
            row = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return row if isinstance(row, dict) else None

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
            index: dict[str, _IndexHit] = {}
            diagnostics: list[str] = []
            required = {"key", "ioc", "params", "fetched_at", "raw"}
            for path in paths:
                try:
                    data = self._read_shard_bytes(path)
                except OSError as exc:
                    diagnostics.append(f"{path.name}: cache read failed: {exc}")
                    continue
                offset = 0
                line_no = 0
                while offset < len(data):
                    newline = data.find(b"\n", offset)
                    if newline == -1:
                        chunk = data[offset:]
                        next_offset = len(data)
                    else:
                        chunk = data[offset:newline]
                        next_offset = newline + 1
                    line_no += 1
                    line_offset = offset
                    offset = next_offset
                    if chunk.endswith(b"\r"):
                        chunk = chunk[:-1]
                    if not chunk.strip():
                        continue
                    try:
                        row = json.loads(chunk.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        message = (
                            exc.msg
                            if isinstance(exc, json.JSONDecodeError)
                            else str(exc)
                        )
                        diagnostics.append(
                            f"{path.name}: line {line_no}: bad JSON: {message}"
                        )
                        continue
                    if not isinstance(row, dict) or not required.issubset(row):
                        diagnostics.append(
                            f"{path.name}: line {line_no}: missing required fields"
                        )
                        continue
                    fetched = self._parse_datetime(row.get("fetched_at"))
                    if fetched is None:
                        diagnostics.append(
                            f"{path.name}: line {line_no}: invalid fetched_at"
                        )
                        continue
                    key = str(row.get("key", ""))
                    latest = index.get(key)
                    if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                        latest.fetched_at
                    ):
                        index[key] = _IndexHit(str(path), line_offset, fetched)
            self._index = index
            self._index_diagnostics = diagnostics
            self._index_signature = signature
            self.diagnostics = list(diagnostics)

    def get(
        self,
        ioc: str,
        params: dict | None = None,
        *,
        now: datetime | None = None,
    ) -> CacheEntry | None:
        query_params = dict(params or {})
        normalized = self._normalize_ioc(ioc)
        expected_key = self.key(normalized, query_params)
        self._ensure_index()
        latest = self._index.get(expected_key)
        if latest is None:
            return None
        row = self._read_row_at(Path(latest.path), latest.offset)
        if row is None:
            self.diagnostics = [
                *self.diagnostics,
                f"cache row missing for {expected_key}",
            ]
            return None
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime):
            raise TypeError("now must be a datetime")
        return CacheEntry(
            key=str(row["key"]),
            ioc=str(row["ioc"]),
            params=dict(row["params"]) if isinstance(row["params"], dict) else {},
            fetched_at=latest.fetched_at,
            raw=row["raw"],
            fresh=self._is_fresh(latest.fetched_at, current),
        )

    def entry_dependency(self, ioc: str, params: dict | None = None) -> str:
        """Stable digest of the latest row for one query key, or an absence marker.

        Reads only the indexed row for this key so fingerprinting many targets
        does not re-parse whole shards. Absence is part of the digest so
        genuinely vanished shard rows invalidate completed results that
        depended on them.
        """
        query_params = dict(params or {})
        try:
            normalized = self._normalize_ioc(ioc)
        except ValueError:
            return "invalid-ioc"
        expected_key = self.key(normalized, query_params)
        self._ensure_index()
        latest = self._index.get(expected_key)
        if latest is None:
            return f"absent:{expected_key}"
        row = self._read_row_at(Path(latest.path), latest.offset)
        if row is None:
            return f"missing-row:{expected_key}"
        shape = {
            "key": expected_key,
            "ioc": str(row.get("ioc", "")),
            "params": row.get("params"),
            "fetched_at": self._utc_naive(latest.fetched_at).isoformat(),
            "raw": row.get("raw"),
        }
        return hashlib.sha256(self._stable_json(shape).encode("utf-8")).hexdigest()

    def dependency_digest(
        self,
        queries: list[tuple[str, dict]] | None = None,
    ) -> str:
        """Combine digests for multiple ``(ioc, params)`` queries in stable order."""
        if not queries:
            return "no-queries"
        parts = [
            self.entry_dependency(ioc, params)
            for ioc, params in queries
        ]
        encoded = self._stable_json(parts).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
