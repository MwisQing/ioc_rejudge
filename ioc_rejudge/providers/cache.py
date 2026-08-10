"""Provider-scoped, daily-rotated append-only JSONL response cache."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from threading import Lock
from typing import Any

from ioc_rejudge.normalize import normalize_ioc


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
        self._index: dict[str, tuple[dict, datetime]] = {}
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
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): (
                    "[REDACTED]" if cls._is_sensitive_key(key) else cls._redact(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        if isinstance(value, tuple):
            return [cls._redact(item) for item in value]
        return value

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
    ) -> CacheEntry:
        normalized = self._normalize_ioc(ioc)
        query_params = dict(params or {})
        fetched = fetched_at or datetime.now(timezone.utc)
        if not isinstance(fetched, datetime):
            raise TypeError("fetched_at must be a datetime")
        cache_key = self.key(normalized, query_params)
        stored_params = self._redact(query_params)
        stored_raw = self._redact(raw)
        row = {
            "key": cache_key,
            "ioc": normalized,
            "params": stored_params,
            "fetched_at": fetched.isoformat(),
            "raw": stored_raw,
        }
        line = self._stable_json(row) + "\n"
        path = self._path_for(fetched)
        lock = self._lock_for(path)
        with lock:
            with path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(line)
                handle.flush()
        with self._index_lock:
            if self._index_signature is not None:
                latest = self._index.get(cache_key)
                if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                    latest[1]
                ):
                    self._index[cache_key] = (row, fetched)
                self._index_signature = self._paths_signature(self._read_paths())
        self.path = path
        return CacheEntry(
            key=cache_key,
            ioc=normalized,
            params=stored_params,
            fetched_at=fetched,
            raw=stored_raw,
            fresh=True,
        )

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _utc_naive(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def _is_fresh(self, fetched_at: datetime, now: datetime) -> bool:
        age = self._utc_naive(now) - self._utc_naive(fetched_at)
        return age <= self.ttl

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
            index: dict[str, tuple[dict, datetime]] = {}
            diagnostics: list[str] = []
            required = {"key", "ioc", "params", "fetched_at", "raw"}
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
                    if fetched is None:
                        diagnostics.append(
                            f"{path.name}: line {line_no}: invalid fetched_at"
                        )
                        continue
                    key = str(row.get("key", ""))
                    latest = index.get(key)
                    if latest is None or self._utc_naive(fetched) >= self._utc_naive(
                        latest[1]
                    ):
                        index[key] = (row, fetched)
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
        row, fetched = latest
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime):
            raise TypeError("now must be a datetime")
        return CacheEntry(
            key=str(row["key"]),
            ioc=str(row["ioc"]),
            params=dict(row["params"]) if isinstance(row["params"], dict) else {},
            fetched_at=fetched,
            raw=row["raw"],
            fresh=self._is_fresh(fetched, current),
        )
