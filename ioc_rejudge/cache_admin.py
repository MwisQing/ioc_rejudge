"""Read-only cache inspection and narrowly scoped dry-run cleanup planning.

This module never calls the cache ``delete`` API.  ``apply_plan`` removes only
complete, pre-resolved date shards listed in a plan created by this module; the
actual deletion remains opt-in via ``execute=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from ioc_rejudge.files import resolve_path
from ioc_rejudge.parser import normalize_datetime, parse_time


PROVIDER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
RESULT_CACHE_DIRNAME = ".cache_adjudication_results"
_SHARD_RE = re.compile(r"^cache_(\d{4}-\d{2}-\d{2})\.jsonl$")
_DEFAULT_TTL: Any = object()
_REQUIRED_PROVIDER_FIELDS = {"key", "ioc", "params", "fetched_at", "raw"}
_REQUIRED_RESULT_FIELDS = {"key", "ioc", "fingerprint", "fetched_at", "result"}


class CacheAdminError(ValueError):
    """Raised when a cache location or cleanup plan is outside the safe boundary."""


@dataclass(frozen=True)
class FileCleanupPlan:
    path: Path
    size: int
    modified_ns: int
    entry_count: int
    sha256: str


@dataclass(frozen=True)
class CacheCleanupPlan:
    cache_root: Path
    cache_type: str
    cutoff_utc: datetime
    generated_at_utc: datetime
    before_date_utc: date | None
    files: tuple[FileCleanupPlan, ...]
    eligible_bytes: int
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cache_root": str(self.cache_root),
            "cache_type": self.cache_type,
            "cutoff_utc": self.cutoff_utc.isoformat(),
            "generated_at_utc": self.generated_at_utc.isoformat(),
            "before_date_utc": self.before_date_utc.isoformat() if self.before_date_utc else None,
            "eligible_bytes": self.eligible_bytes,
            "files": [
                {
                    "path": str(item.path),
                    "size": item.size,
                    "modified_ns": item.modified_ns,
                    "entry_count": item.entry_count,
                    "sha256": item.sha256,
                }
                for item in self.files
            ],
        }


def _ensure_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise CacheAdminError(f"{label} must be a datetime")
    if value.tzinfo is None:
        raise CacheAdminError(f"{label} must be timezone-aware UTC")
    return value.astimezone(timezone.utc)


def _resolve_cache_root(root: str | os.PathLike[str] | Path) -> Path:
    try:
        resolved = resolve_path(root)
    except OSError as exc:
        raise CacheAdminError(f"cannot resolve cache root: {exc}") from exc
    if not resolved.is_absolute():
        raise CacheAdminError("cache root must resolve to an absolute path")
    return resolved


def _provider_roots(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.glob(".cache_*")
        if path.is_dir() and path != root / RESULT_CACHE_DIRNAME
    )


def _legacy_provider_files(root: Path) -> list[Path]:
    result = []
    for path in root.glob("*.jsonl"):
        name = path.stem
        if path.is_file() and PROVIDER_NAME_RE.fullmatch(name):
            result.append(path)
    return sorted(result)


def _cache_paths(root: Path, cache_type: str) -> list[Path]:
    paths: list[Path] = []
    if cache_type in {"all", "provider"}:
        for provider_dir in _provider_roots(root):
            paths.extend(path for path in provider_dir.glob("cache_*.jsonl") if path.is_file())
        paths.extend(_legacy_provider_files(root))
    if cache_type in {"all", "result"}:
        result_dir = root / RESULT_CACHE_DIRNAME
        if result_dir.is_dir():
            paths.extend(path for path in result_dir.glob("cache_*.jsonl") if path.is_file())
    return sorted(set(paths), key=lambda path: str(path))


def _effective_cache_type(path: Path, cache_type: str) -> str:
    """Resolve ``all`` to the shard's actual cache schema."""
    if cache_type != "all":
        return cache_type
    return "result" if RESULT_CACHE_DIRNAME in path.parts else "provider"


def _read_rows(path: Path, cache_type: str) -> tuple[list[datetime], int]:
    rows: list[datetime] = []
    invalid = 0
    effective_type = _effective_cache_type(path, cache_type)
    required = (
        _REQUIRED_RESULT_FIELDS
        if effective_type == "result"
        else _REQUIRED_PROVIDER_FIELDS
    )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return rows, 1
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            fetched = parse_time(row.get("fetched_at")) if isinstance(row, dict) else None
            if not isinstance(row, dict) or not required.issubset(row) or fetched is None:
                invalid += 1
                continue
            normalized = normalize_datetime(fetched)
            if normalized is None:
                invalid += 1
                continue
            rows.append(normalized.replace(tzinfo=timezone.utc))
        except (json.JSONDecodeError, TypeError, ValueError):
            invalid += 1
    return rows, invalid


def _bounded_datetimes(values: list[datetime]) -> tuple[datetime | None, datetime | None]:
    if not values:
        return None, None
    normalized = [value.astimezone(timezone.utc) for value in values]
    return min(normalized), max(normalized)


def cache_stats(
    root: str | os.PathLike[str] | Path,
    *,
    cache_type: str = "all",
) -> dict[str, Any]:
    """Summarize provider/result cache size, shards, entries, and time bounds."""
    if cache_type not in {"all", "provider", "result"}:
        raise CacheAdminError(f"unknown cache_type: {cache_type}")
    resolved = _resolve_cache_root(root)
    if not resolved.exists():
        raise CacheAdminError(f"cache root does not exist: {resolved}")
    if not resolved.is_dir():
        raise CacheAdminError(f"cache root is not a directory: {resolved}")

    sections: dict[str, dict[str, Any]] = {}
    selected_types = ["provider", "result"] if cache_type == "all" else [cache_type]
    for section in selected_types:
        paths = _cache_paths(resolved, section)
        all_fetched: list[datetime] = []
        valid_entries = 0
        invalid_entries = 0
        total_bytes = 0
        readable_files = 0
        for path in paths:
            try:
                total_bytes += path.stat().st_size
            except OSError:
                continue
            fetched, invalid = _read_rows(path, section)
            all_fetched.extend(fetched)
            valid_entries += len(fetched)
            invalid_entries += invalid
            readable_files += 1
        oldest, latest = _bounded_datetimes(all_fetched)
        sections[section] = {
            "cache_directories": len(_provider_roots(resolved)) if section == "provider" else (
                1 if (resolved / RESULT_CACHE_DIRNAME).is_dir() else 0
            ),
            "files": len(paths),
            "readable_files": readable_files,
            "bytes": total_bytes,
            "valid_entries": valid_entries,
            "invalid_entries": invalid_entries,
            "oldest_entry_utc": oldest.isoformat() if oldest else None,
            "latest_entry_utc": latest.isoformat() if latest else None,
        }

    total_bytes = sum(section["bytes"] for section in sections.values())
    total_valid = sum(section["valid_entries"] for section in sections.values())
    total_invalid = sum(section["invalid_entries"] for section in sections.values())
    return {
        "root": str(resolved),
        "cache_type": cache_type,
        "sections": sections,
        "total": {
            "bytes": total_bytes,
            "valid_entries": total_valid,
            "invalid_entries": total_invalid,
        },
    }


def _hash_file(path: Path) -> tuple[int, int, int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    stat = path.stat()
    return size, stat.st_mtime_ns, size, digest.hexdigest()


def _eligible_for_whole_file(path: Path, cutoff: datetime, cache_type: str) -> tuple[bool, int]:
    rows, invalid = _read_rows(path, cache_type)
    if invalid:
        return False, len(rows)
    # Empty shards are safe to remove.
    if not rows:
        return True, 0
    if any(row.astimezone(timezone.utc) >= cutoff for row in rows):
        return False, len(rows)
    return True, len(rows)


def _plan_fingerprint(root: Path, cache_type: str, cutoff: datetime, files: tuple[FileCleanupPlan, ...]) -> str:
    payload = {
        "cache_root": str(root),
        "cache_type": cache_type,
        "cutoff_utc": cutoff.isoformat(),
        "files": [
            [str(item.path), item.size, item.modified_ns, item.entry_count, item.sha256]
            for item in files
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_cleanup_plan(
    root: str | os.PathLike[str] | Path,
    *,
    cache_type: str = "all",
    ttl: timedelta | None = _DEFAULT_TTL,
    before_date_utc: date | str | None = None,
    now: datetime | None = None,
) -> CacheCleanupPlan:
    """Build a whole-shard deletion plan without deleting anything.

    Only shards whose every valid entry is older than the cutoff are selected.
    Unreadable or malformed entries block deletion of their containing shard.
    """
    if cache_type not in {"all", "provider", "result"}:
        raise CacheAdminError(f"unknown cache_type: {cache_type}")
    if ttl is _DEFAULT_TTL:
        ttl = None if before_date_utc is not None else timedelta(days=7)
    if ttl is not None and before_date_utc is not None:
        raise CacheAdminError("set either ttl or before_date_utc, not both")
    resolved = _resolve_cache_root(root)
    current = _ensure_utc(now or datetime.now(timezone.utc), "now")
    parsed_before_date: date | None = None
    if ttl is None and before_date_utc is None:
        raise CacheAdminError("ttl or before_date_utc is required")
    if ttl is not None:
        if not isinstance(ttl, timedelta) or ttl < timedelta(0):
            raise CacheAdminError("ttl must be a non-negative timedelta")
        cutoff = current - ttl
    else:
        if isinstance(before_date_utc, str):
            try:
                parsed_before_date = date.fromisoformat(before_date_utc)
            except ValueError as exc:
                raise CacheAdminError("before_date_utc must be an ISO date (YYYY-MM-DD)") from exc
        elif isinstance(before_date_utc, date):
            parsed_before_date = before_date_utc
        else:
            raise CacheAdminError("before_date_utc must be a datetime.date or ISO date string")
        cutoff = datetime.combine(parsed_before_date, time.min, tzinfo=timezone.utc)

    planned: list[FileCleanupPlan] = []
    for path in _cache_paths(resolved, cache_type):
        relative = path.relative_to(resolved)
        # A dated shard is considered only if its entire UTC day ended before
        # the cutoff. This prevents accidental removal of a mixed-date shard.
        match = _SHARD_RE.fullmatch(path.name)
        if match:
            try:
                shard_date = date.fromisoformat(match.group(1))
            except ValueError:
                continue
            shard_end = datetime.combine(shard_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
            if shard_end > cutoff:
                continue
        eligible, entry_count = _eligible_for_whole_file(path, cutoff, cache_type)
        if not eligible:
            continue
        try:
            size, modified_ns, _, digest = _hash_file(path)
        except OSError:
            continue
        planned.append(
            FileCleanupPlan(
                path=path,
                size=size,
                modified_ns=modified_ns,
                entry_count=entry_count,
                sha256=digest,
            )
        )
    files = tuple(sorted(planned, key=lambda item: str(item.path)))
    return CacheCleanupPlan(
        cache_root=resolved,
        cache_type=cache_type,
        cutoff_utc=cutoff,
        generated_at_utc=current,
        before_date_utc=parsed_before_date,
        files=files,
        eligible_bytes=sum(item.size for item in files),
        fingerprint=_plan_fingerprint(resolved, cache_type, cutoff, files),
    )


def apply_plan(plan: CacheCleanupPlan, *, execute: bool = False) -> dict[str, Any]:
    """Apply a generated plan only after explicit ``execute=True``.

    The plan's root and every file are re-resolved and re-hashed immediately
    before deletion.  Any append, replacement, path move, or hash mismatch
    aborts without deleting any listed file.
    """
    if not isinstance(plan, CacheCleanupPlan):
        raise CacheAdminError("plan must be created by build_cleanup_plan")
    if not execute:
        return {
            "executed": False,
            "cache_root": str(plan.cache_root),
            "would_delete_files": len(plan.files),
            "would_delete_bytes": plan.eligible_bytes,
        }

    if _plan_fingerprint(plan.cache_root, plan.cache_type, plan.cutoff_utc, plan.files) != plan.fingerprint:
        raise CacheAdminError("cleanup plan fingerprint mismatch")
    resolved_root = _resolve_cache_root(plan.cache_root)
    if plan.cache_root != resolved_root:
        raise CacheAdminError(f"cleanup plan cache root does not match resolved root: {resolved_root}")
    if not resolved_root.is_dir():
        raise CacheAdminError(f"cache root does not exist or is not a directory: {resolved_root}")

    checked: list[FileCleanupPlan] = []
    for item in plan.files:
        try:
            current_path = resolve_path(item.path)
        except OSError as exc:
            raise CacheAdminError(f"cannot resolve planned cache file {item.path}: {exc}") from exc
        if current_path != item.path:
            raise CacheAdminError(f"planned cache path is not resolved: {current_path}")
        try:
            if not _is_within(current_path, resolved_root):
                raise CacheAdminError(f"planned cache path escapes cache root: {current_path}")
        except CacheAdminError:
            raise
        except OSError as exc:
            raise CacheAdminError(f"cannot validate planned cache path {current_path}: {exc}") from exc
        try:
            size, modified_ns, _, digest = _hash_file(current_path)
        except OSError as exc:
            raise CacheAdminError(f"planned cache file changed or is unreadable: {current_path}: {exc}") from exc
        if (
            size != item.size
            or modified_ns != item.modified_ns
            or digest != item.sha256
        ):
            raise CacheAdminError(f"planned cache file changed since planning: {current_path}")
        checked.append(item)

    deleted_files = 0
    deleted_bytes = 0
    # Only unlink after every hash check has succeeded.
    for item in checked:
        try:
            current_path = resolve_path(item.path)
            size, modified_ns, _, digest = _hash_file(current_path)
        except OSError as exc:
            raise CacheAdminError(f"planned cache file changed before deletion: {item.path}: {exc}") from exc
        if (size, modified_ns, digest) != (item.size, item.modified_ns, item.sha256):
            raise CacheAdminError(f"planned cache file changed before deletion: {item.path}")
        try:
            current_path.unlink()
        except OSError as exc:
            raise CacheAdminError(f"failed to delete cache shard {current_path}: {exc}") from exc
        deleted_files += 1
        deleted_bytes += item.size

    return {
        "executed": True,
        "cache_root": str(resolved_root),
        "deleted_files": deleted_files,
        "deleted_bytes": deleted_bytes,
    }


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError as exc:
        return False


__all__ = [
    "CacheAdminError",
    "CacheCleanupPlan",
    "FileCleanupPlan",
    "apply_plan",
    "build_cleanup_plan",
    "cache_stats",
]
