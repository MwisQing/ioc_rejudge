"""Read JSON snapshot files, handle prefix text and missing fields."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from math import isfinite
from pathlib import Path
from typing import Iterable

_TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y%m%d",
    "%Y-%m-%d",
]


@dataclass
class JsonlReadResult:
    records: list[dict]
    skipped: int = 0
    parse_error_samples: list[str] = field(default_factory=list)


def parse_time(value: object) -> datetime | None:
    """Parse a supported timestamp without changing its timezone shape.

    Naive timestamps are retained as naive values for legacy compatibility.
    Offset-aware ISO-8601 timestamps are accepted and retained as aware values;
    callers that compare timestamps must use ``normalize_datetime``.
    """
    if isinstance(value, datetime):
        return value
    if value is None or isinstance(value, bool) or not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except (TypeError, ValueError, OverflowError):
            continue
    iso_value = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(iso_value)
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_datetime(value: object) -> datetime | None:
    """Return a comparable naive UTC datetime, or ``None`` for bad input.

    Project timestamps without an explicit offset are interpreted using their
    existing wall-clock value. This preserves the historical snapshot
    convention while making aware and naive values safe to compare together.
    """
    parsed = parse_time(value)
    if parsed is None:
        return None
    try:
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return parsed.replace(tzinfo=None)
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def parse_epoch_time(value: object) -> datetime | None:
    """Parse a finite, non-negative Unix timestamp as an aware UTC value."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        numeric = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            numeric = float(text)
        except (TypeError, ValueError, OverflowError):
            return None
    else:
        return None
    try:
        numeric = float(numeric)
    except (TypeError, ValueError, OverflowError):
        return None
    if not isfinite(numeric) or numeric < 0:
        return None
    if numeric > 10_000_000_000:
        numeric /= 1000
    try:
        return datetime.fromtimestamp(numeric, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def compare_datetimes(left: object, right: object) -> int | None:
    """Compare two timestamps after UTC normalization.

    ``None`` means at least one side is missing or invalid.
    """
    normalized_left = normalize_datetime(left)
    normalized_right = normalize_datetime(right)
    if normalized_left is None or normalized_right is None:
        return None
    if normalized_left < normalized_right:
        return -1
    if normalized_left > normalized_right:
        return 1
    return 0


def latest_datetime(values: Iterable[object]) -> datetime | None:
    """Return the latest valid timestamp as naive UTC, ignoring bad values."""
    latest = None
    for value in values:
        normalized = normalize_datetime(value)
        if normalized is not None and (latest is None or normalized > latest):
            latest = normalized
    return latest


def is_recent(value: object, now: object, window: timedelta) -> bool:
    """Return whether *value* is within ``window`` and not in the future."""
    if not isinstance(window, timedelta) or window < timedelta(0):
        return False
    normalized_value = normalize_datetime(value)
    normalized_now = normalize_datetime(now)
    if normalized_value is None or normalized_now is None:
        return False
    age = normalized_now - normalized_value
    return timedelta(0) <= age <= window


def is_fresh(fetched_at: object, now: object, ttl: timedelta) -> bool:
    """Return whether a fetched value is fresh at *now*.

    Exact TTL equality is fresh. Missing, invalid, and future fetch times are
    conservative misses rather than fresh data.
    """
    if not isinstance(ttl, timedelta) or ttl < timedelta(0):
        return False
    normalized_fetched = normalize_datetime(fetched_at)
    normalized_now = normalize_datetime(now)
    if normalized_fetched is None or normalized_now is None:
        return False
    age = normalized_now - normalized_fetched
    return timedelta(0) <= age <= ttl


def is_unexpired(value: object, now: object) -> bool:
    """Return whether a valid date is on or after the evaluation date."""
    normalized_value = normalize_datetime(value)
    normalized_now = normalize_datetime(now)
    return (
        normalized_value is not None
        and normalized_now is not None
        and normalized_value.date() >= normalized_now.date()
    )


def read_jsonl_snapshot_with_diagnostics(filepath: str, sample_limit: int = 20) -> JsonlReadResult:
    """Read JSONL snapshot file with bounded parse error samples."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Snapshot file not found: {filepath}")

    for encoding in ("utf-8", "gbk"):
        try:
            text = path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"Cannot decode file with UTF-8 or GBK: {filepath}")

    results = []
    skipped = 0
    parse_error_samples = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            results.append(parsed)
            continue
        except json.JSONDecodeError:
            pass
        match = re.search(r'\{.*\}', line, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                results.append(parsed)
                continue
            except json.JSONDecodeError:
                pass
        skipped += 1
        if len(parse_error_samples) < sample_limit:
            parse_error_samples.append(f"line {line_no}: {line[:200]}")

    return JsonlReadResult(results, skipped, parse_error_samples)


def read_jsonl_snapshot(filepath: str) -> tuple[list[dict], int]:
    """Read JSONL snapshot file. Each line: {"ioc": "...", "data": [...]}."""
    result = read_jsonl_snapshot_with_diagnostics(filepath)
    return result.records, result.skipped


def safe_get(record: dict, *keys: str, default=None):
    current = record
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            if isinstance(key, int) and 0 <= key < len(current):
                current = current[key]
            else:
                return default
        else:
            return default
        if current is None:
            return default
    return current
