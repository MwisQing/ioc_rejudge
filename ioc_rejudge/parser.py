"""Read JSON snapshot files, handle prefix text and missing fields."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

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


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    value = str(value).strip()
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


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
