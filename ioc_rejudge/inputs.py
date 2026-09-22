"""Unified input parsing for bare IOC files, inline IOCs, and legacy JSONL snapshots.

Produces an InputBundle with normalized IocTarget objects while preserving
original values, input order, and error visibility.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

from ioc_rejudge.normalize import parse_ioc_value
from ioc_rejudge.observations import IocTarget
from ioc_rejudge.parser import read_jsonl_snapshot_with_diagnostics

# DNS label: 1-63 chars, alphanumeric at start and end, hyphens allowed in middle.
_DOMAIN_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
# IPv4 dotted-octet shape (range validated separately).
_IP_SHAPE_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


class InputKind(str, Enum):
    IOC_LIST = "ioc_list"
    SNAPSHOT = "snapshot"


@dataclass
class InputBundle:
    kind: InputKind
    targets: list[IocTarget] = field(default_factory=list)
    snapshots: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Unbounded counters kept separate from bounded error samples.
    parse_error_count: int = 0
    nested_data_error_count: int = 0


def is_valid_host(host: str) -> bool:
    """Return True when *host* is a well-formed domain name or IPv4 address.

    Domain labels must conform to DNS label rules (alphanumeric start/end,
    hyphens in middle only, 1-63 chars, no underscores).  IPv4 octets must
    be 0-255.
    """
    if not host:
        return False
    # IPv4
    if _IP_SHAPE_RE.match(host):
        return all(0 <= int(o) <= 255 for o in host.split("."))
    # Domain: each label must be DNS-legal
    labels = host.lower().split(".")
    return all(_DOMAIN_LABEL_RE.match(label) for label in labels)


def is_valid_port(port_str: str) -> bool:
    """Return True when *port_str* is an integer in 1-65535."""
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


# Legacy aliases kept for internal compatibility.
_is_valid_host = is_valid_host
_is_valid_port = is_valid_port


def _target(value: str) -> IocTarget | None:
    """Normalize a single IOC value string into an IocTarget.

    Returns None when the value cannot be parsed as a valid IOC target
    (empty after normalization, unknown type, contains spaces, no host,
    invalid host structure, or out-of-range ports).

    Canonical ``normalized`` keeps URL scheme so bare domain, ``http://``, and
    ``https://`` are distinct targets; host casing and trailing dots still
    collapse within the same scope.
    """
    try:
        normalized, ioc_type, ports, scheme = parse_ioc_value(value)
    except ValueError:
        # parse_ioc_value may call urllib.parse which validates port range.
        return None
    if not normalized or ioc_type == "unknown" or " " in normalized:
        return None

    if ioc_type == "url":
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or not _is_valid_host(host):
            return None
        if parsed.port is not None and not _is_valid_port(str(parsed.port)):
            return None
        scheme = scheme or (parsed.scheme or "").lower()
    elif ioc_type in {"domain_port", "ip_port"}:
        host = normalized.rsplit(":", 1)[0]
        if not _is_valid_host(host):
            return None
        if not all(_is_valid_port(p) for p in ports):
            return None
    else:
        host = normalized.split("/", 1)[0]
        if not _is_valid_host(host):
            return None

    return IocTarget(
        value,
        normalized,
        ioc_type,
        host,
        tuple(ports),
        scheme=scheme,
    )


def read_input_bundle(path: str | None, inline_iocs: list[str] | None = None) -> InputBundle:
    """Parse input from a file path and/or inline IOC strings into a unified InputBundle.

    Args:
        path: Path to a bare-IOC text file or legacy JSONL snapshot. May be None
              when only inline IOCs are provided.
        inline_iocs: Additional IOC strings to append after file values.

    Returns:
        An InputBundle with kind, targets, snapshots, and any parse errors.

    Raises:
        ValueError: If the file cannot be decoded with UTF-8-SIG or GBK.
        FileNotFoundError: If path is provided but the file does not exist.
    """
    lines: list[str] = []
    if path:
        for encoding in ("utf-8-sig", "gbk"):
            try:
                lines = Path(path).read_text(encoding=encoding).splitlines()
                break
            except UnicodeDecodeError:
                continue
        else:
            raise ValueError(f"Cannot decode input file: {path}")

    # Detect legacy JSONL snapshot by structured parsing, not first-char guess.
    snapshot_candidate = False
    for line in lines:
        stripped = line.strip()
        match = re.search(r"\{.*\}", stripped)
        if not match:
            continue
        try:
            candidate = json.loads(match.group())
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "ioc" in candidate and "data" in candidate:
            snapshot_candidate = True
            break

    errors: list[str] = []
    parse_error_count = 0
    nested_data_error_count = 0
    # (location_label, raw_value) pairs preserve physical file line numbers and
    # distinguish inline --ioc values from file rows.
    labeled_values: list[tuple[str, str]] = []
    if snapshot_candidate:
        read_result = read_jsonl_snapshot_with_diagnostics(path)
        snapshots = read_result.records
        line_numbers = read_result.record_line_numbers
        for index, row in enumerate(snapshots):
            if not isinstance(row, dict):
                continue
            physical_line = (
                line_numbers[index]
                if index < len(line_numbers)
                else index + 1
            )
            labeled_values.append(
                (f"line {physical_line}", str(row.get("ioc", "")))
            )
        errors.extend(read_result.parse_error_samples)
        parse_error_count = read_result.skipped
        nested_data_error_count = read_result.nested_data_error_count
        kind = InputKind.SNAPSHOT
    else:
        snapshots = []
        kind = InputKind.IOC_LIST
        for physical_line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.lstrip().startswith("#"):
                continue
            labeled_values.append((f"line {physical_line_no}", stripped))

    for inline_index, value in enumerate(inline_iocs or [], 1):
        labeled_values.append((f"inline IOC {inline_index}", value))

    targets: list[IocTarget] = []
    seen: set[str] = set()
    for location, value in labeled_values:
        target = _target(value)
        if target is None:
            errors.append(f"{location}: invalid IOC {value!r}")
            continue
        if target.normalized not in seen:
            seen.add(target.normalized)
            targets.append(target)

    return InputBundle(
        kind,
        targets,
        snapshots,
        errors,
        parse_error_count=parse_error_count,
        nested_data_error_count=nested_data_error_count,
    )
