"""Anonymize IOC cache data for safe sharing.

Replace IOCs, IPs, domains, hashes, emails, person names, and credential-like
fields in JSONL cache files with deterministic or random surrogates.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import random
import re
import string
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CREDENTIAL_FIELDS = {
    "api_token",
    "authorization",
    "token",
    "api_key",
    "apikey",
    "password",
    "secret",
    "access_key",
    "secret_key",
}

_REDACTED_MARKER = "[REDACTED]"

_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")

# Rough patterns for detection (not validation).
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)
_EMAIL_RE = re.compile(r"\b[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,63}\b")
_URL_PATH_RE = re.compile(r"(https?://[^/\s]+)(/[^\s]*)")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_hex(length: int = 32) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def _random_private_ip(rng: random.Random) -> str:
    """Return a random private IPv4 address string."""
    blocks = [
        ("10.", lambda r: f"10.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"),
        (
            "172.",
            lambda r: f"172.{r.randint(16,31)}.{r.randint(0,255)}.{r.randint(1,254)}",
        ),
        ("192.168.", lambda r: f"192.168.{r.randint(0,255)}.{r.randint(1,254)}"),
    ]
    prefix, factory = random.choice(blocks)  # noqa: S311 – not security-sensitive
    return factory(rng)


def _random_domain(rng: random.Random) -> str:
    label = "".join(
        random.choice(string.ascii_lowercase + string.digits)  # noqa: S311
        for _ in range(rng.randint(6, 14))
    )
    return f"{label}.invalid"


def _is_credential_field(key: str) -> bool:
    return key.lower() in _CREDENTIAL_FIELDS


# ---------------------------------------------------------------------------
# Core anonymization
# ---------------------------------------------------------------------------


def _build_ioc_set(rows: list[dict]) -> set[str]:
    """Collect all IOC values from the top-level 'ioc' field."""
    iocs: set[str] = set()
    for row in rows:
        ioc = row.get("ioc")
        if isinstance(ioc, str) and ioc:
            iocs.add(ioc)
    return iocs


def _load_names(names_path: str | None) -> list[str]:
    if not names_path:
        return []
    path = Path(names_path)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [line.strip() for line in lines if line.strip()]


class _Anonymizer:
    """Stateful anonymizer that maps each seen value to a consistent surrogate."""

    def __init__(self, iocs: set[str], names: list[str], rng: random.Random):
        self._iocs = iocs
        self._names = names
        self._rng = rng
        self._ip_map: dict[str, str] = {}
        self._domain_map: dict[str, str] = {}
        self._email_map: dict[str, str] = {}
        self._hash_map: dict[str, str] = {}
        self._name_map: dict[str, str] = {}
        self._url_path_map: dict[str, str] = {}
        self._name_counter = 0

    def anonymize_value(self, value, parent_key: str = "") -> object:
        """Recursively anonymize a value, returning the sanitized equivalent."""
        if isinstance(value, str):
            return self._anonymize_str(value, parent_key)
        if isinstance(value, list):
            return [self.anonymize_value(v, parent_key) for v in value]
        if isinstance(value, dict):
            return {k: self.anonymize_value(v, k) for k, v in value.items()}
        return value

    def _anonymize_str(self, s: str, parent_key: str = "") -> str:
        if not s:
            return s

        # Credential fields → redacted wholesale
        if _is_credential_field(parent_key):
            return _REDACTED_MARKER

        result = s

        # URLs: anonymize path/query while preserving scheme+host mapping
        result = _URL_PATH_RE.sub(
            lambda m: self._map_url(m.group(1), m.group(2)), result
        )

        # IPs
        result = _IP_RE.sub(lambda m: self._map_ip(m.group(0)), result)

        # Emails
        result = _EMAIL_RE.sub(lambda m: self._map_email(m.group(0)), result)

        # Domains (after emails and URLs, which contain dots)
        result = _DOMAIN_RE.sub(lambda m: self._map_domain(m.group(0)), result)

        # 32-char hex hashes
        result = _HEX32_RE.sub(lambda m: self._map_hash(m.group(0)), result)

        # Person names
        for name in self._names:
            if name and name in result:
                result = result.replace(name, self._map_person_name(name))

        return result

    def _map_ip(self, ip_str: str) -> str:
        if ip_str not in self._ip_map:
            self._ip_map[ip_str] = _random_private_ip(self._rng)
        return self._ip_map[ip_str]

    def _map_domain(self, domain: str) -> str:
        if domain not in self._domain_map:
            self._domain_map[domain] = _random_domain(self._rng)
        return self._domain_map[domain]

    def _map_email(self, email: str) -> str:
        if email not in self._email_map:
            local = "".join(
                random.choice(string.ascii_lowercase)  # noqa: S311
                for _ in range(8)
            )
            self._email_map[email] = f"{local}@example.invalid"
        return self._email_map[email]

    def _map_hash(self, h: str) -> str:
        if h not in self._hash_map:
            self._hash_map[h] = _random_hex(len(h))
        return self._hash_map[h]

    def _map_person_name(self, name: str) -> str:
        if name not in self._name_map:
            self._name_counter += 1
            self._name_map[name] = f"PERSON_{self._name_counter:04d}"
        return self._name_map[name]

    def _map_url(self, base: str, path_and_query: str) -> str:
        key = (base, path_and_query)
        if key not in self._url_path_map:
            # Replace each path segment
            segments = re.split(r"(/)", path_and_query)
            new_segments = []
            for seg in segments:
                if seg == "/" or not seg:
                    new_segments.append(seg)
                elif "=" in seg:
                    # query param: keep key, replace value
                    parts = seg.split("=", 1)
                    new_segments.append(f"{parts[0]}=sanitized")
                else:
                    new_segments.append("path")
            self._url_path_map[key] = "".join(new_segments)
        return base + self._url_path_map[key]


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def _read_input(input_path: str) -> list[dict]:
    """Read JSONL or pretty-printed JSON array."""
    text = Path(input_path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return json.loads(text)
    # JSONL
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _write_jsonl(output_path: str, rows: list[dict]) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Anonymize IOC cache JSONL files.")
    parser.add_argument("-i", "--input", required=True, help="Input JSONL or JSON array file")
    parser.add_argument("-o", "--output", required=True, help="Output JSONL file")
    parser.add_argument("--names-file", default=None, help="File with person names to redact, one per line")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for deterministic output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        print(f"Output file already exists: {args.output}. Use --force to overwrite.", file=sys.stderr)
        raise SystemExit(1)

    rows = _read_input(args.input)
    iocs = _build_ioc_set(rows)
    names = _load_names(args.names_file)
    rng = random.Random(args.seed) if args.seed is not None else random.Random()

    anonymizer = _Anonymizer(iocs, names, rng)
    result = [anonymizer.anonymize_value(row) for row in rows]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl(str(output_path), result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
