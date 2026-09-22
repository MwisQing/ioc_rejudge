"""Shared credential-value redaction for live provider persistence surfaces."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

REDACTED = "[REDACTED]"


def secret_values(secrets: Mapping[str, object] | None) -> tuple[str, ...]:
    """Return nonempty configured secret strings, longest first for stable replace."""
    values = {
        str(secret)
        for secret in (secrets or {}).values()
        if isinstance(secret, str) and secret
    }
    return tuple(sorted(values, key=len, reverse=True))


def redact_secret_values(value: object, secrets: Sequence[str]) -> object:
    """Recursively replace known secret strings in nested structures and keys."""
    if not secrets:
        return value
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            redacted = redacted.replace(secret, REDACTED)
        return redacted
    if isinstance(value, dict):
        return {
            redact_secret_values(key, secrets): redact_secret_values(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secret_values(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secret_values(item, secrets) for item in value)
    return value


def safe_text(message: object, secrets: Sequence[str]) -> str:
    """Render any message with known secret substrings removed."""
    return str(redact_secret_values(str(message), secrets))


__all__ = [
    "REDACTED",
    "redact_secret_values",
    "safe_text",
    "secret_values",
]
