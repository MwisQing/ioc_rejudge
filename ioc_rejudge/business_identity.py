"""Validation helpers for trusted business identity evidence."""

from __future__ import annotations

import re
from collections.abc import Sequence
from ipaddress import ip_address
from urllib.parse import urlsplit

from ioc_rejudge.inputs import is_valid_host, is_valid_port
from ioc_rejudge.models import IocDossier


_SCHEME_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DOMAIN_SHAPE_RE = re.compile(
    r"(?<![A-Za-z0-9-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"\.?"
    r"(?::[0-9]+)?"
    r"(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)


def _text_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value) if value else ""
    return str(value).strip()


def _normalise_host(host: str) -> str | None:
    if not host or any(char.isspace() for char in host):
        return None
    host = host.rstrip(".").lower()
    if not host or not is_valid_host(host):
        return None
    return host


def _parse_bare_host(value: str) -> str | None:
    """Parse a bare host with an optional validated port."""
    if (
        not value
        or any(char.isspace() for char in value)
        or "://" in value
        or value.startswith("//")
        or any(marker in value for marker in "/?#")
        or value.count(":") > 1
    ):
        return None

    host = value
    if ":" in value:
        host, port = value.rsplit(":", 1)
        if not is_valid_port(port):
            return None
    return _normalise_host(host)


def _host_from_split(parsed) -> str | None:
    if not parsed.netloc or "@" in parsed.netloc or parsed.netloc.endswith(":"):
        return None
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    host = _normalise_host(hostname or "")
    if host is None:
        return None
    if port is not None and not is_valid_port(str(port)):
        return None
    return host


def _parse_http_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    return _host_from_split(parsed)


def _parse_website(value: str) -> str | None:
    """Return a normalized host for an HTTP(S) URL or a bare host."""
    if not value or any(char.isspace() for char in value):
        return None
    if _SCHEME_URL_RE.match(value):
        return _parse_http_url(value)
    if "://" in value:
        return None
    return _parse_bare_host(value)


def _parse_target_url(value: str) -> str | None:
    """Parse a URL IOC, including the normalized scheme-less form."""
    if not value or any(char.isspace() for char in value):
        return None
    if _SCHEME_URL_RE.match(value):
        return _parse_http_url(value)
    if "://" in value:
        return None
    try:
        parsed = urlsplit("//" + value)
    except ValueError:
        return None
    return _host_from_split(parsed)


def _target_host(dossier: IocDossier) -> str | None:
    ioc = _text_value(getattr(dossier, "ioc", ""))
    ioc_type = _text_value(getattr(dossier, "ioc_type", ""))

    if ioc_type == "domain":
        return _normalise_host(ioc)

    if ioc_type == "domain_port":
        return _parse_bare_host(ioc) if ":" in ioc else None

    if ioc_type == "url":
        return _parse_target_url(ioc)

    return None


def _hosts_match(left: str, right: str) -> bool:
    if left == right:
        return True
    if left.startswith("www.") and left[4:] == right:
        return True
    return right.startswith("www.") and right[4:] == left


def _contains_url_or_domain_shape(value: str) -> bool:
    return "://" in value or _DOMAIN_SHAPE_RE.search(value) is not None


def trusted_business_identity(
    dossier: IocDossier, field_names: Sequence[str]
) -> bool:
    """Validate configured business identity fields against the IOC host."""
    if isinstance(field_names, (str, bytes)):
        return False
    try:
        selected_fields = tuple(field_names)
    except TypeError:
        return False
    if not selected_fields:
        return False

    selected_values: dict[str, str] = {}
    for field_name in selected_fields:
        if not isinstance(field_name, str):
            return False
        value = _text_value(getattr(dossier, field_name, ""))
        if not value:
            return False
        selected_values[field_name] = value

    if getattr(dossier, "current_icp_conflict", False) is True:
        return False

    target_host = _target_host(dossier)
    if target_host is None:
        return False
    try:
        ip_address(target_host)
    except ValueError:
        pass
    else:
        return False

    has_anchor = False

    if "official_website" in selected_values:
        official_host = _parse_website(selected_values["official_website"])
        if official_host is None or not _hosts_match(official_host, target_host):
            return False
        has_anchor = True

    if "icp_website" in selected_values and _contains_url_or_domain_shape(
        selected_values["icp_website"]
    ):
        icp_host = _parse_website(selected_values["icp_website"])
        if icp_host is None or not _hosts_match(icp_host, target_host):
            return False
        has_anchor = True

    return has_anchor
