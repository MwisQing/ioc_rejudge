"""Configuration and injected provider health checks."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from pathlib import Path


STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_ERROR = "error"
STATUS_NOT_PROBED = "not_probed"


def _normalise_provider_names(provider_names):
    if not isinstance(provider_names, list):
        raise TypeError("provider_names must be a list")
    return list(dict.fromkeys(provider_names))


def _configuration_check(provider_name):
    if not isinstance(provider_name, str) or not provider_name.strip():
        return {"status": STATUS_ERROR, "reason": "invalid_provider_name"}
    return {"status": STATUS_OK}


def _credentials_check(provider_name, credentials):
    credential_name = f"{provider_name}_API_KEY"
    if not isinstance(credentials, Mapping) or provider_name not in credentials:
        return {"status": "missing", "credential_name": credential_name}
    return {"status": "present", "credential_name": credential_name}


def _endpoint_check(provider_name, endpoints):
    if not isinstance(endpoints, Mapping) or provider_name not in endpoints:
        return {"status": "missing"}

    endpoint = endpoints[provider_name]
    if not isinstance(endpoint, str):
        return {"status": STATUS_ERROR, "reason": "invalid_endpoint"}

    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        return {"status": STATUS_ERROR, "reason": "invalid_endpoint"}

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return {"status": STATUS_ERROR, "reason": "invalid_endpoint"}
    return {"status": STATUS_OK}


def _cache_check(cache_root):
    if cache_root is None:
        return {"status": STATUS_WARN, "reason": "cache_root_not_configured"}
    if not isinstance(cache_root, (str, bytes, os.PathLike)):
        return {"status": STATUS_ERROR, "reason": "invalid_cache_root"}

    try:
        cache_path = Path(cache_root)
        cache_path.mkdir(parents=True, exist_ok=True)
        probe = cache_path / ".health-write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except (AttributeError, OSError, TypeError):
        return {"status": STATUS_ERROR, "reason": "cache_root_not_writable"}
    return {"status": STATUS_OK}


def _transport_error_reason(exc):
    exception_name = type(exc).__name__.lower()
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in exception_name:
        return "timeout"
    if isinstance(exc, HTTPError) or "http" in exception_name:
        return "http"
    if isinstance(exc, (json.JSONDecodeError, ValueError)) or "json" in exception_name:
        return "json"
    if isinstance(exc, (ConnectionError, URLError, OSError)) or "connection" in exception_name:
        return "connection"
    return "error"


def _transport_check(provider_name, endpoints, transport, offline):
    if offline or transport is None:
        return {"status": STATUS_NOT_PROBED}

    endpoint_check = _endpoint_check(provider_name, endpoints)
    if endpoint_check["status"] != STATUS_OK:
        return {"status": STATUS_NOT_PROBED}

    try:
        transport.get_json(endpoints[provider_name], timeout=5)
    except Exception as exc:  # The exception value is deliberately not returned.
        return {"status": STATUS_ERROR, "reason": _transport_error_reason(exc)}
    return {"status": STATUS_OK}


def _overall_status(checks):
    statuses = {check["status"] for check in checks.values()}
    if STATUS_ERROR in statuses:
        return STATUS_ERROR
    if STATUS_WARN in statuses:
        return STATUS_WARN
    return STATUS_OK


def _provider_status(severities):
    severities = list(severities)
    if STATUS_ERROR in severities:
        return STATUS_ERROR
    if STATUS_WARN in severities:
        return STATUS_WARN
    return STATUS_OK


def check_configuration(
    provider_names,
    credentials=None,
    endpoints=None,
    cache_root=None,
    offline=False,
):
    """Check configuration-only provider health without any network access."""
    providers = {}
    for provider_name in _normalise_provider_names(provider_names):
        configuration = _configuration_check(provider_name)
        credential = _credentials_check(provider_name, credentials)
        endpoint = _endpoint_check(provider_name, endpoints)
        cache = _cache_check(cache_root)
        transport = {"status": STATUS_NOT_PROBED}

        credential_severity = STATUS_OK if credential["status"] == "present" else STATUS_WARN
        endpoint_severity = (
            STATUS_OK
            if endpoint["status"] == STATUS_OK
            else STATUS_ERROR
            if endpoint["status"] == STATUS_ERROR
            else STATUS_WARN
        )
        checks = {
            "configuration": configuration,
            "credentials": credential,
            "endpoint": endpoint,
            "cache": cache,
            "transport": transport,
        }
        severities = {
            "configuration": configuration["status"],
            "credentials": credential_severity,
            "endpoint": endpoint_severity,
            "cache": cache["status"],
            "transport": STATUS_OK,
        }
        provider_status = _provider_status(severities.values())
        providers[provider_name] = {"status": provider_status, "checks": checks}

    return {
        "overall_status": _provider_status(p["status"] for p in providers.values()),
        "providers": providers,
    }


def probe_provider_health(
    provider_names,
    endpoints=None,
    credentials=None,
    transport=None,
    offline=False,
):
    """Probe providers using only the explicitly injected transport."""
    providers = {}
    for provider_name in _normalise_provider_names(provider_names):
        configuration = _configuration_check(provider_name)
        credential = _credentials_check(provider_name, credentials)
        endpoint = _endpoint_check(provider_name, endpoints)
        transport_check = _transport_check(
            provider_name, endpoints, transport, offline
        )
        checks = {
            "configuration": configuration,
            "credentials": credential,
            "endpoint": endpoint,
            "cache": {"status": STATUS_NOT_PROBED},
            "transport": transport_check,
        }

        severities = {
            "configuration": configuration["status"],
            "credentials": STATUS_OK if credential["status"] == "present" else STATUS_WARN,
            "endpoint": endpoint["status"],
            "cache": STATUS_OK,
            "transport": STATUS_OK if transport_check["status"] in {STATUS_OK, STATUS_NOT_PROBED} else STATUS_ERROR,
        }
        provider_status = _provider_status(severities.values())
        providers[provider_name] = {"status": provider_status, "checks": checks}

    return {
        "overall_status": _provider_status(p["status"] for p in providers.values()),
        "providers": providers,
    }
