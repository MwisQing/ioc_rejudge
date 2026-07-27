"""Injectable, secret-safe HTTP JSON transport."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import requests


class TransportError(RuntimeError):
    def __init__(
        self,
        kind: str,
        message: str,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


def _safe_endpoint(url: object) -> str:
    """Return an endpoint without credentials, query parameters, or fragments."""
    raw = str(url)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw.split("?", 1)[0].split("#", 1)[0]
    if not parsed.scheme or not parsed.hostname:
        return raw.split("?", 1)[0].split("#", 1)[0]

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    authority = f"{hostname}:{port}" if port is not None else hostname
    return f"{parsed.scheme}://{authority}{parsed.path or ''}"


class RequestsTransport:
    def __init__(self, session=None) -> None:
        self.session = session or requests.Session()

    def get_json(
        self,
        url,
        *,
        headers=None,
        params=None,
        timeout=30,
    ) -> Any:
        endpoint = _safe_endpoint(url)
        try:
            response = self.session.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
            )
        except requests.Timeout as exc:
            raise TransportError(
                "timeout",
                f"Request timed out for {endpoint}",
            ) from exc
        except requests.ConnectionError as exc:
            raise TransportError(
                "connection",
                f"Connection failed for {endpoint}",
            ) from exc
        return self._json(response, endpoint)

    def post_json(
        self,
        url,
        *,
        headers=None,
        body=None,
        timeout=30,
    ) -> Any:
        endpoint = _safe_endpoint(url)
        try:
            response = self.session.post(
                url,
                headers=headers,
                json=body,
                timeout=timeout,
            )
        except requests.Timeout as exc:
            raise TransportError(
                "timeout",
                f"Request timed out for {endpoint}",
            ) from exc
        except requests.ConnectionError as exc:
            raise TransportError(
                "connection",
                f"Connection failed for {endpoint}",
            ) from exc
        return self._json(response, endpoint)

    @staticmethod
    def _json(response, endpoint: str) -> Any:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            status_code = getattr(response, "status_code", None)
            if status_code is None and getattr(exc, "response", None) is not None:
                status_code = getattr(exc.response, "status_code", None)
            status_text = str(status_code) if status_code is not None else "unknown"
            raise TransportError(
                "http",
                f"HTTP {status_text} for {endpoint}",
                status_code=status_code,
            ) from exc

        try:
            return response.json()
        except (requests.exceptions.JSONDecodeError, json.JSONDecodeError) as exc:
            status_code = getattr(response, "status_code", None)
            status_text = str(status_code) if status_code is not None else "unknown"
            raise TransportError(
                "json_decode",
                f"Invalid JSON response from {endpoint} (status {status_text})",
                status_code=status_code,
            ) from exc
