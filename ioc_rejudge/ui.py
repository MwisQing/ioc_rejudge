"""Local single-page assistant for the share bundle workflow.

The server is a thin wrapper around :mod:`ioc_rejudge.share`
create/restore/scan, plus an optional IOC Info lookup that reuses the same
provider cache as the adjudication CLI.  It binds to loopback only, guards
every request with a per-process session token plus Host/Origin checks, and
keeps the key passphrase in process memory (also persisted next to the key
file for auto-unlock on the next start until the user locks).  It never runs
the adjudication pipeline; lookup talks only to the ``ioc_info`` provider.
The human copies sanitized text to a cloud AI and pastes the answer back.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import requests

from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.factory import build_providers
from ioc_rejudge.providers.transport import RequestsTransport
from ioc_rejudge.share import (
    ShareError,
    create_bundle,
    ensure_key,
    restore_bundle,
    scan_bundle,
)

DEFAULT_PORT = 8731
MAX_BUNDLES = 20
MAX_BODY_BYTES = 32 * 1024 * 1024
DEFAULT_CACHE_DIR = Path("provider-cache")
DEFAULT_CREDENTIALS_FILE = Path("credentials.local.json")
LOOKUP_CREDENTIALS_ERROR = (
    "ioc_info is disabled (missing credentials); cannot query. "
    "Start with --credentials-file credentials.local.json "
    "or set IOC_INFO_API_KEY in this terminal."
)
# Interactive lookup must not inherit the pipeline's 10 empty-result retries
# or spawn a Go HTTP worker; either can leave the page spinning for minutes.
LOOKUP_MAX_ATTEMPTS = 1
LOOKUP_CONNECT_TIMEOUT_SECONDS = 5
LOOKUP_READ_TIMEOUT_SECONDS = 15
_PARALLEL_API_PATHS = frozenset({"/api/status", "/api/lookup"})

# Bundle directories are named by the 20-hex-char bundle id; the fullmatch
# also keeps user-supplied ids from ever escaping the bundle directory.
_BUNDLE_ID_RE = re.compile(r"[0-9a-f]{20}")
_INVALID_IOC_RE = re.compile(r"^line (\d+): invalid IOC (.+)$")
_PAGE_FILE = Path(__file__).with_name("ui.html")


def _rejected_rows_from_errors(errors: list[str]) -> list[dict]:
    """Turn input-bundle parse errors into lookup JSONL error rows."""
    rows: list[dict] = []
    for message in errors:
        original = ""
        match = _INVALID_IOC_RE.match(message)
        if match:
            try:
                value = ast.literal_eval(match.group(2))
            except (SyntaxError, ValueError):
                value = match.group(2)
            original = value if isinstance(value, str) else str(value)
        rows.append(
            {
                "ioc": original,
                "normalized": "",
                "ioc_type": "",
                "status": "error",
                "freshness": "unknown",
                "source": "none",
                "data": [],
                "error": message,
            }
        )
    return rows


def _fresh_cache_hit_keys(provider: Any, targets: list) -> set[str]:
    """Normalized IOC keys that the ioc_info provider would serve from cache.

    Live fetches that write through the cache also store ``raw_ref`` values
    with a ``cache:`` prefix, so lookup source mapping cannot rely on the
    prefix alone and must detect pre-collect fresh hits separately.
    """
    hits: set[str] = set()
    cache = getattr(provider, "cache", None)
    if cache is None or not getattr(provider.settings, "enabled", False):
        return hits
    now_fn = getattr(provider, "now_fn", None)
    now = now_fn() if callable(now_fn) else None
    for target in targets:
        if not provider.supports(target):
            continue
        try:
            entry = cache.get(
                target.original,
                provider.cache_params(target),
                now=now,
            )
        except (OSError, TypeError, ValueError):
            continue
        if entry is not None and entry.fresh:
            hits.add(target.normalized)
    return hits


def _lookup_source(status: ProviderStatus, cache_hit: bool) -> str:
    if status in (ProviderStatus.SUCCESS, ProviderStatus.NO_DATA):
        return "cache" if cache_hit else "live"
    return "none"


def _timestamp() -> str:
    """A sortable, collision-resistant suffix for audit file names."""
    return f"{int(time.time() * 1000):013d}-{secrets.token_hex(2)}"


def resolve_ui_credentials_path(explicit: str | None) -> Path | None:
    """Return the credentials file the UI should use.

    An explicit ``--credentials-file`` always wins. Otherwise a project-root
    ``credentials.local.json`` is used when it exists, matching the usual
    adjudication CLI workflow on the official machine.
    """
    if explicit:
        return Path(explicit).expanduser()
    if DEFAULT_CREDENTIALS_FILE.is_file():
        return DEFAULT_CREDENTIALS_FILE
    return None


class _LookupTransport(RequestsTransport):
    """Interactive lookup HTTP: ignore env proxies, bound connect/read time."""

    def __init__(self) -> None:
        session = requests.Session()
        session.trust_env = False
        super().__init__(session)

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        bounded = (
            timeout
            if isinstance(timeout, tuple)
            else (
                LOOKUP_CONNECT_TIMEOUT_SECONDS,
                min(int(timeout), LOOKUP_READ_TIMEOUT_SECONDS),
            )
        )
        return super().post_json(url, headers=headers, body=body, timeout=bounded)


def _lookup_transport_factory(state: Any):
    """Python HTTP for interactive lookup; tests may inject FakeTransport."""
    if getattr(state, "transport_factory", None) is not None:
        return state.transport_factory
    return lambda _name: _LookupTransport()


def _build_lookup_provider(state: Any) -> tuple[Any, bool]:
    """Return ``(provider, offline)`` for every UI lookup in this process."""
    build_kwargs: dict[str, Any] = {
        "cache_dir": state.cache_dir,
        "offline": False,
        "transport_factory": _lookup_transport_factory(state),
    }
    if state.credentials_path is not None:
        build_kwargs["credentials_path"] = state.credentials_path
    elif state.provider_env is not None:
        build_kwargs["env"] = state.provider_env
    provider = build_providers(["ioc_info"], **build_kwargs)[0]
    provider.max_attempts = LOOKUP_MAX_ATTEMPTS
    provider.settings.timeout = LOOKUP_READ_TIMEOUT_SECONDS
    if not provider.settings.enabled:
        build_kwargs["offline"] = True
        provider = build_providers(["ioc_info"], **build_kwargs)[0]
        provider.max_attempts = LOOKUP_MAX_ATTEMPTS
        return provider, True
    return provider, False


def _warmup_lookup_cache(state: Any) -> None:
    """Load the ioc_info cache index once so the first click is not a full scan."""
    provider = getattr(state, "lookup_provider", None)
    cache = getattr(provider, "cache", None) if provider is not None else None
    if cache is None:
        return
    started = time.monotonic()
    try:
        cache.get("__ui_warmup__", {})
    except (OSError, TypeError, ValueError):
        return
    elapsed = time.monotonic() - started
    if elapsed >= 1:
        print(f"ioc info cache index loaded in {elapsed:.1f}s", file=sys.stderr)


def _cached_lookup(provider: Any, target: Any):
    """Return (status, observations, entry) from cache, including stale rows."""
    cache = getattr(provider, "cache", None)
    consume = getattr(provider, "_consume_cache", None)
    if cache is None or not callable(consume):
        return None
    try:
        now_fn = getattr(provider, "now_fn", None)
        entry = cache.get(
            target.original,
            provider.cache_params(target),
            now=now_fn() if callable(now_fn) else None,
        )
    except (OSError, TypeError, ValueError):
        return None
    if entry is None:
        return None
    status, observations = consume(target, entry)
    return status, observations, entry


def _ioc_info_enabled(
    *,
    cache_dir: Path,
    credentials_path: Path | None,
    provider_env: dict[str, str] | None,
    transport_factory,
) -> bool:
    """True when the ioc_info provider has credentials; never echoes secrets."""
    build_kwargs: dict[str, Any] = {
        "cache_dir": cache_dir,
        "offline": False,
        "transport_factory": transport_factory,
    }
    if credentials_path is not None:
        build_kwargs["credentials_path"] = credentials_path
    elif provider_env is not None:
        build_kwargs["env"] = provider_env
    try:
        provider = build_providers(["ioc_info"], **build_kwargs)[0]
    except (OSError, ValueError):
        return False
    return bool(getattr(provider.settings, "enabled", False))


def _passphrase_path(key_path: Path) -> Path:
    """Path of the remembered passphrase file beside the key file."""
    return Path(key_path).expanduser().parent / "passphrase"


def _write_passphrase_file(key_path: Path, passphrase: str) -> None:
    """Atomically persist the passphrase next to the key; best-effort 0o600."""
    path = _passphrase_path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(passphrase)
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, path)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_passphrase_file(key_path: Path) -> str | None:
    """Return the saved passphrase, or None when missing/unreadable/empty."""
    path = _passphrase_path(key_path)
    if not path.is_file():
        return None
    try:
        value = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return value if value else None


def _delete_passphrase_file(key_path: Path) -> None:
    """Remove the remembered passphrase file; missing file is fine."""
    path = _passphrase_path(key_path)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _optional_path(value: Any) -> Path | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.strip():
        raise ShareError("path values must be non-empty strings")
    return Path(value).expanduser()


def _read_names(path: Path | None) -> list[str]:
    if path is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ShareError(f"cannot read names file: {path}") from exc
    return [line.strip() for line in lines if line.strip()]


def _write_input_file(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ShareError(f"cannot write temporary input: {path}") from exc


def _read_manifest(manifest: Path) -> dict | None:
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _bundle_dirs(bundles_dir: Path) -> list[Path]:
    if not bundles_dir.is_dir():
        return []
    return [
        child
        for child in sorted(bundles_dir.iterdir())
        if child.is_dir() and _BUNDLE_ID_RE.fullmatch(child.name)
    ]


def _manifest_path(bundle_dir: Path) -> Path:
    return bundle_dir / "share.jsonl.manifest.json"


def _list_bundles(bundles_dir: Path) -> list[dict]:
    entries = []
    for bundle_dir in _bundle_dirs(bundles_dir):
        data = _read_manifest(_manifest_path(bundle_dir))
        if data is None:
            continue
        entries.append(
            {
                "bundle_id": data.get("bundle_id"),
                "created_at": data.get("created_at"),
                "rows": data.get("rows"),
            }
        )
    entries.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return entries


def _prune_bundles(bundles_dir: Path, max_bundles: int) -> None:
    """Keep only the newest ``max_bundles`` bundle directories."""
    entries = []
    for bundle_dir in _bundle_dirs(bundles_dir):
        data = _read_manifest(_manifest_path(bundle_dir))
        entries.append((str((data or {}).get("created_at") or ""), bundle_dir))
    entries.sort(key=lambda item: item[0], reverse=True)
    for _, bundle_dir in entries[max_bundles:]:
        shutil.rmtree(bundle_dir, ignore_errors=True)


def _first_row_bundle_id(path: Path) -> str | None:
    """Best-effort bundle_id from the first JSONL row, if any."""
    try:
        with path.open("rb") as handle:
            raw = handle.readline()
        value = json.loads(raw.decode("utf-8").lstrip("\ufeff"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if isinstance(value, dict):
        bundle_id = value.get("bundle_id")
        if isinstance(bundle_id, str):
            return bundle_id
    return None


def _match_manifest(bundles_dir: Path, input_path: Path) -> Path:
    """Locate the local manifest for a restore input.

    A cloud response carries the bundle id on every row, so the first row is
    enough to find the bundle directly.  An exact replay of a bundle has no
    such marker and is matched by the sha256 recorded in the manifest.
    """
    bundle_id = _first_row_bundle_id(input_path)
    if bundle_id and _BUNDLE_ID_RE.fullmatch(bundle_id):
        manifest = _manifest_path(bundles_dir / bundle_id)
        if manifest.is_file():
            return manifest
    digest = hashlib.sha256(input_path.read_bytes()).hexdigest()
    for bundle_dir in _bundle_dirs(bundles_dir):
        manifest = _manifest_path(bundle_dir)
        data = _read_manifest(manifest)
        if data is not None and data.get("output_sha256") == digest:
            return manifest
    raise ShareError("no matching local bundle; create a bundle before restoring")


class _UiHttpServer(ThreadingHTTPServer):
    # Windows permits a second process to bind an occupied port when
    # SO_REUSEADDR is set, silently pairing two UI servers on one port;
    # refusing address reuse keeps the occupied-port fallback honest.
    allow_reuse_address = False
    daemon_threads = True


class UiState:
    """Mutable server state; every handler runs under ``lock``."""

    def __init__(
        self,
        key_path: Path,
        bundles_dir: Path,
        token: str,
        max_bundles: int = MAX_BUNDLES,
        *,
        cache_dir: Path | None = None,
        credentials_path: Path | None = None,
        provider_env: dict[str, str] | None = None,
        transport_factory=None,
    ) -> None:
        if max_bundles < 1:
            raise ValueError("max_bundles must be at least 1")
        if credentials_path is not None and provider_env is not None:
            raise ValueError("credentials_path and provider_env cannot be used together")
        self.key_path = key_path
        self.bundles_dir = bundles_dir
        self.token = token
        self.max_bundles = max_bundles
        self.cache_dir = Path(cache_dir) if cache_dir is not None else DEFAULT_CACHE_DIR
        self.credentials_path = (
            Path(credentials_path).expanduser() if credentials_path is not None else None
        )
        self.provider_env = provider_env
        self.transport_factory = transport_factory
        self.ioc_info_enabled = False
        self.lookup_provider = None
        self.lookup_offline = True
        # The passphrase (not the derived key) is kept, because the wrapped
        # share functions re-load and re-verify the key file per operation.
        self.passphrase: str | None = None
        self.key_id: str | None = None
        self.lock = threading.Lock()
        self.lookup_lock = threading.Lock()

    @property
    def unlocked(self) -> bool:
        return self.passphrase is not None


class _UiRequestHandler(BaseHTTPRequestHandler):
    ui_state: UiState
    page_path: Path
    protocol_version = "HTTP/1.1"
    server_version = "ioc-rejudge-ui"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # The default request log prints the query string, which carries the
        # session token; the local UI stays silent instead.
        return

    # -- request plumbing -------------------------------------------------

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if status != 200:
            # Error paths may return before the request body was consumed;
            # closing the connection keeps keep-alive reuse in sync.
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ShareError("invalid Content-Length header") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ShareError("request body is too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ShareError("request body is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ShareError("request body must be a JSON object")
        return value

    def _request_token(self) -> str | None:
        auth = self.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            return auth[len("Bearer "):].strip()
        values = parse_qs(urlsplit(self.path).query).get("token")
        return values[0] if values else None

    def _valid_host(self, host: str) -> bool:
        # Loopback hostname plus, when present, the actual server port; a
        # forged Host value must never pass the DNS rebinding gate.
        hostname, separator, port = host.partition(":")
        hostname = hostname.strip("[]")
        if hostname not in ("127.0.0.1", "localhost"):
            return False
        if separator and port and port != str(self.server.server_address[1]):
            return False
        return True

    def _authorized(self) -> bool:
        # Host/Origin checks block DNS rebinding and cross-site requests;
        # the session token blocks anything that is not the launched page.
        host = (self.headers.get("Host") or "").strip().lower()
        if not host or not self._valid_host(host):
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            parts = urlsplit(origin)
            if parts.scheme != "http" or not self._valid_host(parts.netloc):
                return False
        token = self._request_token()
        return bool(token) and secrets.compare_digest(token, self.ui_state.token)

    # -- routing ----------------------------------------------------------

    def _drain_request_body(self) -> None:
        """Discard an unread request body before an early error response.

        Closing a socket while its receive buffer still holds request bytes
        makes Windows send RST instead of FIN, and the RST can destroy the
        already-written response before the client reads it.  Draining keeps
        the rejection path clean for well-formed requests; oversized bodies
        (above the request limit) are not worth draining.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        if 0 < length <= MAX_BODY_BYTES:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def do_GET(self) -> None:
        if urlsplit(self.path).path != "/":
            self._drain_request_body()
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._drain_request_body()
            self._send_json(403, {"error": "forbidden"})
            return
        try:
            page = self.page_path.read_bytes()
        except OSError:
            self._send_json(500, {"error": "ui page is missing from the installation"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self) -> None:
        if not urlsplit(self.path).path.startswith("/api/"):
            self._drain_request_body()
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._drain_request_body()
            self._send_json(403, {"error": "forbidden"})
            return
        try:
            body = self._read_json_body()
        except ShareError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        handlers = {
            "/api/status": self._handle_status,
            "/api/key": self._handle_key,
            "/api/lookup": self._handle_lookup,
            "/api/create": self._handle_create,
            "/api/restore": self._handle_restore,
            "/api/scan": self._handle_scan,
            "/api/lock": self._handle_lock,
        }
        handler = handlers.get(urlsplit(self.path).path)
        if handler is None:
            self._send_json(404, {"error": "unknown api endpoint"})
            return
        try:
            # Key/bundle mutations stay serialized. Status and lookup do not
            # take that lock: a slow IOC Info call must not freeze the page
            # or queue the next query behind a request the browser already
            # abandoned.
            if urlsplit(self.path).path in _PARALLEL_API_PATHS:
                result = handler(body)
            else:
                with self.ui_state.lock:
                    result = handler(body)
        except ShareError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # surfaced to the page without a stack trace
            self._send_json(500, {"error": f"internal error: {exc}"})
            return
        self._send_json(200, result)

    # -- api handlers -----------------------------------------------------

    def _handle_status(self, body: dict) -> dict:
        state = self.ui_state
        return {
            "key_file": str(state.key_path),
            "key_exists": state.key_path.is_file(),
            "unlocked": state.unlocked,
            "key_id": state.key_id,
            "passphrase_saved": _passphrase_path(state.key_path).is_file(),
            "ioc_info_enabled": state.ioc_info_enabled,
            "bundles": _list_bundles(state.bundles_dir),
        }

    def _handle_key(self, body: dict) -> dict:
        state = self.ui_state
        passphrase = body.get("passphrase")
        if not isinstance(passphrase, str) or not passphrase:
            raise ShareError("passphrase is required")
        key_id = ensure_key(
            state.key_path,
            passphrase,
            generate=bool(body.get("generate")),
            force=bool(body.get("force")),
        )
        state.passphrase = passphrase
        state.key_id = key_id
        _write_passphrase_file(state.key_path, passphrase)
        return {"key_id": key_id}

    def _handle_lock(self, body: dict) -> dict:
        state = self.ui_state
        was_unlocked = state.unlocked
        passphrase_path = _passphrase_path(state.key_path)
        had_saved_passphrase = passphrase_path.is_file()
        state.passphrase = None
        state.key_id = None
        _delete_passphrase_file(state.key_path)
        return {
            "unlocked": False,
            "was_unlocked": was_unlocked,
            "passphrase_cleared": had_saved_passphrase
            and not passphrase_path.is_file(),
            "had_saved_passphrase": had_saved_passphrase,
        }

    def _require_unlocked(self) -> None:
        if not self.ui_state.unlocked:
            raise ShareError("share key is locked; unlock it before running this operation")

    def _resolve_input(self, body: dict, target_dir: Path, prefix: str) -> tuple[Path, Path | None]:
        """Return (input path, staged file or None for a user-provided path)."""
        input_path = _optional_path(body.get("input_path"))
        if input_path is not None:
            return input_path, None
        content = body.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ShareError("content or input_path is required")
        staged = target_dir / f"{prefix}-{_timestamp()}.jsonl"
        _write_input_file(staged, content)
        return staged, staged

    def _handle_create(self, body: dict) -> dict:
        state = self.ui_state
        self._require_unlocked()
        staging = state.bundles_dir / f".staging-{_timestamp()}"
        staging.mkdir(parents=True, exist_ok=False)
        try:
            input_path, _ = self._resolve_input(body, staging, "input")
            names = _read_names(_optional_path(body.get("names_path")))
            manifest_data = create_bundle(
                input_path,
                staging / "share.jsonl",
                state.key_path,
                names=names,
                force=True,
                passphrase=state.passphrase,
            )
            bundle_id = manifest_data.get("bundle_id")
            if not isinstance(bundle_id, str) or not _BUNDLE_ID_RE.fullmatch(bundle_id):
                raise ShareError("created bundle has an invalid bundle_id")
            target = state.bundles_dir / bundle_id
            if target.exists():
                # Same content shared again: the fresh copy replaces the old
                # bundle so the newest manifest and audit files win.
                shutil.rmtree(target)
            staging.rename(target)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        _prune_bundles(state.bundles_dir, state.max_bundles)
        text = (target / "share.jsonl").read_text(encoding="utf-8")
        return {
            "text": text,
            "bundle_id": bundle_id,
            "rows": manifest_data.get("rows"),
            "token_occurrences": manifest_data.get("token_occurrences"),
            "redacted_occurrences": manifest_data.get("redacted_occurrences"),
            "source_findings": manifest_data.get("source_findings"),
        }

    def _handle_restore(self, body: dict) -> dict:
        state = self.ui_state
        self._require_unlocked()
        staging_dir = state.bundles_dir
        input_path, staged = self._resolve_input(body, staging_dir, "cloud")
        try:
            manifest = _match_manifest(staging_dir, input_path)
            output = manifest.parent / f"restored-{_timestamp()}.jsonl"
            rows = restore_bundle(
                input_path,
                output,
                state.key_path,
                manifest_path=manifest,
                force=True,
                passphrase=state.passphrase,
            )
        except Exception:
            if staged is not None:
                staged.unlink(missing_ok=True)
            raise
        if staged is not None:
            # Keep the pasted cloud response beside its bundle for audit.
            staged.replace(manifest.parent / f"cloud-{_timestamp()}.jsonl")
        return {
            "text": output.read_text(encoding="utf-8"),
            "rows": rows,
            "matched_bundle_id": manifest.parent.name,
        }

    def _handle_scan(self, body: dict) -> dict:
        state = self.ui_state
        input_path, staged = self._resolve_input(body, state.bundles_dir, "scan")
        try:
            return scan_bundle(input_path)
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)

    def _handle_lookup(self, body: dict) -> dict:
        """Query only the ioc_info provider; unlock is not required."""
        state = self.ui_state
        input_path, staged = self._resolve_input(body, state.bundles_dir, "lookup")
        try:
            try:
                bundle = read_input_bundle(str(input_path))
            except FileNotFoundError as exc:
                raise ShareError(f"lookup input not found: {input_path}") from exc
            except (OSError, ValueError) as exc:
                raise ShareError(f"cannot read lookup input: {exc}") from exc

            rejected_rows = _rejected_rows_from_errors(bundle.errors)
            targets = list(bundle.targets)

            provider = state.lookup_provider
            if provider is None:
                raise ShareError(LOOKUP_CREDENTIALS_ERROR)
            offline = bool(state.lookup_offline)

            started = time.monotonic()
            with state.lookup_lock:
                cache_hit_keys = _fresh_cache_hit_keys(provider, targets)
                try:
                    if targets:
                        result = provider.collect(
                            targets,
                            ProviderContext(refresh=False, offline=offline),
                        )
                    else:
                        result = ProviderResult(name="ioc_info")
                except Exception:
                    print(
                        f"ioc info lookup failed after {time.monotonic() - started:.1f}s",
                        file=sys.stderr,
                    )
                    raise
            print(
                f"ioc info lookup: {len(targets)} ioc in {time.monotonic() - started:.1f}s",
                file=sys.stderr,
            )

            for target in targets:
                status = result.statuses.get(
                    target.normalized, ProviderStatus.ERROR
                )
                if status != ProviderStatus.ERROR:
                    continue
                cached = _cached_lookup(provider, target)
                if cached is None:
                    continue
                status, cached_observations, entry = cached
                result.statuses[target.normalized] = status
                result.freshnesses[target.normalized] = (
                    Freshness.FRESH if entry.fresh else Freshness.STALE
                )
                result.observations = [
                    obs
                    for obs in result.observations
                    if obs.ioc != target.normalized
                ]
                result.observations.extend(cached_observations)
                cache_hit_keys.add(target.normalized)

            if targets and offline and not cache_hit_keys and result.cache_hits == 0:
                raise ShareError(LOOKUP_CREDENTIALS_ERROR)

            rows: list[dict] = []
            for target in targets:
                status = result.statuses.get(
                    target.normalized, ProviderStatus.ERROR
                )
                freshness = result.freshnesses.get(
                    target.normalized, Freshness.UNKNOWN
                )
                observations = [
                    obs
                    for obs in result.observations
                    if obs.ioc == target.normalized and obs.kind == "ioc_info_record"
                ]
                cache_hit = target.normalized in cache_hit_keys
                row = {
                    "ioc": target.original,
                    "normalized": target.normalized,
                    "ioc_type": target.ioc_type,
                    "status": (
                        status.value
                        if isinstance(status, ProviderStatus)
                        else str(status)
                    ),
                    "freshness": (
                        freshness.value
                        if isinstance(freshness, Freshness)
                        else str(freshness)
                    ),
                    "source": _lookup_source(status, cache_hit),
                    "data": [
                        dict(obs.payload) if isinstance(obs.payload, dict) else obs.payload
                        for obs in observations
                    ],
                }
                rows.append(row)
            rows.extend(rejected_rows)

            # Rejected input rows always carry an "error" message field; provider
            # ERROR status rows from collect do not.
            cache_hits = sum(1 for row in rows if row["source"] == "cache")
            live_fetches = sum(1 for row in rows if row["source"] == "live")
            no_data = sum(1 for row in rows if row["status"] == "no_data")
            errors = sum(
                1
                for row in rows
                if row["status"] == "error" and "error" not in row
            )
            disabled = sum(1 for row in rows if row["status"] == "disabled")
            rejected = len(rejected_rows)
            text = "".join(
                json.dumps(row, ensure_ascii=False) + "\n" for row in rows
            )
            return {
                "text": text,
                "rows": len(rows),
                "cache_hits": cache_hits,
                "live_fetches": live_fetches,
                "no_data": no_data,
                "errors": errors,
                "disabled": disabled,
                "rejected": rejected,
            }
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)


def build_server(
    key_path: str | Path,
    bundles_dir: str | Path,
    *,
    port: int = DEFAULT_PORT,
    max_bundles: int = MAX_BUNDLES,
    token: str | None = None,
    cache_dir: str | Path | None = None,
    credentials_path: str | Path | None = None,
    provider_env: dict[str, str] | None = None,
    transport_factory=None,
) -> tuple[ThreadingHTTPServer, str]:
    """Create the loopback UI server and return it with its tokenized URL."""
    resolved_key = Path(key_path).expanduser()
    resolved_bundles = Path(bundles_dir).expanduser()
    resolved_key.parent.mkdir(parents=True, exist_ok=True)
    resolved_bundles.mkdir(parents=True, exist_ok=True)
    session_token = token or secrets.token_urlsafe(24)
    resolved_cache = (
        Path(cache_dir).expanduser() if cache_dir is not None else DEFAULT_CACHE_DIR
    )
    resolved_credentials = (
        Path(credentials_path).expanduser() if credentials_path is not None else None
    )

    class Handler(_UiRequestHandler):
        pass

    state = UiState(
        resolved_key,
        resolved_bundles,
        session_token,
        max_bundles,
        cache_dir=resolved_cache,
        credentials_path=resolved_credentials,
        provider_env=provider_env,
        transport_factory=transport_factory,
    )
    saved = _read_passphrase_file(resolved_key)
    if saved is not None and resolved_key.is_file():
        try:
            key_id = ensure_key(resolved_key, saved, generate=False)
        except ShareError as exc:
            # Keep the saved file so the user can fix the key or passphrase;
            # never echo the passphrase itself.
            print(
                f"ioc rejudge share ui: auto-unlock failed: {exc}",
                file=sys.stderr,
            )
        else:
            state.passphrase = saved
            state.key_id = key_id
    state.ioc_info_enabled = _ioc_info_enabled(
        cache_dir=resolved_cache,
        credentials_path=resolved_credentials,
        provider_env=provider_env,
        transport_factory=transport_factory,
    )
    try:
        state.lookup_provider, state.lookup_offline = _build_lookup_provider(state)
    except (OSError, ValueError):
        state.lookup_provider = None
        state.lookup_offline = True
    _warmup_lookup_cache(state)
    Handler.ui_state = state
    Handler.page_path = _PAGE_FILE
    try:
        server = _UiHttpServer(("127.0.0.1", port), Handler)
    except OSError:
        if port == 0:
            raise
        # The preferred port is taken; fall back to an ephemeral one so the
        # assistant still starts and prints its actual URL.
        server = _UiHttpServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/?token={session_token}"
    return server, url


def serve(server: ThreadingHTTPServer, *, url: str, open_browser: bool) -> None:
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ioc_rejudge ui",
        description="run the local share assistant UI on loopback",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="port to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "--key-file",
        default=str(Path.home() / ".ioc-share" / "key.json"),
        help="share key file path (default: %(default)s)",
    )
    parser.add_argument(
        "--bundle-dir",
        default=str(Path.home() / ".ioc-share" / "bundles"),
        help="directory holding share bundles (default: %(default)s)",
    )
    parser.add_argument(
        "--cache-dir",
        default=str(DEFAULT_CACHE_DIR),
        help="provider cache directory for IOC Info lookup (default: %(default)s)",
    )
    parser.add_argument(
        "--credentials-file",
        default=None,
        help="credentials JSON for IOC Info lookup (default: credentials.local.json if present, else process env)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="print the URL instead of opening the browser",
    )
    args = parser.parse_args(argv)
    cache_dir = Path(args.cache_dir).expanduser()
    credentials_path = resolve_ui_credentials_path(args.credentials_file)
    server, url = build_server(
        Path(args.key_file).expanduser(),
        Path(args.bundle_dir).expanduser(),
        port=args.port,
        cache_dir=cache_dir,
        credentials_path=credentials_path,
    )
    print(f"ioc rejudge share ui: {url}")
    print(f"share key file: {Path(args.key_file).expanduser()}")
    print(f"bundle directory: {Path(args.bundle_dir).expanduser()}")
    print(f"provider cache: {cache_dir.resolve()}")
    if credentials_path is not None:
        print(f"ioc info credentials: {credentials_path}")
    else:
        print(
            "ioc info credentials: process environment "
            "(no credentials.local.json in the current directory)"
        )
    if not server.RequestHandlerClass.ui_state.ioc_info_enabled:
        print(
            "ioc info lookup: no credentials; queries only read the local 7-day cache",
            file=sys.stderr,
        )
    print(
        "press Ctrl+C to stop; passphrase is remembered next to the key file "
        "until you clear it"
    )
    serve(server, url=url, open_browser=not args.no_browser)
    return 0
