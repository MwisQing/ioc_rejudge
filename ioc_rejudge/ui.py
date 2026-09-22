"""Local single-page assistant for the share bundle workflow.

The server is a thin wrapper around :mod:`ioc_rejudge.share`
create/restore/scan, plus an optional IOC Info lookup that reuses the same
provider cache as the adjudication CLI.  It binds to loopback only, guards
every request with a per-process session token plus Host/Origin checks, and
keeps the key passphrase in process memory (also persisted next to the key
file for auto-unlock on the next start until the user locks).  The share flow
never runs the adjudication pipeline; the default workbench backend runs only
the local legacy snapshot pipeline. Lookup talks only to ``ioc_info``.
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
from ioc_rejudge.workbench import (
    LocalWorkbenchAdapter,
    WorkbenchAdapter,
    WorkbenchError,
    WorkbenchUnavailable,
)
from ioc_rejudge.workbench_backend import OfflineWorkbenchAdapter

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
_WORKBENCH_API_PREFIX = "/api/workbench/"
_SENSITIVE_SUMMARY_KEY_RE = re.compile(
    r"(?:^|_)(?:secret|password|credential|authorization|api[_-]?key|token)(?:$|_)",
    re.IGNORECASE,
)

# Bundle directories are named by the 20-hex-char bundle id; the fullmatch
# also keeps user-supplied ids from ever escaping the bundle directory.
_BUNDLE_ID_RE = re.compile(r"[0-9a-f]{20}")
_WORKBENCH_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")
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


def _list_bundles(bundles_dir: Path, *, limit: int | None = None) -> list[dict]:
    """List bundle manifests, newest first.

    ``limit`` caps the *visible* recent-history window only. Bundle directories
    themselves are retained so older restores keep matching after restart.
    """
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
    if limit is not None and limit >= 0:
        return entries[:limit]
    return entries


def _count_bundles(bundles_dir: Path) -> int:
    """Count bundle directories that still have a readable manifest."""
    total = 0
    for bundle_dir in _bundle_dirs(bundles_dir):
        if _read_manifest(_manifest_path(bundle_dir)) is not None:
            total += 1
    return total


def _prune_bundles(bundles_dir: Path, max_bundles: int) -> None:
    """History retention is a display limit; never delete restore metadata.

    Older ``max_bundles`` configuration still bounds the recent-history list
    returned by status APIs. Manifests, restored outputs, and cloud response
    copies stay on disk indefinitely so auto-match restore keeps working after
    overflow and after server restart. Regenerable share payloads are also
    retained by default (disk is cheap relative to lost recovery context).
    """
    del bundles_dir, max_bundles


_STAGING_FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _write_complete_file(path: Path, data: bytes) -> None:
    """Write ``data`` fully to ``path`` via temp + replace; verify byte length."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(6)
    tmp = path.with_name(f".tmp-write-{path.name}-{token}")
    try:
        if tmp.exists() or tmp.is_symlink():
            if tmp.is_dir() and not tmp.is_symlink():
                raise ShareError(f"refusing to overwrite directory temp path: {tmp}")
            tmp.unlink()
        tmp.write_bytes(data)
        written = tmp.stat().st_size
        if written != len(data):
            raise OSError(f"incomplete write for {path}: got {written} bytes, expected {len(data)}")
        os.replace(tmp, path)
        final = path.stat().st_size
        if final != len(data):
            raise OSError(f"incomplete write for {path}: got {final} bytes, expected {len(data)}")
    finally:
        if tmp.exists() or tmp.is_symlink():
            try:
                tmp.unlink()
            except OSError:
                pass


def _validate_staging_flat_files(staging: Path) -> list[Path]:
    """Return sorted regular files in staging; reject dirs/symlinks/unsafe names."""
    staging_resolved = staging.resolve()
    items: list[Path] = []
    for item in sorted(staging.iterdir(), key=lambda p: p.name):
        name = item.name
        if not _STAGING_FILE_NAME_RE.fullmatch(name):
            raise ShareError(f"unsafe staging artifact name: {name!r}")
        try:
            resolved = item.resolve(strict=False)
        except OSError as exc:
            raise ShareError(f"cannot resolve staging artifact: {name}") from exc
        if not resolved.is_relative_to(staging_resolved):
            raise ShareError(f"staging artifact escapes staging directory: {name}")
        if item.is_symlink():
            raise ShareError(f"staging rejects symlinks: {name}")
        if item.is_dir():
            raise ShareError(f"staging rejects directories: {name}")
        if not item.is_file():
            raise ShareError(f"staging requires regular files: {name}")
        items.append(item)
    return items


def _install_flat_file(src: Path, dest: Path) -> None:
    """Install one regular file onto ``dest`` only after the full payload is present."""
    if src.is_symlink() or not src.is_file():
        raise ShareError(f"install source must be a regular file: {src.name}")
    if dest.exists() and (dest.is_symlink() or dest.is_dir()):
        raise ShareError(f"refusing to replace non-file target: {dest.name}")
    data = src.read_bytes()
    token = secrets.token_hex(6)
    tmp = dest.with_name(f".tmp-install-{dest.name}-{token}")
    try:
        if tmp.exists() or tmp.is_symlink():
            if tmp.is_dir() and not tmp.is_symlink():
                raise ShareError(f"refusing to use directory as install temp: {tmp}")
            tmp.unlink()
        tmp.write_bytes(data)
        if tmp.stat().st_size != len(data):
            raise OSError(f"incomplete install payload for {dest.name}")
        os.replace(tmp, dest)
    finally:
        if tmp.exists() or tmp.is_symlink():
            try:
                tmp.unlink()
            except OSError:
                pass


def _restore_flat_file(backup: Path, dest: Path) -> None:
    """Atomically restore ``dest`` from a complete backup file (no pre-unlink)."""
    if backup.is_symlink() or not backup.is_file():
        raise OSError(f"complete backup missing or not a file: {backup}")
    if dest.exists() and (dest.is_symlink() or dest.is_dir()):
        raise OSError(f"cannot restore over non-file destination: {dest}")
    data = backup.read_bytes()
    token = secrets.token_hex(6)
    tmp = dest.with_name(f".tmp-restore-{dest.name}-{token}")
    try:
        if tmp.exists() or tmp.is_symlink():
            if tmp.is_dir() and not tmp.is_symlink():
                raise OSError(f"restore temp path is a directory: {tmp}")
            tmp.unlink()
        tmp.write_bytes(data)
        if tmp.stat().st_size != len(data):
            raise OSError(f"incomplete restore payload for {dest.name}")
        os.replace(tmp, dest)
        if dest.stat().st_size != len(data):
            raise OSError(f"restore size mismatch for {dest.name}")
    finally:
        if tmp.exists() or tmp.is_symlink():
            try:
                tmp.unlink()
            except OSError:
                pass


def _merge_bundle_dir(staging: Path, target: Path) -> None:
    """Install staging artifacts into ``target`` without wiping recovery files.

    Bounded flat-file transaction for generated share/manifest/input files:
    validate staging, complete every backup before any install, commit only
    successful installs, and on failure restore only those installs from
    complete backups. Existing ``restored-*``, ``cloud-*``, and other
    user-authored files are never touched.

    A failed or partial backup never writes back into an untouched target.
    If rollback itself fails, complete backups are retained and the error
    names their path so operators can recover manually.
    """
    target.mkdir(parents=True, exist_ok=True)
    staging_items = _validate_staging_flat_files(staging)
    backup_root = target.parent / f".merge-backup-{target.name}-{secrets.token_hex(6)}"
    phase = "validate"
    complete_backups: dict[str, Path] = {}
    # (name, existed_before_install) for successfully committed installs only.
    installed: list[tuple[str, bool]] = []

    try:
        phase = "backup"
        backup_root.mkdir(parents=True, exist_ok=False)
        for item in staging_items:
            dest = target / item.name
            if dest.is_symlink() or dest.is_dir():
                raise ShareError(f"refusing to replace non-file target: {item.name}")
            if dest.is_file():
                backup_path = backup_root / item.name
                _write_complete_file(backup_path, dest.read_bytes())
                complete_backups[item.name] = backup_path

        phase = "commit"
        for item in staging_items:
            dest = target / item.name
            existed = dest.is_file()
            _install_flat_file(item, dest)
            installed.append((item.name, existed))

        phase = "cleanup"
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(backup_root, ignore_errors=True)
    except Exception as exc:
        if phase in {"validate", "backup"}:
            # No target installs occurred. Drop incomplete backup material only.
            if backup_root.exists():
                shutil.rmtree(backup_root, ignore_errors=True)
            raise

        if phase == "commit":
            rollback_errors: list[str] = []
            for name, existed in reversed(installed):
                dest = target / name
                if not existed:
                    try:
                        if dest.is_file() or dest.is_symlink():
                            dest.unlink()
                    except OSError as rollback_exc:
                        rollback_errors.append(f"{name}: remove created file failed: {rollback_exc}")
                    continue
                backup_path = complete_backups.get(name)
                if backup_path is None or not backup_path.is_file():
                    rollback_errors.append(f"{name}: complete backup missing")
                    continue
                try:
                    _restore_flat_file(backup_path, dest)
                except OSError as rollback_exc:
                    rollback_errors.append(f"{name}: restore failed: {rollback_exc}")

            if rollback_errors:
                # Keep complete backups; never delete the only recovery copy.
                detail = "; ".join(rollback_errors)
                raise ShareError(
                    "bundle merge install failed and rollback was incomplete; "
                    f"complete backups retained at {backup_root} ({detail})"
                ) from exc

            # Full rollback succeeded — safe to drop known temps/backups.
            if backup_root.exists():
                shutil.rmtree(backup_root, ignore_errors=True)
            raise

        raise


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
        workbench_adapter: WorkbenchAdapter | None = None,
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
        self.workbench_adapter = workbench_adapter
        # The passphrase (not the derived key) is kept, because the wrapped
        # share functions re-load and re-verify the key file per operation.
        self.passphrase: str | None = None
        self.key_id: str | None = None
        self.lock = threading.Lock()
        self.lookup_lock = threading.Lock()

    @property
    def unlocked(self) -> bool:
        return self.passphrase is not None

    @property
    def workbench_dir(self) -> Path | None:
        adapter = self.workbench_adapter
        root = getattr(adapter, "workbench_dir", None)
        return Path(root) if root is not None else None


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

    @staticmethod
    def _valid_workbench_id(value: str) -> bool:
        return bool(value) and ".." not in value and bool(
            _WORKBENCH_ID_RE.fullmatch(value)
        )

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
        path = urlsplit(self.path).path
        if path != "/" and not path.startswith("/api/"):
            self._drain_request_body()
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._drain_request_body()
            self._send_json(403, {"error": "forbidden"})
            return
        if path.startswith("/api/"):
            if not path.startswith(_WORKBENCH_API_PREFIX):
                self._drain_request_body()
                self._send_json(404, {"error": "not found"})
                return
            try:
                self._handle_workbench_get(path)
            except WorkbenchUnavailable as exc:
                self._send_json(
                    501,
                    {
                        "error": str(exc),
                        "capability": exc.capability,
                        "available": False,
                    },
                )
            except WorkbenchError as exc:
                self._send_json(400, {"error": str(exc), "available": False})
            except ShareError as exc:
                self._send_json(400, {"error": str(exc)})
            except OSError as exc:
                self._send_json(500, {"error": f"cannot read export: {exc}"})
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
            "/api/workbench/import": self._handle_workbench_import,
            "/api/workbench/task": self._handle_workbench_start,
            "/api/workbench/cancel": self._handle_workbench_cancel,
            "/api/workbench/results": self._handle_workbench_results,
            "/api/workbench/explanation": self._handle_workbench_explanation,
            "/api/workbench/review": self._handle_workbench_review,
            "/api/workbench/export": self._handle_workbench_export,
            "/api/workbench/diagnostics": self._handle_workbench_diagnostics,
            "/api/workbench/diff": self._handle_workbench_diff,
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
        except WorkbenchUnavailable as exc:
            self._send_json(
                501,
                {
                    "error": str(exc),
                    "capability": exc.capability,
                    "available": False,
                },
            )
            return
        except WorkbenchError as exc:
            self._send_json(400, {"error": str(exc), "available": False})
            return
        except Exception as exc:  # surfaced to the page without a stack trace
            self._send_json(500, {"error": f"internal error: {exc}"})
            return
        self._send_json(200, result)

    # -- workbench api handlers -------------------------------------------

    def _handle_workbench_get(self, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        state = self.ui_state
        if len(parts) == 4 and parts[:3] == ["api", "workbench", "task"]:
            task_id = parts[3]
            if not self._valid_workbench_id(task_id):
                raise WorkbenchError("task_id is invalid")
            with state.lock:
                result = state.workbench_adapter.task_status(task_id)
            self._send_json(200, self._public_workbench_task(result))
            return
        if len(parts) == 5 and parts[:3] == ["api", "workbench", "task"]:
            task_id = parts[3]
            if parts[4] not in {"diagnostics", "summary"} or not self._valid_workbench_id(task_id):
                raise WorkbenchError("task diagnostics path is invalid")
            with state.lock:
                if parts[4] == "summary":
                    result = state.workbench_adapter.summary(task_id)
                    result = self._public_workbench_summary(result)
                else:
                    result = state.workbench_adapter.diagnostics(task_id)
                    result = self._public_workbench_diagnostics(result)
            self._send_json(200, result)
            return
        if len(parts) == 5 and parts[:3] == ["api", "workbench", "export"]:
            export_id = parts[3]
            if parts[4] != "download" or not self._valid_workbench_id(export_id):
                raise WorkbenchError("export_id is invalid")
            with state.lock:
                file_path = state.workbench_adapter.export_file(export_id)
            self._send_controlled_file(file_path)
            return
        self._drain_request_body()
        self._send_json(404, {"error": "unknown workbench endpoint"})

    @staticmethod
    def _optional_providers(body: dict) -> list[str] | None:
        value = body.get("providers")
        if value is None:
            return None
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise WorkbenchError("providers must be a list of non-empty strings")
        return value

    @staticmethod
    def _filters(body: dict) -> tuple[list[str] | None, str | None, bool | None]:
        dispositions = body.get("dispositions")
        if dispositions is not None:
            if not isinstance(dispositions, list) or not all(
                isinstance(item, str) and item for item in dispositions
            ):
                raise WorkbenchError("dispositions must be a list of non-empty strings")
        query = body.get("query")
        if query is not None and (not isinstance(query, str) or len(query) > 512):
            raise WorkbenchError("query must be a string of at most 512 characters")
        provider_issues = body.get("provider_issues")
        if provider_issues is not None and not isinstance(provider_issues, bool):
            raise WorkbenchError("provider_issues must be a boolean")
        return dispositions, query, provider_issues

    @staticmethod
    def _valid_id(value: Any, field: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or ".." in value
            or not _WORKBENCH_ID_RE.fullmatch(value)
        ):
            raise WorkbenchError(f"{field} is required")
        return value

    def _handle_workbench_import(self, body: dict) -> dict:
        adapter = self.ui_state.workbench_adapter
        return adapter.stage_input(body.get("filename"), body.get("content"))

    def _handle_workbench_start(self, body: dict) -> dict:
        adapter = self.ui_state.workbench_adapter
        import_id = self._valid_id(body.get("import_id"), "import_id")
        options = body.get("options")
        if options is not None and not isinstance(options, dict):
            raise WorkbenchError("options must be an object")
        return self._public_workbench_task(adapter.start_task(
            import_id,
            providers=self._optional_providers(body),
            options=options,
        ))

    @staticmethod
    def _public_workbench_task(result: dict) -> dict:
        """Keep local filesystem paths out of browser-visible task JSON."""
        if not isinstance(result, dict):
            return result
        public = dict(result)
        public.pop("result_path", None)
        public.pop("diagnostics_path", None)
        return public

    @staticmethod
    def _public_workbench_diagnostics(result: dict) -> dict:
        """Keep local input/output paths out of browser-visible diagnostics."""
        if not isinstance(result, dict):
            return result
        public = dict(result)
        for field in ("input_path", "result_path", "diagnostics_path"):
            public.pop(field, None)
        return public

    @classmethod
    def _public_workbench_summary(cls, result: Any, key: str | None = None) -> Any:
        """Recursively remove paths and redact sensitive summary fields."""
        if key and _SENSITIVE_SUMMARY_KEY_RE.search(key):
            return "[redacted]"
        if isinstance(result, dict):
            return {
                child_key: cls._public_workbench_summary(value, child_key)
                for child_key, value in result.items()
                if child_key not in {"path", "input_path", "result_path", "diagnostics_path"}
                and not child_key.endswith("_path")
            }
        if isinstance(result, list):
            return [cls._public_workbench_summary(value) for value in result]
        return result

    def _handle_workbench_cancel(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        return self.ui_state.workbench_adapter.cancel_task(task_id)

    def _handle_workbench_results(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        dispositions, query, provider_issues = self._filters(body)
        offset = body.get("offset", 0)
        limit = body.get("limit", 100)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise WorkbenchError("offset must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise WorkbenchError("limit must be an integer between 1 and 500")
        kwargs = {
            "dispositions": dispositions,
            "query": query,
            "offset": offset,
            "limit": limit,
        }
        if provider_issues is not None:
            kwargs["provider_issues"] = provider_issues
        return self.ui_state.workbench_adapter.results(task_id, **kwargs)

    def _handle_workbench_explanation(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        result_id = self._valid_id(body.get("result_id"), "result_id")
        return self.ui_state.workbench_adapter.explanation(task_id, result_id)

    def _handle_workbench_review(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        result_id = self._valid_id(body.get("result_id"), "result_id")
        decision = body.get("decision")
        if not isinstance(decision, str) or not decision.strip():
            raise WorkbenchError("decision is required")
        reason = body.get("reason", "")
        reviewer = body.get("reviewer", "")
        if not isinstance(reason, str) or not isinstance(reviewer, str):
            raise WorkbenchError("reason and reviewer must be strings")
        return self.ui_state.workbench_adapter.submit_review(
            task_id,
            result_id,
            decision=decision.strip(),
            reason=reason,
            reviewer=reviewer,
        )

    def _handle_workbench_export(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        dispositions, query, provider_issues = self._filters(body)
        export_format = body.get("format", "jsonl")
        if export_format in {"diagnostics", "diff", "bundle"}:
            baseline_task_id = body.get("baseline_task_id")
            if export_format in {"diff", "bundle"}:
                baseline_task_id = self._valid_id(baseline_task_id, "baseline_task_id")
                if baseline_task_id == task_id:
                    raise WorkbenchError("task_id and baseline_task_id must differ")
            kwargs = {
                "artifact_format": export_format,
                "dispositions": dispositions,
                "query": query,
                "baseline_task_id": baseline_task_id,
            }
            if provider_issues is not None:
                kwargs["provider_issues"] = provider_issues
            return self.ui_state.workbench_adapter.export_artifact(task_id, **kwargs)
        if export_format not in {"jsonl", "csv", "xlsx"}:
            raise WorkbenchError("format must be jsonl, csv, xlsx, diagnostics, diff, or bundle")
        kwargs = {
            "dispositions": dispositions,
            "query": query,
            "export_format": export_format,
        }
        if provider_issues is not None:
            kwargs["provider_issues"] = provider_issues
        return self.ui_state.workbench_adapter.export(task_id, **kwargs)

    def _handle_workbench_diagnostics(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        return self._public_workbench_diagnostics(
            self.ui_state.workbench_adapter.diagnostics(task_id)
        )

    def _handle_workbench_diff(self, body: dict) -> dict:
        task_id = self._valid_id(body.get("task_id"), "task_id")
        baseline_task_id = self._valid_id(
            body.get("baseline_task_id"), "baseline_task_id"
        )
        if task_id == baseline_task_id:
            raise WorkbenchError("task_id and baseline_task_id must differ")
        return self.ui_state.workbench_adapter.diff(task_id, baseline_task_id)

    def _send_controlled_file(self, path: Path) -> None:
        state = self.ui_state
        root = state.workbench_dir
        if root is None:
            raise WorkbenchUnavailable("export.download")
        try:
            resolved = path.resolve()
            root_resolved = root.resolve()
            resolved.relative_to(root_resolved)
        except (OSError, ValueError) as exc:
            raise WorkbenchError("export file is outside the workbench directory") from exc
        if not resolved.is_file():
            self._send_json(404, {"error": "export file not found"})
            return
        content_type = "application/octet-stream"
        if resolved.suffix.lower() == ".jsonl":
            content_type = "application/x-ndjson; charset=utf-8"
        elif resolved.suffix.lower() == ".csv":
            content_type = "text/csv; charset=utf-8"
        elif resolved.suffix.lower() == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        data = resolved.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{resolved.name}"',
        )
        self.end_headers()
        self.wfile.write(data)

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
            "bundles": _list_bundles(state.bundles_dir, limit=state.max_bundles),
            "bundle_history_limit": state.max_bundles,
            "bundle_total": _count_bundles(state.bundles_dir),
            "workbench": {
                "configured": state.workbench_adapter is not None,
                "backend_available": type(state.workbench_adapter)
                is not LocalWorkbenchAdapter,
            },
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
                # Same content shared again: refresh generated artifacts while
                # preserving restored/cloud recovery files already on disk.
                _merge_bundle_dir(staging, target)
            else:
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
    workbench_adapter: WorkbenchAdapter | None = None,
    workbench_dir: str | Path | None = None,
) -> tuple[ThreadingHTTPServer, str]:
    """Create the loopback UI server and return it with its tokenized URL."""
    resolved_key = Path(key_path).expanduser()
    resolved_bundles = Path(bundles_dir).expanduser()
    resolved_workbench = (
        Path(workbench_dir).expanduser()
        if workbench_dir is not None
        else resolved_bundles.parent / ".workbench"
    )
    resolved_key.parent.mkdir(parents=True, exist_ok=True)
    resolved_bundles.mkdir(parents=True, exist_ok=True)
    resolved_workbench.mkdir(parents=True, exist_ok=True)
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
        workbench_adapter=(
            workbench_adapter
            if workbench_adapter is not None
            else OfflineWorkbenchAdapter(resolved_workbench)
        ),
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


def _positive_history_limit(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("history limit must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("history limit must be a positive integer")
    return parsed


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
        "--history-limit",
        type=_positive_history_limit,
        default=MAX_BUNDLES,
        help=(
            "recent bundle history display limit "
            f"(default: {MAX_BUNDLES}; older bundles remain on disk for restore)"
        ),
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
        max_bundles=args.history_limit,
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
