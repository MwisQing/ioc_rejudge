"""Local single-page assistant for the share bundle workflow.

The server is a thin wrapper around :mod:`ioc_rejudge.share`
create/restore/scan.  It binds to loopback only, guards every request with a
per-process session token plus Host/Origin checks, and keeps the key
passphrase in process memory until the user locks it or the process exits.
It never runs the adjudication pipeline and never makes network requests of
its own; the human copies sanitized text to a cloud AI and pastes the answer
back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import shutil
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

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

# Bundle directories are named by the 20-hex-char bundle id; the fullmatch
# also keeps user-supplied ids from ever escaping the bundle directory.
_BUNDLE_ID_RE = re.compile(r"[0-9a-f]{20}")
_PAGE_FILE = Path(__file__).with_name("ui.html")


def _timestamp() -> str:
    """A sortable, collision-resistant suffix for audit file names."""
    return f"{int(time.time() * 1000):013d}-{secrets.token_hex(2)}"


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
    ) -> None:
        if max_bundles < 1:
            raise ValueError("max_bundles must be at least 1")
        self.key_path = key_path
        self.bundles_dir = bundles_dir
        self.token = token
        self.max_bundles = max_bundles
        # The passphrase (not the derived key) is kept, because the wrapped
        # share functions re-load and re-verify the key file per operation.
        self.passphrase: str | None = None
        self.key_id: str | None = None
        self.lock = threading.Lock()

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
            # One lock serializes key and bundle directory mutations so
            # concurrent page actions cannot interleave file operations.
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
        return {"key_id": key_id}

    def _handle_lock(self, body: dict) -> dict:
        state = self.ui_state
        state.passphrase = None
        state.key_id = None
        return {"unlocked": False}

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


def build_server(
    key_path: str | Path,
    bundles_dir: str | Path,
    *,
    port: int = DEFAULT_PORT,
    max_bundles: int = MAX_BUNDLES,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, str]:
    """Create the loopback UI server and return it with its tokenized URL."""
    resolved_key = Path(key_path).expanduser()
    resolved_bundles = Path(bundles_dir).expanduser()
    resolved_key.parent.mkdir(parents=True, exist_ok=True)
    resolved_bundles.mkdir(parents=True, exist_ok=True)
    session_token = token or secrets.token_urlsafe(24)

    class Handler(_UiRequestHandler):
        pass

    Handler.ui_state = UiState(resolved_key, resolved_bundles, session_token, max_bundles)
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
        "--no-browser",
        action="store_true",
        help="print the URL instead of opening the browser",
    )
    args = parser.parse_args(argv)
    server, url = build_server(
        Path(args.key_file).expanduser(),
        Path(args.bundle_dir).expanduser(),
        port=args.port,
    )
    print(f"ioc rejudge share ui: {url}")
    print(f"share key file: {Path(args.key_file).expanduser()}")
    print(f"bundle directory: {Path(args.bundle_dir).expanduser()}")
    print("press Ctrl+C to stop; the passphrase lives only in this process")
    serve(server, url=url, open_browser=not args.no_browser)
    return 0
