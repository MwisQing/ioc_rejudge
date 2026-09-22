"""Path safety helpers and atomic file replacement writes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Callable


def resolve_path(path: str | os.PathLike[str] | Path) -> Path:
    """Return an absolute, normalized path suitable for equality checks."""
    resolved = Path(path).expanduser().resolve()
    if os.name == "nt":
        return Path(os.path.normcase(str(resolved)))
    return resolved


def paths_equal(
    left: str | os.PathLike[str] | Path | None,
    right: str | os.PathLike[str] | Path | None,
) -> bool:
    if left is None or right is None:
        return False
    try:
        return resolve_path(left) == resolve_path(right)
    except OSError:
        return False


def path_in_set(
    candidate: str | os.PathLike[str] | Path,
    paths: list[str | os.PathLike[str] | Path],
) -> str | os.PathLike[str] | Path | None:
    """Return the first path in *paths* that resolves equal to *candidate*."""
    try:
        target = resolve_path(candidate)
    except OSError:
        return None
    for item in paths:
        try:
            if resolve_path(item) == target:
                return item
        except OSError:
            continue
    return None


def ensure_parent_dir(path: str | os.PathLike[str] | Path) -> Path:
    destination = Path(path)
    parent = destination.parent
    if str(parent) in ("", "."):
        return destination
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(
            f"cannot create output directory {parent}: {exc}"
        ) from exc
    return destination


def _parent_dir(destination: Path) -> Path:
    parent = destination.parent
    if str(parent) in ("", "."):
        return Path.cwd()
    return parent


def _probe_sibling_temp(parent: Path, destination_name: str) -> None:
    """Ensure the parent directory can host a sibling temp for atomic replace."""
    try:
        fd, probe = tempfile.mkstemp(
            prefix=f".{destination_name}.",
            suffix=".writetest",
            dir=str(parent),
        )
    except OSError as exc:
        raise OSError(
            f"output directory is not writable for atomic replace: {parent}: {exc}"
        ) from exc
    try:
        os.close(fd)
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass


def assert_path_writable(path: str | os.PathLike[str] | Path) -> None:
    """Verify *path* can be replaced without truncating an existing file.

    Always probes sibling temporary creation so atomic replace is possible even
    when the destination already exists. Existing destinations are also opened
    non-truncating to detect locks; a lock leaves the original bytes untouched.
    """
    destination = ensure_parent_dir(path)
    parent = _parent_dir(destination)
    _probe_sibling_temp(parent, destination.name)

    if not destination.exists():
        return
    if destination.is_dir():
        raise OSError(f"output path is a directory: {destination}")
    try:
        fd = os.open(destination, os.O_RDWR)
    except OSError as exc:
        raise OSError(
            f"output path is not writable (is the file open in Excel or "
            f"another program?): {destination}: {exc}"
        ) from exc
    else:
        os.close(fd)


def _atomic_replace(temp_path: Path, destination: Path) -> None:
    """Replace *destination* with *temp_path* only via ``os.replace``.

    Never opens the destination for truncation after a failed replace. A locked
    destination raises an actionable error and leaves original bytes intact.
    """
    try:
        os.replace(temp_path, destination)
    except PermissionError as exc:
        raise OSError(
            f"cannot replace output (is the file open in Excel or another "
            f"program?): {destination}: {exc}"
        ) from exc


def atomic_write_via(
    path: str | os.PathLike[str] | Path,
    writer: Callable[[Path], None],
) -> None:
    """Write through *writer(temp_path)* then atomically replace the destination.

    This is the single atomic writing primitive. Callers stream into the sibling
    temp path; the destination is replaced only after the writer returns.
    """
    destination = ensure_parent_dir(path)
    parent = _parent_dir(destination)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(parent),
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        writer(temp_path)
        _atomic_replace(temp_path, destination)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: str | os.PathLike[str] | Path, data: bytes) -> None:
    """Write *data* via the shared atomic primitive."""

    def _write(temp_path: Path) -> None:
        with open(temp_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    atomic_write_via(path, _write)


def atomic_write_text(
    path: str | os.PathLike[str] | Path,
    text: str,
    *,
    encoding: str = "utf-8",
    newline: str | None = None,
) -> None:
    if newline is not None:
        text = text.replace("\n", newline)
    atomic_write_bytes(path, text.encode(encoding))
