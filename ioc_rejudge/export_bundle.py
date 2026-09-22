"""One-call, multi-format result export with conflict preflight.

This module composes the existing export functions.  It intentionally does not
change their field contract or redaction behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Mapping

from ioc_rejudge.export import export_csv, export_excel, export_jsonl
from ioc_rejudge.files import assert_path_writable, atomic_write_bytes, resolve_path


class ExportConflictError(ValueError):
    """Raised before writing when export destinations collide or are protected."""


@dataclass
class ExportBundleResult:
    outputs: dict[str, Path]


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _default_filename(base_name: str, extension: str) -> str:
    if not base_name or base_name in {".", ".."}:
        raise ExportConflictError("base_name must be a non-empty file name")
    candidate = Path(base_name)
    if candidate.is_absolute() or candidate.parent != Path("."):
        raise ExportConflictError("base_name must be a file name, not a path")
    if candidate.name != base_name:
        raise ExportConflictError("base_name must be a simple file name")
    return f"{base_name}{extension}"


def _resolve_destinations(
    *,
    output_dir: str | os.PathLike[str] | None,
    base_name: str,
    jsonl_path: str | os.PathLike[str] | None,
    csv_path: str | os.PathLike[str] | None,
    xlsx_path: str | os.PathLike[str] | None,
    diagnostics_path: str | os.PathLike[str] | None,
    diff_path: str | os.PathLike[str] | None,
    write_jsonl: bool,
    write_csv: bool,
    write_xlsx: bool,
    diagnostics: object,
    diff: object,
) -> dict[str, Path]:
    if output_dir is None:
        explicit = [path for path in (jsonl_path, csv_path, xlsx_path, diagnostics_path, diff_path) if path is not None]
        if not explicit:
            raise ExportConflictError("output_dir is required unless all paths are explicit")
    else:
        output_dir = Path(output_dir)
    requested: dict[str, Path] = {}

    def add(key: str, explicit_path, extension: str, enabled: bool):
        if not enabled:
            return
        if explicit_path is None:
            if output_dir is None:
                raise ExportConflictError(f"{key}_path is required when output_dir is omitted")
            explicit_path = output_dir / _default_filename(base_name, extension)
        requested[key] = Path(explicit_path)

    add("jsonl", jsonl_path, ".jsonl", write_jsonl)
    add("csv", csv_path, ".csv", write_csv)
    add("xlsx", xlsx_path, ".xlsx", write_xlsx)
    add("diagnostics", diagnostics_path, ".diagnostics.json", diagnostics is not None)
    add("diff", diff_path, ".diff.json", diff is not None)

    if diagnostics is not None and "diagnostics" not in requested:
        raise ExportConflictError("diagnostics_path is required when diagnostics is supplied")
    if diff is not None and "diff" not in requested:
        raise ExportConflictError("diff_path is required when diff is supplied")
    if not requested:
        raise ExportConflictError("at least one export destination must be selected")

    resolved: dict[str, Path] = {}
    for key, path in requested.items():
        resolved_path = resolve_path(path)
        if resolved_path in resolved.values():
            other = next(original for original, value in resolved.items() if value == resolved_path)
            raise ExportConflictError(f"export destination collision: {key} and {other} resolve to {resolved_path}")
        resolved[key] = resolved_path
    return resolved


def _assert_not_protected(
    destinations: Mapping[str, Path],
    protected_paths: list[str | os.PathLike[str] | Path] | None,
) -> None:
    protected: list[tuple[str, Path]] = []
    for index, item in enumerate(protected_paths or []):
        try:
            resolved = resolve_path(item)
        except OSError as exc:
            raise ExportConflictError(f"cannot resolve protected path {item}: {exc}") from exc
        label = str(item)
        protected.append((label, resolved))

    for key, destination in destinations.items():
        for label, protected_path in protected:
            if destination == protected_path:
                raise ExportConflictError(
                    f"export destination {key} equals protected path {label}: {destination}"
                )
            if _is_within(destination, protected_path):
                raise ExportConflictError(
                    f"export destination {key} is inside protected path {label}: {destination}"
                )


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def export_bundle(
    verdicts: list[dict],
    *,
    output_dir: str | os.PathLike[str] | None = None,
    base_name: str = "results",
    jsonl: bool = True,
    csv: bool = True,
    xlsx: bool = True,
    jsonl_path: str | os.PathLike[str] | None = None,
    csv_path: str | os.PathLike[str] | None = None,
    xlsx_path: str | os.PathLike[str] | None = None,
    diagnostics: Mapping | object | None = None,
    diagnostics_path: str | os.PathLike[str] | None = None,
    diff: Mapping | object | None = None,
    diff_path: str | os.PathLike[str] | None = None,
    protected_paths: list[str | os.PathLike[str] | Path] | None = None,
) -> ExportBundleResult:
    """Write selected formats after preflighting all sibling atomic destinations.

    ``diagnostics`` and ``diff`` are optional JSON documents.  Every destination
    is checked for aliasing/collisions and sibling-temp writability before any
    final output is replaced.  Each file is still individually atomic because
    filesystem transactions across multiple files are not available.
    """
    destinations = _resolve_destinations(
        output_dir=output_dir,
        base_name=base_name,
        jsonl_path=jsonl_path,
        csv_path=csv_path,
        xlsx_path=xlsx_path,
        diagnostics_path=diagnostics_path,
        diff_path=diff_path,
        write_jsonl=jsonl,
        write_csv=csv,
        write_xlsx=xlsx,
        diagnostics=diagnostics,
        diff=diff,
    )
    _assert_not_protected(destinations, protected_paths)

    # Preflight before replacing any existing output. This catches locked
    # destinations, unwritable directories, and directories-as-files early.
    for destination in destinations.values():
        assert_path_writable(destination)

    if "jsonl" in destinations:
        export_jsonl(verdicts, str(destinations["jsonl"]))
    if "csv" in destinations:
        export_csv(verdicts, str(destinations["csv"]))
    if "xlsx" in destinations:
        export_excel(verdicts, str(destinations["xlsx"]), diagnostics if isinstance(diagnostics, Mapping) else None)
    if "diagnostics" in destinations:
        atomic_write_bytes(destinations["diagnostics"], _json_bytes(diagnostics))
    if "diff" in destinations:
        atomic_write_bytes(destinations["diff"], _json_bytes(diff))

    return ExportBundleResult(outputs=destinations)


__all__ = [
    "ExportBundleResult",
    "ExportConflictError",
    "export_bundle",
]
