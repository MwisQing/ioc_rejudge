"""CSV and XLSX table adapters for IOC inputs.

The adapter produces an ``InputBundle`` compatible with the normal pipeline and
keeps an explicit per-row report so callers can show source locations, defang
restoration, and duplicate decisions without changing the input contract.
"""

from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from openpyxl import load_workbook

from ioc_rejudge.inputs import InputBundle, InputKind, _target


DEFAULT_IOC_COLUMNS = (
    "ioc",
    "indicator",
    "ioc_value",
    "indicator_value",
    "value",
)
_DEFAULT_COLUMN_KEYS = {key.lower() for key in DEFAULT_IOC_COLUMNS}
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_DEFANG_REPLACEMENTS = {
    "[.]": ".",
    "(.)": ".",
    "{.}": ".",
    "[dot]": ".",
    "(dot)": ".",
    "{dot}": ".",
    "[:]": ":",
    "(:)": ":",
    "[::]": "::",
}


class TableAdapterError(ValueError):
    """Raised when a table cannot be interpreted as an IOC input."""


@dataclass
class AdapterRow:
    source_path: str
    source_line: int
    source_column: str | None
    raw_value: str
    candidate_value: str
    restored: bool = False
    formula_risk: bool = False
    duplicate: bool = False
    target: object | None = None


@dataclass
class TableAdapterReport:
    source_type: str
    selected_column: str | None
    total_rows: int
    parsed_count: int
    error_count: int
    duplicate_count: int
    defang_restored_count: int
    formula_risk_count: int
    rows: list[AdapterRow] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duplicates: list[dict] = field(default_factory=list)


@dataclass
class AdaptedInput:
    bundle: InputBundle
    report: TableAdapterReport


def _as_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def has_formula_risk(value: object) -> bool:
    """Identify Excel/CSV-style cell prefixes that should never be trusted."""
    if value is None:
        return False
    return str(value).startswith(_FORMULA_PREFIXES)


def formula_safe_preview(value: object) -> str:
    """Return a display-safe value by quoting dangerous spreadsheet prefixes.

    Adapter output is never intended to reopen as a spreadsheet, but this keeps
    a report viewer from treating an untrusted cell as a formula.
    """
    text = "" if value is None else str(value)
    if has_formula_risk(text):
        return "'" + text
    return text


def defang(value: str) -> str:
    """Return a display-safe defanged IOC string."""
    text = _as_text(value)
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("https://"):
        text = "hXXps://" + text[8:]
    elif lowered.startswith("http://"):
        text = "hXXp://" + text[7:]
    return text.replace(".", "[.]").replace(":", "[:]")


def restore_defang(value: str) -> str | None:
    """Restore a defanged IOC, returning ``None`` when nothing changed."""
    text = _as_text(value)
    if not text:
        return None
    restored = text
    for token, replacement in _DEFANG_REPLACEMENTS.items():
        restored = restored.replace(token, replacement)
    # Upper-case dot labels are common in incident reports.
    restored = restored.replace("[DOT]", ".").replace("(DOT)", ".").replace("{DOT}", ".")
    lowered = lowered_text = restored.lower()
    if lowered.startswith("hxxps://"):
        restored = "https://" + restored[8:]
    elif lowered.startswith("hxxp://"):
        restored = "http://" + restored[7:]
    return restored if restored != text else None


def _selected_column(
    fieldnames: Iterable[str],
    column_map: Mapping[str, str] | None,
) -> str | None:
    if column_map:
        for source, canonical in column_map.items():
            if canonical.lower() in _DEFAULT_COLUMN_KEYS and source in fieldnames:
                return source
        return None
    for name in fieldnames:
        if _as_text(name).lower() in _DEFAULT_COLUMN_KEYS:
            return name
    return None


def _normalize_column_map(column_map: Mapping[str, str] | None) -> dict[str, str]:
    if column_map is None:
        return {}
    if not isinstance(column_map, Mapping):
        raise TableAdapterError("column_map must be a mapping of source column to IOC")
    return {str(source): str(canonical) for source, canonical in column_map.items()}


def _make_report(
    *,
    source_type: str,
    source_path: str,
    selected_column: str | None,
    values: list[tuple[int, str | None, str]],
) -> tuple[TableAdapterReport, InputBundle]:
    report = TableAdapterReport(
        source_type=source_type,
        selected_column=selected_column,
        total_rows=len(values),
        parsed_count=0,
        error_count=0,
        duplicate_count=0,
        defang_restored_count=0,
        formula_risk_count=0,
    )
    targets = []
    seen: dict[str, dict] = {}
    bundle_errors: list[str] = []
    parse_error_count = 0

    for source_line, source_column, raw_value in values:
        candidate = _as_text(raw_value)
        restored = restore_defang(candidate)
        was_restored = restored is not None
        candidate = restored or candidate
        row = AdapterRow(
            source_path=source_path,
            source_line=source_line,
            source_column=source_column,
            raw_value=_as_text(raw_value),
            candidate_value=candidate,
            restored=was_restored,
            formula_risk=has_formula_risk(raw_value),
        )
        if was_restored:
            report.defang_restored_count += 1
        if row.formula_risk:
            report.formula_risk_count += 1

        target = None
        if row.formula_risk:
            error = (
                f"line {source_line}: formula-like cell rejected: "
                f"{formula_safe_preview(raw_value)!r}"
            )
            report.errors.append(error)
            bundle_errors.append(error)
            parse_error_count += 1
        elif not candidate:
            error = f"line {source_line}: empty IOC"
            report.errors.append(error)
            bundle_errors.append(error)
            parse_error_count += 1
        else:
            target = _target(candidate)
            if target is None:
                error = f"line {source_line}: invalid IOC {candidate!r}"
                report.errors.append(error)
                bundle_errors.append(error)
                parse_error_count += 1

        if target is not None:
            entry = seen.get(target.normalized)
            if entry is None:
                seen[target.normalized] = {
                    "normalized": target.normalized,
                    "value": target.original,
                    "count": 1,
                    "source_locations": [f"line {source_line}"],
                }
                report.parsed_count += 1
                targets.append(target)
            else:
                entry["count"] += 1
                entry["source_locations"].append(f"line {source_line}")
                row.duplicate = True
                report.duplicate_count += 1

        report.rows.append(row)

    report.error_count = len(report.errors)
    report.duplicates = [
        item for item in seen.values() if item["count"] > 1
    ]
    bundle = InputBundle(
        kind=InputKind.IOC_LIST,
        targets=targets,
        snapshots=[],
        errors=bundle_errors,
        parse_error_count=parse_error_count,
        nested_data_error_count=0,
    )
    return report, bundle


def adapt_csv(
    path: str | os.PathLike[str],
    *,
    column_map: Mapping[str, str] | None = None,
    encoding: str = "utf-8-sig",
    fallback_encoding: str = "gbk",
) -> AdaptedInput:
    """Adapt a CSV file while retaining the physical CSV row number."""
    source = Path(path)
    normalized_map = _normalize_column_map(column_map)
    text = None
    last_error: UnicodeDecodeError | None = None
    for candidate_encoding in (encoding, fallback_encoding):
        try:
            text = source.read_text(encoding=candidate_encoding)
            break
        except UnicodeDecodeError as exc:
            last_error = exc
    if text is None:
        raise TableAdapterError(f"cannot decode CSV input {source}: {last_error}")

    csv_stream = io.StringIO(text, newline="")
    reader = csv.reader(csv_stream)
    try:
        headers = next(reader)
    except StopIteration as exc:
        raise TableAdapterError(f"CSV input has no header: {source}")
    selected = _selected_column(headers, normalized_map)
    if selected is None:
        raise TableAdapterError(
            f"CSV input does not contain a mapped IOC column: {source}"
        )
    selected_index = headers.index(selected)
    values: list[tuple[int, str | None, str]] = []
    while True:
        physical_line = text.count("\n", 0, csv_stream.tell()) + 1
        try:
            row = next(reader)
        except StopIteration:
            break
        if not row or all(_as_text(value) == "" for value in row):
            continue
        raw_value = row[selected_index] if selected_index < len(row) else ""
        values.append((physical_line, selected, raw_value))
    report, bundle = _make_report(
        source_type="csv",
        source_path=str(source),
        selected_column=selected,
        values=values,
    )
    return AdaptedInput(bundle=bundle, report=report)


def adapt_xlsx(
    path: str | os.PathLike[str],
    *,
    column_map: Mapping[str, str] | None = None,
    sheet_name: str | None = None,
    header_row: int = 1,
) -> AdaptedInput:
    """Adapt the first worksheet (or named worksheet) in an XLSX workbook."""
    source = Path(path)
    if header_row < 1:
        raise TableAdapterError("header_row must be one-based")
    normalized_map = _normalize_column_map(column_map)
    try:
        workbook = load_workbook(
            source,
            read_only=True,
            data_only=True,
            keep_links=False,
        )
    except Exception as exc:
        raise TableAdapterError(f"cannot read XLSX input {source}: {exc}") from exc

    try:
        worksheet = workbook[sheet_name] if sheet_name else workbook.active
    except KeyError as exc:
        workbook.close()
        raise TableAdapterError(f"XLSX sheet not found: {sheet_name}") from exc

    try:
        rows = worksheet.iter_rows(min_row=header_row, values_only=True)
        try:
            headers = next(rows)
        except StopIteration as exc:
            raise TableAdapterError(f"XLSX input has no header: {source}") from exc
        fieldnames = [_as_text(value) for value in headers]
        selected = _selected_column(fieldnames, normalized_map)
        if selected is None:
            raise TableAdapterError(
                f"XLSX input does not contain a mapped IOC column: {source}"
            )
        values: list[tuple[int, str | None, str]] = []
        for physical_row, row in enumerate(rows, start=header_row + 1):
            if row is None or all(_as_text(value) == "" for value in row):
                continue
            column_index = fieldnames.index(selected)
            raw_value = row[column_index] if column_index < len(row) else ""
            values.append((physical_row, selected, _as_text(raw_value)))
    finally:
        workbook.close()
    report, bundle = _make_report(
        source_type="xlsx",
        source_path=str(source),
        selected_column=selected,
        values=values,
    )
    return AdaptedInput(bundle=bundle, report=report)


def adapt_table(
    path: str | os.PathLike[str],
    *,
    column_map: Mapping[str, str] | None = None,
    **kwargs,
) -> AdaptedInput:
    """Dispatch on the table file suffix."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return adapt_csv(path, column_map=column_map, **kwargs)
    if suffix in {".xlsx", ".xlsm"}:
        return adapt_xlsx(path, column_map=column_map, **kwargs)
    raise TableAdapterError(f"unsupported table input type: {suffix}")


__all__ = [
    "AdaptedInput",
    "AdapterRow",
    "DEFAULT_IOC_COLUMNS",
    "TableAdapterError",
    "TableAdapterReport",
    "adapt_csv",
    "adapt_table",
    "adapt_xlsx",
    "defang",
    "formula_safe_preview",
    "has_formula_risk",
    "restore_defang",
]
