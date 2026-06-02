"""Export verdicts to JSONL, CSV, and Excel formats."""
import json
import csv
from urllib.parse import urlparse
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font
from openpyxl.utils import get_column_letter


_OUTPUT_FIELDS = [
    "ioc",
    "conclusion",
    "malicious_nature",
    "activity_status",
    "confidence",
    "review_suggestion",
    "candidate_label",
    "hit_evidence",
    "forbidden_labels",
    "reason",
    "original_ioc",
    "ioc_type",
    "ports",
    "record_count",
    "latest_material_activity_time",
    "latest_intel_update_time",
    "source_set",
    "family",
    "tag",
    "evidence_a_detail",
    "evidence_b_detail",
    "evidence_c_detail",
    "evidence_d_detail",
    "evidence_e_detail",
    "evidence_f_detail",
]

_REVIEW_ORDER = {"必看": 0, "抽检": 1, "不看": 2}
_CONCLUSION_ORDER = {"待复核": 0, "存活有效": 1, "失活有效": 2, "误报": 3}

_FILL_REVIEW_REQUIRED = PatternFill(start_color="FFD7D7", end_color="FFD7D7", fill_type="solid")
_FILL_CONCLUSION = {
    "存活有效": PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid"),
    "失活有效": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
    "误报": PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid"),
    "待复核": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
}


def export_jsonl(verdicts: list[dict], filepath: str):
    with open(filepath, "w", encoding="utf-8") as f:
        for v in verdicts:
            row = {field: v.get(field, "") for field in _OUTPUT_FIELDS}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def export_csv(verdicts: list[dict], filepath: str):
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for v in verdicts:
            writer.writerow(v)


def _display_width(text: str) -> int:
    """Estimate display width: CJK chars count as 2, others as 1."""
    return sum(2 if "一" <= ch <= "鿿" or "　" <= ch <= "〿" or "＀" <= ch <= "￯" else 1 for ch in text)


def _sort_key(v: dict) -> tuple:
    """Sort key for review workflow: 必看 -> 抽检 -> 不看, then conclusion order."""
    review = _REVIEW_ORDER.get(v.get("review_suggestion", ""), 9)
    conclusion = _CONCLUSION_ORDER.get(v.get("conclusion", ""), 9)
    host_or_ip, port = _indicator_sort_parts(v)
    return (review, conclusion, host_or_ip, port, v.get("ioc_type", ""), v.get("ioc", ""))


def _indicator_sort_parts(v: dict) -> tuple[str, str]:
    ioc = str(v.get("ioc", "") or "")
    original_ioc = str(v.get("original_ioc", "") or "")
    raw = original_ioc or ioc

    if raw.lower().startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = str(parsed.port or v.get("ports", "") or "")
        return host, port

    candidate = ioc.split("/", 1)[0]
    if ":" in candidate:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            return host.rstrip(".").lower(), port
    return candidate.rstrip(".").lower(), str(v.get("ports", "") or "")


def _auto_width(ws, fields: list[str]):
    """Set column widths based on content, CJK-aware."""
    for col_idx, field in enumerate(fields, 1):
        max_len = _display_width(field)
        for row in ws.iter_rows(min_row=2, min_col=col_idx, max_col=col_idx):
            for cell in row:
                if cell.value:
                    max_len = max(max_len, _display_width(str(cell.value)))
        adjusted = min(max(max_len + 2, 8), 60)
        ws.column_dimensions[get_column_letter(col_idx)].width = adjusted


def _add_summary_sheet(wb: Workbook, verdicts: list[dict], diagnostics: dict | None):
    """Add summary sheet with counts and diagnostics."""
    ws = wb.create_sheet("summary", 0)
    ws.append(["IOC Rejudge Summary"])
    ws.merge_cells("A1:B1")
    ws["A1"].font = Font(bold=True, size=14)

    ws.append(["Total Processed IOCs", len(verdicts)])

    # Counts by conclusion
    conclusion_counts: dict[str, int] = {}
    for v in verdicts:
        c = v.get("conclusion", "")
        conclusion_counts[c] = conclusion_counts.get(c, 0) + 1

    ws.append(["", ""])
    ws.append(["Conclusion Counts", ""])
    ws[f"A{ws.max_row}"].font = Font(bold=True)
    for conclusion, count in sorted(conclusion_counts.items(), key=lambda x: -x[1]):
        ws.append([f"  {conclusion}", count])

    # Counts by review suggestion
    review_counts: dict[str, int] = {}
    for v in verdicts:
        r = v.get("review_suggestion", "")
        review_counts[r] = review_counts.get(r, 0) + 1

    ws.append(["", ""])
    ws.append(["Review Suggestion Counts", ""])
    ws[f"A{ws.max_row}"].font = Font(bold=True)
    for suggestion, count in sorted(review_counts.items(), key=lambda x: _REVIEW_ORDER.get(x[0], 9)):
        ws.append([f"  {suggestion}", count])

    # Diagnostics
    if diagnostics:
        ws.append(["", ""])
        ws.append(["Diagnostics", ""])
        ws[f"A{ws.max_row}"].font = Font(bold=True)
        diag_fields = [
            ("Parse Errors", "parse_error_count"),
            ("Missing Data", "missing_data_count"),
            ("Empty Data", "empty_data_count"),
            ("Non-list Data", "non_list_data_count"),
            ("No IOC", "no_ioc_count"),
            ("Total Skipped", "skipped_total"),
        ]
        for label, key in diag_fields:
            ws.append([f"  {label}", diagnostics.get(key, 0)])

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 15


def export_excel(
    verdicts: list[dict],
    filepath: str,
    diagnostics: dict | None = None,
):
    """Export Excel workbook with summary and results sheets.

    Args:
        verdicts: List of verdict dicts.
        filepath: Output .xlsx path.
        diagnostics: Optional diagnostics dict for summary sheet.
    """
    wb = Workbook()

    # Summary sheet
    _add_summary_sheet(wb, verdicts, diagnostics)

    # Results sheet
    ws = wb.create_sheet("results")
    ws.title = "results"

    # Sort by review workflow
    sorted_verdicts = sorted(verdicts, key=_sort_key)

    # Header row
    ws.append(_OUTPUT_FIELDS)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    # Data rows
    for v in sorted_verdicts:
        ws.append([v.get(field, "") for field in _OUTPUT_FIELDS])

    # Styling
    for row_idx in range(2, len(sorted_verdicts) + 2):
        review_val = ws.cell(row=row_idx, column=_OUTPUT_FIELDS.index("review_suggestion") + 1).value
        conclusion_val = ws.cell(row=row_idx, column=_OUTPUT_FIELDS.index("conclusion") + 1).value

        if review_val == "必看":
            for cell in ws[row_idx]:
                cell.fill = _FILL_REVIEW_REQUIRED
        elif conclusion_val in _FILL_CONCLUSION:
            for cell in ws[row_idx]:
                cell.fill = _FILL_CONCLUSION[conclusion_val]

    # Auto column width
    _auto_width(ws, _OUTPUT_FIELDS)

    # Freeze header row
    ws.freeze_panes = "A2"

    # Auto filter on header row
    if sorted_verdicts:
        last_col = get_column_letter(len(_OUTPUT_FIELDS))
        ws.auto_filter.ref = f"A1:{last_col}{len(sorted_verdicts) + 1}"

    wb.save(filepath)
