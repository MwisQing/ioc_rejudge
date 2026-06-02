import json
import csv
import tempfile
import os
from openpyxl import load_workbook
from ioc_rejudge.export import (
    export_jsonl,
    export_csv,
    export_excel,
    _CONCLUSION_ORDER,
    _OUTPUT_FIELDS,
    _REVIEW_ORDER,
)
from ioc_rejudge.models import Conclusion


def _make_verdict(ioc="test.com"):
    return {
        "original_ioc": ioc,
        "ioc": ioc,
        "ioc_type": "domain",
        "ports": "",
        "record_count": 1,
        "conclusion": Conclusion.ALIVE_VALID.value,
        "malicious_nature": "direct",
        "activity_status": "recent",
        "confidence": "high",
        "review_suggestion": "skip",
        "candidate_label": "",
        "latest_material_activity_time": "2026-03-20 17:10:41",
        "latest_intel_update_time": "",
        "source_set": "sample-base",
        "family": "SilverFox",
        "tag": "",
        "evidence_a_detail": "context/comment [strong,direct]: test",
        "evidence_b_detail": "hash.time [normal]: test",
        "evidence_c_detail": "",
        "evidence_d_detail": "",
        "evidence_e_detail": "",
        "evidence_f_detail": "",
        "hit_evidence": "A=context; B=hash.time",
        "forbidden_labels": "none",
        "reason": "alive valid",
    }


def test_export_jsonl():
    verdicts = [_make_verdict("evil.com"), _make_verdict("bad.com")]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        export_jsonl(verdicts, f.name)
        f.flush()
        with open(f.name, encoding="utf-8") as rf:
            lines = rf.readlines()
        assert len(lines) == 2
        data = json.loads(lines[0])
        assert data["ioc"] == "evil.com"
        assert data["conclusion"] == Conclusion.ALIVE_VALID.value
    os.unlink(f.name)


def test_export_csv():
    verdicts = [_make_verdict("evil.com")]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        export_csv(verdicts, f.name)
        f.flush()
        with open(f.name, encoding="utf-8") as rf:
            reader = csv.DictReader(rf)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["ioc"] == "evil.com"
    os.unlink(f.name)


def test_export_fields_keep_legacy_order_before_new_fields():
    legacy_fields = [
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
    ]
    assert _OUTPUT_FIELDS[:len(legacy_fields)] == legacy_fields
    assert "original_ioc" in _OUTPUT_FIELDS[len(legacy_fields):]
    assert "evidence_a_detail" in _OUTPUT_FIELDS[len(legacy_fields):]


def test_export_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        export_jsonl([], f.name)
        f.flush()
        with open(f.name) as rf:
            assert rf.read() == ""
    os.unlink(f.name)


def test_export_excel():
    verdicts = [_make_verdict("evil.com"), _make_verdict("bad.com")]
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        export_excel(verdicts, f.name)
        wb = load_workbook(f.name)
        assert "summary" in wb.sheetnames
        assert "results" in wb.sheetnames
        ws = wb["results"]
        assert ws.max_row == 3  # header + 2 data rows
        assert ws.cell(1, 1).value == "ioc"
        assert {ws.cell(2, 1).value, ws.cell(3, 1).value} == {"evil.com", "bad.com"}
        assert ws.freeze_panes == "A2"
        assert ws.auto_filter.ref is not None
        wb.close()
    os.unlink(f.name)


def test_export_excel_empty():
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        export_excel([], f.name)
        wb = load_workbook(f.name)
        assert "summary" in wb.sheetnames
        assert "results" in wb.sheetnames
        ws = wb["results"]
        assert ws.max_row == 1  # header only
        assert ws.freeze_panes == "A2"
        assert ws.auto_filter.ref is None  # no filter when no data
        wb.close()
    os.unlink(f.name)


def test_export_excel_review_sort():
    v1 = _make_verdict("a.com")
    v1["review_suggestion"] = list(_REVIEW_ORDER)[2]
    v1["conclusion"] = list(_CONCLUSION_ORDER)[3]
    v2 = _make_verdict("b.com")
    v2["review_suggestion"] = list(_REVIEW_ORDER)[0]
    v2["conclusion"] = list(_CONCLUSION_ORDER)[0]
    v3 = _make_verdict("c.com")
    v3["review_suggestion"] = list(_REVIEW_ORDER)[1]
    v3["conclusion"] = list(_CONCLUSION_ORDER)[1]
    verdicts = [v1, v2, v3]
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        export_excel(verdicts, f.name)
        wb = load_workbook(f.name)
        ws = wb["results"]
        # Should be sorted: 蹇呯湅 -> 鎶芥 -> 涓嶇湅
        assert ws.cell(2, 1).value == "b.com"  # 蹇呯湅
        assert ws.cell(3, 1).value == "c.com"  # 鎶芥
        assert ws.cell(4, 1).value == "a.com"  # 涓嶇湅
        wb.close()
    os.unlink(f.name)


def test_export_excel_keeps_similar_indicators_adjacent():
    v1 = _make_verdict("evil.com")
    v1["review_suggestion"] = list(_REVIEW_ORDER)[1]
    v1["conclusion"] = list(_CONCLUSION_ORDER)[1]
    v2 = _make_verdict("a-other.com")
    v2["review_suggestion"] = list(_REVIEW_ORDER)[1]
    v2["conclusion"] = list(_CONCLUSION_ORDER)[1]
    v3 = _make_verdict("http://evil.com/path")
    v3["ioc"] = "evil.com/path"
    v3["ioc_type"] = "url"
    v3["review_suggestion"] = list(_REVIEW_ORDER)[1]
    v3["conclusion"] = list(_CONCLUSION_ORDER)[1]
    verdicts = [v1, v2, v3]
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        export_excel(verdicts, f.name)
        wb = load_workbook(f.name)
        ws = wb["results"]
        ioc_col = _OUTPUT_FIELDS.index("ioc") + 1
        exported = [ws.cell(row, ioc_col).value for row in range(2, 5)]
        assert exported.index("evil.com") + 1 == exported.index("evil.com/path")
        wb.close()
    os.unlink(f.name)


def test_export_excel_with_diagnostics():
    verdicts = [_make_verdict("evil.com")]
    diag = {"processed_count": 1, "parse_error_count": 0, "skipped_total": 0}
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        export_excel(verdicts, f.name, diagnostics=diag)
        wb = load_workbook(f.name)
        ws = wb["summary"]
        # Summary should have data
        assert ws.max_row >= 2
        wb.close()
    os.unlink(f.name)
