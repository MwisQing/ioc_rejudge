"""Persistent human review queue helpers."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def _needs_default_queue(row: dict[str, Any]) -> bool:
    """Return True when a verdict belongs in the default (pending) review queue.

    Inclusion covers explicit review disposition, 待复核 conclusions, and
    mandatory-review black rows (block + review_suggestion=必看). Ordinary
    block rows with 无需复核 stay out of the default queue.
    """
    if row.get("disposition") == "review":
        return True
    if row.get("conclusion") == "待复核":
        return True
    if row.get("review_suggestion") == "必看":
        return True
    return False


def build_queue(rows: Iterable[dict[str, Any]], *, pending_only: bool = True) -> list[dict[str, Any]]:
    items=[]
    for row in rows:
        if not isinstance(row, dict) or not row.get("ioc"): continue
        if pending_only and not _needs_default_queue(row): continue
        item=dict(row); item.setdefault("label", ""); item.setdefault("note", ""); item.setdefault("reviewer", ""); item.setdefault("reviewed_at", "")
        items.append(item)
    return sorted(items, key=lambda x: str(x.get("ioc", "")))

def append_label(path: str | Path, ioc: str, *, label: str, note: str = "", reviewer: str = "", reviewed_at: str | None = None) -> None:
    record={"_type":"label", "ioc":ioc, "label":label, "note":note, "reviewer":reviewer, "reviewed_at": reviewed_at or datetime.now(timezone.utc).isoformat()}
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f: f.write(json.dumps(record, ensure_ascii=False, sort_keys=True)+"\n")

def append_reopen(path: str | Path, ioc: str, *, note: str = "", reviewer: str = "") -> None:
    """Append a reopen overlay that clears prior analyst fields."""
    record = {
        "_type": "reopen",
        "ioc": ioc,
        "label": "",
        "note": note,
        "reviewer": reviewer,
        "reviewed_at": "",
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

def load_queue(path: str | Path, *, strict: bool = False) -> list[dict[str, Any]]:
    rows={}
    try: lines=Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError: return []
    for line in lines:
        try: obj=json.loads(line)
        except (json.JSONDecodeError, TypeError):
            if strict: raise
            continue
        if not isinstance(obj, dict) or not obj.get("ioc"): continue
        ioc=str(obj["ioc"])
        if obj.get("_type") in {"label", "reopen"}:
            rows.setdefault(ioc, {"ioc":ioc}).update({k:obj.get(k,"") for k in ("label","note","reviewer","reviewed_at")})
        else: rows[ioc]=dict(obj)
    return sorted(rows.values(), key=lambda x:x["ioc"])

def summarize(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    out={"total":0,"reviewed":0,"unreviewed":0,"by_conclusion":{},"by_disposition":{}}
    for row in rows:
        out["total"]+=1; reviewed=bool(row.get("label") or row.get("reviewed_at")); out["reviewed" if reviewed else "unreviewed"]+=1
        for field,key in (("conclusion","by_conclusion"),("disposition","by_disposition")):
            value=str(row.get(field) or "未知"); out[key][value]=out[key].get(value,0)+1
    return out


def _read_labels(path: str | Path) -> dict[str, dict[str, Any]]:
    """Read label overlay records without changing the queue format."""
    labels: dict[str, dict[str, Any]] = {}
    queue_path = Path(path)
    try:
        lines = queue_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return labels
    for line_number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or record.get("_type") not in {"label", "reopen"}:
            continue
        ioc = str(record.get("ioc", "")).strip()
        if not ioc:
            continue
        labels[ioc] = {
            "label": record.get("label", ""),
            "note": record.get("note", ""),
            "reviewer": record.get("reviewer", ""),
            "reviewed_at": record.get("reviewed_at", ""),
        }
    return labels


def _validate_identity(ioc: str) -> str:
    if not isinstance(ioc, str) or not ioc.strip():
        raise ValueError("ioc is required")
    return ioc.strip()


def _validate_text(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def list_review_queue(
    results_path: str | Path,
    queue_path: str | Path,
) -> list[dict[str, Any]]:
    """Build the pending queue from results and apply only analyst overlays.

    Result fields such as ``conclusion`` and ``disposition`` remain the system
    conclusion; analyst values are confined to ``label``, ``note``,
    ``reviewer``, and ``reviewed_at``.
    """
    rows = _read_jsonl_rows(results_path)
    queue = build_queue(rows, pending_only=True)
    labels = _read_labels(queue_path)
    for row in queue:
        label = labels.get(str(row.get("ioc", "")))
        if label is not None:
            row.update(label)
    return queue


def _read_jsonl_rows(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError as exc:
        raise ValueError(f"results input does not exist: {source}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read results input {source}: {exc}") from exc

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"results input line {line_number} is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError(f"results input line {line_number} must be an object")
        rows.append(value)
    return rows


def label_review_queue(
    path: str | Path,
    ioc: str,
    *,
    decision: str,
    note: str = "",
    reviewer: str = "",
) -> dict[str, Any]:
    """Append one analyst label without modifying any system verdict field."""
    safe_ioc = _validate_identity(ioc)
    if not isinstance(decision, str) or decision.strip() not in {
        "approved",
        "rejected",
        "pending",
    }:
        raise ValueError("decision must be approved, rejected, or pending")
    safe_note = _validate_text(note, "note")
    safe_reviewer = _validate_text(reviewer, "reviewer")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    append_label(
        path,
        safe_ioc,
        label=decision.strip(),
        note=safe_note,
        reviewer=safe_reviewer,
        reviewed_at=reviewed_at,
    )
    return {
        "ioc": safe_ioc,
        "label": decision.strip(),
        "note": safe_note,
        "reviewer": safe_reviewer,
        "reviewed_at": reviewed_at,
    }


def reopen_review_queue(
    path: str | Path,
    ioc: str,
    *,
    note: str = "",
    reviewer: str = "",
) -> dict[str, Any]:
    """Clear a prior analyst label; the system verdict is never rewritten."""
    safe_ioc = _validate_identity(ioc)
    safe_note = _validate_text(note, "note")
    safe_reviewer = _validate_text(reviewer, "reviewer")
    append_reopen(path, safe_ioc, note=safe_note, reviewer=safe_reviewer)
    return {
        "ioc": safe_ioc,
        "label": "",
        "note": safe_note,
        "reviewer": safe_reviewer,
        "reviewed_at": "",
    }
