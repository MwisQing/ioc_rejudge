"""Persistent human review queue helpers."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

def build_queue(rows: Iterable[dict[str, Any]], *, pending_only: bool = True) -> list[dict[str, Any]]:
    items=[]
    for row in rows:
        if not isinstance(row, dict) or not row.get("ioc"): continue
        if pending_only and row.get("disposition") != "review" and row.get("conclusion") != "待复核": continue
        item=dict(row); item.setdefault("label", ""); item.setdefault("note", ""); item.setdefault("reviewer", ""); item.setdefault("reviewed_at", "")
        items.append(item)
    return sorted(items, key=lambda x: str(x.get("ioc", "")))

def append_label(path: str | Path, ioc: str, *, label: str, note: str = "", reviewer: str = "", reviewed_at: str | None = None) -> None:
    record={"_type":"label", "ioc":ioc, "label":label, "note":note, "reviewer":reviewer, "reviewed_at": reviewed_at or datetime.now(timezone.utc).isoformat()}
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f: f.write(json.dumps(record, ensure_ascii=False, sort_keys=True)+"\n")

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
        if obj.get("_type")=="label": rows.setdefault(ioc, {"ioc":ioc}).update({k:obj.get(k,"") for k in ("label","note","reviewer","reviewed_at")})
        else: rows[ioc]=dict(obj)
    return sorted(rows.values(), key=lambda x:x["ioc"])

def summarize(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    out={"total":0,"reviewed":0,"unreviewed":0,"by_conclusion":{},"by_disposition":{}}
    for row in rows:
        out["total"]+=1; reviewed=bool(row.get("label") or row.get("reviewed_at")); out["reviewed" if reviewed else "unreviewed"]+=1
        for field,key in (("conclusion","by_conclusion"),("disposition","by_disposition")):
            value=str(row.get(field) or "未知"); out[key][value]=out[key].get(value,0)+1
    return out
