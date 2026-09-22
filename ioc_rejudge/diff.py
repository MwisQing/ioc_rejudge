"""Deterministic before/after verdict comparison."""

from __future__ import annotations

import json
from typing import Any


_BLACK = {"存活有效", "失活有效"}
_WHITE = {"误报"}

# Operational fields compared when conclusion labels stay the same.
_OPERATIONAL_FIELDS = (
    "disposition",
    "scope_actions",
    "retained_urls",
    "review_suggestion",
    "missing_required_providers",
    "classification_unknown",
)


def _index_verdicts(
    rows: list[dict],
    label: str,
) -> tuple[dict[str, dict], dict[str, int]]:
    if not isinstance(rows, list):
        raise TypeError(f"{label} must be a list of verdict dictionaries")

    indexed: dict[str, dict] = {}
    counts: dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{label}[{index}] must be a verdict dictionary")
        for field in ("ioc", "conclusion"):
            if field not in row:
                raise ValueError(
                    f"{label}[{index}] missing required field '{field}'"
                )
        ioc = row["ioc"]
        if not isinstance(ioc, str) or not ioc.strip():
            raise ValueError(f"{label}[{index}] field 'ioc' must be a non-empty string")
        conclusion = row["conclusion"]
        if not isinstance(conclusion, str) or not conclusion.strip():
            raise ValueError(
                f"{label}[{index}] field 'conclusion' must be a non-empty string"
            )
        indexed[ioc] = row
        counts[ioc] = counts.get(ioc, 0) + 1
    duplicates = {
        ioc: count for ioc, count in sorted(counts.items()) if count > 1
    }
    return indexed, duplicates


def _raw_fingerprint(value: Any) -> str:
    """Stable, non-secret fingerprint for malformed raw values."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _as_str_list(value: Any) -> list[str] | None:
    """Normalize string-list operational fields; None marks malformed input."""
    if value is None:
        return []
    if isinstance(value, str):
        return None
    if not isinstance(value, (list, tuple)):
        return None
    items: list[str] = []
    for item in value:
        if isinstance(item, str):
            items.append(item)
        else:
            items.append(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str))
    # Order-only / duplicate-only noise collapses away.
    return sorted(set(items))


def _as_scope_actions(value: Any) -> list[dict] | None:
    """Canonicalize scope_actions; None marks malformed non-list input."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        return None
    canonical: list[dict] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, dict):
            payload = {str(k): item[k] for k in sorted(item.keys(), key=str)}
            key = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        else:
            key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
            payload = {"_raw": item}
        if key in seen:
            continue
        seen.add(key)
        canonical.append(payload if isinstance(item, dict) else {"_raw": item})
    canonical.sort(
        key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
    )
    return canonical


def _as_bool(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return bool(value)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _collection_slot(raw: Any, normalizer) -> dict[str, Any]:
    """Build a comparable/display slot for list-like operational fields.

    Valid lists use canonical equality (order/duplicates ignored). Non-list
    malformed values keep their raw form in both comparison and public output
    so operators can see what actually changed.
    """
    canonical = normalizer(raw)
    if canonical is None:
        return {
            "kind": "malformed",
            "canonical": None,
            "display": raw,
            "fingerprint": _raw_fingerprint(raw),
        }
    return {
        "kind": "ok",
        "canonical": canonical,
        "display": canonical,
        "fingerprint": "",
    }


def _operational_snapshot(row: dict) -> dict[str, Any]:
    """Extract comparable operational field values with safe legacy defaults."""
    retained = _collection_slot(row.get("retained_urls"), _as_str_list)
    providers = _collection_slot(row.get("missing_required_providers"), _as_str_list)
    scopes = _collection_slot(row.get("scope_actions"), _as_scope_actions)
    return {
        "disposition": _as_text(row.get("disposition")),
        "scope_actions": scopes,
        "retained_urls": retained,
        "review_suggestion": _as_text(row.get("review_suggestion")),
        "missing_required_providers": providers,
        "classification_unknown": _as_bool(row.get("classification_unknown")),
    }


def _slot_compare_key(slot: dict[str, Any]) -> tuple:
    if slot["kind"] == "malformed":
        return ("malformed", slot["fingerprint"])
    return ("ok", json.dumps(slot["canonical"], ensure_ascii=False, sort_keys=True, default=str))


def _operational_compare_key(snapshot: dict[str, Any]) -> tuple:
    return (
        snapshot["disposition"],
        _slot_compare_key(snapshot["scope_actions"]),
        _slot_compare_key(snapshot["retained_urls"]),
        snapshot["review_suggestion"],
        _slot_compare_key(snapshot["missing_required_providers"]),
        snapshot["classification_unknown"],
    )


def _public_operational_view(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "disposition": snapshot["disposition"],
        "scope_actions": snapshot["scope_actions"]["display"],
        "retained_urls": snapshot["retained_urls"]["display"],
        "review_suggestion": snapshot["review_suggestion"],
        "missing_required_providers": snapshot["missing_required_providers"]["display"],
        "classification_unknown": snapshot["classification_unknown"],
    }


def _diff_operational_fields(
    before_row: dict,
    after_row: dict,
) -> dict[str, Any] | None:
    before_snap = _operational_snapshot(before_row)
    after_snap = _operational_snapshot(after_row)
    if _operational_compare_key(before_snap) == _operational_compare_key(after_snap):
        return None

    before_view = _public_operational_view(before_snap)
    after_view = _public_operational_view(after_snap)

    changed_fields = [
        field
        for field in _OPERATIONAL_FIELDS
        if before_view.get(field) != after_view.get(field)
        or (
            field in {"scope_actions", "retained_urls", "missing_required_providers"}
            and _slot_compare_key(before_snap[field]) != _slot_compare_key(after_snap[field])
        )
    ]
    if not changed_fields:
        changed_fields = [
            field
            for field in _OPERATIONAL_FIELDS
            if before_view.get(field) != after_view.get(field)
        ]
    if not changed_fields:
        changed_fields = list(_OPERATIONAL_FIELDS)

    return {
        "ioc": before_row["ioc"],
        "fields": changed_fields,
        "before": before_view,
        "after": after_view,
    }


def compare_verdicts(before: list[dict], after: list[dict]) -> dict:
    """Compare verdicts by IOC and return stable transition groups.

    Transitions cover IOCs present in both inputs. Membership-only IOCs are
    reported separately because they do not have a before/after conclusion.

    ``changed`` remains conclusion-label transitions only. Operational field
    updates (disposition, scope_actions, retained_urls, review obligation) are
    reported in the additive ``operational_changes`` list so same-label action
    updates are visible without being misreported as label transitions.
    """
    before_by_ioc, duplicate_before = _index_verdicts(before, "before")
    after_by_ioc, duplicate_after = _index_verdicts(after, "after")

    transitions: dict[str, int] = {}
    changed: list[dict] = []
    operational_changes: list[dict] = []
    for ioc in sorted(before_by_ioc.keys() & after_by_ioc.keys()):
        old = before_by_ioc[ioc]["conclusion"]
        new = after_by_ioc[ioc]["conclusion"]
        key = f"{old}->{new}"
        transitions[key] = transitions.get(key, 0) + 1
        if old != new:
            changed.append({
                "ioc": ioc,
                "before": old,
                "after": new,
                "reason": after_by_ioc[ioc].get("reason", ""),
            })
        op = _diff_operational_fields(before_by_ioc[ioc], after_by_ioc[ioc])
        if op is not None:
            operational_changes.append(op)

    black_to_white = [
        item for item in changed
        if item["before"] in _BLACK and item["after"] in _WHITE
    ]
    white_to_black = [
        item for item in changed
        if item["before"] in _WHITE and item["after"] in _BLACK
    ]
    to_gray = [item for item in changed if item["after"] == "灰"]
    to_review = [item for item in changed if item["after"] == "待复核"]
    operations = len(before_by_ioc.keys() & after_by_ioc.keys())

    return {
        "operations": operations,
        "transitions": transitions,
        "changed": changed,
        "operational_changes": operational_changes,
        "only_before": sorted(before_by_ioc.keys() - after_by_ioc.keys()),
        "only_after": sorted(after_by_ioc.keys() - before_by_ioc.keys()),
        "duplicate_before": duplicate_before,
        "duplicate_after": duplicate_after,
        "black_to_white": black_to_white,
        "white_to_black": white_to_black,
        "to_gray": to_gray,
        "to_review": to_review,
    }
