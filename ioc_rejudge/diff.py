"""Deterministic before/after verdict comparison."""

from __future__ import annotations


_BLACK = {"存活有效", "失活有效"}
_WHITE = {"误报"}


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


def compare_verdicts(before: list[dict], after: list[dict]) -> dict:
    """Compare verdicts by IOC and return stable transition groups.

    Transitions cover IOCs present in both inputs. Membership-only IOCs are
    reported separately because they do not have a before/after conclusion.
    """
    before_by_ioc, duplicate_before = _index_verdicts(before, "before")
    after_by_ioc, duplicate_after = _index_verdicts(after, "after")

    transitions: dict[str, int] = {}
    changed: list[dict] = []
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

    return {
        "transitions": transitions,
        "changed": changed,
        "only_before": sorted(before_by_ioc.keys() - after_by_ioc.keys()),
        "only_after": sorted(after_by_ioc.keys() - before_by_ioc.keys()),
        "duplicate_before": duplicate_before,
        "duplicate_after": duplicate_after,
        "black_to_white": black_to_white,
        "white_to_black": white_to_black,
        "to_gray": to_gray,
        "to_review": to_review,
    }
