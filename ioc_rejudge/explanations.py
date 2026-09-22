"""Deterministic, JSON-safe explanations for IOC rejudge verdicts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


_EVIDENCE_FIELDS = ("field", "detail", "level", "tags", "missing")
_EMPTY_VALUES = (None, "", [], {})


def _mapping(value: Any, argument_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TypeError(f"{argument_name} must be a mapping or None")
    return value


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _list_value(source: dict[str, Any] | None, name: str) -> list[Any]:
    if source is None:
        return []
    value = source.get(name)
    return list(value) if isinstance(value, list) else []


def _first_list(*values: list[Any]) -> list[Any]:
    for value in values:
        if value:
            return value
    return []


def _rule_path(source: dict[str, Any] | None) -> Any:
    if source is None:
        return None
    direct = source.get("rule_path")
    if direct is not None:
        return direct
    rule = source.get("rule")
    if isinstance(rule, dict):
        return rule.get("path")
    return None


def _normalise_evidence_entry(entry: Any) -> dict[str, Any]:
    """Copy only the supported evidence fields, in a stable order."""

    if not isinstance(entry, dict):
        return {}
    return {name: entry[name] for name in _EVIDENCE_FIELDS if name in entry}


def _has_meaningful_content(entry: dict[str, Any]) -> bool:
    return any(
        name in entry and entry[name] not in _EMPTY_VALUES
        for name in ("detail", "level", "tags")
    )


def _explicitly_missing(
    entry: dict[str, Any], missing_required_providers: list[Any]
) -> bool:
    """Return whether an otherwise empty entry is explicitly marked missing."""

    if entry.get("missing"):
        return True
    field = entry.get("field")
    return isinstance(field, str) and field in missing_required_providers


def _evidence_from_sources(
    verdict: dict[str, Any],
    dossier: dict[str, Any] | None,
    diagnostics: dict[str, Any] | None,
) -> tuple[list[Any], list[Any]]:
    sources = (diagnostics, dossier, verdict)

    for source in sources:
        if source is None:
            continue
        accepted = source.get("accepted_evidence")
        rejected = source.get("rejected_evidence")
        if isinstance(accepted, list) or isinstance(rejected, list):
            return (
                list(accepted) if isinstance(accepted, list) else [],
                list(rejected) if isinstance(rejected, list) else [],
            )

    for source in sources:
        if source is not None and isinstance(source.get("evidence"), list):
            return list(source["evidence"]), []

    return [], []


def _classify_evidence(
    raw_evidence: list[Any],
    raw_rejected_evidence: list[Any],
    missing_required_providers: list[Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for raw_entry in raw_rejected_evidence:
        rejected.append(_normalise_evidence_entry(raw_entry))

    for raw_entry in raw_evidence:
        entry = _normalise_evidence_entry(raw_entry)
        if (
            not _has_meaningful_content(entry)
            and _explicitly_missing(entry, missing_required_providers)
        ):
            rejected.append(entry)
        else:
            accepted.append(entry)

    return accepted, rejected


def _evidence_fingerprint(
    accepted_evidence: list[dict[str, Any]],
    rejected_evidence: list[dict[str, Any]],
) -> str:
    payload = json.dumps(
        {
            "accepted_evidence": accepted_evidence,
            "rejected_evidence": rejected_evidence,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def explain_verdict(
    verdict: dict[str, Any],
    dossier: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic JSON-compatible explanation from supplied fields.

    The function does not generate timestamps, change ``verdict["conclusion"]``,
    or synthesize facts that are absent from its inputs.  When an evidence
    placeholder has no substantive content, it is rejected only when the input
    explicitly identifies that field as missing (either with ``missing`` on the
    entry or by listing its ``field`` in ``missing_required_providers``).
    """

    verdict_mapping = _mapping(verdict, "verdict")
    if verdict_mapping is None:
        raise TypeError("verdict must be a mapping")
    dossier_mapping = _mapping(dossier, "dossier")
    diagnostics_mapping = _mapping(diagnostics, "diagnostics")

    missing_required_providers = _first_list(
        _list_value(diagnostics_mapping, "missing_required_providers"),
        _list_value(verdict_mapping, "missing_required_providers"),
        _list_value(dossier_mapping, "missing_required_providers"),
    )

    raw_accepted, raw_rejected = _evidence_from_sources(
        verdict_mapping, dossier_mapping, diagnostics_mapping
    )
    accepted_evidence, rejected_evidence = _classify_evidence(
        raw_accepted, raw_rejected, missing_required_providers
    )

    explanation = {
        "ioc": _first_present(
            verdict_mapping.get("ioc"),
            dossier_mapping.get("ioc") if dossier_mapping is not None else None,
            diagnostics_mapping.get("ioc")
            if diagnostics_mapping is not None
            else None,
        ),
        "conclusion": verdict_mapping.get("conclusion"),
        "reason": _first_present(
            diagnostics_mapping.get("reason")
            if diagnostics_mapping is not None
            else None,
            verdict_mapping.get("reason"),
            dossier_mapping.get("reason") if dossier_mapping is not None else None,
        ),
        "rule_path": _first_present(
            _rule_path(diagnostics_mapping),
            _rule_path(verdict_mapping),
            _rule_path(dossier_mapping),
        ),
        "accepted_evidence": accepted_evidence,
        "rejected_evidence": rejected_evidence,
        "freshness": _first_present(
            diagnostics_mapping.get("freshness")
            if diagnostics_mapping is not None
            else None,
            verdict_mapping.get("freshness"),
            dossier_mapping.get("freshness")
            if dossier_mapping is not None
            else None,
        ),
        "missing_required_providers": missing_required_providers,
        "next_actions": _first_list(
            _list_value(diagnostics_mapping, "next_actions"),
            _list_value(verdict_mapping, "next_actions"),
            _list_value(dossier_mapping, "next_actions"),
        ),
    }
    explanation["evidence_fingerprint"] = _evidence_fingerprint(
        accepted_evidence, rejected_evidence
    )
    return explanation
