"""Unified provider collection, routing, and adjudication pipeline."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Callable, Iterable

from ioc_rejudge.adjudicator import (
    adjudicate,
    _has_historical_or_phishing_url_evidence,
    _has_threat_residue,
)
from ioc_rejudge.config import Config
from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.evidence import (
    extract_evidence,
    has_authoritative_clue,
    is_malicious_sample,
)
from ioc_rejudge.inputs import InputBundle
from ioc_rejudge.models import Conclusion, Evidence, IocDossier, Verdict
from ioc_rejudge.normalize import merge_records, normalize_ioc
from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
    Route,
)
from ioc_rejudge.parser import parse_time
from ioc_rejudge.providers.base import Provider, ProviderContext, ProviderResult
from ioc_rejudge.routing import RouteDecision, select_route
from ioc_rejudge.result_cache import AdjudicationResultCache


DGA_PROVIDER_NAME = "k01_compromise"
REQUIRED_SAMPLE_PROVIDERS = ("ioc_info", "fdark")
_COMPLETE_STATUSES = {ProviderStatus.SUCCESS, ProviderStatus.NO_DATA}
_DISCOVERY_PROVIDER_NAMES = {DGA_PROVIDER_NAME, *REQUIRED_SAMPLE_PROVIDERS}
_LIFECYCLE_PROVIDER_NAMES = {"whois", "pdns", "icp"}


@dataclass
class ProviderDiagnostics:
    request: int = 0
    cache_hit: int = 0
    success: int = 0
    no_data: int = 0
    error: int = 0
    disabled: int = 0
    stale: int = 0
    retry: int = 0
    missing: int = 0
    duration_seconds: float = 0.0


@dataclass
class PipelineDiagnostics:
    input_errors: list[str] = field(default_factory=list)
    provider_errors: dict[str, list[str]] = field(default_factory=dict)
    providers: dict[str, ProviderDiagnostics] = field(default_factory=dict)
    routes: dict[str, str] = field(default_factory=dict)
    classification_unknown: list[str] = field(default_factory=list)
    missing_required_providers: dict[str, list[str]] = field(default_factory=dict)
    processing_errors: dict[str, str] = field(default_factory=dict)
    result_cache_hit: int = 0
    result_cache_miss: int = 0
    result_cache_errors: list[str] = field(default_factory=list)
    processed_count: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["provider_metrics"] = data.pop("providers")
        return data


@dataclass
class UnifiedPipelineResult:
    verdicts: list[dict] = field(default_factory=list)
    diagnostics: PipelineDiagnostics = field(default_factory=PipelineDiagnostics)
    observations: list[Observation] = field(default_factory=list)


class _PlannedProvider:
    """Restrict a live provider to targets selected by the request planner."""

    def __init__(self, provider: Provider, target_keys: set[str]) -> None:
        self._provider = provider
        self._target_keys = target_keys
        self.name = provider.name
        self.disabled_reason = getattr(provider, "disabled_reason", "")

    def supports(self, target: IocTarget) -> bool:
        return (
            target.normalized in self._target_keys
            and self._provider.supports(target)
        )

    def collect(
        self, targets: list[IocTarget], context: ProviderContext
    ) -> ProviderResult:
        return self._provider.collect(targets, context)


def _safe_provider_error(exc: Exception) -> str:
    message = str(exc).strip()
    return message or type(exc).__name__


def _provider_status_value(status: ProviderStatus | str) -> str:
    return status.value if isinstance(status, ProviderStatus) else str(status)


def _timed_collect(
    provider: Provider,
    supported: list[IocTarget],
    context: ProviderContext,
    name: str,
    progress: Callable[[str], None] | None,
) -> tuple[object, float, Exception | None]:
    start = time.perf_counter()
    value: object = None
    error: Exception | None = None
    try:
        value = provider.collect(supported, context)
    except Exception as exc:  # provider boundary: one failure must not abort the batch
        error = exc
    duration = time.perf_counter() - start
    if progress is not None:
        if error is None:
            message = (
                f"provider '{name}': completed in {duration:.1f}s "
                f"({len(supported)} target(s))"
            )
        else:
            message = f"provider '{name}': failed after {duration:.1f}s"
        try:
            progress(message)
        except Exception:  # progress reporting must never affect collection results
            pass
    return value, duration, error


def _collect_observations(
    targets: list[IocTarget],
    providers: Iterable[Provider],
    context: ProviderContext,
    diagnostics: PipelineDiagnostics,
    max_workers: int,
    progress: Callable[[str], None] | None = None,
) -> tuple[
    dict[str, list[Observation]],
    dict[str, dict[str, ProviderStatus]],
    dict[str, dict[str, Freshness]],
    list[Observation],
]:
    provider_list = list(providers)
    provider_names = [str(provider.name) for provider in provider_list]
    observations_by_ioc = {target.normalized: [] for target in targets}
    statuses_by_ioc = {
        target.normalized: {
            name: ProviderStatus.ERROR for name in provider_names
        }
        for target in targets
    }
    freshness_by_ioc = {target.normalized: {} for target in targets}
    all_observations: list[Observation] = []
    work: list[tuple[Provider, str, list[IocTarget], ProviderDiagnostics]] = []

    for provider in provider_list:
        name = str(provider.name)
        metric = diagnostics.providers.setdefault(name, ProviderDiagnostics())
        disabled_reason = str(getattr(provider, "disabled_reason", "") or "")
        if disabled_reason:
            diagnostics.provider_errors.setdefault(name, []).append(disabled_reason)
        supported: list[IocTarget] = []
        for target in targets:
            supports_failed = False
            try:
                is_supported = bool(provider.supports(target))
            except Exception as exc:  # provider boundary: one failure must not abort the batch
                is_supported = False
                supports_failed = True
                diagnostics.provider_errors.setdefault(name, []).append(
                    f"supports({target.normalized}): {_safe_provider_error(exc)}"
                )
                statuses_by_ioc[target.normalized][name] = ProviderStatus.ERROR
                metric.error += 1
            if is_supported:
                supported.append(target)
            elif not supports_failed:
                statuses_by_ioc[target.normalized][name] = ProviderStatus.DISABLED
                metric.disabled += 1

        metric.request += len(supported)
        if supported:
            work.append((provider, name, supported, metric))

    results: list[tuple[object, float, Exception | None]] = []
    if work:
        worker_count = min(len(work), max_workers)
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="ioc-provider",
        ) as executor:
            futures = [
                executor.submit(_timed_collect, provider, supported, context, name, progress)
                for provider, name, supported, _ in work
            ]
            results = [future.result() for future in futures]

    for (provider, name, supported, metric), (value, duration, error) in zip(work, results):
        metric.duration_seconds = duration
        if error is None and not isinstance(value, ProviderResult):
            error = TypeError("collect() did not return ProviderResult")
        if error is not None:
            message = _safe_provider_error(error)
            diagnostics.provider_errors.setdefault(name, []).append(message)
            for target in supported:
                statuses_by_ioc[target.normalized][name] = ProviderStatus.ERROR
                metric.error += 1
            continue
        result = value

        try:
            metric.cache_hit += max(0, int(result.cache_hits or 0))
        except (TypeError, ValueError):
            diagnostics.provider_errors.setdefault(name, []).append(
                "invalid cache_hits value"
            )
        if result.errors:
            diagnostics.provider_errors.setdefault(name, []).extend(
                str(error) for error in result.errors
            )

        supported_keys = {target.normalized for target in supported}
        for target in supported:
            raw_status = result.statuses.get(target.normalized)
            if isinstance(raw_status, ProviderStatus):
                status = raw_status
            else:
                status = ProviderStatus.ERROR
                metric.missing += 1
                diagnostics.provider_errors.setdefault(name, []).append(
                    f"missing status for {target.normalized}"
                )
            statuses_by_ioc[target.normalized][name] = status
            setattr(metric, status.value, getattr(metric, status.value) + 1)

            raw_freshness = result.freshnesses.get(target.normalized)
            if isinstance(raw_freshness, Freshness):
                freshness_by_ioc[target.normalized][name] = raw_freshness
            elif raw_freshness is not None:
                freshness_by_ioc[target.normalized][name] = Freshness.UNKNOWN
                diagnostics.provider_errors.setdefault(name, []).append(
                    f"invalid freshness for {target.normalized}"
                )

        stale_iocs = {
            target.normalized
            for target in supported
            if freshness_by_ioc[target.normalized].get(name) == Freshness.STALE
        }
        for observation in result.observations:
            if observation.ioc not in supported_keys:
                diagnostics.provider_errors.setdefault(name, []).append(
                    f"observation for unrequested IOC {observation.ioc}"
                )
                continue
            observations_by_ioc[observation.ioc].append(observation)
            all_observations.append(observation)
            if observation.freshness == Freshness.STALE:
                stale_iocs.add(observation.ioc)
                freshness_by_ioc[observation.ioc][name] = Freshness.STALE
        metric.stale += len(stale_iocs)

    return (
        observations_by_ioc,
        statuses_by_ioc,
        freshness_by_ioc,
        all_observations,
    )


def _coerce_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value in (None, ""):
        return None
    text = str(value).strip()
    parsed = parse_time(text)
    if parsed is not None:
        return parsed
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _observation_payload_record(observation: Observation) -> dict:
    payload = observation.payload
    record = payload.get("record") if isinstance(payload, dict) else None
    if isinstance(record, dict):
        return dict(record)
    return dict(payload) if isinstance(payload, dict) else {}


def _sample_entries(observations: list[Observation]) -> list[tuple[dict, datetime | None]]:
    entries: list[tuple[dict, datetime | None]] = []
    for observation in observations:
        if observation.status != ProviderStatus.SUCCESS:
            continue
        if observation.kind == "associated_sample":
            entries.append((dict(observation.payload), observation.observed_at))
        elif observation.kind == "ioc_info_record":
            record = _observation_payload_record(observation)
            hashes = record.get("hash", [])
            if isinstance(hashes, dict):
                hashes = [hashes]
            if isinstance(hashes, list):
                entries.extend(
                    (dict(entry), observation.observed_at)
                    for entry in hashes
                    if isinstance(entry, dict)
                )
    return entries


def _entry_is_malicious(entry: dict, config: Config) -> bool:
    explicit = entry.get("malicious")
    if isinstance(explicit, bool):
        return explicit
    return is_malicious_sample(entry, config)


def _entry_time(entry: dict, fallback: datetime | None) -> datetime | None:
    for key in ("observed_at", "time", "last_seen", "update_time"):
        parsed = _coerce_datetime(entry.get(key))
        if parsed is not None:
            return parsed
    return fallback


def _has_current_icp(
    observations: list[Observation],
    provider_statuses: dict[str, ProviderStatus] | None = None,
) -> bool:
    for observation in observations:
        if (
            observation.status != ProviderStatus.SUCCESS
            or observation.freshness == Freshness.STALE
            or (
                provider_statuses is not None
                and provider_statuses.get(observation.provider) != ProviderStatus.SUCCESS
            )
        ):
            continue
        payload = _observation_payload_record(observation)
        values = (
            payload.get("icp_website"),
            payload.get("icp"),
            payload.get("registration"),
        )
        if payload.get("current") is True:
            return True
        if any(isinstance(value, str) and value.strip() for value in values):
            return True
    return False


def _apply_current_icp_state(
    dossier: IocDossier,
    observations: list[Observation],
    provider_statuses: dict[str, ProviderStatus] | None = None,
) -> None:
    for observation in observations:
        if (
            observation.kind not in {"icp", "icp_record", "icp_registration"}
            or observation.status != ProviderStatus.SUCCESS
            or observation.freshness == Freshness.STALE
            or (
                provider_statuses is not None
                and provider_statuses.get(observation.provider) != ProviderStatus.SUCCESS
            )
        ):
            continue
        payload = observation.payload if isinstance(observation.payload, dict) else {}
        current = payload.get("current")
        if not isinstance(current, bool):
            continue
        if current is False:
            dossier.icp_website = ""
            dossier.current_icp_check_complete = True
            continue
        registration = payload.get("registration")
        if not isinstance(registration, str) or not registration.strip():
            continue
        dossier.icp_website = registration.strip()
        dossier.current_icp_check_complete = True


def _latest_observed_time(
    observations: list[Observation],
    kinds: set[str],
    payload_keys: tuple[str, ...],
    *,
    include_observation_time: bool = True,
) -> datetime | None:
    values: list[datetime] = []
    for observation in observations:
        if (
            observation.kind not in kinds
            or observation.status != ProviderStatus.SUCCESS
            or observation.freshness == Freshness.STALE
        ):
            continue
        if include_observation_time and observation.observed_at is not None:
            values.append(observation.observed_at)
        for key in payload_keys:
            value = _coerce_datetime(observation.payload.get(key))
            if value is not None:
                values.append(value)
    if not values:
        return None
    latest = values[0]
    for value in values[1:]:
        try:
            if value > latest:
                latest = value
        except TypeError:
            continue
    return latest


def _build_dga_facts(
    observations: list[Observation],
    statuses: dict[str, ProviderStatus],
    config: Config,
    freshnesses: dict[str, Freshness] | None = None,
) -> tuple[DgaFacts, list[str]]:
    completeness_freshness = freshnesses or {}
    missing = [
        name for name in REQUIRED_SAMPLE_PROVIDERS
        if (
            statuses.get(name) not in _COMPLETE_STATUSES
            or completeness_freshness.get(name) in {
                Freshness.STALE,
                Freshness.UNKNOWN,
            }
        )
    ]
    malicious_times: list[datetime] = []
    has_malicious = False
    for entry, fallback in _sample_entries(observations):
        if not _entry_is_malicious(entry, config):
            continue
        has_malicious = True
        observed_at = _entry_time(entry, fallback)
        if observed_at is not None:
            malicious_times.append(observed_at)

    whois_expires = _latest_observed_time(
        observations,
        {"whois", "whois_record"},
        ("expires_at", "expiresDate", "expiration_date"),
        include_observation_time=False,
    )
    pdns_last_seen = _latest_observed_time(
        observations,
        {"pdns", "pdns_activity"},
        ("time_last", "last_seen", "observed_at"),
    )
    facts = DgaFacts(
        sample_check_complete=not missing,
        has_malicious_sample=has_malicious,
        malicious_sample_times=malicious_times,
        has_current_icp=_has_current_icp(observations, statuses),
        whois_expires=whois_expires,
        pdns_last_seen=pdns_last_seen,
        provider_statuses={
            name: _provider_status_value(status)
            for name, status in statuses.items()
        },
    )
    return facts, missing


def _snapshot_records(bundle: InputBundle) -> dict[str, list[dict]]:
    records_by_ioc: dict[str, list[dict]] = {}
    for row in bundle.snapshots:
        if not isinstance(row, dict):
            continue
        try:
            normalized = normalize_ioc(str(row.get("ioc", "")))[0]
        except (TypeError, ValueError):
            continue
        records = row.get("data")
        if isinstance(records, list):
            records_by_ioc.setdefault(normalized, []).extend(
                dict(record) for record in records if isinstance(record, dict)
            )
    return records_by_ioc


def _route_records(
    snapshot_records: list[dict],
    observations: list[Observation],
) -> list[dict]:
    records = [dict(record) for record in snapshot_records]
    records.extend(
        _observation_payload_record(observation)
        for observation in observations
        if observation.status == ProviderStatus.SUCCESS
        and observation.kind == "ioc_info_record"
    )
    return records


def _build_standard_dossier(
    target: IocTarget,
    snapshot_records: list[dict],
    observations: list[Observation],
    provider_statuses: dict[str, ProviderStatus],
    config: Config,
) -> tuple[IocDossier, int]:
    records = [dict(record) for record in snapshot_records]
    enrichment: dict = {"key": target.normalized, "host": target.host}
    hashes: list[dict] = []
    dtree: list[dict] = []

    for observation in observations:
        if observation.status != ProviderStatus.SUCCESS:
            continue
        payload = _observation_payload_record(observation)
        if observation.kind == "ioc_info_record":
            payload.setdefault("key", target.normalized)
            payload.setdefault("host", target.host)
            records.append(payload)
        elif observation.kind == "associated_sample":
            hashes.append(payload)
        elif observation.kind in {"whois", "whois_record"} and observation.freshness != Freshness.STALE:
            enrichment["whois"] = {
                "createdDate": payload.get("created_at", payload.get("createdDate", "")),
                "updatedDate": payload.get("updated_at", payload.get("updatedDate", "")),
                "expiresDate": payload.get(
                    "expires_at",
                    payload.get("expiresDate", payload.get("expiration_date", "")),
                ),
            }
        elif observation.kind in {"pdns", "pdns_activity"} and observation.freshness != Freshness.STALE:
            dtree.append({
                "key": payload.get("rdata", ""),
                "last": payload.get("time_last", payload.get("last_seen", "")),
                "count": payload.get("count", 0),
                "level": payload.get("level", 0),
            })
    if hashes:
        enrichment["hash"] = hashes
    if dtree:
        enrichment["dtree"] = dtree
    if len(enrichment) > 2:
        records.append(enrichment)

    if records:
        for record in records:
            record.setdefault("key", target.normalized)
            record.setdefault("host", target.host)
        dossier = merge_records(records)
    else:
        dossier = IocDossier(
            ioc=target.normalized,
            ioc_type=target.ioc_type,
            ports=list(target.ports),
        )
    _apply_current_icp_state(dossier, observations, provider_statuses)
    return extract_evidence(dossier, config), len(records)


def _downgrade_unknown_classification(verdict: Verdict) -> Verdict:
    if verdict.disposition == "block":
        return verdict
    candidate = verdict.conclusion.value
    verdict.conclusion = Conclusion.PENDING_REVIEW
    verdict.malicious_nature = "分类状态未知"
    verdict.activity_status = "未知"
    verdict.confidence = "低"
    verdict.review_suggestion = "必看"
    verdict.candidate_label = candidate
    verdict.reason = (
        "DGA分类查询失败；原白/灰候选不能自动提交，已降级为待复核。"
    )
    verdict.disposition = "review"
    verdict.scope_actions = []
    return verdict


def _format_time(value: datetime | None) -> str:
    return value.isoformat(sep=" ") if value is not None else ""


def _format_evidence(evidence: list[Evidence]) -> str:
    return "; ".join(
        f"{item.field} [{item.strength.value}{',' if item.tags else ''}{','.join(item.tags)}]: {item.detail}"
        for item in evidence
    )


def _evidence_origins(observations: list[Observation]) -> list[dict]:
    return [
        {
            "provider": observation.provider,
            "kind": observation.kind,
            "status": observation.status.value,
            "fetched_at": _format_time(observation.fetched_at),
            "observed_at": _format_time(observation.observed_at),
            "raw_ref": observation.raw_ref,
        }
        for observation in observations
    ]


def _serialize_verdict(
    target: IocTarget,
    verdict: Verdict,
    statuses: dict[str, ProviderStatus],
    observations: list[Observation],
    *,
    dossier: IocDossier | None,
    record_count: int,
    classification_unknown: bool,
    missing_required_providers: list[str],
    config: Config,
) -> dict:
    if not verdict.scope_actions:
        verdict.scope_actions = [{
            "ioc": target.normalized,
            "scope": target.ioc_type,
            "action": verdict.disposition,
        }]
    provider_statuses = {
        name: _provider_status_value(status) for name, status in statuses.items()
    }
    verdict.provider_statuses = dict(provider_statuses)
    verdict.evidence_origins = _evidence_origins(observations)
    verdict.missing_required_providers = list(missing_required_providers)

    row = {
        "original_ioc": target.original,
        "ioc": target.normalized,
        "ioc_type": target.ioc_type,
        "ports": ",".join(target.ports),
        "record_count": record_count,
        "conclusion": verdict.conclusion.value,
        "malicious_nature": verdict.malicious_nature,
        "activity_status": verdict.activity_status,
        "confidence": verdict.confidence,
        "review_suggestion": verdict.review_suggestion,
        "candidate_label": verdict.candidate_label or "",
        "hit_evidence": verdict.hit_evidence,
        "forbidden_labels": verdict.forbidden_labels,
        "reason": verdict.reason,
        "route": verdict.route,
        "disposition": verdict.disposition,
        "scope_actions": list(verdict.scope_actions),
        "retained_urls": list(verdict.retained_urls),
        "provider_statuses": provider_statuses,
        "evidence_origins": list(verdict.evidence_origins),
        "missing_required_providers": list(missing_required_providers),
        "classification_unknown": classification_unknown,
    }
    if dossier is None:
        row.update({
            "latest_material_activity_time": "",
            "latest_intel_update_time": "",
            "source_set": "",
            "family": "",
            "tag": "",
            "evidence_a_detail": "",
            "evidence_b_detail": "",
            "evidence_c_detail": "",
            "evidence_d_detail": "",
            "evidence_e_detail": "",
            "evidence_f_detail": "",
            "profile_observation_detail": "",
            "profile_domain_summary": "",
            "profile_ip_summary": "",
            "profile_runtime_summary": "",
            "threat_residue": "false",
            "threat_residue_detail": "",
            "review_blank": "",
            "alert_info": "",
            "submitter": "",
            "comment": "",
            "context": "",
            "md5": "",
            "md5_list": "",
        })
        return row

    profile = dossier.profile
    has_residue = _has_threat_residue(dossier, config)
    md5_values = [str(item.get("md5")) for item in dossier.hash_entries if item.get("md5")]
    row.update({
        "latest_material_activity_time": _format_time(dossier.latest_material_activity_time),
        "latest_intel_update_time": _format_time(dossier.latest_intel_update_time),
        "source_set": ",".join(dossier.source_set),
        "family": ",".join(dossier.family),
        "tag": ",".join(dossier.tag),
        "evidence_a_detail": _format_evidence(dossier.evidence_a),
        "evidence_b_detail": _format_evidence(dossier.evidence_b),
        "evidence_c_detail": _format_evidence(dossier.evidence_c),
        "evidence_d_detail": _format_evidence(dossier.evidence_d),
        "evidence_e_detail": _format_evidence(dossier.evidence_e),
        "evidence_f_detail": _format_evidence(dossier.evidence_f),
        "profile_observation_detail": "; ".join(
            observation.detail for observation in (profile.observations if profile else [])
        ),
        "profile_domain_summary": str(profile.domain) if profile else "",
        "profile_ip_summary": str(profile.ip) if profile else "",
        "profile_runtime_summary": str(profile.runtime) if profile else "",
        "threat_residue": "true" if has_residue else "false",
        "threat_residue_detail": "",
        "review_blank": "",
        "alert_info": "",
        "submitter": "",
        "comment": dossier.comment,
        "context": dossier.context,
        "md5": md5_values[0] if md5_values else "",
        "md5_list": ",".join(dict.fromkeys(md5_values)),
    })
    return row


def _fallback_review(target: IocTarget, reason: str) -> Verdict:
    return Verdict(
        conclusion=Conclusion.PENDING_REVIEW,
        malicious_nature="证据处理失败",
        activity_status="未知",
        confidence="低",
        review_suggestion="必看",
        candidate_label=None,
        hit_evidence="",
        forbidden_labels="不能在证据处理失败时自动提交结论",
        reason=reason,
        route="standard",
        disposition="review",
    )


def _uses_live_request_planning(providers: list[Provider]) -> bool:
    return any(
        getattr(provider, "is_live_provider", False)
        and provider.name == DGA_PROVIDER_NAME
        for provider in providers
    )


def _merge_collection_stage(
    targets: list[IocTarget],
    provider_names: list[str],
    stages: list[tuple[
        dict[str, list[Observation]],
        dict[str, dict[str, ProviderStatus]],
        dict[str, dict[str, Freshness]],
        list[Observation],
    ]],
) -> tuple[
    dict[str, list[Observation]],
    dict[str, dict[str, ProviderStatus]],
    dict[str, dict[str, Freshness]],
    list[Observation],
]:
    observations = {target.normalized: [] for target in targets}
    statuses = {
        target.normalized: {
            name: ProviderStatus.DISABLED for name in provider_names
        }
        for target in targets
    }
    freshnesses = {target.normalized: {} for target in targets}
    all_observations: list[Observation] = []
    for stage_observations, stage_statuses, stage_freshnesses, stage_all in stages:
        for target in targets:
            key = target.normalized
            observations[key].extend(stage_observations.get(key, []))
            statuses[key].update(stage_statuses.get(key, {}))
            freshnesses[key].update(stage_freshnesses.get(key, {}))
        all_observations.extend(stage_all)

    provider_order = {name: index for index, name in enumerate(provider_names)}
    target_order = {target.normalized: index for index, target in enumerate(targets)}
    all_observations.sort(key=lambda item: (
        provider_order.get(item.provider, len(provider_order)),
        target_order.get(item.ioc, len(target_order)),
    ))
    for key in observations:
        observations[key].sort(
            key=lambda item: provider_order.get(item.provider, len(provider_order))
        )
    return observations, statuses, freshnesses, all_observations


def _lifecycle_request_keys(
    targets: list[IocTarget],
    observations_by_ioc: dict[str, list[Observation]],
    statuses_by_ioc: dict[str, dict[str, ProviderStatus]],
    snapshots: dict[str, list[dict]],
    config: Config,
    dga_configured: bool,
) -> dict[str, set[str]]:
    plan = {name: set() for name in _LIFECYCLE_PROVIDER_NAMES}
    for target in targets:
        if target.ioc_type not in {"domain", "url", "domain_port"}:
            continue
        key = target.normalized
        observations = observations_by_ioc.get(key, [])
        statuses = statuses_by_ioc.get(key, {})
        records = snapshots.get(key, [])
        authoritative_clue = has_authoritative_clue(
            _route_records(records, observations),
            config,
        )
        decision = select_route(
            target,
            observations,
            dga_configured,
            statuses.get(DGA_PROVIDER_NAME),
            authoritative_clue=authoritative_clue,
        )

        # Current ICP is decisive for both standard and DGA domain judgments.
        plan["icp"].add(key)
        if decision.route == Route.DGA:
            plan["whois"].add(key)
            plan["pdns"].add(key)
            continue

        # WHOIS is only useful on the standard route when historical URL or
        # phishing evidence could form the expired-domain gray branch.
        try:
            dossier, _ = _build_standard_dossier(
                target, records, observations, statuses, config
            )
        except Exception:
            continue
        if dossier.retained_urls and _has_historical_or_phishing_url_evidence(
            dossier
        ):
            plan["whois"].add(key)
    return plan


def _run_unified_pipeline_uncached(
    bundle: InputBundle,
    providers: Iterable[Provider],
    config: Config,
    context: ProviderContext,
    *,
    now: datetime | None = None,
    progress: Callable[[str], None] | None = None,
) -> UnifiedPipelineResult:
    """Collect provider facts and adjudicate all targets in input order."""
    provider_list = list(providers)
    provider_names = [str(provider.name) for provider in provider_list]
    if len(provider_names) != len(set(provider_names)):
        raise ValueError("provider names must be unique within one pipeline run")
    snapshots = _snapshot_records(bundle)
    dga_configured = any(provider.name == DGA_PROVIDER_NAME for provider in provider_list)
    diagnostics = PipelineDiagnostics(input_errors=list(bundle.errors))
    if _uses_live_request_planning(provider_list):
        live_lifecycle = [
            provider
            for provider in provider_list
            if getattr(provider, "is_live_provider", False)
            and provider.name in _LIFECYCLE_PROVIDER_NAMES
        ]
        discovery = [
            provider for provider in provider_list if provider not in live_lifecycle
        ]
        first_stage = _collect_observations(
            bundle.targets,
            discovery,
            context,
            diagnostics,
            config.provider_workers,
            progress,
        )
        request_keys = _lifecycle_request_keys(
            bundle.targets,
            first_stage[0],
            first_stage[1],
            snapshots,
            config,
            dga_configured,
        )
        planned_lifecycle = [
            _PlannedProvider(
                provider, request_keys.get(str(provider.name), set())
            )
            for provider in live_lifecycle
        ]
        second_stage = _collect_observations(
            bundle.targets,
            planned_lifecycle,
            context,
            diagnostics,
            config.provider_workers,
            progress,
        )
        (
            observations_by_ioc,
            statuses_by_ioc,
            freshness_by_ioc,
            all_observations,
        ) = _merge_collection_stage(
            bundle.targets,
            provider_names,
            [first_stage, second_stage],
        )
    else:
        (
            observations_by_ioc,
            statuses_by_ioc,
            freshness_by_ioc,
            all_observations,
        ) = _collect_observations(
            bundle.targets,
            provider_list,
            context,
            diagnostics,
            config.provider_workers,
            progress,
        )
    verdicts: list[dict] = []

    for target in bundle.targets:
        observations = observations_by_ioc[target.normalized]
        statuses = statuses_by_ioc[target.normalized]
        snapshot_records = snapshots.get(target.normalized, [])
        authoritative_clue = has_authoritative_clue(
            _route_records(snapshot_records, observations),
            config,
        )
        decision: RouteDecision = select_route(
            target,
            observations,
            dga_configured,
            statuses.get(DGA_PROVIDER_NAME),
            authoritative_clue=authoritative_clue,
        )
        diagnostics.routes[target.normalized] = decision.route.value
        if decision.classification_unknown:
            diagnostics.classification_unknown.append(target.normalized)

        dossier: IocDossier | None = None
        record_count = 0
        missing_required: list[str] = []
        try:
            if decision.route == Route.DGA:
                facts, missing_required = _build_dga_facts(
                    observations,
                    statuses,
                    config,
                    freshness_by_ioc[target.normalized],
                )
                verdict = adjudicate_dga(
                    target.normalized,
                    facts,
                    now=now,
                    pdns_recent_days=config.dga_pdns_recent_days,
                    activity_window_days=config.activity_window_days,
                )
            else:
                dossier, record_count = _build_standard_dossier(
                    target,
                    snapshot_records,
                    observations,
                    statuses,
                    config,
                )
                verdict = adjudicate(dossier, config)
                if decision.classification_unknown:
                    verdict = _downgrade_unknown_classification(verdict)
        except Exception as exc:
            message = _safe_provider_error(exc)
            diagnostics.processing_errors[target.normalized] = message
            verdict = _fallback_review(
                target,
                f"证据处理失败，已降级为待复核：{message}",
            )

        if missing_required:
            diagnostics.missing_required_providers[target.normalized] = list(missing_required)
        try:
            row = _serialize_verdict(
                target,
                verdict,
                statuses,
                observations,
                dossier=dossier,
                record_count=record_count,
                classification_unknown=decision.classification_unknown,
                missing_required_providers=missing_required,
                config=config,
            )
        except Exception as exc:  # per-IOC boundary: one bad dossier must not kill the batch
            message = _safe_provider_error(exc)
            diagnostics.processing_errors[target.normalized] = message
            row = _serialize_verdict(
                target,
                _fallback_review(
                    target,
                    f"证据处理失败，已降级为待复核：{message}",
                ),
                statuses,
                observations,
                dossier=None,
                record_count=record_count,
                classification_unknown=decision.classification_unknown,
                missing_required_providers=missing_required,
                config=config,
            )
        verdicts.append(row)

    diagnostics.processed_count = len(verdicts)
    return UnifiedPipelineResult(verdicts, diagnostics, all_observations)


def _provider_result_cache_shape(provider: Provider) -> dict:
    shape: dict[str, object] = {
        "name": str(provider.name),
        "class": f"{type(provider).__module__}.{type(provider).__qualname__}",
    }
    settings = getattr(provider, "settings", None)
    public_dict = getattr(settings, "public_dict", None)
    if callable(public_dict):
        shape["settings"] = public_dict()
    secrets = getattr(settings, "secrets", None)
    if isinstance(secrets, dict) and secrets:
        secret_identity = json.dumps(
            secrets, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        shape["credential_identity_sha256"] = hashlib.sha256(
            secret_identity
        ).hexdigest()
    for name in (
        "ignore_port",
        "ignore_url",
        "ignore_top",
        "max_attempts",
        "include_slow_variants",
        "include_url_param",
        "query_params",
    ):
        value = getattr(provider, name, None)
        if isinstance(value, (str, int, float, bool, list, tuple, dict, type(None))):
            shape[name] = value
    sidecar_path = getattr(provider, "_path", None)
    if sidecar_path is not None:
        try:
            content = sidecar_path.read_bytes()
        except OSError:
            content = b""
        shape["sidecar_sha256"] = hashlib.sha256(content).hexdigest()
    return shape


def result_cache_fingerprint(
    target: IocTarget,
    snapshot_records: list[dict],
    providers: Iterable[Provider],
    config: Config,
) -> str:
    """Hash every local input that can change a completed verdict row."""
    shape = {
        "contract": 1,
        "target": {
            "normalized": target.normalized,
            "ioc_type": target.ioc_type,
            "host": target.host,
            "ports": list(target.ports),
        },
        "snapshot_records": snapshot_records,
        "config": asdict(config),
        "providers": [
            _provider_result_cache_shape(provider) for provider in providers
        ],
    }
    encoded = json.dumps(
        shape,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_cacheable_verdict_row(row: dict) -> bool:
    statuses = row.get("provider_statuses")
    if isinstance(statuses, dict) and any(
        status == ProviderStatus.ERROR.value for status in statuses.values()
    ):
        return False
    missing = row.get("missing_required_providers")
    return not isinstance(missing, list) or not missing


def run_unified_pipeline(
    bundle: InputBundle,
    providers: Iterable[Provider],
    config: Config,
    context: ProviderContext,
    *,
    now: datetime | None = None,
    progress: Callable[[str], None] | None = None,
    result_cache: AdjudicationResultCache | None = None,
) -> UnifiedPipelineResult:
    """Reuse compatible completed verdicts and adjudicate cache misses."""
    provider_list = list(providers)
    if result_cache is None:
        return _run_unified_pipeline_uncached(
            bundle, provider_list, config, context, now=now, progress=progress
        )

    snapshots = _snapshot_records(bundle)
    fingerprints = {
        target.normalized: result_cache_fingerprint(
            target, snapshots.get(target.normalized, []), provider_list, config
        )
        for target in bundle.targets
    }
    cached_rows: dict[str, dict] = {}
    pending_targets: list[IocTarget] = []
    cache_errors: list[str] = []
    current = now or datetime.now(timezone.utc)
    for target in bundle.targets:
        entry = None
        if not context.refresh:
            entry = result_cache.get(
                target.normalized, fingerprints[target.normalized], now=current
            )
            cache_errors.extend(result_cache.diagnostics)
        if entry is not None and entry.fresh:
            cached_row = dict(entry.result)
            cached_row["original_ioc"] = target.original
            cached_rows[target.normalized] = cached_row
        else:
            pending_targets.append(target)

    if pending_targets:
        pending_bundle = InputBundle(
            kind=bundle.kind,
            targets=pending_targets,
            snapshots=bundle.snapshots,
            errors=bundle.errors,
        )
        result = _run_unified_pipeline_uncached(
            pending_bundle,
            provider_list,
            config,
            context,
            now=now,
            progress=progress,
        )
    else:
        result = UnifiedPipelineResult(
            diagnostics=PipelineDiagnostics(input_errors=list(bundle.errors))
        )

    computed_rows = {row["ioc"]: row for row in result.verdicts}
    for target in pending_targets:
        row = computed_rows.get(target.normalized)
        if row is None or not _is_cacheable_verdict_row(row):
            continue
        try:
            result_cache.put(
                target.normalized,
                fingerprints[target.normalized],
                row,
                fetched_at=current,
            )
        except (OSError, TypeError, ValueError) as exc:
            cache_errors.append(
                f"result cache write failed for {target.normalized}: {exc}"
            )

    result.verdicts = [
        cached_rows.get(target.normalized)
        or computed_rows[target.normalized]
        for target in bundle.targets
        if target.normalized in cached_rows or target.normalized in computed_rows
    ]
    result.diagnostics.result_cache_hit = len(cached_rows)
    result.diagnostics.result_cache_miss = len(pending_targets)
    result.diagnostics.result_cache_errors.extend(dict.fromkeys(cache_errors))
    for target in bundle.targets:
        row = cached_rows.get(target.normalized)
        if row is not None and isinstance(row.get("route"), str):
            result.diagnostics.routes[target.normalized] = row["route"]
    result.diagnostics.processed_count = len(result.verdicts)
    return result
