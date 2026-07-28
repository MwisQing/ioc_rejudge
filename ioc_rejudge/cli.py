"""CLI entry point and pipeline orchestration."""
import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from ioc_rejudge.config import Config, load_config
from ioc_rejudge.diff import compare_verdicts
from ioc_rejudge.inputs import InputKind, read_input_bundle
from ioc_rejudge.models import Evidence, IocDossier
from ioc_rejudge.parser import read_jsonl_snapshot_with_diagnostics
from ioc_rejudge.normalize import coerce_level, merge_records
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.adjudicator import adjudicate, _has_threat_residue
from ioc_rejudge.export import export_jsonl, export_csv, export_excel
from ioc_rejudge.pipeline import PipelineDiagnostics, run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.factory import (
    DEFAULT_PROVIDERS,
    build_providers,
    load_result_cache_settings,
    parse_provider_names,
)
from ioc_rejudge.providers.sidecar import SidecarProvider
from ioc_rejudge.result_cache import AdjudicationResultCache

_SAMPLE_LIMIT = 20


@dataclass
class Diagnostics:
    """Pipeline diagnostics for batch review."""
    input_path: str = ""
    processed_count: int = 0
    parse_error_count: int = 0
    missing_data_count: int = 0
    empty_data_count: int = 0
    non_list_data_count: int = 0
    no_ioc_count: int = 0
    invalid_ioc_count: int = 0
    skipped_total: int = 0
    parse_error_samples: list[str] = field(default_factory=list)
    skipped_row_samples: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Structured result from pipeline run."""
    verdicts: list[dict] = field(default_factory=list)
    diagnostics: Diagnostics = field(default_factory=Diagnostics)


def _format_evidence_detail(e: Evidence) -> str:
    """Format a single evidence item as detail string."""
    strength_tag = e.strength.value
    if e.tags:
        strength_tag += "," + ",".join(e.tags)
    return f"{e.field} [{strength_tag}]: {e.detail}"


def _format_evidence_list(evidence_list: list[Evidence]) -> str:
    """Format evidence list as detail string."""
    if not evidence_list:
        return ""
    return "; ".join(_format_evidence_detail(e) for e in evidence_list)


def _format_profile_observations(dossier: IocDossier) -> str:
    """Format profile observations as detail string."""
    if not dossier.profile or not dossier.profile.observations:
        return ""
    parts = []
    for obs in dossier.profile.observations:
        parts.append(f"{obs.field} [{obs.severity},{','.join(obs.tags)}]: {obs.detail}")
    return "; ".join(parts)


def _format_profile_summary(summary: dict) -> str:
    """Format profile summary dict as string."""
    if not summary:
        return ""
    return "; ".join(f"{k}={v}" for k, v in summary.items())


def _format_threat_residue_detail(dossier: IocDossier, config: Config) -> str:
    """Format threat residue detail for analyst review."""
    hml = config.historical_malicious_level
    hash_ml = config.hash_malicious_level
    parts = []

    # D evidence with suspicious markers
    suspicious_d = [
        e for e in dossier.evidence_d
        if any(t in e.field for t in ("suspicious", "threat", "random", "hash", "source"))
    ]
    if suspicious_d:
        parts.append("D_suspicious: " + "; ".join(e.field for e in suspicious_d))

    # High-level related domains
    high_rid = [
        e for e in dossier.relate_ip_domain_entries
        if coerce_level(e.get("level")) >= hml
    ]
    if high_rid:
        parts.append(f"high_related_domains: {len(high_rid)} entries level >= {hml}")

    # High-level dtree
    high_dt = [
        e for e in dossier.dtree_entries
        if coerce_level(e.get("level")) >= hml
    ]
    if high_dt:
        parts.append(f"high_dtree: {len(high_dt)} entries level >= {hml}")

    # Hash entries
    if dossier.hash_entries:
        max_level = max((coerce_level(h.get("level")) for h in dossier.hash_entries), default=0.0)
        if max_level >= hash_ml:
            parts.append(f"hash_max_level={max_level}")

    # Malicious type / attck
    if dossier.malicious_type:
        parts.append(f"malicious_type: {','.join(dossier.malicious_type)}")
    if dossier.attck:
        parts.append(f"attck: {','.join(dossier.attck)}")

    # Runtime flags
    rf = dossier.runtime_flags
    if rf:
        threat_flags = []
        if rf.get("block") is True:
            threat_flags.append("block")
        if rf.get("black") is True:
            threat_flags.append("black")
        if rf.get("ml_black") is True:
            threat_flags.append("ml_black")
        if rf.get("alert_score", 0) >= 70:
            threat_flags.append(f"alert_score={rf['alert_score']}")
        if threat_flags:
            parts.append(f"runtime_threat: {','.join(threat_flags)}")

    return "; ".join(parts) if parts else ""


def _stringify_value(value) -> str:
    """Convert scalar/list values to a compact review string."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value if v not in (None, ""))
    return str(value)


def _first_nonempty(records: list[dict], *fields: str) -> str:
    """Return first non-empty value across records for any named field."""
    for field in fields:
        for rec in records:
            value = rec.get(field)
            text = _stringify_value(value)
            if text:
                return text
    return ""


def _join_unique(values: list) -> str:
    seen = set()
    result = []
    for value in values:
        text = _stringify_value(value)
        if not text:
            continue
        for part in text.split(","):
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                result.append(part)
    return ",".join(result)


def _primary_md5(dossier: IocDossier) -> str:
    """Pick md5 from the highest-level hash entry."""
    best = None
    best_level = float("-inf")
    for entry in dossier.hash_entries:
        md5 = entry.get("md5", "")
        level = entry.get("level", 0)
        try:
            numeric_level = float(level)
        except (TypeError, ValueError):
            numeric_level = 0
        if md5 and numeric_level > best_level:
            best = md5
            best_level = numeric_level
    return best or ""


def _md5_list(dossier: IocDossier) -> str:
    return _join_unique([entry.get("md5", "") for entry in dossier.hash_entries])


def _alert_info(records: list[dict], dossier: IocDossier) -> str:
    """Build the combined alert information column for Excel review."""
    malicious_family = _first_nonempty(records, "malicious_family")
    if not malicious_family:
        malicious_family = _join_unique(dossier.family)

    malicious_type = _first_nonempty(records, "malicious_type")
    if not malicious_type:
        malicious_type = _join_unique(dossier.malicious_type)

    parts = [
        ("alert_name", _first_nonempty(records, "alert_name")),
        ("add_date", _first_nonempty(records, "add_date", "inserttime")),
        ("update_date", _first_nonempty(records, "update_date", "updatetime")),
        ("campaign", _first_nonempty(records, "campaign")),
        ("malicious_family", malicious_family),
        ("malicious_type", malicious_type),
    ]
    return "\n".join(f"{key}:{value}" for key, value in parts)


def run_pipeline_with_diagnostics(input_path: str, config: Config) -> PipelineResult:
    """Run full pipeline, returning verdicts and diagnostics."""
    diag = Diagnostics(input_path=input_path)
    read_result = read_jsonl_snapshot_with_diagnostics(input_path, sample_limit=_SAMPLE_LIMIT)
    data = read_result.records
    parse_skipped = read_result.skipped
    diag.parse_error_count = parse_skipped
    diag.parse_error_samples = read_result.parse_error_samples

    if not data and parse_skipped > 0:
        print(f"ERROR: all {parse_skipped} line(s) failed to parse", file=sys.stderr)
        diag.skipped_total = parse_skipped
        return PipelineResult(verdicts=[], diagnostics=diag)
    if not data:
        print("No IOC data found in snapshot.", file=sys.stderr)
        diag.skipped_total = parse_skipped
        return PipelineResult(verdicts=[], diagnostics=diag)

    verdicts = []

    for row in data:
        records = row.get("data")
        ioc_name = row.get("ioc", "unknown")

        if records is None:
            diag.missing_data_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(f"no 'data' key: {ioc_name}")
            print(f"WARNING: row '{ioc_name}' has no 'data' key", file=sys.stderr)
            continue
        if not isinstance(records, list):
            diag.non_list_data_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(f"data not list: {ioc_name}")
            print(f"WARNING: row '{ioc_name}' 'data' is not a list", file=sys.stderr)
            continue
        if not records:
            diag.empty_data_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(f"empty data: {ioc_name}")
            continue

        original_ioc = row.get("ioc", "")
        try:
            dossier = merge_records(records)
        except ValueError as exc:
            diag.invalid_ioc_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(
                    f"invalid IOC: {original_ioc or ioc_name} ({exc})"
                )
            print(
                f"WARNING: row '{ioc_name}' has invalid IOC data: {exc}",
                file=sys.stderr,
            )
            continue
        if not dossier.ioc:
            diag.no_ioc_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(f"no IOC: {ioc_name}")
            print("WARNING: row has no identifiable IOC value", file=sys.stderr)
            continue

        dossier = extract_evidence(dossier, config)
        verdict = adjudicate(dossier, config)

        activity_time = ""
        if dossier.latest_material_activity_time:
            activity_time = dossier.latest_material_activity_time.strftime("%Y-%m-%d %H:%M:%S")

        intel_time = ""
        if dossier.latest_intel_update_time:
            intel_time = dossier.latest_intel_update_time.strftime("%Y-%m-%d %H:%M:%S")

        has_residue = _has_threat_residue(dossier, config)
        profile_domain = dossier.profile.domain if dossier.profile else {}
        profile_ip = dossier.profile.ip if dossier.profile else {}
        profile_runtime = dossier.profile.runtime if dossier.profile else {}

        verdicts.append({
            "original_ioc": original_ioc,
            "ioc": dossier.ioc,
            "ioc_type": dossier.ioc_type,
            "ports": ",".join(dossier.ports) if dossier.ports else "",
            "record_count": len(records),
            "conclusion": verdict.conclusion.value,
            "malicious_nature": verdict.malicious_nature,
            "activity_status": verdict.activity_status,
            "confidence": verdict.confidence,
            "review_suggestion": verdict.review_suggestion,
            "candidate_label": verdict.candidate_label or "",
            "latest_material_activity_time": activity_time,
            "latest_intel_update_time": intel_time,
            "source_set": ",".join(dossier.source_set) if dossier.source_set else "",
            "family": ",".join(dossier.family) if dossier.family else "",
            "tag": ",".join(dossier.tag) if dossier.tag else "",
            "evidence_a_detail": _format_evidence_list(dossier.evidence_a),
            "evidence_b_detail": _format_evidence_list(dossier.evidence_b),
            "evidence_c_detail": _format_evidence_list(dossier.evidence_c),
            "evidence_d_detail": _format_evidence_list(dossier.evidence_d),
            "evidence_e_detail": _format_evidence_list(dossier.evidence_e),
            "evidence_f_detail": _format_evidence_list(dossier.evidence_f),
            "profile_observation_detail": _format_profile_observations(dossier),
            "profile_domain_summary": _format_profile_summary(profile_domain),
            "profile_ip_summary": _format_profile_summary(profile_ip),
            "profile_runtime_summary": _format_profile_summary(profile_runtime),
            "threat_residue": "true" if has_residue else "false",
            "threat_residue_detail": _format_threat_residue_detail(dossier, config) if has_residue else "",
            "review_blank": "",
            "alert_info": _alert_info(records, dossier),
            "submitter": _first_nonempty(records, "submitter"),
            "comment": dossier.comment,
            "context": dossier.context,
            "md5": _primary_md5(dossier),
            "md5_list": _md5_list(dossier),
            "hit_evidence": verdict.hit_evidence,
            "forbidden_labels": verdict.forbidden_labels,
            "reason": verdict.reason,
        })

    diag.processed_count = len(verdicts)
    diag.skipped_total = (
        diag.parse_error_count + diag.missing_data_count +
        diag.empty_data_count + diag.non_list_data_count +
        diag.no_ioc_count + diag.invalid_ioc_count
    )

    if diag.skipped_total:
        print(
            f"WARNING: {diag.skipped_total} line(s) skipped "
            f"({diag.parse_error_count} parse errors, "
            f"{diag.missing_data_count + diag.empty_data_count + diag.non_list_data_count + diag.no_ioc_count + diag.invalid_ioc_count} data issues)",
            file=sys.stderr,
        )

    return PipelineResult(verdicts=verdicts, diagnostics=diag)


def run_pipeline(input_path: str, config: Config) -> list[dict]:
    """Compatibility wrapper returning only verdicts."""
    result = run_pipeline_with_diagnostics(input_path, config)
    return result.verdicts


def _diagnostics_data(diag: Diagnostics | PipelineDiagnostics) -> dict:
    if isinstance(diag, PipelineDiagnostics):
        return diag.to_dict()
    return {
        "input_path": diag.input_path,
        "processed_count": diag.processed_count,
        "parse_error_count": diag.parse_error_count,
        "missing_data_count": diag.missing_data_count,
        "empty_data_count": diag.empty_data_count,
        "non_list_data_count": diag.non_list_data_count,
        "no_ioc_count": diag.no_ioc_count,
        "invalid_ioc_count": diag.invalid_ioc_count,
        "skipped_total": diag.skipped_total,
        "parse_error_samples": diag.parse_error_samples,
        "skipped_row_samples": diag.skipped_row_samples,
    }


def export_diagnostics(diag: Diagnostics | PipelineDiagnostics, filepath: str):
    """Export diagnostics to JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(_diagnostics_data(diag), f, ensure_ascii=False, indent=2)


def _default_diagnostics_path(input_path: str) -> str:
    return os.path.splitext(input_path)[0] + "_diagnostics.json"


def _maybe_export_diagnostics(
    diag: Diagnostics | PipelineDiagnostics,
    filepath: str | None,
):
    if filepath:
        export_diagnostics(diag, filepath)
        print(f"Diagnostics written to {filepath}")


def _print_provider_startup(providers: list) -> None:
    """Show which providers this run will use before collection starts."""
    parts = []
    for provider in providers:
        name = str(provider.name)
        disabled_reason = str(getattr(provider, "disabled_reason", "") or "")
        if disabled_reason:
            parts.append(f"{name} [disabled]")
            print(
                f"WARNING: provider '{name}' disabled: {disabled_reason}",
                file=sys.stderr,
            )
        elif isinstance(provider, SidecarProvider):
            parts.append(f"{name} (sidecar)")
        else:
            parts.append(name)
    print("Providers: " + (", ".join(parts) if parts else "(none)"))


def _warn_input_errors(diag: Diagnostics | PipelineDiagnostics) -> None:
    input_errors = getattr(diag, "input_errors", None)
    if not input_errors:
        return
    print(
        f"WARNING: {len(input_errors)} input line(s) rejected",
        file=sys.stderr,
    )
    for sample in input_errors[:5]:
        print(f"  {sample}", file=sys.stderr)


def _print_provider_status(diag: Diagnostics | PipelineDiagnostics) -> None:
    result_cache_hit = getattr(diag, "result_cache_hit", 0)
    result_cache_miss = getattr(diag, "result_cache_miss", 0)
    if result_cache_hit or result_cache_miss:
        print(
            f"Adjudication result cache: hit={result_cache_hit} "
            f"miss={result_cache_miss}"
        )
    providers = getattr(diag, "providers", None)
    if not providers:
        return
    print("Provider status:")
    for name, metric in providers.items():
        print(
            f"  {name}: success={metric.success} no_data={metric.no_data} "
            f"error={metric.error} disabled={metric.disabled} "
            f"cache_hit={metric.cache_hit} ({metric.duration_seconds:.1f}s)"
        )


def _load_diff_baseline(
    path_str: str,
    parser: argparse.ArgumentParser,
) -> list[dict]:
    """Load and validate a previous result JSONL before the pipeline runs."""
    path = Path(path_str)
    if not path.is_file():
        parser.error(f"diff baseline does not exist or is not a file: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"diff baseline {path}: cannot read: {exc}")
    rows: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            parser.error(f"diff baseline {path}:{line_no}: invalid JSON: {exc}")
        if not isinstance(row, dict):
            parser.error(f"diff baseline {path}:{line_no}: expected JSON object")
        for field_name in ("ioc", "conclusion"):
            value = row.get(field_name)
            if not isinstance(value, str) or not value.strip():
                parser.error(
                    f"diff baseline {path}:{line_no}: missing or empty '{field_name}'"
                )
        rows.append(row)
    if not rows:
        parser.error(f"diff baseline has no verdict rows: {path}")
    return rows


def _default_diff_path(args: argparse.Namespace) -> str:
    if args.jsonl:
        base = os.path.splitext(args.jsonl)[0]
    elif args.csv:
        base = os.path.splitext(args.csv)[0]
    else:
        base = os.path.splitext(args.input or "ioc_rejudge")[0] + "_result"
    return base + "_diff.json"


def _export_diff_report(baseline: list[dict], verdicts: list[dict], args) -> None:
    report = compare_verdicts(baseline, verdicts)
    diff_path = args.diff_output or _default_diff_path(args)
    with open(diff_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"Diff report written to {diff_path}")
    print(
        "Diff vs baseline: "
        f"changed={len(report['changed'])} "
        f"black_to_white={len(report['black_to_white'])} "
        f"white_to_black={len(report['white_to_black'])} "
        f"to_gray={len(report['to_gray'])} "
        f"to_review={len(report['to_review'])} "
        f"only_before={len(report['only_before'])} "
        f"only_after={len(report['only_after'])}"
    )


_PROVIDER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _parse_provider_data(
    values: list[str],
    parser: argparse.ArgumentParser,
) -> list[SidecarProvider]:
    providers: list[SidecarProvider] = []
    seen: set[str] = set()
    for value in values:
        if "=" not in value:
            parser.error("--provider-data must use NAME=PATH")
        name, raw_path = value.split("=", 1)
        name = name.strip()
        raw_path = raw_path.strip()
        if not name or not _PROVIDER_NAME_RE.fullmatch(name):
            parser.error(f"invalid provider name in --provider-data: {name!r}")
        if name in seen:
            parser.error(f"duplicate --provider-data name: {name}")
        if not raw_path:
            parser.error(f"missing sidecar path for provider {name}")
        path = Path(raw_path)
        if not path.is_file():
            parser.error(f"sidecar file does not exist or is not a file: {path}")
        seen.add(name)
        providers.append(SidecarProvider(name, path))
    return providers


def main():
    parser = argparse.ArgumentParser(description="APT IOC Snapshot Rejudgement Tool")
    parser.add_argument("--input", "-i", help="Path to a JSONL snapshot or bare IOC file")
    parser.add_argument("--ioc", action="append", default=[], help="IOC value; may be repeated")
    parser.add_argument("--offline", action="store_true", help="Use local data and cache only")
    parser.add_argument("--refresh", action="store_true", help="Bypass provider cache")
    parser.add_argument(
        "--providers",
        help=("Comma-separated live providers (default: "
              + ",".join(DEFAULT_PROVIDERS) + ")"),
    )
    parser.add_argument("--provider-config", help="Local JSON provider configuration")
    parser.add_argument(
        "--credentials-file",
        help="Local JSON credentials file; when set, provider credentials are read only from this file",
    )
    parser.add_argument(
        "--cache-dir",
        help="Reusable provider response cache directory (default: .\\provider-cache)",
    )
    parser.add_argument("--run-dir", help="Current run audit directory")
    parser.add_argument(
        "--provider-data",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Local provider observation JSONL; may be repeated",
    )
    parser.add_argument("--jsonl", "-j", help="Output JSONL file path")
    parser.add_argument("--csv", "-c", help="Output CSV file path")
    parser.add_argument("--rules", help="Path to JSON rule configuration file")
    parser.add_argument("--diagnostics", help="Output diagnostics JSON file path")
    parser.add_argument(
        "--diff-baseline",
        metavar="PATH",
        help="Previous result JSONL to compare conclusions against",
    )
    parser.add_argument(
        "--diff-output",
        metavar="PATH",
        help="Diff report JSON path (default: derived from the primary output)",
    )
    parser.add_argument("--activity-window", type=int, default=None, help=f"Activity window in days (default: {Config().activity_window_days})")
    parser.add_argument("--hash-malicious-level", type=int, default=None, help=f"Minimum hash level for malicious (default: {Config().hash_malicious_level})")
    parser.add_argument("--relate-url-malicious-level", type=int, default=None, help=f"Minimum relate_url level for malicious (default: {Config().relate_url_malicious_level})")
    parser.add_argument("--historical-malicious-level", type=int, default=None, help=f"Minimum level for historical malicious (default: {Config().historical_malicious_level})")
    parser.add_argument("--high-level-no-a-threshold", type=int, default=None, help=f"Level threshold for review pool without A evidence (default: {Config().high_level_no_a_threshold})")

    args = parser.parse_args()

    if not args.input and not args.ioc:
        parser.error("--input is required when no --ioc value is supplied")
    if args.offline and args.refresh:
        parser.error("--offline and --refresh cannot be used together")
    if args.diff_output and not args.diff_baseline:
        parser.error("--diff-output requires --diff-baseline")

    start_time = time.perf_counter()
    baseline_verdicts = (
        _load_diff_baseline(args.diff_baseline, parser) if args.diff_baseline else None
    )

    sidecar_providers = _parse_provider_data(args.provider_data, parser)

    config = load_config(
        activity_window_days=args.activity_window,
        hash_malicious_level=args.hash_malicious_level,
        relate_url_malicious_level=args.relate_url_malicious_level,
        historical_malicious_level=args.historical_malicious_level,
        high_level_no_a_threshold=args.high_level_no_a_threshold,
        rules_path=args.rules,
    )

    new_mode_requested = bool(
        args.ioc
        or args.provider_data
        or args.offline
        or args.refresh
        or args.providers is not None
        or args.provider_config
        or args.credentials_file
        or args.cache_dir
        or args.run_dir
    )
    input_suffix = Path(args.input).suffix.lower() if args.input else ""
    if not new_mode_requested and input_suffix == ".jsonl":
        result = run_pipeline_with_diagnostics(args.input, config)
    else:
        try:
            bundle = read_input_bundle(args.input, args.ioc)
        except (FileNotFoundError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if bundle.kind == InputKind.SNAPSHOT and not new_mode_requested:
            result = run_pipeline_with_diagnostics(args.input, config)
        else:
            try:
                live_names = parse_provider_names(args.providers)
            except ValueError as exc:
                parser.error(str(exc))
            sidecar_names = {provider.name for provider in sidecar_providers}
            collisions = sidecar_names.intersection(live_names)
            if collisions and not args.offline:
                parser.error(
                    "live/sidecar provider name collision: "
                    + ", ".join(sorted(collisions))
                )
            cache_path = (
                Path(args.cache_dir) if args.cache_dir else Path("provider-cache")
            )
            if args.offline:
                live_names = [name for name in live_names if name not in sidecar_names]
                if (
                    args.providers is None
                    and not args.cache_dir
                    and sidecar_providers
                ):
                    live_names = []
            try:
                result_cache_settings = load_result_cache_settings(
                    Path(args.provider_config) if args.provider_config else None
                )
                live_providers = build_providers(
                    live_names,
                    credentials_path=(
                        Path(args.credentials_file) if args.credentials_file else None
                    ),
                    config_path=Path(args.provider_config) if args.provider_config else None,
                    cache_dir=cache_path,
                    run_dir=Path(args.run_dir) if args.run_dir else None,
                    adjudication_config=config,
                    offline=args.offline,
                )
            except (OSError, TypeError, ValueError) as exc:
                parser.error(str(exc))
            providers = [*live_providers, *sidecar_providers]
            _print_provider_startup(providers)
            result_cache = (
                AdjudicationResultCache(
                    cache_path, ttl=result_cache_settings.ttl
                )
                if result_cache_settings.enabled
                else None
            )
            result = run_unified_pipeline(
                bundle,
                providers,
                config,
                ProviderContext(
                    offline=args.offline,
                    refresh=args.refresh,
                    run_dir=Path(args.run_dir) if args.run_dir else None,
                ),
                progress=lambda message: print(message, file=sys.stderr),
                result_cache=result_cache,
            )
    verdicts = result.verdicts
    diag = result.diagnostics
    _warn_input_errors(diag)

    diag_path = args.diagnostics
    if not diag_path and not args.jsonl and not args.csv:
        # Auto-generate diagnostics path when Excel would be produced.
        diag_path = _default_diagnostics_path(args.input or "ioc_rejudge")

    if not verdicts:
        _maybe_export_diagnostics(diag, diag_path)
        print(
            "ERROR: no valid IOC rows were processed; output files were not generated. "
            "Check the diagnostics JSON and ensure each JSONL line is "
            "{\"ioc\": \"...\", \"data\": [...]}",
            file=sys.stderr,
        )
        sys.exit(2)

    if args.jsonl:
        export_jsonl(verdicts, args.jsonl)
        print(f"JSONL output written to {args.jsonl}")

    if args.csv:
        export_csv(verdicts, args.csv)
        print(f"CSV output written to {args.csv}")
    elif not args.jsonl:
        # Default: export Excel when neither -c nor -j specified
        base = os.path.splitext(args.input or "ioc_rejudge")[0]
        xlsx_path = base + "_result.xlsx"
        diag_data = _diagnostics_data(diag)
        export_excel(verdicts, xlsx_path, diagnostics=diag_data)
        print(f"Excel output written to {xlsx_path}")

    # Diagnostics export
    _maybe_export_diagnostics(diag, diag_path)

    if baseline_verdicts is not None:
        _export_diff_report(baseline_verdicts, verdicts, args)

    print(f"\nProcessed {len(verdicts)} IOCs:")
    counts = {}
    for v in verdicts:
        c = v["conclusion"]
        counts[c] = counts.get(c, 0) + 1
    for conclusion, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {conclusion}: {count}")
    _print_provider_status(diag)
    print(f"Total time: {time.perf_counter() - start_time:.1f}s")


if __name__ == "__main__":
    main()
