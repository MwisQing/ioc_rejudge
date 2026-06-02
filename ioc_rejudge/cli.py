"""CLI entry point and pipeline orchestration."""
import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from ioc_rejudge.config import Config, load_config
from ioc_rejudge.models import Evidence, IocDossier
from ioc_rejudge.parser import read_jsonl_snapshot_with_diagnostics
from ioc_rejudge.normalize import merge_records
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.export import export_jsonl, export_csv, export_excel

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

        dossier = merge_records(records)
        if not dossier.ioc:
            diag.no_ioc_count += 1
            if len(diag.skipped_row_samples) < _SAMPLE_LIMIT:
                diag.skipped_row_samples.append(f"no IOC: {ioc_name}")
            print("WARNING: row has no identifiable IOC value", file=sys.stderr)
            continue

        original_ioc = row.get("ioc", "")
        dossier = extract_evidence(dossier, config)
        verdict = adjudicate(dossier)

        activity_time = ""
        if dossier.latest_material_activity_time:
            activity_time = dossier.latest_material_activity_time.strftime("%Y-%m-%d %H:%M:%S")

        intel_time = ""
        if dossier.latest_intel_update_time:
            intel_time = dossier.latest_intel_update_time.strftime("%Y-%m-%d %H:%M:%S")

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
            "hit_evidence": verdict.hit_evidence,
            "forbidden_labels": verdict.forbidden_labels,
            "reason": verdict.reason,
        })

    diag.processed_count = len(verdicts)
    diag.skipped_total = (
        diag.parse_error_count + diag.missing_data_count +
        diag.empty_data_count + diag.non_list_data_count + diag.no_ioc_count
    )

    if diag.skipped_total:
        print(
            f"WARNING: {diag.skipped_total} line(s) skipped "
            f"({diag.parse_error_count} parse errors, "
            f"{diag.missing_data_count + diag.empty_data_count + diag.non_list_data_count + diag.no_ioc_count} data issues)",
            file=sys.stderr,
        )

    return PipelineResult(verdicts=verdicts, diagnostics=diag)


def run_pipeline(input_path: str, config: Config) -> list[dict]:
    """Compatibility wrapper returning only verdicts."""
    result = run_pipeline_with_diagnostics(input_path, config)
    return result.verdicts


def export_diagnostics(diag: Diagnostics, filepath: str):
    """Export diagnostics to JSON file."""
    data = {
        "input_path": diag.input_path,
        "processed_count": diag.processed_count,
        "parse_error_count": diag.parse_error_count,
        "missing_data_count": diag.missing_data_count,
        "empty_data_count": diag.empty_data_count,
        "non_list_data_count": diag.non_list_data_count,
        "no_ioc_count": diag.no_ioc_count,
        "skipped_total": diag.skipped_total,
        "parse_error_samples": diag.parse_error_samples,
        "skipped_row_samples": diag.skipped_row_samples,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description="APT IOC Snapshot Rejudgement Tool")
    parser.add_argument("--input", "-i", required=True, help="Path to JSONL snapshot file (one JSON object per line)")
    parser.add_argument("--jsonl", "-j", help="Output JSONL file path")
    parser.add_argument("--csv", "-c", help="Output CSV file path")
    parser.add_argument("--rules", help="Path to JSON rule configuration file")
    parser.add_argument("--diagnostics", help="Output diagnostics JSON file path")
    parser.add_argument("--activity-window", type=int, default=None, help=f"Activity window in days (default: {Config().activity_window_days})")
    parser.add_argument("--hash-malicious-level", type=int, default=None, help=f"Minimum hash level for malicious (default: {Config().hash_malicious_level})")
    parser.add_argument("--relate-url-malicious-level", type=int, default=None, help=f"Minimum relate_url level for malicious (default: {Config().relate_url_malicious_level})")
    parser.add_argument("--historical-malicious-level", type=int, default=None, help=f"Minimum level for historical malicious (default: {Config().historical_malicious_level})")
    parser.add_argument("--high-level-no-a-threshold", type=int, default=None, help=f"Level threshold for review pool without A evidence (default: {Config().high_level_no_a_threshold})")

    args = parser.parse_args()

    config = load_config(
        activity_window_days=args.activity_window,
        hash_malicious_level=args.hash_malicious_level,
        relate_url_malicious_level=args.relate_url_malicious_level,
        historical_malicious_level=args.historical_malicious_level,
        high_level_no_a_threshold=args.high_level_no_a_threshold,
        rules_path=args.rules,
    )

    result = run_pipeline_with_diagnostics(args.input, config)
    verdicts = result.verdicts
    diag = result.diagnostics

    if args.jsonl:
        export_jsonl(verdicts, args.jsonl)
        print(f"JSONL output written to {args.jsonl}")

    if args.csv:
        export_csv(verdicts, args.csv)
        print(f"CSV output written to {args.csv}")
    elif not args.jsonl:
        # Default: export Excel when neither -c nor -j specified
        base = os.path.splitext(args.input)[0]
        xlsx_path = base + "_result.xlsx"
        diag_data = {
            "input_path": diag.input_path,
            "processed_count": diag.processed_count,
            "parse_error_count": diag.parse_error_count,
            "missing_data_count": diag.missing_data_count,
            "empty_data_count": diag.empty_data_count,
            "non_list_data_count": diag.non_list_data_count,
            "no_ioc_count": diag.no_ioc_count,
            "skipped_total": diag.skipped_total,
        }
        export_excel(verdicts, xlsx_path, diagnostics=diag_data)
        print(f"Excel output written to {xlsx_path}")

    # Diagnostics export
    diag_path = args.diagnostics
    if not diag_path and not args.jsonl and not args.csv:
        # Auto-generate diagnostics path when Excel is produced
        diag_path = os.path.splitext(args.input)[0] + "_diagnostics.json"
    if diag_path:
        export_diagnostics(diag, diag_path)
        print(f"Diagnostics written to {diag_path}")

    print(f"\nProcessed {len(verdicts)} IOCs:")
    counts = {}
    for v in verdicts:
        c = v["conclusion"]
        counts[c] = counts.get(c, 0) + 1
    for conclusion, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {conclusion}: {count}")


if __name__ == "__main__":
    main()
