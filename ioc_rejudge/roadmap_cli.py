"""Offline roadmap operations CLI.

This module is an adapter around the accepted job, explanation, health, table,
export, and cache operations.  It intentionally does not build providers or
call the network.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_rejudge.cache_admin import (
    CacheAdminError,
    apply_plan,
    build_cleanup_plan,
    cache_stats,
)
from ioc_rejudge.cli import run_pipeline_with_diagnostics
from ioc_rejudge.config import Config
from ioc_rejudge.explanations import explain_verdict
from ioc_rejudge.export import export_jsonl
from ioc_rejudge.export_bundle import export_bundle
from ioc_rejudge.files import atomic_write_text, path_in_set, resolve_path
from ioc_rejudge.health import check_configuration
from ioc_rejudge.input_adapters import TableAdapterError, adapt_table
from ioc_rejudge.job_runner import JobRunner
from ioc_rejudge.job_store import (
    CANCELLED,
    FAILED,
    PENDING,
    RUNNING,
    SUCCEEDED,
    JobStore,
)
from ioc_rejudge.run_history import RunHistory
from ioc_rejudge.review_queue import (
    list_review_queue,
    label_review_queue,
    reopen_review_queue,
    summarize,
)


class RoadmapCliError(ValueError):
    """An actionable, safe-to-display command error."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RoadmapCliError(message)


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_document_path(root: Path, *parts: str) -> Path:
    root_resolved = root.resolve()
    candidate = root_resolved.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise RoadmapCliError("path escapes the requested directory") from exc
    return candidate


def _read_jsonl(path: str | Path, *, argument_name: str) -> list[dict[str, Any]]:
    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError as exc:
        raise RoadmapCliError(f"{argument_name} does not exist: {source}") from exc
    except OSError as exc:
        raise RoadmapCliError(f"cannot read {argument_name} {source}: {exc}") from exc

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise RoadmapCliError(
                f"{argument_name} line {line_number} is not valid JSON"
            ) from exc
        if not isinstance(row, dict):
            raise RoadmapCliError(
                f"{argument_name} line {line_number} must contain a JSON object"
            )
        rows.append(row)
    if not rows:
        raise RoadmapCliError(f"{argument_name} contains no JSON objects: {source}")
    return rows


def _read_json(path: str | Path | None, *, argument_name: str) -> Any:
    if path is None:
        return None
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise RoadmapCliError(f"{argument_name} does not exist: {source}") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise RoadmapCliError(f"{argument_name} is not valid JSON: {source}") from exc
    return value


def _job_state(document: dict[str, Any]) -> str:
    targets = document.get("targets", {})
    states = [
        target.get("state")
        for target in targets.values()
        if isinstance(target, dict)
    ]
    if not states:
        return FAILED
    if any(state == FAILED for state in states):
        return FAILED
    if any(state == CANCELLED for state in states):
        return CANCELLED
    if any(state == RUNNING for state in states):
        return RUNNING
    if any(state == PENDING for state in states):
        return PENDING
    if all(state == SUCCEEDED for state in states):
        return SUCCEEDED
    return FAILED


def _snapshot_job_view(document: dict[str, Any]) -> dict[str, Any]:
    view = dict(document)
    view["state"] = _job_state(document)
    return view


def _execute_snapshot_job(job_dir: Path, job_id: str) -> dict[str, Any]:
    """Run the accepted legacy snapshot pipeline and persist its artifacts."""
    store = JobStore(job_dir)
    document = store.load(job_id)
    metadata = document.get("metadata", {})
    input_path = Path(str(metadata.get("input_path", "")))
    try:
        pipeline = run_pipeline_with_diagnostics(str(input_path), Config())
    except Exception as exc:
        raise RuntimeError(f"snapshot pipeline failed: {exc}") from exc

    job_root = _safe_document_path(job_dir, job_id)
    job_root.mkdir(parents=True, exist_ok=True)
    result_path = _safe_document_path(job_root, "results.jsonl")
    diagnostics_path = _safe_document_path(job_root, "diagnostics.json")
    diagnostic_data = {
        "input_path": pipeline.diagnostics.input_path,
        "processed_count": pipeline.diagnostics.processed_count,
        "parse_error_count": pipeline.diagnostics.parse_error_count,
        "nested_data_error_count": pipeline.diagnostics.nested_data_error_count,
        "missing_data_count": pipeline.diagnostics.missing_data_count,
        "empty_data_count": pipeline.diagnostics.empty_data_count,
        "non_list_data_count": pipeline.diagnostics.non_list_data_count,
        "no_ioc_count": pipeline.diagnostics.no_ioc_count,
        "invalid_ioc_count": pipeline.diagnostics.invalid_ioc_count,
        "skipped_total": pipeline.diagnostics.skipped_total,
        "parse_error_samples": pipeline.diagnostics.parse_error_samples,
        "skipped_row_samples": pipeline.diagnostics.skipped_row_samples,
    }
    atomic_write_text(
        diagnostics_path,
        json.dumps(diagnostic_data, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    if not pipeline.verdicts:
        raise RuntimeError(
            "snapshot pipeline produced no verdicts; see diagnostics.json for details"
        )
    export_jsonl(pipeline.verdicts, str(result_path))
    return {
        "result_count": len(pipeline.verdicts),
        "result_path": str(result_path),
        "diagnostics_path": str(diagnostics_path),
        "diagnostics": diagnostic_data,
    }


def _run_job_command(args: argparse.Namespace) -> int:
    job_dir = Path(args.job_dir).expanduser()
    store = JobStore(job_dir)
    if args.job_command == "start":
        input_path = Path(args.input).expanduser()
        if input_path.suffix.lower() != ".jsonl":
            raise RoadmapCliError("job start requires a legacy snapshot .jsonl input")
        if not input_path.is_file():
            raise RoadmapCliError(f"input does not exist: {input_path}")
        job_id = f"job-{secrets.token_hex(10)}"
        store.create(
            job_id,
            ["run"],
            {
                "input_path": str(resolve_path(input_path)),
                "offline": bool(args.offline),
                "pipeline": "legacy_snapshot",
                "created_at_utc": _now_utc(),
            },
        )
        JobRunner(store).run(job_id, lambda _target: _execute_snapshot_job(job_dir, job_id))
        document = store.load(job_id)
        _emit(_snapshot_job_view(document))
        return 0 if _job_state(document) == SUCCEEDED else 1

    job_id = args.job_id
    if args.job_command == "status":
        document = store.load(job_id)
        _emit(_snapshot_job_view(document))
        return 0
    if args.job_command == "resume":
        document = JobRunner(store).run(job_id, lambda _target: _execute_snapshot_job(job_dir, job_id))
        _emit(_snapshot_job_view(document))
        return 0 if _job_state(document) == SUCCEEDED else 1
    if args.job_command == "retry-failed":
        document = JobRunner(store).run(
            job_id,
            lambda _target: _execute_snapshot_job(job_dir, job_id),
            retry_failed=True,
        )
        _emit(_snapshot_job_view(document))
        return 0 if _job_state(document) == SUCCEEDED else 1
    if args.job_command == "cancel":
        document = store.cancel(job_id)
        _emit(_snapshot_job_view(document))
        return 0
    raise RoadmapCliError(f"unknown job command: {args.job_command}")


def _run_review_command(args: argparse.Namespace) -> dict[str, Any]:
    if args.review_command == "list":
        rows = list_review_queue(args.input, args.queue)
        return {"rows": rows, "summary": summarize(rows)}
    if args.review_command == "label":
        return {
            "labelled": label_review_queue(
                args.queue,
                args.ioc,
                decision=args.decision,
                note=args.note,
                reviewer=args.reviewer,
            )
        }
    if args.review_command == "reopen":
        return {
            "reopened": reopen_review_queue(
                args.queue,
                args.ioc,
                note=args.note,
                reviewer=args.reviewer,
            )
        }
    raise RoadmapCliError(f"unknown review command: {args.review_command}")


def _run_health_command(args: argparse.Namespace) -> dict[str, Any]:
    providers = [name.strip() for name in args.providers.split(",") if name.strip()]
    if not providers:
        raise RoadmapCliError("--providers must name at least one provider")
    result = check_configuration(
        providers,
        cache_root=Path(args.cache_dir).expanduser() if args.cache_dir else None,
    )
    result["offline"] = bool(args.offline)
    result["network_access"] = "disabled"
    return result


def _run_history_command(args: argparse.Namespace) -> dict[str, Any]:
    history = RunHistory(Path(args.history_dir).expanduser())
    if args.history_command == "list":
        return {"runs": history.list_runs()}
    if args.history_command == "get":
        record = history.get(args.run_id)
        if record is None:
            raise RoadmapCliError(f"run not found: {args.run_id}")
        return record
    if args.history_command == "baseline":
        return {
            "run": history.select_baseline(args.current_run_id),
            "current_run_id": args.current_run_id,
        }
    raise RoadmapCliError(f"unknown history command: {args.history_command}")


def _run_cache_command(args: argparse.Namespace) -> dict[str, Any]:
    if args.cache_command == "inspect":
        return cache_stats(
            Path(args.cache_dir).expanduser(),
            cache_type=args.cache_type,
        )
    if args.cache_command == "cleanup":
        try:
            plan = build_cleanup_plan(
                Path(args.cache_dir).expanduser(),
                cache_type=args.cache_type,
                ttl=None,
                before_date_utc=args.before,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise CacheAdminError(str(exc)) from exc
        result = apply_plan(plan, execute=bool(args.apply))
        result["before_date_utc"] = str(plan.before_date_utc)
        result["cutoff_utc"] = plan.cutoff_utc.isoformat()
        result["planned_files"] = [
            {
                "path": str(item.path),
                "bytes": item.size,
                "entries": item.entry_count,
            }
            for item in plan.files
        ]
        return result
    raise RoadmapCliError(f"unknown cache command: {args.cache_command}")


def _run_import_table(args: argparse.Namespace) -> dict[str, Any]:
    adapted = adapt_table(args.input, column_map={args.column: "indicator"})
    if not adapted.bundle.targets:
        raise RoadmapCliError(
            "table adapter produced no valid IOC targets; "
            + "; ".join(adapted.bundle.errors[:5])
        )
    output_path = Path(args.output).expanduser()
    if path_in_set(output_path, [args.input]) is not None:
        raise RoadmapCliError("output must not overwrite the table input")
    snapshots = [
        {"ioc": target.normalized, "data": []}
        for target in adapted.bundle.targets
    ]
    payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in snapshots)
    atomic_write_text(output_path, payload)
    report = adapted.report
    return {
        "output": str(resolve_path(output_path)),
        "selected_column": report.selected_column,
        "total_rows": report.total_rows,
        "parsed_count": report.parsed_count,
        "duplicate_count": report.duplicate_count,
        "error_count": report.error_count,
        "defang_restored_count": report.defang_restored_count,
        "formula_risk_count": report.formula_risk_count,
        "errors": report.errors[:20],
    }


def _run_export_bundle(args: argparse.Namespace) -> dict[str, Any]:
    verdicts = _read_jsonl(args.input, argument_name="--input")
    diagnostics = _read_json(args.diagnostics, argument_name="--diagnostics")
    diff = _read_json(args.diff, argument_name="--diff")
    protected = [args.input]
    if args.diagnostics:
        protected.append(args.diagnostics)
    if args.diff:
        protected.append(args.diff)
    result = export_bundle(
        verdicts,
        output_dir=Path(args.output_dir).expanduser(),
        base_name=args.base_name,
        diagnostics=diagnostics,
        diff=diff,
        protected_paths=protected,
    )
    return {
        "outputs": {name: str(path) for name, path in result.outputs.items()},
        "rows": len(verdicts),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="python -m ioc_rejudge roadmap",
        description="Offline roadmap operations adapter",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    job = commands.add_parser("job", help="run and inspect durable snapshot jobs")
    job_sub = job.add_subparsers(dest="job_command", required=True)
    job_start = job_sub.add_parser("start", help="start a legacy snapshot pipeline")
    job_start.add_argument("--input", required=True)
    job_start.add_argument("--job-dir", required=True)
    job_start.add_argument("--offline", action="store_true")
    for name, help_text in (
        ("status", "show one job"),
        ("resume", "resume pending targets"),
        ("retry-failed", "retry failed targets"),
        ("cancel", "cancel non-terminal targets"),
    ):
        command = job_sub.add_parser(name, help=help_text)
        command.add_argument("job_id")
        command.add_argument("--job-dir", required=True)

    review = commands.add_parser("review", help="list and label human review rows")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    review_list = review_sub.add_parser("list", help="list pending review rows")
    review_list.add_argument("--input", required=True)
    review_list.add_argument("--queue", required=True)
    review_label = review_sub.add_parser("label", help="append an analyst label")
    review_label.add_argument("--queue", required=True)
    review_label.add_argument("--ioc", required=True)
    review_label.add_argument("--decision", required=True, choices=("approved", "rejected", "pending"))
    review_label.add_argument("--note", default="")
    review_label.add_argument("--reviewer", default="")
    review_reopen = review_sub.add_parser("reopen", help="clear an analyst label")
    review_reopen.add_argument("--queue", required=True)
    review_reopen.add_argument("--ioc", required=True)
    review_reopen.add_argument("--note", default="")
    review_reopen.add_argument("--reviewer", default="")

    explain = commands.add_parser("explain", help="explain one verdict")
    explain.add_argument("--input", required=True)
    explain.add_argument("--ioc", required=True)

    health = commands.add_parser("health", help="configuration-only health checks")
    health.add_argument("--providers", required=True)
    health.add_argument("--cache-dir")
    health.add_argument("--offline", action="store_true")

    history = commands.add_parser("history", help="inspect persisted run history")
    history_sub = history.add_subparsers(dest="history_command", required=True)
    history_list = history_sub.add_parser("list", help="list stored runs")
    history_list.add_argument("--history-dir", required=True)
    history_get = history_sub.add_parser("get", help="show one stored run")
    history_get.add_argument("run_id")
    history_get.add_argument("--history-dir", required=True)
    history_baseline = history_sub.add_parser("baseline", help="select the previous run")
    history_baseline.add_argument("--history-dir", required=True)
    history_baseline.add_argument("--current-run-id")

    cache = commands.add_parser("cache", help="inspect or clean local caches")
    cache_sub = cache.add_subparsers(dest="cache_command", required=True)
    cache_inspect = cache_sub.add_parser("inspect", help="summarize cache contents")
    cache_inspect.add_argument("--cache-dir", required=True)
    cache_inspect.add_argument("--cache-type", choices=("all", "provider", "result"), default="all")
    cache_cleanup = cache_sub.add_parser("cleanup", help="plan or apply whole-shard cleanup")
    cache_cleanup.add_argument("--cache-dir", required=True)
    cache_cleanup.add_argument("--before", required=True)
    cache_cleanup.add_argument("--cache-type", choices=("all", "provider", "result"), default="all")
    cache_cleanup.add_argument("--apply", action="store_true")

    import_table = commands.add_parser("import-table", help="adapt CSV/XLSX to JSONL")
    import_table.add_argument("--input", required=True)
    import_table.add_argument("--column", required=True)
    import_table.add_argument("--output", required=True)

    export_bundle_parser = commands.add_parser("export-bundle", help="export result formats")
    export_bundle_parser.add_argument("--input", required=True)
    export_bundle_parser.add_argument("--output-dir", required=True)
    export_bundle_parser.add_argument("--base-name", default="results")
    export_bundle_parser.add_argument("--diagnostics")
    export_bundle_parser.add_argument("--diff")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "job":
            return _run_job_command(args)
        if args.command == "review":
            _emit(_run_review_command(args))
            return 0
        if args.command == "explain":
            rows = _read_jsonl(args.input, argument_name="--input")
            matches = [row for row in rows if row.get("ioc") == args.ioc]
            if not matches:
                raise RoadmapCliError(f"IOC not found in {args.input}: {args.ioc}")
            _emit(explain_verdict(matches[0]))
            return 0
        if args.command == "health":
            _emit(_run_health_command(args))
            return 0
        if args.command == "history":
            _emit(_run_history_command(args))
            return 0
        if args.command == "cache":
            _emit(_run_cache_command(args))
            return 0
        if args.command == "import-table":
            _emit(_run_import_table(args))
            return 0
        if args.command == "export-bundle":
            _emit(_run_export_bundle(args))
            return 0
        raise RoadmapCliError(f"unknown command: {args.command}")
    except (OSError, TypeError, ValueError, KeyError) as exc:
        payload = {"error": str(exc), "available": False}
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 1
    except Exception as exc:  # Keep the CLI contract JSON-only on unexpected failures.
        payload = {"error": f"internal error: {exc}", "available": False}
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 1


__all__ = ["main", "build_parser", "RoadmapCliError"]
