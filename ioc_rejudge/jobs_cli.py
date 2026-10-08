"""CLI command family for the unified job queue runner.

Commands::

    python -m ioc_rejudge jobs list|status|run|cancel|prune|results|export|explain|review|diff

The runner claims a queued job, runs bare (unified offline/online) or
jsonl (legacy offline) adjudication, writes results/diagnostics, and
finishes the job record. Online mode builds providers like the main CLI
(credentials from process env or an explicit credentials file only).

``results`` and ``export`` consume ``results.jsonl`` after a job succeeds.
``explain`` / ``review`` / ``diff`` reuse ``jobs_consumers`` over the same
job storage (review overlay is append-only and never rewrites conclusions).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import secrets
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from ioc_rejudge.job_queue import (
    DEFAULT_JOBS_DIR,
    DEFAULT_KEEP,
    JOB_STATES,
    InvalidJobStateError,
    JobNotFoundError,
    JobsQueueError,
    UnifiedJobQueue,
)
from ioc_rejudge.jobs_consumers import (
    ALLOWED_REVIEW_LABELS,
    JobsConsumerError,
    JobsConsumerUsageError,
    append_review,
    diff_jobs,
    explain_result,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_JOB = 3
EXIT_RUNNER = 4

DEFAULT_CACHE_DIR = Path("provider-cache")
RUNNER_NAME = "jobs-cli"
_PRUNE_PROTECTED_STATES = frozenset({"queued", "running"})
_EXPORT_FORMATS = frozenset({"jsonl", "csv", "xlsx"})
_RESULTS_DEFAULT_LIMIT = 20


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ioc_rejudge jobs",
        description=(
            "Unified job queue: list, status, run, cancel, prune, results, "
            "export, explain, review, diff"
        ),
    )
    parser.add_argument(
        "--jobs-dir",
        default=str(DEFAULT_JOBS_DIR),
        help=f"Job queue root directory (default: {DEFAULT_JOBS_DIR})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a single compact JSON object/array on stdout",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List jobs (newest first)")
    list_p.add_argument(
        "--state",
        choices=sorted(JOB_STATES | {"corrupt"}),
        default=None,
        help="Optional state filter",
    )
    list_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    list_p.add_argument("--json", action="store_true", help="JSON output")

    status_p = sub.add_parser("status", help="Show one job record")
    status_p.add_argument("job_id", help="Job id")
    status_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    status_p.add_argument("--json", action="store_true", help="JSON output")

    run_p = sub.add_parser("run", help="Claim and run one queued job (offline or online)")
    run_p.add_argument("job_id", help="Job id")
    run_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    run_p.add_argument(
        "--cache-dir",
        default=None,
        help=f"Provider cache directory (default: {DEFAULT_CACHE_DIR})",
    )
    run_p.add_argument(
        "--credentials-file",
        default=None,
        help="Provider credentials JSON (online only; default: process environment)",
    )
    run_p.add_argument(
        "--provider-config",
        default=None,
        help="Provider config JSON (online options + result_cache settings)",
    )
    run_p.add_argument(
        "--run-dir",
        default=None,
        help="Optional run audit directory for online provider raw copies",
    )
    run_p.add_argument("--json", action="store_true", help="JSON output")

    cancel_p = sub.add_parser("cancel", help="Cancel a queued or running job")
    cancel_p.add_argument("job_id", help="Job id")
    cancel_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    cancel_p.add_argument("--json", action="store_true", help="JSON output")

    prune_p = sub.add_parser("prune", help="Prune old jobs (default dry-run)")
    prune_p.add_argument(
        "--keep",
        type=int,
        default=DEFAULT_KEEP,
        help=f"Number of newest jobs to keep (default: {DEFAULT_KEEP})",
    )
    prune_p.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete; without this flag prune is dry-run only",
    )
    prune_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    prune_p.add_argument("--json", action="store_true", help="JSON output")

    results_p = sub.add_parser("results", help="Show adjudication result rows")
    results_p.add_argument("job_id", help="Job id")
    results_p.add_argument(
        "--limit",
        type=int,
        default=_RESULTS_DEFAULT_LIMIT,
        help=(
            f"Max rows to print (default: {_RESULTS_DEFAULT_LIMIT}; "
            "0 = all rows)"
        ),
    )
    results_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    results_p.add_argument("--json", action="store_true", help="JSON output")

    export_p = sub.add_parser("export", help="Export job results to jsonl/csv/xlsx")
    export_p.add_argument("job_id", help="Job id")
    export_p.add_argument(
        "--format",
        choices=sorted(_EXPORT_FORMATS),
        default="jsonl",
        dest="export_format",
        help="Export format (default: jsonl)",
    )
    export_p.add_argument(
        "--out",
        default=None,
        help="Explicit output path (refuse if the path already exists)",
    )
    export_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    export_p.add_argument("--json", action="store_true", help="JSON output")

    explain_p = sub.add_parser("explain", help="Explain one result row")
    explain_p.add_argument("job_id", help="Job id")
    explain_p.add_argument(
        "--result-id",
        required=True,
        help="Result id (embedded or derived {job_id}-{ordinal:06d})",
    )
    explain_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    explain_p.add_argument("--json", action="store_true", help="JSON output")

    review_p = sub.add_parser(
        "review",
        help="Append a human review label (overlay only; never rewrites conclusions)",
    )
    review_p.add_argument("job_id", help="Job id")
    review_p.add_argument("--ioc", required=True, help="IOC identity to label")
    review_p.add_argument(
        "--label",
        required=True,
        choices=sorted(ALLOWED_REVIEW_LABELS),
        help="Review label (whitelist)",
    )
    review_p.add_argument("--note", default="", help="Optional analyst note")
    review_p.add_argument("--reviewer", default="", help="Optional reviewer name")
    review_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    review_p.add_argument("--json", action="store_true", help="JSON output")

    diff_p = sub.add_parser(
        "diff",
        help="Compare a succeeded job against a succeeded baseline (report only)",
    )
    diff_p.add_argument("job_id", help="Current job id")
    diff_p.add_argument(
        "--baseline",
        required=True,
        dest="baseline_job_id",
        help="Baseline job id (must be succeeded)",
    )
    diff_p.add_argument("--jobs-dir", default=None, help="Override jobs directory")
    diff_p.add_argument("--json", action="store_true", help="JSON output")

    return parser


def _resolve_jobs_dir(args: argparse.Namespace, root_jobs_dir: str) -> Path:
    override = getattr(args, "jobs_dir", None)
    if override:
        return Path(override)
    return Path(root_jobs_dir)


def _emit_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _emit_error(message: str, *, as_json: bool, extra: dict[str, Any] | None = None) -> None:
    if as_json:
        body: dict[str, Any] = {"ok": False, "error": message}
        if extra:
            body.update(extra)
        _emit_json(body)
    else:
        print(f"ERROR: {message}", file=sys.stderr)


def _jsonable(value: Any) -> Any:
    """Convert *value* into a JSON-serializable structure."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    # Enum-like
    enum_value = getattr(value, "value", None)
    if enum_value is not None and not callable(enum_value) and value.__class__.__name__:
        try:
            from enum import Enum

            if isinstance(value, Enum):
                return _jsonable(enum_value)
        except Exception:
            pass
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _jsonable(to_dict())
        except Exception:
            pass
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return _jsonable(dataclasses.asdict(value))
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            raw = {
                k: v
                for k, v in vars(value).items()
                if not str(k).startswith("_")
            }
            return _jsonable(raw)
        except Exception:
            pass
    return str(value)


def _verdict_to_dict(verdict: Any) -> dict[str, Any]:
    if isinstance(verdict, dict):
        converted = _jsonable(verdict)
        return converted if isinstance(converted, dict) else {"value": converted}
    to_dict = getattr(verdict, "to_dict", None)
    if callable(to_dict):
        try:
            converted = _jsonable(to_dict())
            if isinstance(converted, dict):
                return converted
        except Exception:
            pass
    asdict_fn = getattr(verdict, "asdict", None)
    if callable(asdict_fn):
        try:
            converted = _jsonable(asdict_fn())
            if isinstance(converted, dict):
                return converted
        except Exception:
            pass
    if dataclasses.is_dataclass(verdict) and not isinstance(verdict, type):
        try:
            converted = _jsonable(dataclasses.asdict(verdict))
            if isinstance(converted, dict):
                return converted
        except Exception:
            pass
    if hasattr(verdict, "__dict__"):
        converted = _jsonable(
            {k: v for k, v in vars(verdict).items() if not str(k).startswith("_")}
        )
        if isinstance(converted, dict):
            return converted
    return {"value": str(verdict)}


def _diagnostics_to_dict(diagnostics: Any) -> dict[str, Any]:
    """Serialize unified or legacy diagnostics with field-level fallbacks."""
    if diagnostics is None:
        return {}
    to_dict = getattr(diagnostics, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
            if isinstance(payload, dict):
                return _jsonable(payload)
        except Exception:
            pass

    fields = (
        "input_path",
        "processed_count",
        "parse_error_count",
        "nested_data_error_count",
        "missing_data_count",
        "empty_data_count",
        "non_list_data_count",
        "no_ioc_count",
        "invalid_ioc_count",
        "skipped_total",
        "parse_error_samples",
        "skipped_row_samples",
        "provider_metrics",
        "provider_errors",
        "input_errors",
        "routes",
        "missing_required_providers",
        "classification_unknown",
        "processing_errors",
        "result_cache_hit",
        "result_cache_miss",
        "result_cache_miss_reasons",
        "result_cache_errors",
    )
    out: dict[str, Any] = {}
    for name in fields:
        if not hasattr(diagnostics, name):
            continue
        try:
            out[name] = _jsonable(getattr(diagnostics, name))
        except Exception as exc:
            out[name] = f"<unserializable: {exc}>"
    if not out:
        try:
            out = _jsonable(diagnostics)
            if not isinstance(out, dict):
                out = {"value": str(diagnostics)}
        except Exception as exc:
            out = {"error": f"diagnostics serialization failed: {exc}"}
    return out if isinstance(out, dict) else {"value": str(out)}


def _result_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    conclusions: Counter[str] = Counter()
    provider_statuses: Counter[str] = Counter()
    for row in rows:
        conclusion = row.get("conclusion")
        if conclusion is not None:
            conclusions[str(conclusion)] += 1
        statuses = row.get("provider_statuses")
        if isinstance(statuses, dict):
            for status in statuses.values():
                provider_statuses[str(status)] += 1
        elif statuses is not None:
            provider_statuses[str(statuses)] += 1
    return {
        "rows": len(rows),
        "conclusions": dict(conclusions),
        "provider_statuses": dict(provider_statuses),
    }


def _make_heartbeat(queue: UnifiedJobQueue, job_id: str):
    def _beat(*_args: Any, **_kwargs: Any) -> None:
        try:
            queue.heartbeat(job_id)
        except Exception:
            # Heartbeat must never abort adjudication mid-flight; lease recovery
            # remains best-effort for truly dead runners.
            pass

    return _beat


def _progress_tee(handlers):
    """Call each progress handler; one failure must not skip the others."""

    cleaned = [handler for handler in handlers if handler is not None]

    def _tee(*args: Any, **kwargs: Any) -> None:
        for handler in cleaned:
            try:
                handler(*args, **kwargs)
            except Exception:
                pass

    return _tee


def _run_bare_unified(
    input_path: Path,
    *,
    mode: str,
    preset: str,
    cache_dir: Path,
    progress,
    on_progress=None,
    credentials_path: Path | None = None,
    provider_config_path: Path | None = None,
    run_dir: Path | None = None,
    transport_factory=None,
    env: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Bare unified path for offline and online jobs (shared result cache)."""
    from ioc_rejudge.config import Config
    from ioc_rejudge.inputs import read_input_bundle
    from ioc_rejudge.pipeline import run_unified_pipeline
    from ioc_rejudge.providers.base import ProviderContext
    from ioc_rejudge.providers.factory import (
        DEFAULT_PROVIDERS,
        build_providers,
        load_result_cache_settings,
    )
    from ioc_rejudge.providers.memory import cap_positive_int, detect_memory_limits
    from ioc_rejudge.result_cache import AdjudicationResultCache

    offline = mode != "online"
    refresh = str(preset or "") == "refresh"
    if offline and refresh:
        raise RuntimeError("--offline and --refresh cannot be used together")
    if env is not None and credentials_path is not None:
        raise RuntimeError("env and credentials_path cannot be used together")

    bundle = read_input_bundle(str(input_path))
    if not bundle.targets:
        detail = "; ".join(bundle.errors[:5]) if bundle.errors else "no targets"
        raise RuntimeError(f"bare input produced no valid IOC targets ({detail})")

    config = Config()
    memory_limits = detect_memory_limits()
    config.provider_workers = cap_positive_int(
        config.provider_workers, memory_limits.provider_workers
    )
    result_cache_settings = load_result_cache_settings(provider_config_path)

    # Pipeline messages use *progress*; per-provider events use *on_progress*
    # (falls back to *progress* so a single heartbeat callback still works).
    event_sink = on_progress if on_progress is not None else progress

    if offline:
        providers = build_providers(
            list(DEFAULT_PROVIDERS),
            env={},
            credentials_path=None,
            config_path=provider_config_path,
            cache_dir=cache_dir,
            adjudication_config=config,
            offline=True,
            memory_limits=memory_limits,
            transport_factory=transport_factory,
        )
        context = ProviderContext(offline=True, refresh=False, on_progress=event_sink)
    else:
        online_kwargs: dict[str, Any] = {
            "config_path": provider_config_path,
            "cache_dir": cache_dir,
            "run_dir": run_dir,
            "adjudication_config": config,
            "offline": False,
            "memory_limits": memory_limits,
            "transport_factory": transport_factory,
        }
        if credentials_path is not None:
            online_kwargs["credentials_path"] = credentials_path
        elif env is not None:
            online_kwargs["env"] = env
        # else: build_providers reads process environment
        providers = build_providers(list(DEFAULT_PROVIDERS), **online_kwargs)
        context = ProviderContext(
            offline=False,
            refresh=refresh,
            run_dir=run_dir,
            on_progress=event_sink,
        )

    result_cache = None
    if (not refresh) and result_cache_settings.enabled:
        result_cache = AdjudicationResultCache(
            cache_dir, ttl=result_cache_settings.ttl
        )

    result = run_unified_pipeline(
        bundle,
        providers,
        config,
        context,
        progress=progress,
        result_cache=result_cache,
    )
    rows = [_verdict_to_dict(v) for v in (result.verdicts or [])]
    diagnostics = _diagnostics_to_dict(getattr(result, "diagnostics", None))
    return rows, diagnostics


def _run_jsonl_legacy(
    input_path: Path,
    *,
    progress,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from ioc_rejudge.cli import run_pipeline_with_diagnostics
    from ioc_rejudge.config import Config

    progress("legacy-pipeline-start")
    result = run_pipeline_with_diagnostics(str(input_path), Config())
    progress("legacy-pipeline-complete")
    rows = [_verdict_to_dict(v) for v in (result.verdicts or [])]
    diagnostics = _diagnostics_to_dict(getattr(result, "diagnostics", None))
    return rows, diagnostics


def _jobs_dir_abs(queue: UnifiedJobQueue) -> str:
    """Absolute path of the jobs root actually being read."""
    try:
        return str(queue.root.resolve())
    except OSError:
        return str(queue.root.absolute())


def _read_result_rows(job_dir: Path) -> tuple[list[dict[str, Any]], int]:
    """Parse ``results.jsonl`` in *job_dir*.

    Returns ``(rows, skipped)`` where *skipped* counts non-empty lines that
    failed ``json.loads`` or did not yield a dict. Blank lines are ignored.
    """
    path = job_dir / "results.jsonl"
    if not path.is_file():
        return [], 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], 0
    rows: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            skipped += 1
    return rows, skipped


def _apply_row_limit(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Return *rows* truncated by *limit* (0 or negative = no truncation)."""
    if limit is None:
        return rows
    if int(limit) <= 0:
        return rows
    return rows[: int(limit)]


def _format_result_line(row: dict[str, Any]) -> str:
    ioc = row.get("ioc", "")
    conclusion = row.get("conclusion", "")
    route = row.get("route", "")
    disposition = row.get("disposition", "")
    return f"{ioc} -> {conclusion} ({route}/{disposition})"


def _unique_default_export_path(export_dir: Path, fmt: str) -> Path:
    """Pick ``results.<fmt>`` or ``results-<hex4>.<fmt>`` without overwriting."""
    export_dir.mkdir(parents=True, exist_ok=True)
    primary = export_dir / f"results.{fmt}"
    if not primary.exists():
        return primary
    # Collision: keep trying a short random suffix until free.
    for _ in range(64):
        candidate = export_dir / f"results-{secrets.token_hex(4)}.{fmt}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"unable to allocate unique export path under {export_dir}")


class JobExportError(Exception):
    """Export failure mapped to a jobs CLI exit code."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: int = EXIT_JOB,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.exit_code = int(exit_code)
        self.message = str(message)
        self.extra = dict(extra) if extra else {}


def export_job_results(
    queue: UnifiedJobQueue,
    job_id: str,
    *,
    fmt: str = "jsonl",
    out: str | Path | None = None,
) -> dict[str, Any]:
    """Export a succeeded job's ``results.jsonl`` to jsonl/csv/xlsx.

    Writes under ``<job>/export/`` by default (collision-safe names) or to
    *out* when provided. Never overwrites an existing file.

    Returns ``{ok, rows, path, format, job_id}`` plus optional ``skipped``.
    Raises :class:`JobExportError` on validation or I/O failure.
    """
    try:
        job = queue.get(job_id)
    except JobNotFoundError as exc:
        raise JobExportError(f"job not found: {job_id}", exit_code=EXIT_JOB) from exc
    except (JobsQueueError, InvalidJobStateError) as exc:
        raise JobExportError(str(exc), exit_code=EXIT_JOB) from exc

    state = str(job.get("state") or "")
    if state != "succeeded":
        raise JobExportError(
            f"job is not succeeded (state={state}); export requires succeeded",
            exit_code=EXIT_JOB,
            extra={"job_id": job_id, "state": state},
        )

    safe_fmt = str(fmt or "jsonl").lower()
    if safe_fmt not in _EXPORT_FORMATS:
        raise JobExportError(
            f"unsupported export format: {safe_fmt}",
            exit_code=EXIT_USAGE,
        )

    job_dir = queue.root / job_id
    rows, skipped = _read_result_rows(job_dir)

    if out is not None:
        destination = Path(out)
        if destination.exists():
            raise JobExportError(
                f"output already exists (refusing overwrite): {destination}",
                exit_code=EXIT_JOB,
                extra={"path": str(destination)},
            )
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise JobExportError(
                f"cannot create output directory: {exc}",
                exit_code=EXIT_RUNNER,
            ) from exc
    else:
        export_dir = job_dir / "export"
        try:
            destination = _unique_default_export_path(export_dir, safe_fmt)
        except RuntimeError as exc:
            raise JobExportError(str(exc), exit_code=EXIT_RUNNER) from exc

    # Final race guard: never overwrite an existing file.
    if destination.exists():
        raise JobExportError(
            f"output already exists (refusing overwrite): {destination}",
            exit_code=EXIT_JOB,
            extra={"path": str(destination)},
        )

    from ioc_rejudge.export import export_csv, export_excel, export_jsonl

    try:
        if safe_fmt == "jsonl":
            export_jsonl(rows, str(destination))
        elif safe_fmt == "csv":
            export_csv(rows, str(destination))
        else:
            export_excel(rows, str(destination))
    except Exception as exc:
        raise JobExportError(
            f"{type(exc).__name__}: {exc}",
            exit_code=EXIT_RUNNER,
            extra={"job_id": job_id},
        ) from exc

    try:
        out_path = str(destination.resolve())
    except OSError:
        out_path = str(destination)

    payload: dict[str, Any] = {
        "ok": True,
        "rows": len(rows),
        "path": out_path,
        "format": safe_fmt,
        "job_id": job_id,
    }
    if skipped:
        payload["skipped"] = skipped
    return payload


def _cmd_list(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    jobs = queue.list_jobs(state=getattr(args, "state", None))
    jobs_dir = _jobs_dir_abs(queue)
    if args.json:
        _emit_json({"jobs": jobs, "count": len(jobs), "jobs_dir": jobs_dir})
        return EXIT_OK
    print(f"jobs dir: {jobs_dir}")
    if not jobs:
        print("(no jobs)")
        return EXIT_OK
    for job in jobs:
        job_id = job.get("job_id", "?")
        state = job.get("state", "?")
        created = job.get("created_at", "")
        inp = job.get("input") if isinstance(job.get("input"), dict) else {}
        valid = inp.get("valid", "")
        mode = job.get("mode", "")
        error = job.get("error") or ""
        line = f"{job_id}  state={state}  mode={mode}  valid={valid}  created={created}"
        if error:
            line += f"  error={error}"
        print(line)
    return EXIT_OK


def _cmd_status(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    try:
        job = queue.get(args.job_id)
    except JobNotFoundError:
        _emit_error(f"job not found: {args.job_id}", as_json=args.json)
        return EXIT_JOB
    except (JobsQueueError, InvalidJobStateError) as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_JOB
    if args.json:
        _emit_json(job)
        return EXIT_OK
    print(f"job_id:   {job.get('job_id')}")
    print(f"state:    {job.get('state')}")
    print(f"mode:     {job.get('mode')}")
    print(f"preset:   {job.get('preset')}")
    print(f"created:  {job.get('created_at')}")
    print(f"updated:  {job.get('updated_at')}")
    inp = job.get("input") if isinstance(job.get("input"), dict) else {}
    print(
        f"input:    kind={inp.get('input_kind')} valid={inp.get('valid')} "
        f"dup={inp.get('duplicated')} rejected={inp.get('rejected')} "
        f"source={inp.get('source')}"
    )
    if job.get("runner"):
        print(f"runner:   {job.get('runner')}")
    if job.get("result_summary"):
        print(f"summary:  {job.get('result_summary')}")
    if job.get("error"):
        print(f"error:    {job.get('error')}")
    if job.get("cancel_requested"):
        print("cancel_requested: true")
    return EXIT_OK


def _cmd_cancel(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    try:
        result = queue.request_cancel(args.job_id)
    except JobNotFoundError:
        _emit_error(f"job not found: {args.job_id}", as_json=args.json)
        return EXIT_JOB
    except InvalidJobStateError as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_JOB
    except JobsQueueError as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_JOB

    action = result.get("action", "unknown")
    try:
        job = queue.get(args.job_id)
        state = job.get("state")
    except JobsQueueError:
        state = None
    payload = {"action": action, "job_id": args.job_id, "state": state, "ok": True}
    if args.json:
        _emit_json(payload)
    else:
        print(f"{action}: {args.job_id}" + (f" (state={state})" if state else ""))
    return EXIT_OK


def prune_jobs(
    queue: UnifiedJobQueue,
    *,
    keep: int = DEFAULT_KEEP,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Prune oldest jobs beyond *keep*, never deleting queued/running jobs.

    Mirrors ``UnifiedJobQueue.prune`` retention math while skipping active
    states so apply cannot remove in-flight work even when it falls outside
    the keep window.
    """
    if not isinstance(keep, int) or keep < 0:
        raise InvalidJobStateError("keep must be a non-negative int")

    entries: list[tuple[str, str, Path, int, str]] = []
    try:
        children = list(queue.root.iterdir())
    except OSError:
        children = []

    for child in children:
        if not child.is_dir() or child.name.startswith("."):
            continue
        job_id = child.name
        try:
            document = queue.get(job_id)
        except (JobNotFoundError, JobsQueueError, InvalidJobStateError):
            continue
        except Exception:
            # Corrupt / unreadable records are excluded from the keep set,
            # matching queue.prune behaviour for bad metadata.
            continue
        created = document.get("created_at")
        created_s = created if isinstance(created, str) else ""
        state = str(document.get("state") or "")
        size = 0
        try:
            for root, _dirs, files in os.walk(child):
                for name in files:
                    try:
                        size += (Path(root) / name).stat().st_size
                    except OSError:
                        pass
        except OSError:
            size = 0
        entries.append((created_s, job_id, child, size, state))

    entries.sort(key=lambda item: (item[0], item[1]))
    removed_ids: list[str] = []
    freed = 0
    if len(entries) > keep:
        candidates = entries[: len(entries) - keep]
        for _created, job_id, path, size, state in candidates:
            if state in _PRUNE_PROTECTED_STATES:
                continue
            removed_ids.append(job_id)
            freed += size
            if not dry_run:
                shutil.rmtree(path, ignore_errors=True)

    kept = len(entries) - len(removed_ids)
    return {
        "kept": kept,
        "removed": removed_ids,
        "freed_bytes": freed,
        "dry_run": dry_run,
        "ok": True,
    }


def _cmd_prune(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    keep = int(args.keep)
    dry_run = not bool(args.apply)
    try:
        result = prune_jobs(queue, keep=keep, dry_run=dry_run)
    except (JobsQueueError, InvalidJobStateError) as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_USAGE
    payload = {
        "kept": result.get("kept"),
        "removed": result.get("removed"),
        "freed_bytes": result.get("freed_bytes"),
        "dry_run": dry_run,
        "ok": True,
    }
    if args.json:
        _emit_json(payload)
    else:
        mode = "dry-run" if dry_run else "applied"
        removed = result.get("removed") or []
        print(
            f"prune ({mode}): kept={result.get('kept')} "
            f"removed={len(removed)} freed_bytes={result.get('freed_bytes')}"
        )
        for job_id in removed:
            print(f"  - {job_id}")
    return EXIT_OK


def run_job(
    queue: UnifiedJobQueue,
    job_id: str,
    *,
    cache_dir: Path,
    runner_name: str = RUNNER_NAME,
    pid: int | None = None,
    credentials_path: Path | str | None = None,
    provider_config_path: Path | str | None = None,
    run_dir: Path | str | None = None,
    transport_factory=None,
    env: dict[str, str] | None = None,
    progress=None,
    on_progress=None,
    live_progress: bool = False,
) -> dict[str, Any]:
    """Claim one queued job, execute offline or online, and finish the record.

    Returns a JSON-serializable status dict. Callers map the dict onto their
    own exit codes or HTTP responses. Does not print or raise for expected
    job-state outcomes (not found, not queued, cancel). Unexpected finish
    failures set ``ok=False`` with ``state="failed"``.

    Online credentials come only from *credentials_path*, explicit *env*, or
    the process environment (when both are omitted). Credential values never
    land in jobs storage files. Optional *transport_factory* is for UI/test
    injection only (same contract as ``build_providers``).

    *progress* receives pipeline completion messages; *on_progress* receives
    per-provider ``ProgressEvent`` values. Both are always combined with the
    queue heartbeat so lease renewal is never dropped. When *live_progress*
    is true, a ``LiveProgress`` renderer is created only after a successful
    claim (cancelled/pre-start paths skip it).
    """
    cache_path = Path(cache_dir)
    runner_pid = os.getpid() if pid is None else pid
    cred_path = Path(credentials_path) if credentials_path else None
    config_path = Path(provider_config_path) if provider_config_path else None
    audit_dir = Path(run_dir) if run_dir else None
    if env is not None and cred_path is not None:
        return {
            "ok": False,
            "error": "env and credentials_path cannot be used together",
            "job_id": job_id,
            "exit_code": EXIT_JOB,
        }

    try:
        existing = queue.get(job_id)
    except JobNotFoundError:
        return {
            "ok": False,
            "error": f"job not found: {job_id}",
            "job_id": job_id,
            "exit_code": EXIT_JOB,
        }
    except JobsQueueError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "job_id": job_id,
            "exit_code": EXIT_JOB,
            "retryable": True,
        }

    mode = str(existing.get("mode") or "offline")
    preset = str(existing.get("preset") or "standard")

    try:
        claimed = queue.claim(job_id, runner_name=runner_name, pid=runner_pid)
    except JobNotFoundError:
        return {
            "ok": False,
            "error": f"job not found: {job_id}",
            "job_id": job_id,
            "exit_code": EXIT_JOB,
        }
    except JobsQueueError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "job_id": job_id,
            "exit_code": EXIT_JOB,
            "retryable": True,
        }

    if claimed is None:
        state = existing.get("state", "unknown")
        return {
            "ok": False,
            "error": f"job is not queued (state={state})",
            "job_id": job_id,
            "state": state,
            "exit_code": EXIT_JOB,
        }

    # Pre-start cancel: claim succeeded but cancel_requested was already set.
    if claimed.get("cancel_requested"):
        try:
            cancelled = queue.mark_cancelled(
                job_id, note="cancel_requested before start"
            )
        except (JobsQueueError, InvalidJobStateError) as exc:
            return {
                "ok": False,
                "error": str(exc),
                "job_id": job_id,
                "exit_code": EXIT_JOB,
            }
        return {
            "ok": True,
            "job_id": job_id,
            "state": cancelled.get("state", "cancelled"),
            "action": "cancelled",
            "exit_code": EXIT_OK,
        }

    heartbeat = _make_heartbeat(queue, job_id)
    heartbeat()

    live = None
    if live_progress:
        from ioc_rejudge.progress import LiveProgress

        live = LiveProgress()

    # Heartbeat always stays on both sinks so long provider collection renews
    # the lease. Render / caller hooks are isolated via _progress_tee.
    message_handlers: list[Any] = [heartbeat]
    if progress is not None:
        message_handlers.append(progress)
    if live is not None:
        message_handlers.append(live.message)
    progress_cb = _progress_tee(message_handlers)

    event_handlers: list[Any] = [heartbeat]
    if on_progress is not None:
        event_handlers.append(on_progress)
    if live is not None:
        event_handlers.append(live.event)
    on_progress_cb = _progress_tee(event_handlers)

    input_block = claimed.get("input") if isinstance(claimed.get("input"), dict) else {}
    input_kind = input_block.get("input_kind", "bare")
    job_dir = queue.root / job_id
    if input_kind == "jsonl":
        input_path = job_dir / "input.jsonl"
    else:
        input_path = job_dir / "input.txt"

    rows: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}
    summary: dict[str, Any] = {}
    try:
        heartbeat()
        if input_kind == "bare":
            rows, diagnostics = _run_bare_unified(
                input_path,
                mode=mode,
                preset=preset,
                cache_dir=cache_path,
                progress=progress_cb,
                on_progress=on_progress_cb,
                credentials_path=cred_path,
                provider_config_path=config_path,
                run_dir=audit_dir,
                transport_factory=transport_factory,
                env=env,
            )
        elif input_kind == "jsonl":
            if mode == "online":
                raise RuntimeError(
                    "online mode does not support legacy jsonl input_kind"
                )
            rows, diagnostics = _run_jsonl_legacy(
                input_path, progress=progress_cb
            )
        else:
            raise RuntimeError(f"unsupported input_kind {input_kind!r}")
        heartbeat()

        queue.append_results(job_id, rows)
        queue.write_diagnostics(
            job_id, diagnostics if isinstance(diagnostics, dict) else {}
        )
        summary = _result_summary(rows)
        # Surface result-cache counters in the job summary when present.
        if isinstance(diagnostics, dict):
            hit = diagnostics.get("result_cache_hit")
            miss = diagnostics.get("result_cache_miss")
            if hit is not None or miss is not None:
                summary = dict(summary)
                if hit is not None:
                    summary["result_cache_hit"] = hit
                if miss is not None:
                    summary["result_cache_miss"] = miss
        finished = queue.finish(
            job_id, state="succeeded", result_summary=summary
        )
    except Exception as exc:
        err_text = str(exc)[:500] or type(exc).__name__
        try:
            queue.finish(job_id, state="failed", error=err_text)
        except Exception as finish_exc:
            return {
                "ok": False,
                "error": (
                    f"runner failed ({err_text}); "
                    f"also failed to finish job: {finish_exc}"
                ),
                "job_id": job_id,
                "exit_code": EXIT_RUNNER,
            }
        return {
            "ok": False,
            "error": err_text,
            "job_id": job_id,
            "state": "failed",
            "exit_code": EXIT_RUNNER,
        }
    finally:
        if live is not None:
            try:
                live.close()
            except Exception:
                pass

    return {
        "ok": True,
        "job_id": job_id,
        "state": finished.get("state", "succeeded"),
        "mode": mode,
        "result_summary": finished.get("result_summary") or summary,
        "exit_code": EXIT_OK,
    }


# Backward-compatible name used by earlier UI wiring.
run_offline_job = run_job


def _cmd_run(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    jobs_dir = _jobs_dir_abs(queue)
    cache_dir = Path(args.cache_dir) if args.cache_dir else DEFAULT_CACHE_DIR
    cred = getattr(args, "credentials_file", None)
    provider_config = getattr(args, "provider_config", None)
    run_dir = getattr(args, "run_dir", None)
    if not args.json:
        print(f"jobs dir: {jobs_dir}")
    # Human-readable mode reuses LiveProgress (TTY redraw / non-TTY throttle).
    # --json must keep stdout as a single final object with no progress lines.
    payload = run_job(
        queue,
        job_id,
        cache_dir=cache_dir,
        credentials_path=Path(cred) if cred else None,
        provider_config_path=Path(provider_config) if provider_config else None,
        run_dir=Path(run_dir) if run_dir else None,
        live_progress=not bool(args.json),
    )
    exit_code = int(payload.get("exit_code", EXIT_RUNNER))

    if not payload.get("ok"):
        extra = {
            key: payload[key]
            for key in ("job_id", "state", "mode")
            if key in payload
        }
        extra["jobs_dir"] = jobs_dir
        _emit_error(
            str(payload.get("error") or "runner failed"),
            as_json=args.json,
            extra=extra,
        )
        return exit_code

    if payload.get("action") == "cancelled":
        if args.json:
            _emit_json(
                {
                    "ok": True,
                    "job_id": job_id,
                    "state": payload.get("state", "cancelled"),
                    "action": "cancelled",
                    "jobs_dir": jobs_dir,
                }
            )
        else:
            print(f"cancelled: {job_id}")
        return EXIT_OK

    if args.json:
        _emit_json(
            {
                "ok": True,
                "job_id": job_id,
                "state": payload.get("state", "succeeded"),
                "result_summary": payload.get("result_summary"),
                "jobs_dir": jobs_dir,
            }
        )
    else:
        summary_out = payload.get("result_summary") or {}
        print(
            f"succeeded: {job_id}  rows={summary_out.get('rows')}  "
            f"conclusions={summary_out.get('conclusions')}"
        )
    return EXIT_OK


def _cmd_results(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    try:
        job = queue.get(job_id)
    except JobNotFoundError:
        _emit_error(f"job not found: {job_id}", as_json=args.json)
        return EXIT_JOB
    except (JobsQueueError, InvalidJobStateError) as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_JOB

    state = str(job.get("state") or "")
    limit = int(getattr(args, "limit", _RESULTS_DEFAULT_LIMIT))

    if state != "succeeded":
        rows: list[dict[str, Any]] = []
        skipped = 0
        if args.json:
            _emit_json(
                {
                    "job_id": job_id,
                    "state": state,
                    "rows": rows,
                    "skipped": skipped,
                    "message": f"no result rows while state={state}",
                }
            )
        else:
            print(f"(no results: job state is {state})")
        return EXIT_OK

    job_dir = queue.root / job_id
    rows, skipped = _read_result_rows(job_dir)
    shown = _apply_row_limit(rows, limit)

    if args.json:
        _emit_json(
            {
                "job_id": job_id,
                "state": state,
                "rows": shown,
                "skipped": skipped,
                "total": len(rows),
            }
        )
        return EXIT_OK

    if not rows:
        print("(no results)")
        if skipped:
            print(f"(skipped {skipped} unreadable line(s))")
        return EXIT_OK

    for row in shown:
        print(_format_result_line(row))
    if limit > 0 and len(rows) > limit:
        print(f"(showing {limit} of {len(rows)} rows; use --limit 0 for all)")
    if skipped:
        print(f"(skipped {skipped} unreadable line(s))")
    return EXIT_OK


def _cmd_export(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    fmt = str(getattr(args, "export_format", None) or "jsonl").lower()
    out_arg = getattr(args, "out", None)
    try:
        payload = export_job_results(queue, job_id, fmt=fmt, out=out_arg)
    except JobExportError as exc:
        _emit_error(
            exc.message,
            as_json=args.json,
            extra=exc.extra or None,
        )
        return int(exc.exit_code)

    if args.json:
        _emit_json(payload)
    else:
        out_path = payload.get("path", "")
        print(f"exported: {payload.get('rows', 0)} rows -> {out_path}")
        skipped = payload.get("skipped")
        if skipped:
            print(f"(skipped {skipped} unreadable line(s) before export)")
    return EXIT_OK


def _cmd_explain(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    result_id = str(getattr(args, "result_id", "") or "")
    try:
        payload = explain_result(queue.root, job_id, result_id=result_id)
    except JobsConsumerUsageError as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_USAGE
    except JobsConsumerError as exc:
        _emit_error(str(exc), as_json=args.json, extra={"job_id": job_id})
        return int(getattr(exc, "exit_code", EXIT_JOB) or EXIT_JOB)

    if args.json:
        _emit_json(payload)
        return EXIT_OK

    print(f"result_id:  {payload.get('result_id')}")
    print(f"ioc:        {payload.get('ioc')}")
    print(f"conclusion: {payload.get('conclusion')}")
    print(f"reason:     {payload.get('reason')}")
    print(f"rule_path:  {payload.get('rule_path')}")
    accepted = payload.get("accepted_evidence") or []
    rejected = payload.get("rejected_evidence") or []
    print(f"evidence:   accepted={len(accepted)} rejected={len(rejected)}")
    if payload.get("evidence_fingerprint"):
        print(f"fingerprint:{payload.get('evidence_fingerprint')}")
    review = payload.get("review")
    if isinstance(review, dict) and (
        review.get("label") or review.get("note") or review.get("reviewed_at")
    ):
        print(
            f"review:     label={review.get('label')} "
            f"reviewer={review.get('reviewer')} "
            f"note={review.get('note')}"
        )
    if payload.get("skipped"):
        print(f"(skipped {payload.get('skipped')} unreadable line(s))")
    return EXIT_OK


def _cmd_review(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    try:
        payload = append_review(
            queue.root,
            job_id,
            ioc=str(getattr(args, "ioc", "") or ""),
            label=str(getattr(args, "label", "") or ""),
            note=str(getattr(args, "note", "") or ""),
            reviewer=str(getattr(args, "reviewer", "") or ""),
        )
    except JobsConsumerUsageError as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_USAGE
    except JobsConsumerError as exc:
        _emit_error(str(exc), as_json=args.json, extra={"job_id": job_id})
        return int(getattr(exc, "exit_code", EXIT_JOB) or EXIT_JOB)

    if args.json:
        _emit_json(payload)
        return EXIT_OK

    print(
        f"reviewed: {payload.get('ioc')} label={payload.get('label')} "
        f"reviewer={payload.get('reviewer')}"
    )
    if payload.get("note"):
        print(f"note: {payload.get('note')}")
    if payload.get("reviewed_at"):
        print(f"reviewed_at: {payload.get('reviewed_at')}")
    return EXIT_OK


def _format_diff_summary(payload: dict[str, Any]) -> str:
    body = payload.get("diff") if isinstance(payload.get("diff"), dict) else payload
    operations = body.get("operations", 0)
    changed = body.get("changed") or []
    b2w = body.get("black_to_white") or []
    w2b = body.get("white_to_black") or []
    to_gray = body.get("to_gray") or []
    to_review = body.get("to_review") or []
    ops_changes = body.get("operational_changes") or []
    return (
        f"diff: job={payload.get('job_id')} baseline={payload.get('baseline_job_id')} "
        f"operations={operations} changed={len(changed)} "
        f"black_to_white={len(b2w)} white_to_black={len(w2b)} "
        f"to_gray={len(to_gray)} to_review={len(to_review)} "
        f"operational_changes={len(ops_changes)}"
    )


def _cmd_diff(queue: UnifiedJobQueue, args: argparse.Namespace) -> int:
    job_id = args.job_id
    baseline_job_id = str(getattr(args, "baseline_job_id", "") or "")
    try:
        payload = diff_jobs(queue.root, job_id, baseline_job_id)
    except JobsConsumerUsageError as exc:
        _emit_error(str(exc), as_json=args.json)
        return EXIT_USAGE
    except JobsConsumerError as exc:
        _emit_error(
            str(exc),
            as_json=args.json,
            extra={"job_id": job_id, "baseline_job_id": baseline_job_id},
        )
        return int(getattr(exc, "exit_code", EXIT_JOB) or EXIT_JOB)

    if args.json:
        _emit_json(payload)
        return EXIT_OK

    print(_format_diff_summary(payload))
    body = payload.get("diff") if isinstance(payload.get("diff"), dict) else {}
    transitions = body.get("transitions") or {}
    if transitions:
        parts = [f"{key}={count}" for key, count in sorted(transitions.items())]
        print("transitions: " + ", ".join(parts))
    skipped = payload.get("skipped")
    if isinstance(skipped, dict) and (skipped.get("current") or skipped.get("baseline")):
        print(
            f"(skipped current={skipped.get('current', 0)} "
            f"baseline={skipped.get('baseline', 0)} unreadable line(s))"
        )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(raw)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return EXIT_OK
        if isinstance(code, int):
            return code
        return EXIT_USAGE

    # Parent-level --jobs-dir / --json apply when subcommand omits them.
    # Subparsers redefine the flags; prefer subcommand value when present,
    # else fall back to values parsed from a lightweight pre-pass.
    root_jobs_dir = str(DEFAULT_JOBS_DIR)
    root_json = False
    # Re-parse known root flags from raw for defaults when subcommand used None.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--jobs-dir", default=str(DEFAULT_JOBS_DIR))
    pre.add_argument("--json", action="store_true")
    pre_args, _ = pre.parse_known_args(raw)
    root_jobs_dir = pre_args.jobs_dir
    root_json = bool(pre_args.json)

    if getattr(args, "jobs_dir", None) is None:
        args.jobs_dir = root_jobs_dir
    if not getattr(args, "json", False) and root_json:
        args.json = True

    jobs_dir = Path(args.jobs_dir) if args.jobs_dir else Path(root_jobs_dir)
    queue = UnifiedJobQueue(jobs_dir)

    # Every jobs command recovers stale leases first.
    try:
        queue.recover_stale()
    except Exception:
        pass

    command = args.command
    if command == "list":
        return _cmd_list(queue, args)
    if command == "status":
        return _cmd_status(queue, args)
    if command == "run":
        return _cmd_run(queue, args)
    if command == "cancel":
        return _cmd_cancel(queue, args)
    if command == "prune":
        return _cmd_prune(queue, args)
    if command == "results":
        return _cmd_results(queue, args)
    if command == "export":
        return _cmd_export(queue, args)
    if command == "explain":
        return _cmd_explain(queue, args)
    if command == "review":
        return _cmd_review(queue, args)
    if command == "diff":
        return _cmd_diff(queue, args)

    _emit_error(f"unknown command: {command}", as_json=bool(getattr(args, "json", False)))
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
