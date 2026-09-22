"""Local offline workbench backend over the legacy snapshot pipeline."""

from __future__ import annotations

import json
import hashlib
import os
import secrets
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_rejudge.cli import run_pipeline_with_diagnostics
from ioc_rejudge.config import Config
from ioc_rejudge.export import export_csv, export_excel, export_jsonl
from ioc_rejudge.explanations import explain_verdict
from ioc_rejudge.files import atomic_write_text
from ioc_rejudge.diff import compare_verdicts
from ioc_rejudge.review_queue import label_review_queue, load_queue
from ioc_rejudge.workbench import (
    LocalWorkbenchAdapter,
    WorkbenchValidationError,
)


_RESULT_EXPORT_FIELDS = {
    "result_id",
    "ioc",
    "conclusion",
    "malicious_nature",
    "activity_status",
    "confidence",
    "review_suggestion",
    "reason",
    "route",
    "disposition",
    "provider_statuses",
    "missing_required_providers",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration_seconds(started: str | None, finished: str | None) -> float | None:
    if not started or not finished:
        return None
    try:
        start = datetime.fromisoformat(started)
        end = datetime.fromisoformat(finished)
    except (TypeError, ValueError):
        return None
    return max(0.0, round((end - start).total_seconds(), 6))


class OfflineWorkbenchAdapter(LocalWorkbenchAdapter):
    """Persist a complete task lifecycle without provider/network transport.

    The backend deliberately runs the accepted legacy snapshot pipeline.  It
    therefore has no live provider mode and fails closed if callers request
    providers or disable offline mode.
    """

    def __init__(self, workbench_dir: str | Path) -> None:
        super().__init__(workbench_dir)
        self._task_lock = threading.RLock()
        self._recover_incomplete_tasks()

    def _recover_incomplete_tasks(self) -> None:
        """Mark work left by a previous process as failed, never as running."""
        tasks_dir = self._safe_join("tasks")
        if not tasks_dir.is_dir():
            return
        for task_path in sorted(tasks_dir.glob("*/task.json")):
            try:
                task = json.loads(task_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError):
                continue
            if not isinstance(task, dict) or task.get("state") not in {
                "queued", "pending", "running"
            }:
                continue
            task["state"] = "failed"
            task["error"] = "workbench service restarted before task completed"
            task["finished_at_utc"] = _utc_now()
            try:
                atomic_write_text(
                    task_path,
                    json.dumps(task, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                )
            except OSError:
                continue

    def _task_path(self, task_id: str) -> Path:
        return self._safe_join("tasks", task_id, "task.json")

    def _load_task(self, task_id: str) -> dict[str, Any]:
        task_id = self._safe_id(task_id, "task_id")
        path = self._task_path(task_id)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise WorkbenchValidationError(f"task not found: {task_id}") from exc
        except (OSError, TypeError, ValueError) as exc:
            raise WorkbenchValidationError(f"task {task_id} is unreadable") from exc
        if not isinstance(document, dict):
            raise WorkbenchValidationError(f"task {task_id} is malformed")
        return document

    def _save_task(self, task: dict[str, Any]) -> None:
        path = self._task_path(str(task["task_id"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            path,
            json.dumps(task, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )

    def _staged_path(self, import_id: str) -> Path:
        import_id = self._safe_id(import_id, "import_id")
        manifest_path = self._safe_join("staging", import_id, "import.json")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise WorkbenchValidationError(f"import not found: {import_id}") from exc
        except (OSError, TypeError, ValueError) as exc:
            raise WorkbenchValidationError(f"import {import_id} is unreadable") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("filename"), str):
            raise WorkbenchValidationError(f"import {import_id} is malformed")
        filename = self._safe_filename(manifest["filename"])
        staged_path = self._safe_join("staging", import_id, filename)
        if not staged_path.is_file():
            raise WorkbenchValidationError(f"imported input is missing: {import_id}")
        return staged_path

    @staticmethod
    def _result_id(task_id: str, ordinal: int) -> str:
        return f"{task_id}-{ordinal:06d}"

    def _read_results(self, task_id: str) -> list[dict[str, Any]]:
        task = self._load_task(task_id)
        if task.get("state") in {"failed", "cancelled", "queued", "pending", "running"}:
            return []
        result_path = self._safe_join("tasks", task_id, "results.jsonl")
        try:
            lines = result_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError as exc:
            raise WorkbenchValidationError(f"task results are missing: {task_id}") from exc
        except OSError as exc:
            raise WorkbenchValidationError(f"cannot read task results: {task_id}") from exc
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(lines, 1):
            try:
                value = json.loads(line)
            except (TypeError, ValueError) as exc:
                raise WorkbenchValidationError(
                    f"task {task_id} result line {line_number} is malformed"
                ) from exc
            if not isinstance(value, dict):
                raise WorkbenchValidationError(
                    f"task {task_id} result line {line_number} is not an object"
                )
            rows.append(value)
        return rows

    @staticmethod
    def _has_provider_issue(row: dict[str, Any]) -> bool:
        """Match actionable provider failures without treating no_data as error."""
        missing = row.get("missing_required_providers")
        if isinstance(missing, (list, tuple, set)) and any(str(item).strip() for item in missing):
            return True
        statuses = row.get("provider_statuses")
        if not isinstance(statuses, dict):
            return False
        return any(
            str(status).casefold() in {"error", "disabled", "failed", "timeout"}
            for status in statuses.values()
        )

    @staticmethod
    def _filter_rows(
        rows: list[dict[str, Any]],
        *,
        dispositions: list[str] | None,
        query: str | None,
        provider_issues: bool | None = None,
    ) -> list[dict[str, Any]]:
        filtered = rows
        if dispositions is not None:
            wanted = set(dispositions)
            filtered = [row for row in filtered if row.get("disposition") in wanted]
        if provider_issues:
            filtered = [row for row in filtered if OfflineWorkbenchAdapter._has_provider_issue(row)]
        if query:
            lowered = query.casefold()
            filtered = [
                row
                for row in filtered
                if lowered in json.dumps(row, ensure_ascii=False).casefold()
            ]
        return filtered

    @classmethod
    def _filter_indexed_rows(
        cls,
        rows: list[dict[str, Any]],
        *,
        dispositions: list[str] | None,
        query: str | None,
        provider_issues: bool | None = None,
    ) -> list[tuple[int, dict[str, Any]]]:
        """Return source ordinals with filtered rows for stable result IDs."""
        filtered = cls._filter_rows(
            rows,
            dispositions=dispositions,
            query=query,
            provider_issues=provider_issues,
        )
        if not filtered:
            return []
        # _filter_rows preserves object identity and order.  Keep the source
        # ordinal separate so a filtered page still points at the same row
        # used by explanation/review endpoints.
        ordinals = {id(row): ordinal for ordinal, row in enumerate(rows, 1)}
        return [(ordinals[id(row)], row) for row in filtered]

    def _diagnostic_data(self, diagnostics: Any) -> dict[str, Any]:
        return {
            "input_path": diagnostics.input_path,
            "processed_count": diagnostics.processed_count,
            "parse_error_count": diagnostics.parse_error_count,
            "nested_data_error_count": diagnostics.nested_data_error_count,
            "missing_data_count": diagnostics.missing_data_count,
            "empty_data_count": diagnostics.empty_data_count,
            "non_list_data_count": diagnostics.non_list_data_count,
            "no_ioc_count": diagnostics.no_ioc_count,
            "invalid_ioc_count": diagnostics.invalid_ioc_count,
            "skipped_total": diagnostics.skipped_total,
            "parse_error_samples": diagnostics.parse_error_samples,
            "skipped_row_samples": diagnostics.skipped_row_samples,
        }

    def _task_paths(self, task_id: str) -> tuple[Path, Path]:
        task_id = self._safe_id(task_id, "task_id")
        return (
            self._safe_join("tasks", task_id, "results.jsonl"),
            self._safe_join("tasks", task_id, "diagnostics.json"),
        )

    def _run_pipeline_task(self, task_id: str, staged_path: Path) -> None:
        result_path, diagnostics_path = self._task_paths(task_id)
        try:
            pipeline = run_pipeline_with_diagnostics(str(staged_path), Config())
            diagnostics = self._diagnostic_data(pipeline.diagnostics)
            atomic_write_text(
                diagnostics_path,
                json.dumps(diagnostics, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            )
            if not pipeline.verdicts:
                raise WorkbenchValidationError(
                    "snapshot pipeline produced no verdicts; see diagnostics"
                )
            export_jsonl(pipeline.verdicts, str(result_path))
            with self._task_lock:
                task = self._load_task(task_id)
                # A queued task can be cancelled before the worker starts.  A
                # running pipeline cannot be interrupted safely at this layer.
                if task.get("state") == "cancelled":
                    return
                task["state"] = "succeeded"
                task["result_count"] = len(pipeline.verdicts)
                task["progress"] = {
                    "phase": "complete",
                    "completed": len(pipeline.verdicts),
                    "total": len(pipeline.verdicts),
                }
                task["finished_at_utc"] = _utc_now()
                self._save_task(task)
        except Exception as exc:
            with self._task_lock:
                task = self._load_task(task_id)
                if task.get("state") == "cancelled":
                    return
                task["state"] = "failed"
                task["error"] = str(exc)
                task["finished_at_utc"] = _utc_now()
                self._save_task(task)

    def start_task(
        self,
        import_id: str,
        *,
        providers: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if providers:
            raise WorkbenchValidationError(
                "offline backend does not provide live providers; use the legacy snapshot input"
            )
        if options is not None:
            if not isinstance(options, dict):
                raise WorkbenchValidationError("options must be an object")
            if options.get("offline") is False:
                raise WorkbenchValidationError("offline mode cannot be disabled")
        background = bool(options and options.get("background") is True)

        staged_path = self._staged_path(import_id)

        task_id = f"task-{secrets.token_hex(10)}"
        task_root = self._safe_join("tasks", task_id)
        task_root.mkdir(parents=True, exist_ok=False)
        task: dict[str, Any] = {
            "task_id": task_id,
            "import_id": import_id,
            "state": "queued" if background else "running",
            "mode": "offline_legacy_snapshot",
            "created_at_utc": _utc_now(),
            "result_count": 0,
            "progress": {"phase": "queued" if background else "pipeline", "completed": 0, "total": None},
        }
        result_path = self._safe_join("tasks", task_id, "results.jsonl")
        diagnostics_path = self._safe_join("tasks", task_id, "diagnostics.json")
        task["result_path"] = str(result_path)
        task["diagnostics_path"] = str(diagnostics_path)
        self._save_task(task)
        if background:
            worker = threading.Thread(
                target=self._background_task_entry,
                args=(task_id, staged_path),
                name=f"ioc-workbench-{task_id}",
                daemon=True,
            )
            worker.start()
        else:
            self._run_pipeline_task(task_id, staged_path)
        return self.task_status(task_id)

    def _background_task_entry(self, task_id: str, staged_path: Path) -> None:
        with self._task_lock:
            task = self._load_task(task_id)
            if task.get("state") != "queued":
                return
            task["state"] = "running"
            task["started_at_utc"] = _utc_now()
            task["progress"] = {"phase": "pipeline", "completed": 0, "total": None}
            self._save_task(task)
        self._run_pipeline_task(task_id, staged_path)

    def task_status(self, task_id: str) -> dict[str, Any]:
        return self._load_task(task_id)

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        with self._task_lock:
            task = self._load_task(task_id)
            if task.get("state") in {"queued", "pending"}:
                task["state"] = "cancelled"
                task["finished_at_utc"] = _utc_now()
                task["progress"] = {"phase": "cancelled", "completed": 0, "total": None}
                self._save_task(task)
            state = task.get("state")
        boundary = (
            "before_run"
            if state == "running"
            else "not_started"
            if state in {"queued", "pending"}
            else "already_finished"
        )
        return {
            "task_id": task["task_id"],
            "state": state,
            "cancellable": state in {"queued", "pending"},
            "cancel_boundary": boundary,
        }

    def results(
        self,
        task_id: str,
        *,
        dispositions: list[str] | None = None,
        query: str | None = None,
        provider_issues: bool | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        task = self._load_task(task_id)
        indexed_rows = self._filter_indexed_rows(
            self._read_results(task_id),
            dispositions=dispositions,
            query=query,
            provider_issues=provider_issues,
        )
        selected = indexed_rows[offset : offset + limit]
        projected = []
        for ordinal, row in selected:
            item = dict(row)
            item["result_id"] = self._result_id(task_id, ordinal)
            projected.append(item)
        return {
            "task_id": task["task_id"],
            "state": task["state"],
            "total": len(indexed_rows),
            "offset": offset,
            "limit": limit,
            "rows": projected,
        }

    def explanation(self, task_id: str, result_id: str) -> dict[str, Any]:
        result_id = self._safe_id(result_id, "result_id")
        rows = self._read_results(task_id)
        for ordinal, row in enumerate(rows, 1):
            if self._result_id(task_id, ordinal) == result_id:
                explanation = explain_verdict(row)
                explanation["task_id"] = task_id
                explanation["result_id"] = result_id
                return explanation
        raise WorkbenchValidationError(f"result not found: {result_id}")

    def submit_review(
        self,
        task_id: str,
        result_id: str,
        *,
        decision: str,
        reason: str = "",
        reviewer: str = "",
    ) -> dict[str, Any]:
        result_id = self._safe_id(result_id, "result_id")
        rows = self._read_results(task_id)
        for ordinal, row in enumerate(rows, 1):
            if self._result_id(task_id, ordinal) != result_id:
                continue
            try:
                label = label_review_queue(
                    self._safe_join("reviews.jsonl"),
                    str(row.get("ioc", "")),
                    decision=decision,
                    note=reason,
                    reviewer=reviewer,
                )
            except ValueError as exc:
                raise WorkbenchValidationError(str(exc)) from exc
            return {
                "task_id": task_id,
                "result_id": result_id,
                "review": label["label"],
                "reviewed_at": label["reviewed_at"],
            }
        raise WorkbenchValidationError(f"result not found: {result_id}")

    def export(
        self,
        task_id: str,
        *,
        dispositions: list[str] | None = None,
        query: str | None = None,
        provider_issues: bool | None = None,
        export_format: str = "jsonl",
    ) -> dict[str, Any]:
        if export_format not in {"jsonl", "csv", "xlsx"}:
            raise WorkbenchValidationError("export format must be jsonl, csv, or xlsx")
        task = self._load_task(task_id)
        if task.get("state") != "succeeded":
            raise WorkbenchValidationError(
                f"task is not complete: {task.get('state', 'unknown')}"
            )
        rows = self._filter_rows(
            self._read_results(task_id),
            dispositions=dispositions,
            query=query,
            provider_issues=provider_issues,
        )
        export_id = f"export-{secrets.token_hex(10)}"
        extension = "jsonl" if export_format == "jsonl" else export_format
        destination = self._safe_join("exports", f"{export_id}.{extension}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "jsonl":
            export_jsonl(rows, str(destination))
        elif export_format == "csv":
            export_csv(rows, str(destination))
        else:
            export_excel(rows, str(destination))
        return {
            "export_id": export_id,
            "filename": destination.name,
            "format": export_format,
            "rows": len(rows),
        }

    def export_file(self, export_id: str) -> Path:
        export_id = self._safe_id(export_id, "export_id")
        matches = sorted((self._safe_join("exports")).glob(f"{export_id}.*"))
        if not matches:
            raise WorkbenchValidationError(f"export not found: {export_id}")
        if len(matches) != 1:
            raise WorkbenchValidationError(f"export {export_id} is ambiguous")
        return matches[0]

    def diagnostics(self, task_id: str) -> dict[str, Any]:
        task = self._load_task(task_id)
        _result_path, diagnostics_path = self._task_paths(task_id)
        if not diagnostics_path.is_file():
            return {
                "task_id": task["task_id"],
                "state": task.get("state"),
                "available": False,
                "message": "diagnostics are not available until the pipeline writes them",
            }
        try:
            value = json.loads(diagnostics_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError) as exc:
            raise WorkbenchValidationError(f"diagnostics are unreadable: {task_id}") from exc
        if not isinstance(value, dict):
            raise WorkbenchValidationError(f"diagnostics are malformed: {task_id}")
        value.pop("input_path", None)
        return {"task_id": task["task_id"], "state": task.get("state"), "available": True, **value}

    def diff(self, task_id: str, baseline_task_id: str) -> dict[str, Any]:
        task = self._load_task(task_id)
        baseline = self._load_task(baseline_task_id)
        if task.get("state") != "succeeded" or baseline.get("state") != "succeeded":
            raise WorkbenchValidationError("both tasks must be succeeded before diff")
        current_rows = self._read_results(task_id)
        baseline_rows = self._read_results(baseline_task_id)
        return {
            "task_id": task["task_id"],
            "baseline_task_id": baseline["task_id"],
            "available": True,
            "diff": compare_verdicts(baseline_rows, current_rows),
        }

    def _input_summary(self, task: dict[str, Any]) -> dict[str, Any]:
        staged_path = self._staged_path(str(task["import_id"]))
        digest = hashlib.sha256()
        size = 0
        with staged_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        manifest_path = self._safe_join("staging", str(task["import_id"]), "import.json")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            manifest = {}
        return {
            "filename": manifest.get("filename", staged_path.name),
            "rows": manifest.get("rows"),
            "size": size,
            "sha256": digest.hexdigest(),
        }

    @staticmethod
    def _is_review_candidate(row: dict[str, Any]) -> bool:
        return row.get("disposition") == "review" or row.get("conclusion") == "待复核" or row.get("review_suggestion") == "必看"

    def summary(self, task_id: str) -> dict[str, Any]:
        task = self._load_task(task_id)
        safe_task = {
            key: task.get(key)
            for key in (
                "task_id", "import_id", "state", "mode", "created_at_utc",
                "started_at_utc", "finished_at_utc", "result_count", "progress", "error",
            )
            if key in task
        }
        safe_task["duration_seconds"] = _duration_seconds(
            task.get("started_at_utc") or task.get("created_at_utc"),
            task.get("finished_at_utc"),
        )
        rows = self._read_results(task_id)
        by_conclusion: dict[str, int] = {}
        by_disposition: dict[str, int] = {}
        pending = 0
        labels = {
            str(row.get("ioc")): row
            for row in load_queue(self._safe_join("reviews.jsonl"))
            if row.get("ioc")
        }
        reviewed = 0
        for row in rows:
            conclusion = str(row.get("conclusion") or "未知")
            disposition = str(row.get("disposition") or "未知")
            by_conclusion[conclusion] = by_conclusion.get(conclusion, 0) + 1
            by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
            if self._is_review_candidate(row):
                pending += 1
            overlay = labels.get(str(row.get("ioc")))
            if overlay and (overlay.get("label") or overlay.get("reviewed_at")):
                reviewed += 1
        diagnostics = self.diagnostics(task_id)
        version_path = Path(__file__).resolve().parent.parent / "VERSION"
        try:
            version = version_path.read_text(encoding="utf-8").strip()
        except OSError:
            version = "unknown"
        return {
            "schema_version": 1,
            "version": version,
            "execution": {
                "mode": task.get("mode", "offline_legacy_snapshot"),
                "providers": [],
                "network": "disabled",
                "cache": {"mode": "not_applicable"},
            },
            "task": safe_task,
            "input": self._input_summary(task),
            "results": {
                "total": len(rows),
                "by_conclusion": dict(sorted(by_conclusion.items())),
                "by_disposition": dict(sorted(by_disposition.items())),
                "review_candidates": pending,
                "reviewed_overlays": reviewed,
            },
            "diagnostics": diagnostics,
            "next_steps": [
                "review pending candidates" if pending else "no pending review candidates",
                "compare a baseline task before changing rules" if task.get("state") == "succeeded" else "wait for a terminal task state",
            ],
        }

    def export_artifact(
        self,
        task_id: str,
        *,
        artifact_format: str,
        dispositions: list[str] | None = None,
        query: str | None = None,
        provider_issues: bool | None = None,
        baseline_task_id: str | None = None,
    ) -> dict[str, Any]:
        if artifact_format not in {"diagnostics", "diff", "bundle"}:
            raise WorkbenchValidationError("artifact format must be diagnostics, diff, or bundle")
        task = self._load_task(task_id)
        if task.get("state") != "succeeded":
            raise WorkbenchValidationError(
                f"task is not complete: {task.get('state', 'unknown')}"
            )
        if artifact_format in {"diff", "bundle"}:
            if not baseline_task_id:
                raise WorkbenchValidationError("baseline_task_id is required for diff and bundle export")
            baseline_task_id = self._safe_id(baseline_task_id, "baseline_task_id")
            if baseline_task_id == task_id:
                raise WorkbenchValidationError("task_id and baseline_task_id must differ")
        export_id = f"export-{secrets.token_hex(10)}"
        exports_dir = self._safe_join("exports")
        exports_dir.mkdir(parents=True, exist_ok=True)
        extension = "zip" if artifact_format == "bundle" else "json"
        destination = self._safe_join("exports", f"{export_id}.{extension}")
        rows = self._filter_rows(
            self._read_results(task_id),
            dispositions=dispositions,
            query=query,
            provider_issues=provider_issues,
        )
        diagnostics = self.diagnostics(task_id)
        diff_document = self.diff(task_id, baseline_task_id) if artifact_format in {"diff", "bundle"} else None
        if artifact_format == "diagnostics":
            atomic_write_text(
                destination,
                json.dumps(diagnostics, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            )
        elif artifact_format == "diff":
            atomic_write_text(
                destination,
                json.dumps(diff_document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            )
        else:
            with tempfile.TemporaryDirectory(prefix=f"{export_id}-", dir=str(exports_dir)) as temp_dir:
                temp_root = Path(temp_dir)
                jsonl_path = temp_root / "results.jsonl"
                csv_path = temp_root / "results.csv"
                xlsx_path = temp_root / "results.xlsx"
                diagnostics_path = temp_root / "diagnostics.json"
                export_jsonl(rows, str(jsonl_path))
                export_csv(rows, str(csv_path))
                export_excel(rows, str(xlsx_path))
                atomic_write_text(
                    diagnostics_path,
                    json.dumps(diagnostics, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                )
                if diff_document is not None:
                    diff_path = temp_root / "diff.json"
                    atomic_write_text(
                        diff_path,
                        json.dumps(diff_document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    )
                temp_zip = destination.with_suffix(".tmp")
                try:
                    with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                        for item in sorted(temp_root.iterdir()):
                            if item.is_file():
                                archive.write(item, item.name)
                    os.replace(temp_zip, destination)
                finally:
                    temp_zip.unlink(missing_ok=True)
        return {
            "export_id": export_id,
            "filename": destination.name,
            "format": artifact_format,
            "rows": len(rows),
            "baseline_task_id": baseline_task_id,
        }
