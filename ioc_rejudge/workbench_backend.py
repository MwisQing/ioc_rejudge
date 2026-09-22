"""Local offline workbench backend over the legacy snapshot pipeline."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_rejudge.cli import run_pipeline_with_diagnostics
from ioc_rejudge.config import Config
from ioc_rejudge.export import export_csv, export_excel, export_jsonl
from ioc_rejudge.explanations import explain_verdict
from ioc_rejudge.files import atomic_write_text
from ioc_rejudge.review_queue import label_review_queue
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


class OfflineWorkbenchAdapter(LocalWorkbenchAdapter):
    """Persist a complete task lifecycle without provider/network transport.

    The backend deliberately runs the accepted legacy snapshot pipeline.  It
    therefore has no live provider mode and fails closed if callers request
    providers or disable offline mode.
    """

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
        if task.get("state") == "failed":
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
    def _filter_rows(
        rows: list[dict[str, Any]],
        *,
        dispositions: list[str] | None,
        query: str | None,
    ) -> list[dict[str, Any]]:
        filtered = rows
        if dispositions is not None:
            wanted = set(dispositions)
            filtered = [row for row in filtered if row.get("disposition") in wanted]
        if query:
            lowered = query.casefold()
            filtered = [
                row
                for row in filtered
                if lowered in json.dumps(row, ensure_ascii=False).casefold()
            ]
        return filtered

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

        staged_path = self._staged_path(import_id)

        task_id = f"task-{secrets.token_hex(10)}"
        task_root = self._safe_join("tasks", task_id)
        task_root.mkdir(parents=True, exist_ok=False)
        task: dict[str, Any] = {
            "task_id": task_id,
            "import_id": import_id,
            "state": "running",
            "mode": "offline_legacy_snapshot",
            "created_at_utc": _utc_now(),
            "result_count": 0,
        }
        self._save_task(task)
        result_path = self._safe_join("tasks", task_id, "results.jsonl")
        diagnostics_path = self._safe_join("tasks", task_id, "diagnostics.json")
        task["result_path"] = str(result_path)
        task["diagnostics_path"] = str(diagnostics_path)
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
            task["state"] = "succeeded"
            task["result_count"] = len(pipeline.verdicts)
            task["finished_at_utc"] = _utc_now()
        except Exception as exc:
            task["state"] = "failed"
            task["error"] = str(exc)
            task["finished_at_utc"] = _utc_now()
        self._save_task(task)
        return self.task_status(task_id)

    def task_status(self, task_id: str) -> dict[str, Any]:
        return self._load_task(task_id)

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        task = self._load_task(task_id)
        if task.get("state") in {"queued", "pending", "running"}:
            task["state"] = "cancelled"
            task["finished_at_utc"] = _utc_now()
            self._save_task(task)
        return {
            "task_id": task["task_id"],
            "state": task["state"],
            "cancellable": task.get("state") in {"queued", "pending", "running"},
        }

    def results(
        self,
        task_id: str,
        *,
        dispositions: list[str] | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        task = self._load_task(task_id)
        rows = self._filter_rows(
            self._read_results(task_id),
            dispositions=dispositions,
            query=query,
        )
        selected = rows[offset : offset + limit]
        projected = []
        for relative_index, row in enumerate(selected, offset + 1):
            item = dict(row)
            item["result_id"] = self._result_id(task_id, relative_index)
            projected.append(item)
        return {
            "task_id": task["task_id"],
            "state": task["state"],
            "total": len(rows),
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
        export_format: str = "jsonl",
    ) -> dict[str, Any]:
        if export_format not in {"jsonl", "csv", "xlsx"}:
            raise WorkbenchValidationError("export format must be jsonl, csv, or xlsx")
        rows = self._filter_rows(
            self._read_results(task_id),
            dispositions=dispositions,
            query=query,
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
