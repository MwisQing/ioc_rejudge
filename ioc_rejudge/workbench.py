"""Security boundary and injectable adapter for the adjudication workbench.

The UI never talks to a backend module directly.  It talks to this adapter.
The default adapter can stage uploaded input safely, but every task/result/
review/export operation is explicitly unavailable until the backend workbench
modules are integrated.  It never pretends that a task succeeded.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_IMPORT_BYTES = 32 * 1024 * 1024
_SAFE_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")


class WorkbenchError(Exception):
    """Base class for expected workbench API failures."""


class WorkbenchValidationError(WorkbenchError):
    """The request did not satisfy the adapter contract."""


class WorkbenchUnavailable(WorkbenchError):
    """A backend capability has not been integrated yet."""

    def __init__(self, capability: str, reason: str | None = None) -> None:
        self.capability = capability
        self.reason = reason or "backend module is not integrated"
        super().__init__(f"{capability} unavailable: {self.reason}")


@dataclass(frozen=True)
class StagedImport:
    import_id: str
    filename: str
    path: Path
    size: int
    rows: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "import_id": self.import_id,
            "filename": self.filename,
            "path": str(self.path),
            "size": self.size,
            "rows": self.rows,
        }


class WorkbenchAdapter:
    """Contract consumed by the workbench UI routes.

    Concrete adapters must keep every filesystem path inside their controlled
    root and must not accept arbitrary filesystem paths from the page.
    """

    @property
    def workbench_dir(self) -> Path:
        raise NotImplementedError

    def stage_input(self, filename: str, content: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("import", "input staging adapter is not configured")

    def start_task(
        self,
        import_id: str,
        *,
        providers: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raise WorkbenchUnavailable("task.start")

    def task_status(self, task_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("task.status")

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("task.cancel")

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
        raise WorkbenchUnavailable("results.filter")

    def explanation(self, task_id: str, result_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("explanation.detail")

    def submit_review(
        self,
        task_id: str,
        result_id: str,
        *,
        decision: str,
        reason: str = "",
        reviewer: str = "",
    ) -> dict[str, Any]:
        raise WorkbenchUnavailable("review.write")

    def export(
        self,
        task_id: str,
        *,
        dispositions: list[str] | None = None,
        query: str | None = None,
        provider_issues: bool | None = None,
        export_format: str = "jsonl",
    ) -> dict[str, Any]:
        raise WorkbenchUnavailable("export.create")

    def export_file(self, export_id: str) -> Path:
        raise WorkbenchUnavailable("export.download")

    def diagnostics(self, task_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("diagnostics.read")

    def diff(self, task_id: str, baseline_task_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("diff.read")

    def summary(self, task_id: str) -> dict[str, Any]:
        raise WorkbenchUnavailable("summary.read")

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
        raise WorkbenchUnavailable("export.artifact")


class LocalWorkbenchAdapter(WorkbenchAdapter):
    """Default adapter with controlled import staging and no backend runner.

    This adapter is intentionally narrow.  Import staging is real because the
    page must be able to upload data; starting, polling, filtering, explaining,
    reviewing and exporting are structured 501 operations.
    """

    def __init__(self, workbench_dir: str | Path) -> None:
        self._dir = Path(workbench_dir).expanduser()
        self._staging_dir = self._safe_join("staging")
        self._staging_dir.mkdir(parents=True, exist_ok=True)

    @property
    def workbench_dir(self) -> Path:
        return self._dir

    def _safe_join(self, *parts: str) -> Path:
        candidate = (self._dir.joinpath(*parts)).resolve()
        root = self._dir.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise WorkbenchValidationError("path escapes the workbench directory") from exc
        return candidate

    @staticmethod
    def _safe_id(value: Any, field: str) -> str:
        if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value) or ".." in value:
            raise WorkbenchValidationError(f"{field} is invalid")
        return value

    @staticmethod
    def _safe_filename(value: Any) -> str:
        if value is None or value == "":
            return "input.jsonl"
        if not isinstance(value, str):
            raise WorkbenchValidationError("filename must be a string")
        filename = Path(value.replace("\\", "/")).name
        filename = "".join(ch for ch in filename if ord(ch) >= 32 and ch not in '<>:"|?*')
        filename = filename.strip(" .")
        if not filename or filename in {".", ".."}:
            raise WorkbenchValidationError("filename is invalid")
        if len(filename.encode("utf-8")) > 180:
            raise WorkbenchValidationError("filename is too long")
        return filename

    def stage_input(self, filename: str, content: str) -> dict[str, Any]:
        if not isinstance(content, str) or not content.strip():
            raise WorkbenchValidationError("content is required")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_IMPORT_BYTES:
            raise WorkbenchValidationError("uploaded input is too large")
        rows = 0
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except ValueError as exc:
                raise WorkbenchValidationError("input is not valid JSONL") from exc
            if not isinstance(value, dict):
                raise WorkbenchValidationError("each JSONL input row must be an object")
            rows += 1
        if rows == 0:
            raise WorkbenchValidationError("input must contain at least one JSONL row")

        import_id = secrets.token_hex(12)
        directory = self._safe_join("staging", import_id)
        directory.mkdir(parents=True, exist_ok=False)
        safe_name = self._safe_filename(filename)
        target = self._safe_join("staging", import_id, safe_name)
        fd, temp_name = tempfile.mkstemp(prefix=".upload-", suffix=".tmp", dir=directory)
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        manifest = {
            "import_id": import_id,
            "filename": safe_name,
            "size": len(encoded),
            "rows": rows,
        }
        manifest_path = self._safe_join("staging", import_id, "import.json")
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return StagedImport(import_id, safe_name, target, len(encoded), rows).as_dict()
