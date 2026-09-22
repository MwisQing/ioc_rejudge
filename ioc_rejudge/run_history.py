"""Small, atomic JSONL storage for IOC rejudge runs."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class RunHistory:
    """Store run records in one bounded, atomically replaced JSONL file."""

    def __init__(self, root: str | os.PathLike[str], max_runs: int = 100) -> None:
        if isinstance(max_runs, bool) or not isinstance(max_runs, int) or max_runs <= 0:
            raise ValueError("max_runs must be a positive integer")

        path = Path(root)
        if ".." in path.parts:
            raise ValueError("root must not contain path traversal")

        self.root = path
        self.max_runs = max_runs
        self.path = self.root / "history.jsonl"

    @staticmethod
    def _run_id(run_id: Any) -> str:
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if (
            run_id in {".", ".."}
            or "/" in run_id
            or "\\" in run_id
            or "\x00" in run_id
            or os.path.isabs(run_id)
            or Path(run_id).name != run_id
        ):
            raise ValueError("run_id must not contain path traversal")
        return run_id

    @staticmethod
    def _record_key(record: dict[str, Any]) -> tuple[str, str]:
        return (str(record.get("created_at", "")), str(record.get("run_id", "")))

    @staticmethod
    def _copy_record(record: dict[str, Any]) -> dict[str, Any]:
        return dict(record)

    def _sorted_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            (self._copy_record(record) for record in records),
            key=self._record_key,
        )

    def load(self) -> list[dict[str, Any]]:
        """Load valid JSON object records; malformed lines are ignored."""

        try:
            with self.path.open("r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except FileNotFoundError:
            return []

        records: list[dict[str, Any]] = []
        for line in lines:
            try:
                value = json.loads(line.lstrip("\ufeff"))
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict) and "run_id" in value:
                records.append(value)
        return records

    def record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Atomically append one JSON object record to the bounded history."""

        if not isinstance(record, dict):
            raise TypeError("record must be a mapping")
        run_id = self._run_id(record.get("run_id"))

        self.root.mkdir(parents=True, exist_ok=True)
        records = self.load()
        if any(existing.get("run_id") == run_id for existing in records):
            raise ValueError(f"run_id already exists: {run_id}")

        records.append(self._copy_record(record))
        records.sort(key=self._record_key)
        records = records[-self.max_runs :]

        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.root,
                prefix=".history-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_name = handle.name
                for entry in records:
                    handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True))
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        except BaseException:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
            raise

        return self._copy_record(records[-1])

    def list_runs(self) -> list[dict[str, Any]]:
        """Return copies of records ordered by ``(created_at, run_id)``."""

        return self._sorted_records(self.load())

    def get(self, run_id: str) -> dict[str, Any] | None:
        """Return one record by its safe run identifier, or ``None``."""

        safe_run_id = self._run_id(run_id)
        for record in self.load():
            if record.get("run_id") == safe_run_id:
                return self._copy_record(record)
        return None

    def select_baseline(self, current_run_id: str | None = None) -> dict[str, Any] | None:
        """Return the deterministic previous run.

        With ``current_run_id``, the record immediately before that run is
        selected.  Without one, the most recent stored run is selected as the
        baseline for a new run.  Both cases order records by
        ``(created_at, run_id)``.
        """

        records = self._sorted_records(self.load())
        if not records:
            return None
        if current_run_id is None:
            return records[-1]

        safe_run_id = self._run_id(current_run_id)
        matches = [
            index
            for index, record in enumerate(records)
            if record.get("run_id") == safe_run_id
        ]
        if not matches:
            raise ValueError(f"current run_id is not in history: {safe_run_id}")
        current_index = matches[0]
        if current_index == 0:
            return None
        return records[current_index - 1]
