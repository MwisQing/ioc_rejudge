"""Batch HTTP JSON execution through the bundled Go worker."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import threading
from typing import Iterable, Iterator

from ioc_rejudge.providers.transport import TransportError


@dataclass(frozen=True)
class BatchRequest:
    id: str
    method: str
    url: str
    headers: dict[str, str] | None = None
    params: dict | None = None
    body: object = None
    timeout: float = 30


@dataclass(frozen=True)
class BatchResult:
    id: str
    payload: object | None = None
    error: TransportError | None = None


def default_executable() -> Path:
    override = os.environ.get("IOC_REJUDGE_GO_HTTP", "").strip()
    if override:
        return Path(override)
    filename = "provider_http.exe" if os.name == "nt" else "provider_http"
    return Path(__file__).resolve().parents[1] / "bin" / filename


class GoBatchTransport:
    def __init__(
        self,
        executable: str | Path | None = None,
        *,
        jobs_per_process: int | None = None,
    ) -> None:
        self.executable = Path(executable) if executable is not None else default_executable()
        if jobs_per_process is not None:
            if isinstance(jobs_per_process, bool) or jobs_per_process <= 0:
                raise ValueError("jobs_per_process must be a positive integer")
        self.jobs_per_process = jobs_per_process

    @property
    def available(self) -> bool:
        return self.executable.is_file()

    def _chunk_size(self, workers: int) -> int:
        if self.jobs_per_process is not None:
            return max(1, int(self.jobs_per_process))
        return max(int(workers) * 2, 8)

    def iter_batch(
        self,
        requests: Iterable[BatchRequest],
        *,
        workers: int,
        rate_per_second: int,
    ) -> Iterator[BatchResult]:
        if not self.available:
            raise RuntimeError(f"Go HTTP worker not found: {self.executable}")
        jobs = list(requests)
        if not jobs:
            return
        worker_count = max(1, int(workers))
        rate = max(1, int(rate_per_second))
        size = self._chunk_size(worker_count)
        for start in range(0, len(jobs), size):
            chunk = jobs[start : start + size]
            received: set[str] = set()
            try:
                for result in self._iter_chunk(
                    chunk, workers=worker_count, rate_per_second=rate
                ):
                    received.add(result.id)
                    yield result
            except Exception as exc:
                message = str(exc).strip() or type(exc).__name__
                if "Go HTTP worker" not in message:
                    message = f"Go HTTP worker failed: {message}"
                for job in chunk:
                    if job.id not in received:
                        yield BatchResult(
                            job.id,
                            error=TransportError("connection", message),
                        )

    def _iter_chunk(
        self,
        requests: list[BatchRequest],
        *,
        workers: int,
        rate_per_second: int,
    ) -> Iterator[BatchResult]:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        process = subprocess.Popen(
            [
                str(self.executable),
                "--workers",
                str(max(1, int(workers))),
                "--rate",
                str(max(1, int(rate_per_second))),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            creationflags=creationflags,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        writer_error: list[BaseException] = []

        def write_requests() -> None:
            try:
                for request in requests:
                    row = {
                        "id": request.id,
                        "method": request.method,
                        "url": request.url,
                        "headers": request.headers or {},
                        "params": request.params or {},
                        "body": request.body,
                        "timeout_seconds": request.timeout,
                    }
                    process.stdin.write(
                        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                    )
                process.stdin.close()
            except BaseException as exc:  # Surface writer failures after stdout closes.
                writer_error.append(exc)
                try:
                    process.stdin.close()
                except OSError:
                    pass

        writer = threading.Thread(target=write_requests, name="ioc-go-http-input")
        writer.start()
        try:
            for line in process.stdout:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise RuntimeError("Go HTTP worker returned invalid JSON") from exc
                request_id = str(row.get("id", ""))
                if row.get("ok") is True:
                    yield BatchResult(request_id, payload=row.get("payload"))
                    continue
                yield BatchResult(
                    request_id,
                    error=TransportError(
                        str(row.get("error_kind") or "connection"),
                        str(row.get("message") or "Go HTTP worker request failed"),
                        status_code=(
                            int(row["status_code"])
                            if row.get("status_code") not in (None, 0, "")
                            else None
                        ),
                    ),
                )
            writer.join()
            if writer_error:
                raise RuntimeError("Could not send requests to Go HTTP worker") from writer_error[0]
            stderr = process.stderr.read().strip()
            code = process.wait()
            if code != 0:
                message = stderr.splitlines()[-1] if stderr else f"exit code {code}"
                raise RuntimeError(f"Go HTTP worker failed: {message}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            writer.join(timeout=1)


__all__ = ["BatchRequest", "BatchResult", "GoBatchTransport", "default_executable"]
