"""Stop the local IOC rejudge UI recorded by start-server.py."""
from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path

RECORD_FILE = Path(".server.pid")
SCRIPT_NAME = "start-server.py"


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _read_record(root: Path) -> dict | None:
    try:
        value = json.loads((root / RECORD_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    if not isinstance(value.get("pid"), int):
        return None
    return value


def _process_alive(pid: int) -> bool:
    if hasattr(os, "kill"):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode == 0 and str(pid) in result.stdout


def _process_is_server(pid: int, record: dict) -> bool:
    if os.name == "posix":
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            return SCRIPT_NAME.encode() in command
        except OSError:
            return False
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode == 0 and (SCRIPT_NAME in result.stdout or "ioc_rejudge ui" in result.stdout):
            return True
    except OSError:
        pass
    return False


def _stop_process(pid: int) -> None:
    if hasattr(os, "kill"):
        os.kill(pid, signal.SIGTERM)
        return
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _remove_record(root: Path) -> None:
    try:
        (root / RECORD_FILE).unlink()
    except OSError:
        pass


def stop() -> int:
    root = _project_root()
    os.chdir(root)
    record = _read_record(root)
    if record is None or not _process_alive(record["pid"]):
        _remove_record(root)
        print("已经停了")
        return 0
    if not _process_is_server(record["pid"], record):
        _remove_record(root)
        print("已经停了")
        return 0
    _stop_process(record["pid"])
    _remove_record(root)
    print("已经停了")
    return 0


if __name__ == "__main__":
    raise SystemExit(stop())