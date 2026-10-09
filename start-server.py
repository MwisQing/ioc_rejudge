"""Start the local IOC rejudge UI from the project directory."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

RECORD_FILE = Path(".server.pid")
SCRIPT_NAME = "start-server.py"


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _preferred_python(root: Path) -> Path:
    candidate = root / ".venv" / "Scripts" / "python.exe"
    return candidate if candidate.is_file() else Path(sys.executable)


def _check_dependencies(python: Path) -> bool:
    result = subprocess.run(
        [str(python), "-c", "import requests, openpyxl"],
        cwd=str(_project_root()),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _read_record(root: Path) -> dict | None:
    try:
        value = json.loads((root / RECORD_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict):
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


def _process_is_server(pid: int) -> bool:
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


def _remove_record(root: Path) -> None:
    try:
        (root / RECORD_FILE).unlink()
    except OSError:
        pass


def _write_record(root: Path, pid: int, port: int) -> None:
    record = {
        "pid": int(pid),
        "port": int(port),
        "start_time": datetime.now(timezone.utc).astimezone().isoformat(),
    }
    (root / RECORD_FILE).write_text(
        json.dumps(record, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def _print_without_token(line: str) -> None:
    marker = "ioc rejudge share ui: "
    if marker in line:
        address = line.split(marker, 1)[1].strip()
        print("服务已启动：" + address)
        return
    if "token=" in line:
        print(line.split("token=", 1)[0].rstrip("&?"))
        return
    print(line.rstrip())


def start() -> int:
    root = _project_root()
    os.chdir(root)
    record = _read_record(root)
    if isinstance(record, dict) and isinstance(record.get("pid"), int):
        pid = record["pid"]
        if _process_alive(pid) and _process_is_server(pid):
            port = record.get("port", "?")
            print(f"服务已在运行：http://127.0.0.1:{port}")
            return 0
        _remove_record(root)

    python = _preferred_python(root)
    if not _check_dependencies(python):
        print("缺少运行依赖：请先安装 requirements.txt 中的依赖。")
        return 1

    print("服务启动中…")
    process = subprocess.Popen(
        [str(python), "-m", "ioc_rejudge", "ui", "--cache-dir", ".\\provider-cache"],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    def _drain(stream):
        assert stream is not None
        for line in iter(stream.readline, ""):
            _print_without_token(line)
        stream.close()

    stderr_thread = threading.Thread(
        target=_drain,
        args=(process.stderr,),
        daemon=True,
    )
    stderr_thread.start()
    address_line = process.stdout.readline() if process.stdout else ""
    if not address_line.strip():
        process.wait()
        _remove_record(root)
        print("服务启动失败，请查看上方错误信息。")
        return 1
    _print_without_token(address_line)
    if process.stdout:
        stdout_thread = threading.Thread(
            target=_drain,
            args=(process.stdout,),
            daemon=True,
        )
        stdout_thread.start()

    payload = address_line.split(":", 1)[1].strip()
    parsed = urlsplit(payload)
    if parsed.port is None:
        process.terminate()
        _remove_record(root)
        print("服务启动失败：没有获得服务端口。")
        return 1
    _write_record(root, process.pid, parsed.port)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        _remove_record(root)
        return 0


if __name__ == "__main__":
    raise SystemExit(start())