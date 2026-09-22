"""Physical-memory caps so large batches stay in RAM on small machines."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys


_PROFILE_ENV = "IOC_REJUDGE_MEMORY_PROFILE"
_GIB = 1024 ** 3
_LOW_GIB = 5.5
_MID_GIB = 9.0


@dataclass(frozen=True)
class MemoryLimits:
    """Optional concurrency ceilings derived from installed RAM."""

    total_bytes: int | None = None
    http_workers: int | None = None
    provider_workers: int | None = None
    go_jobs_per_process: int | None = None

    @classmethod
    def unlimited(cls, total_bytes: int | None = None) -> MemoryLimits:
        return cls(total_bytes=total_bytes)


def physical_memory_bytes() -> int | None:
    """Return installed RAM in bytes, or None when the platform value is unavailable."""

    if os.name == "nt":
        return _windows_total_phys()
    if sys.platform == "darwin":
        return _darwin_hw_memsize()
    return _linux_memtotal()


def detect_memory_limits(
    total_bytes: int | None = None,
    *,
    env: dict[str, str] | None = None,
) -> MemoryLimits:
    """Choose caps from RAM or `IOC_REJUDGE_MEMORY_PROFILE`."""

    environment = os.environ if env is None else env
    profile = str(environment.get(_PROFILE_ENV, "") or "").strip().lower()
    detected = physical_memory_bytes() if total_bytes is None else int(total_bytes)
    if profile in {"full", "off", "unlimited"}:
        return MemoryLimits.unlimited(detected)
    if profile == "low":
        return MemoryLimits(
            total_bytes=detected,
            http_workers=2,
            provider_workers=2,
            go_jobs_per_process=4,
        )
    if detected is None or detected <= 0:
        return MemoryLimits.unlimited(detected)
    gib = detected / _GIB
    if gib < _LOW_GIB:
        return MemoryLimits(
            total_bytes=detected,
            http_workers=2,
            provider_workers=2,
            go_jobs_per_process=4,
        )
    if gib < _MID_GIB:
        return MemoryLimits(
            total_bytes=detected,
            http_workers=4,
            provider_workers=3,
            go_jobs_per_process=8,
        )
    return MemoryLimits.unlimited(detected)


def cap_positive_int(value: int, ceiling: int | None) -> int:
    """Keep a positive integer at or below an optional ceiling."""

    parsed = int(value)
    if parsed <= 0:
        raise ValueError("value must be a positive integer")
    if ceiling is None:
        return parsed
    bound = int(ceiling)
    if bound <= 0:
        raise ValueError("ceiling must be a positive integer")
    return max(1, min(parsed, bound))


def _windows_total_phys() -> int | None:
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_uint32),
            ("dwMemoryLoad", ctypes.c_uint32),
            ("ullTotalPhys", ctypes.c_uint64),
            ("ullAvailPhys", ctypes.c_uint64),
            ("ullTotalPageFile", ctypes.c_uint64),
            ("ullAvailPageFile", ctypes.c_uint64),
            ("ullTotalVirtual", ctypes.c_uint64),
            ("ullAvailVirtual", ctypes.c_uint64),
            ("ullAvailExtendedVirtual", ctypes.c_uint64),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32 = ctypes.windll.kernel32
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    total = int(status.ullTotalPhys)
    return total if total > 0 else None


def _linux_memtotal() -> int | None:
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    return int(parts[1]) * 1024
    except (OSError, IndexError, ValueError):
        return None
    return None


def _darwin_hw_memsize() -> int | None:
    import subprocess

    try:
        output = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"],
            text=True,
            timeout=2,
        )
        total = int(output.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return total if total > 0 else None


__all__ = [
    "MemoryLimits",
    "cap_positive_int",
    "detect_memory_limits",
    "physical_memory_bytes",
]
