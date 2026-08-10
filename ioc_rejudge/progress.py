"""TTY-aware, thread-safe live progress rendering for provider collection.

Keeps one in-place block on stderr while providers are collecting so a batch
run shows per-provider "done/total" lines instead of sitting silent. When
stderr is a terminal the block is redrawn with ANSI escape sequences; when it
is redirected or piped, updates fall back to throttled one-line writes so logs
stay readable. All writes go through a single lock because providers report
progress from parallel worker threads.
"""

from __future__ import annotations

import re
import sys
import threading
import time
from typing import TextIO

from ioc_rejudge.providers.base import ProgressEvent

_COMPLETION_RE = re.compile(r"^provider '([^']+)':")
_TTY_REDRAW_INTERVAL = 0.1
_PLAIN_UPDATE_INTERVAL = 1.0


def _format_line(provider: str, event: ProgressEvent, elapsed: str) -> str:
    line = f"[{provider}] {event.done}/{event.total}  {elapsed}"
    if event.detail:
        line += f"  {event.detail}"
    return line


class LiveProgress:
    """Thread-safe progress sink that renders provider progress to a stream.

    event() records one per-provider update; message() prints a permanent
    completion line and drops that provider from the live block; close()
    clears the remaining block so later output starts on a clean line.
    """

    def __init__(self, stream: TextIO | None = None, *, tty: bool | None = None) -> None:
        self._stream = stream or sys.stderr
        # When tty is not forced, respect the active stream (not always stderr).
        self._tty = self._stream.isatty() if tty is None else tty
        self._lock = threading.Lock()
        self._states: dict[str, ProgressEvent] = {}
        self._started: dict[str, float] = {}
        self._height = 0
        self._last_redraw: float | None = None
        self._last_update: dict[str, float] = {}
        if self._tty:
            self._enable_vt()

    @staticmethod
    def _enable_vt() -> None:
        if sys.platform != "win32":
            return
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_ERROR_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(
                    handle, mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                )
        except Exception:
            pass

    def event(self, event: ProgressEvent) -> None:
        """Record one per-provider progress update and redraw as needed.

        Identical events for the same provider are ignored so a repeated
        terminal N/N does not print twice in plain mode.
        """
        with self._lock:
            current = self._states.get(event.provider)
            if current is not None and current == event:
                return
            self._states[event.provider] = event
            self._started.setdefault(event.provider, time.perf_counter())
            self._update_locked()

    def message(self, text: str) -> None:
        """Print a permanent completion line above the remaining live block."""
        with self._lock:
            match = _COMPLETION_RE.match(text)
            if match is not None:
                self._states.pop(match.group(1), None)
            self._seal_locked(text, self._lines_locked())

    def close(self) -> None:
        """Clear any remaining live block so later output starts clean."""
        with self._lock:
            self._clear_locked()

    def _update_locked(self) -> None:
        if not self._states:
            return
        if self._tty:
            now = time.perf_counter()
            if (
                self._last_redraw is not None
                and now - self._last_redraw < _TTY_REDRAW_INTERVAL
            ):
                return
            self._last_redraw = now
            self._render_locked()
            return
        now = time.perf_counter()
        lines: list[str] = []
        for provider, event in self._states.items():
            last = self._last_update.get(provider)
            if (
                last is not None
                and event.done < event.total
                and now - last < _PLAIN_UPDATE_INTERVAL
            ):
                continue
            self._last_update[provider] = now
            started = self._started.get(provider)
            elapsed = f"{now - started:.1f}s" if started is not None else "--"
            lines.append(_format_line(provider, event, elapsed) + "\n")
        if lines:
            self._stream.write("".join(lines))
            self._stream.flush()

    def _lines_locked(self) -> list[str]:
        providers = list(self._states)
        width = max((len(provider) for provider in providers), default=0)
        now = time.perf_counter()
        lines: list[str] = []
        for provider in providers:
            started = self._started.get(provider)
            elapsed = f"{now - started:.1f}s" if started is not None else "--"
            lines.append(
                _format_line(provider.ljust(width), self._states[provider], elapsed)
            )
        return lines

    def _render_locked(self) -> None:
        if not self._tty:
            return
        lines = self._lines_locked()
        move_up = f"\x1b[{self._height}A" if self._height else ""
        pad = max(0, self._height - len(lines))
        out = move_up + "".join("\x1b[K" + line + "\n" for line in lines)
        if pad:
            out += "\x1b[K" * pad + f"\x1b[{pad}A"
        self._stream.write(out)
        self._stream.flush()
        self._height = len(lines)

    def _seal_locked(self, text: str, lines: list[str]) -> None:
        """Replace the live block with a permanent line followed by remaining lines."""
        if not self._tty:
            self._stream.write(text + "\n")
            self._stream.flush()
            return
        out = ""
        if self._height:
            out += f"\x1b[{self._height}A"
        out += "\x1b[K" + text + "\n"
        for line in lines:
            out += "\x1b[K" + line + "\n"
        extra = self._height - (1 + len(lines))
        if extra > 0:
            out += "\x1b[K" * extra + f"\x1b[{extra}A"
        self._stream.write(out)
        self._stream.flush()
        self._height = len(lines)

    def _clear_locked(self) -> None:
        if not self._tty or not self._height:
            return
        out = f"\x1b[{self._height}A"
        out += "\x1b[K\n" * (self._height - 1)
        out += "\x1b[K"
        self._stream.write(out)
        self._stream.flush()
        self._height = 0


__all__ = ["LiveProgress"]
