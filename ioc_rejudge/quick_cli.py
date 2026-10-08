"""Lightweight high-frequency ``judge`` CLI adapter.

Collects bare IOC values from positional args, optional stdin lines, and an
optional file, then hands a reconstructed argv to the existing main CLI.
Does not duplicate provider, pipeline, or adjudication logic.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable, TextIO


class QuickCliError(Exception):
    """User-facing adapter error with a stable message."""


# Expand --ioc argv only while both stay under these caps; beyond either limit
# hand values off through a temporary bare-IOC file via --input.
_ARGV_LENGTH_THRESHOLD = 8192
_VALUE_COUNT_THRESHOLD = 500


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ioc_rejudge judge",
        description=(
            "High-frequency bare-IOC entry. Positional values, --stdin lines, "
            "and --file content are adapted into the existing main CLI."
        ),
    )
    parser.add_argument(
        "iocs",
        nargs="*",
        metavar="IOC",
        help="Bare IOC value(s); may be repeated as positional arguments",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read bare IOC lines from stdin (non-interactive; UTF-8)",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        metavar="PATH",
        help="Bare IOC text file (one value per line; # comments and blanks skipped)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Forward --offline to the main CLI (local data and cache only)",
    )
    parser.add_argument(
        "--preset",
        choices=("fast", "standard", "refresh"),
        default="standard",
        help=(
            "Convenience mapping onto existing options: "
            "fast/standard use default cache and full providers; "
            "refresh maps to --refresh (bypass cache)"
        ),
    )
    parser.add_argument(
        "--queue",
        action="store_true",
        help=(
            "Enqueue collected IOCs into the unified job queue and exit "
            "(do not run adjudication inline)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("offline", "online"),
        default="offline",
        help="Queue mode recorded on the job (default: offline); online runner is later",
    )
    parser.add_argument(
        "--jobs-dir",
        default=None,
        metavar="PATH",
        help="Job queue root directory when using --queue (default: jobs)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="adapter_json",
        help=(
            "Emit a machine-readable adapter summary on stderr; "
            "result JSONL/CSV remain main-CLI responsibilities"
        ),
    )
    return parser


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.lstrip().startswith("#")


def _iter_bare_ioc_lines(lines: Iterable[str]) -> list[str]:
    values: list[str] = []
    for line in lines:
        if _is_comment_or_blank(line):
            continue
        values.append(line.strip())
    return values


def _read_stdin_lines() -> list[str]:
    stream: TextIO = sys.stdin
    if hasattr(stream, "isatty") and stream.isatty():
        raise QuickCliError(
            "stdin is interactive; pipe input, or pass positional IOCs / --file"
        )
    # Prefer binary UTF-8 when a buffer is available so Windows console
    # encodings cannot silently corrupt pasted IOC text.
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        try:
            raw = buffer.read()
        except OSError as exc:
            raise QuickCliError(f"cannot read stdin: {exc}") from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise QuickCliError(
                f"stdin is not valid UTF-8 ({exc.reason} at byte {exc.start})"
            ) from exc
    else:
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (OSError, ValueError, AttributeError):
                pass
        try:
            text = stream.read()
        except OSError as exc:
            raise QuickCliError(f"cannot read stdin: {exc}") from exc
    return _iter_bare_ioc_lines(text.splitlines())


def _read_file_lines(path: str) -> list[str]:
    source = Path(path)
    last_error: Exception | None = None
    for encoding in ("utf-8-sig", "gbk"):
        try:
            text = source.read_text(encoding=encoding)
            break
        except FileNotFoundError as exc:
            raise QuickCliError(f"--file does not exist: {source}") from exc
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
        except OSError as exc:
            raise QuickCliError(f"cannot read --file {source}: {exc}") from exc
    else:
        raise QuickCliError(
            f"Cannot decode --file as UTF-8 or GBK: {source}"
            + (f" ({last_error})" if last_error else "")
        )
    return _iter_bare_ioc_lines(text.splitlines())


def _collect_values(args: argparse.Namespace) -> list[str]:
    has_source = bool(args.iocs) or args.stdin or bool(args.file_path)
    if not has_source:
        raise QuickCliError(
            "at least one input source is required: positional IOC, --stdin, or --file"
        )

    values: list[str] = list(args.iocs)
    sources_empty: list[str] = []

    if args.stdin:
        stdin_values = _read_stdin_lines()
        if not stdin_values and not args.iocs and not args.file_path:
            raise QuickCliError(
                "stdin contained no IOC values (empty or only blank/# comment lines)"
            )
        if not stdin_values:
            sources_empty.append("stdin")
        values.extend(stdin_values)

    if args.file_path:
        file_values = _read_file_lines(args.file_path)
        if not file_values and not values:
            raise QuickCliError(
                f"--file contained no IOC values (empty or only blank/# comment lines): "
                f"{args.file_path}"
            )
        if not file_values:
            sources_empty.append(f"--file {args.file_path}")
        values.extend(file_values)

    if not values:
        detail = ", ".join(sources_empty) if sources_empty else "all sources"
        raise QuickCliError(f"no IOC values found from {detail}")

    return values


def _preset_flags(preset: str) -> list[str]:
    # fast / standard: default cache + default full providers (no extra flags).
    # refresh: existing main-CLI bypass-cache semantics.
    if preset == "refresh":
        return ["--refresh"]
    return []


_JUDGE_BOOL_FLAGS = frozenset(
    {"--stdin", "--offline", "--json", "--queue", "-h", "--help"}
)
_JUDGE_VALUE_FLAGS = frozenset({"--file", "--preset", "--mode", "--jobs-dir"})


def _partition_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split judge-owned tokens from main-CLI passthrough tokens.

    ``argparse.parse_known_args`` treats the value after an unknown option such
    as ``--jsonl PATH`` as a positional IOC.  This partition keeps those pairs
    in the remainder so only real IOC tokens become positionals.
    """
    judge: list[str] = []
    remainder: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in _JUDGE_BOOL_FLAGS:
            judge.append(token)
            index += 1
            continue
        if token in _JUDGE_VALUE_FLAGS:
            judge.append(token)
            index += 1
            if index < len(argv) and not argv[index].startswith("-"):
                judge.append(argv[index])
                index += 1
            continue
        if (
            token.startswith("--file=")
            or token.startswith("--preset=")
            or token.startswith("--mode=")
            or token.startswith("--jobs-dir=")
        ):
            judge.append(token)
            index += 1
            continue
        if token.startswith("-"):
            remainder.append(token)
            if "=" in token:
                index += 1
                continue
            if index + 1 < len(argv) and not argv[index + 1].startswith("-"):
                remainder.append(argv[index + 1])
                index += 2
            else:
                index += 1
            continue
        judge.append(token)
        index += 1
    return judge, remainder


def _estimate_ioc_argv_length(values: list[str]) -> int:
    """Estimate argv character length for the expanded ``--ioc`` form.

    Mirrors ``_build_main_argv`` ioc expansion: each value becomes
    ``"--ioc"`` + value (plus one space separator per token in a joined view).
    """
    # Join-style estimate matching how CreateProcess sees the command line:
    # "ioc_rejudge" + for each value: " --ioc " + value
    total = len("ioc_rejudge")
    for value in values:
        total += 1 + len("--ioc") + 1 + len(value)
    return total


def _should_transfer_to_file(values: list[str]) -> bool:
    """True when expanded --ioc argv would exceed length or count thresholds."""
    if len(values) > _VALUE_COUNT_THRESHOLD:
        return True
    return _estimate_ioc_argv_length(values) > _ARGV_LENGTH_THRESHOLD


def _write_temp_ioc_file(values: list[str]) -> str:
    """Write values as bare IOC lines to a UTF-8 temp file; return its path."""
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="ioc_rejudge_judge_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for value in values:
                handle.write(value)
                handle.write("\n")
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _build_main_argv(
    values: list[str],
    *,
    offline: bool,
    preset: str,
    remainder: list[str],
    input_path: str | None = None,
) -> list[str]:
    argv: list[str] = ["ioc_rejudge"]
    if input_path is not None:
        argv.extend(["--input", input_path])
    else:
        for value in values:
            argv.extend(["--ioc", value])
    if offline:
        argv.append("--offline")
    argv.extend(_preset_flags(preset))
    argv.extend(remainder)
    return argv


def _emit_adapter_json(payload: dict) -> None:
    print(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        file=sys.stderr,
    )


def _print_error(message: str, *, as_json: bool) -> None:
    if as_json:
        _emit_adapter_json({"command": "judge", "error": message, "ok": False})
    else:
        print(f"ERROR: {message}", file=sys.stderr)


def _unlink_quiet(path: str | None) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _enqueue_values(
    values: list[str],
    *,
    mode: str,
    preset: str,
    jobs_dir: str | None,
    sources: dict,
    as_json: bool,
) -> int:
    """Create a bare offline/online job and print the new job id."""
    from ioc_rejudge.job_queue import DEFAULT_JOBS_DIR, UnifiedJobQueue
    from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS

    input_text = "".join(f"{value}\n" for value in values)
    root = Path(jobs_dir) if jobs_dir else DEFAULT_JOBS_DIR
    queue = UnifiedJobQueue(root)
    job = queue.create_job(
        input_text,
        input_kind="bare",
        mode=mode,
        providers=list(DEFAULT_PROVIDERS),
        preset=preset,
        source="judge",
    )
    job_id = job["job_id"]
    if as_json:
        _emit_adapter_json(
            {
                "command": "judge",
                "ioc_count": len(values),
                "job_id": job_id,
                "jobs_dir": str(root),
                "mode": mode,
                "ok": True,
                "preset": preset,
                "queued": True,
                "sources": sources,
                "state": job.get("state", "queued"),
                "value_count": len(values),
            }
        )
    print(f"queued: {job_id}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse judge-specific args and forward into ``ioc_rejudge.cli.main``."""
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    judge_argv, remainder = _partition_argv(raw)
    args = parser.parse_args(judge_argv)

    try:
        values = _collect_values(args)
    except QuickCliError as exc:
        _print_error(str(exc), as_json=args.adapter_json)
        return 2

    # --queue enqueues only; it is mutually exclusive with direct main-CLI execution.
    if args.queue:
        if remainder:
            message = (
                "--queue cannot be combined with main CLI execution options: "
                + " ".join(remainder)
            )
            _print_error(message, as_json=args.adapter_json)
            return 2
        sources = {
            "file": bool(args.file_path),
            "positional": len(args.iocs),
            "stdin": bool(args.stdin),
        }
        try:
            return _enqueue_values(
                values,
                mode=args.mode,
                preset=args.preset,
                jobs_dir=args.jobs_dir,
                sources=sources,
                as_json=args.adapter_json,
            )
        except Exception as exc:
            _print_error(str(exc), as_json=args.adapter_json)
            return 2

    transfer_to_file = _should_transfer_to_file(values)
    temp_input_path: str | None = None
    try:
        if transfer_to_file:
            temp_input_path = _write_temp_ioc_file(values)
            main_argv = _build_main_argv(
                values,
                offline=args.offline,
                preset=args.preset,
                remainder=remainder,
                input_path=temp_input_path,
            )
        else:
            main_argv = _build_main_argv(
                values,
                offline=args.offline,
                preset=args.preset,
                remainder=remainder,
            )

        if args.adapter_json:
            _emit_adapter_json(
                {
                    "command": "judge",
                    "ioc_count": len(values),
                    "offline": bool(args.offline),
                    "ok": True,
                    "preset": args.preset,
                    "sources": {
                        "file": bool(args.file_path),
                        "positional": len(args.iocs),
                        "stdin": bool(args.stdin),
                    },
                    "transferred_to_file": transfer_to_file,
                    "value_count": len(values),
                }
            )

        from ioc_rejudge.cli import main as cli_main

        previous_argv = sys.argv
        try:
            sys.argv = main_argv
            cli_main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            print(code, file=sys.stderr)
            return 1
        finally:
            sys.argv = previous_argv
        return 0
    finally:
        _unlink_quiet(temp_input_path)


if __name__ == "__main__":
    raise SystemExit(main())
