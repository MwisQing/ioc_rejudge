"""Build a deterministic, non-Git release archive."""

import argparse
import json
import os
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

_INCLUDE_PATHS = [
    "ioc_rejudge/",
    "rules/",
    "tests/",
    "iocProducer_api_ioc_info.py",
    "ioc_rejudge/anonymize_ioc.py",
    "README.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "VERSION",
    "requirements.txt",
    "requirements-dev.txt",
    "credentials.example.json",
    "provider-config.example.json",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/HISTORY.md",
    "pack.py",
    "push.py",
    "upgrade.py",
    ".gitignore",
]

_EXCLUDE_PREFIXES = (
    "docs/agent-prompts/",
    "docs/superpowers/",
    "ioc_info/",
    "outputs/",
    "release/",
)

_ZIP_PREFIX = "ioc_rejudge"
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _read_version(root: Path) -> str:
    version_file = root / "VERSION"
    if not version_file.is_file():
        raise ValueError("VERSION file is missing")
    version = version_file.read_text(encoding="utf-8").strip()
    _validate_version(version)
    return version


def _validate_version(version: str) -> None:
    if not _SEMVER_RE.fullmatch(version):
        raise ValueError(f"VERSION is not strict semver: {version!r}")


def _should_exclude(member_path: str) -> bool:
    normalized = member_path.replace("\\", "/")
    if normalized.startswith(_EXCLUDE_PREFIXES):
        return True

    parts = Path(normalized).parts
    if any(part in {"__pycache__", ".pytest_cache", ".git"} for part in parts):
        return True

    filename = parts[-1] if parts else ""
    return filename.endswith(
        (".pyc", ".pyo", ".tmp", ".temp", ".zip", ".log")
    )


def _iter_package_files(root: Path) -> list[tuple[Path, str]]:
    by_member: dict[str, Path] = {}
    for include in _INCLUDE_PATHS:
        target = root / include
        if not target.exists():
            continue
        if target.is_file():
            member = target.relative_to(root).as_posix()
            if not _should_exclude(member):
                by_member[member] = target
            continue
        for file_path in target.rglob("*"):
            if not file_path.is_file():
                continue
            member = file_path.relative_to(root).as_posix()
            if not _should_exclude(member):
                by_member[member] = file_path
    return [(by_member[member], member) for member in sorted(by_member)]


def _build_manifest(
    version: str,
    created_at: str,
    zip_name: str,
    included_paths: list[str],
) -> dict:
    return {
        "project": _ZIP_PREFIX,
        "version": version,
        "created_at": created_at,
        "zip_name": zip_name,
        "included_paths": included_paths,
        "source": "filesystem",
    }


def _create_zip(root: Path, version: str, output_dir: Path) -> Path:
    _validate_version(version)
    created_at = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_name = f"{_ZIP_PREFIX}_v{version}_{created_at}.zip"
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / zip_name
    package_files = _iter_package_files(root)
    included_paths = [member for _, member in package_files]
    manifest = _build_manifest(
        version,
        created_at,
        zip_name,
        included_paths,
    )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path, member in package_files:
            archive.write(file_path, member)
        archive.writestr(
            "RELEASE.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )
    return zip_path


def _run_checks(root: Path) -> list[tuple[Path, str]]:
    version = _read_version(root)
    missing = [path for path in _INCLUDE_PATHS if not (root / path).exists()]
    if missing:
        raise ValueError("Missing release paths: " + ", ".join(missing))

    gitignore = root / ".gitignore"
    ignored = gitignore.read_text(encoding="utf-8", errors="ignore")
    if "release/" not in ignored and "/release/" not in ignored:
        raise ValueError(".gitignore must exclude release/")

    package_files = _iter_package_files(root)
    if not package_files:
        raise ValueError("Release package would be empty")
    print(f"版本: v{version}")
    print(f"发布文件: {len(package_files)}")
    print("检查完成：未创建 Git、tag 或 zip")
    return package_files


def _resolve_output_dir(root: Path, value: str) -> Path:
    output = Path(value).expanduser()
    return output if output.is_absolute() else root / output


def _pause() -> None:
    try:
        input("按任意键继续...")
    except EOFError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC Rejudge 非 Git 发布打包工具")
    parser.add_argument(
        "--check",
        action="store_true",
        help="只检查版本、路径和排除规则，不创建 zip",
    )
    parser.add_argument(
        "--output-dir",
        default="release",
        help="发布包输出目录（默认 release）",
    )
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)
    root = SCRIPT_DIR
    _run_checks(root)
    if args.check:
        return

    version = _read_version(root)
    output_dir = _resolve_output_dir(root, args.output_dir)
    zip_path = _create_zip(root, version, output_dir)
    print(f"发布包: {zip_path}")
    print("VERSION 保持不变；本工具未执行 Git 或网络操作。")
    _pause()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, ValueError) as exc:
        if isinstance(exc, KeyboardInterrupt):
            print("\n操作已取消。")
            sys.exit(0)
        sys.exit(f"错误: {exc}")
