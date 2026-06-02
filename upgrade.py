"""Update the project from a local release zip or GitHub."""

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent

_REPO = "MwisQing/ioc_rejudge"
_REMOTE_URL = f"https://github.com/{_REPO}.git"

_ZIP_PREFIX = "ioc_rejudge"


def _read_version(root: Path) -> str:
    version_file = root / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "0.0.0"


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string like '1.2.3' into comparable tuple."""
    parts = version_str.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (0,)


def _read_version_from_zip(zf: zipfile.ZipFile) -> Optional[str]:
    """Extract VERSION file content from zip without extracting all files."""
    for name in zf.namelist():
        if Path(name).name == "VERSION" and not name.startswith("__"):
            try:
                return zf.read(name).decode("utf-8").strip()
            except Exception:
                return None
    return None


def _show_version(root: Path, label: str = "当前版本") -> None:
    print(f"{label}: v{_read_version(root)}")


def run_git(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        sys.exit("错误: 系统中未找到 git 命令，请确认 git 已安装并在 PATH 中")
    except subprocess.TimeoutExpired:
        sys.exit(f"错误: Git 操作超时 ({timeout}s): {' '.join(cmd)}")


def resolve_branch() -> str:
    code, stdout, _ = run_git(["git", "branch", "--show-current"])
    branch = stdout.strip() if code == 0 else ""
    if branch:
        return branch
    for name in ("main", "master"):
        code2, stdout2, _ = run_git(["git", "branch", "--list", name])
        if code2 == 0 and stdout2.strip():
            return name
    return "main"


def _find_latest_zip(root: Path) -> Optional[Path]:
    release_dir = root / "release"
    if not release_dir.is_dir():
        return None
    zips = sorted(release_dir.glob(f"{_ZIP_PREFIX}_*.zip"), reverse=True)
    return zips[0] if zips else None


def _is_safe_member(root: Path, member_name: str) -> bool:
    member_path = Path(member_name)
    if member_path.is_absolute():
        return False
    target = (root / member_path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _validate_zip(root: Path, zf: zipfile.ZipFile) -> None:
    for member in zf.infolist():
        if member.is_dir():
            continue
        if not _is_safe_member(root, member.filename):
            sys.exit(f"错误: 更新包包含不安全路径: {member.filename}")


def _merge_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        dest_item = dst / item.name
        if item.is_dir():
            _merge_dir(item, dest_item)
        else:
            shutil.copy2(item, dest_item)


def _offline_update(root: Path, zip_path: Path) -> None:
    print(f"找到本地更新包: {zip_path.name}")
    current_version = _read_version(root)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            _validate_zip(root, zf)

            new_version = _read_version_from_zip(zf) or "0.0.0"
            print(f"当前版本: v{current_version} -> 更新包版本: v{new_version}")

            cur_ver = _parse_version(current_version)
            new_ver = _parse_version(new_version)

            if new_ver < cur_ver:
                print(f"警告: 更新包版本 (v{new_version}) 低于当前版本 (v{current_version})，这是降级操作")
                if not _confirm("是否继续降级安装？"):
                    print("已取消更新")
                    return
            elif new_ver == cur_ver:
                print(f"更新包版本 (v{new_version}) 与当前版本相同")
                if not _confirm("是否强制重新安装？"):
                    print("已取消更新")
                    return

            with tempfile.TemporaryDirectory(prefix="project-upgrade-") as tmp:
                tmp_root = Path(tmp)
                zf.extractall(tmp_root)

                source_dir = tmp_root
                for item in tmp_root.iterdir():
                    if item.is_dir() and (item / "VERSION").exists():
                        source_dir = item
                        break

                _merge_dir(source_dir, root)

        releases_dir = root / "release"
        releases_dir.mkdir(exist_ok=True)
        used_name = f"_used_{zip_path.name}"
        shutil.move(str(zip_path), str(releases_dir / used_name))
    except (OSError, zipfile.BadZipFile) as e:
        sys.exit(f"错误: 离线更新失败: {e}")
    print("离线更新完成")


def _get_remote_url() -> Optional[str]:
    code, stdout, _ = run_git(["git", "remote", "get-url", "origin"])
    if code == 0:
        url = stdout.strip()
        if url:
            return url
    return None


def _ensure_remote() -> None:
    existing = _get_remote_url()
    if existing is None:
        print(f"正在添加 origin -> {_REMOTE_URL}")
        code, _, stderr = run_git(["git", "remote", "add", "origin", _REMOTE_URL])
        if code != 0:
            sys.exit(f"错误: 添加远程仓库失败\n{stderr.strip()}")
        return

    if existing == _REMOTE_URL:
        return

    print("错误: origin 已指向其他远程仓库")
    print(f"  当前: {existing}")
    print(f"  目标: {_REMOTE_URL}")
    sys.exit("请确认仓库地址后再从 GitHub 更新")


def _github_update() -> None:
    _ensure_remote()
    branch = resolve_branch()
    print(f"正在从 GitHub 拉取 {branch} 分支 ...")
    code, stdout, stderr = run_git(["git", "pull", "origin", branch], timeout=120)
    if code != 0:
        output = (stderr + stdout).strip()
        sys.exit(f"错误: 拉取失败\n{output}")
    print(stdout.strip() or "GitHub 更新完成")


def _confirm(prompt: str) -> bool:
    try:
        answer = input(prompt + " (y/n): ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def main() -> None:
    os.chdir(SCRIPT_DIR)
    root = SCRIPT_DIR

    _show_version(root, "更新前版本")

    print("[1/2] 检测更新源...")
    zip_path = _find_latest_zip(root)
    if zip_path:
        _offline_update(root, zip_path)
    else:
        print("未找到本地更新包")
        if _confirm("是否从 GitHub 拉取更新？"):
            _github_update()
        else:
            print("已取消更新")
            return

    print("[2/2] 确认版本...")
    _show_version(root, "更新后版本")

    print("\n更新完成。")
    input("按任意键继续...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n操作已取消。")
        sys.exit(0)
