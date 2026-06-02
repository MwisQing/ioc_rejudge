"""Pack the project into a distributable zip archive with a rollback tag."""

import argparse
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

_INCLUDE_PATHS = [
    "ioc_rejudge/",
    "rules/",
    "tests/",
    "CLAUDE.md",
    "VERSION",
    "pack.py",
    "push.py",
    "upgrade.py",
    ".gitignore",
]

_STAGE_PATHS = list(_INCLUDE_PATHS)

_EXCLUDE_PREFIXES = [
    "docs/",
    "release/",
    "ioc.txt",
    "ioc_info_result_diagnostics.json",
    "history.md",
    "ai开发提示词.md",
    "AGENTS.md",
    ".clinerules/",
]

_ZIP_PREFIX = "ioc_rejudge"

_GITIGNORE_CONTENT = """\
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.tmp
*.temp
json_temp.*
/dist/
*.egg-info/
*.zip
release/
"""


def _read_version(root: Path) -> str:
    version_file = root / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "0.0.0"


def _show_version(root: Path) -> None:
    print(f"当前版本: v{_read_version(root)}")


def _check_git() -> None:
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("错误: 未找到 Git，请先安装 Git 并添加到 PATH。")
        sys.exit(1)


def _ensure_gitignore(root: Path) -> None:
    gitignore = root / ".gitignore"
    if gitignore.exists():
        return
    gitignore.write_text(_GITIGNORE_CONTENT, encoding="utf-8")
    print("已创建 .gitignore")


def _ensure_version(root: Path) -> None:
    version_file = root / "VERSION"
    if version_file.exists():
        return
    version_file.write_text("1.0.0\n", encoding="utf-8")
    print("已创建 VERSION: 1.0.0")


def _git_init(root: Path) -> None:
    if (root / ".git").exists():
        print("Git 仓库已存在，跳过 git init")
        return
    try:
        subprocess.run(["git", "init"], cwd=str(root), capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"错误: git init 失败:\n{e.stderr.strip()}")
        sys.exit(1)
    print("已初始化 Git 仓库")


def _git_add(root: Path) -> None:
    try:
        subprocess.run(
            ["git", "add", "--"] + _STAGE_PATHS,
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"错误: git add 失败:\n{e.stderr.strip()}")
        sys.exit(1)
    print("已添加发布文件到暂存区")


def _git_commit(root: Path, message: str) -> bool:
    try:
        diff = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=str(root),
            capture_output=True,
        )
        if diff.returncode == 0:
            print("没有暂存变更，跳过 git commit 和 tag")
            return False

        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"错误: git commit 失败:\n{e.stderr.strip()}")
        sys.exit(1)
    print(f"已提交: {message}")
    return True


def _git_tag(root: Path, version: str) -> str:
    now = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = f"v{version}-{now}"
    try:
        subprocess.run(
            ["git", "tag", "-a", tag, "-m", f"Release v{version}"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"错误: 创建 tag 失败:\n{e.stderr.strip()}")
        sys.exit(1)
    print(f"已打回退标签: {tag}")
    return tag


def _bump_version(root: Path, current: str) -> str:
    print()
    print(f"下一次发布版本设置 (当前已打包版本: {current})")
    print("  p) patch  {}.{}.{}  (小修复)".format(*_parse_version(current, "patch")))
    print("  n) minor  {}.{}.{}  (新功能)".format(*_parse_version(current, "minor")))
    print("  m) major  {}.{}.{}  (大版本)".format(*_parse_version(current, "major")))
    print(f"  s) skip   保持 {current}")
    try:
        choice = input("选择下一次版本 [p/n/m/s]: ").strip().lower()
    except EOFError:
        choice = "s"

    if choice == "p":
        new = _bump(current, "patch")
    elif choice == "n":
        new = _bump(current, "minor")
    elif choice == "m":
        new = _bump(current, "major")
    else:
        print(f"VERSION 保持为 {current}")
        return current

    (root / "VERSION").write_text(new + "\n", encoding="utf-8")
    print(f"VERSION 已更新为 {new}，将在下一次 pack 时提交和打包")
    return new


def _parse_version(v: str, part: str) -> tuple[int, int, int]:
    try:
        pieces = [int(piece) for piece in v.split(".")]
    except ValueError:
        print(f"错误: VERSION 不是合法 semver: {v}")
        sys.exit(1)
    major = pieces[0] if len(pieces) > 0 else 0
    minor = pieces[1] if len(pieces) > 1 else 0
    patch = pieces[2] if len(pieces) > 2 else 0
    if part == "major":
        return major + 1, 0, 0
    if part == "minor":
        return major, minor + 1, 0
    return major, minor, patch + 1


def _bump(v: str, part: str) -> str:
    return "{}.{}.{}".format(*_parse_version(v, part))


def _should_exclude(member_path: str) -> bool:
    parts = Path(member_path).parts
    if any(part in {"__pycache__", ".pytest_cache"} for part in parts):
        return True

    filename = parts[-1] if parts else ""
    if filename.endswith((".pyc", ".pyo", ".tmp", ".temp", ".zip")):
        return True
    if filename.startswith("json_temp."):
        return True

    normalized = member_path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in _EXCLUDE_PREFIXES)


def _create_zip(root: Path, version: str) -> Path:
    now = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_name = f"{_ZIP_PREFIX}_{version}_{now}.zip"
    release_dir = root / "release"
    release_dir.mkdir(exist_ok=True)
    zip_path = release_dir / zip_name

    included_count = 0
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for include in _INCLUDE_PATHS:
                target = root / include
                if not target.exists():
                    print(f"跳过不存在的路径: {include}")
                    continue

                if target.is_file():
                    if _should_exclude(include):
                        continue
                    zf.write(target, include)
                    included_count += 1
                    print(f"  + {include}")
                elif target.is_dir():
                    for file_path in target.rglob("*"):
                        if not file_path.is_file():
                            continue
                        rel = file_path.relative_to(root).as_posix()
                        if _should_exclude(rel):
                            continue
                        zf.write(file_path, rel)
                        included_count += 1
                        print(f"  + {rel}")
    except OSError as e:
        print(f"错误: 创建 zip 文件失败: {e}")
        sys.exit(1)

    print(f"\n已生成完整包: {zip_path}")
    print(f"包内版本: v{version}")
    print(f"包含 {included_count} 个文件")
    return zip_path


def main() -> None:
    parser = argparse.ArgumentParser(description="项目打包工具")
    parser.add_argument("-m", "--message", default=None, help="提交信息")
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)
    root = SCRIPT_DIR

    _show_version(root)

    print("[1/4] 环境准备...")
    _check_git()
    _ensure_gitignore(root)
    _ensure_version(root)
    _git_init(root)

    print("[2/4] 提交代码...")
    if args.message:
        message = args.message
    else:
        try:
            message = input("\n请输入提交信息: ").strip()
        except EOFError:
            print("错误: 无法读取输入，请使用 -m 参数指定提交信息")
            sys.exit(1)
    if not message:
        print("错误: 提交信息不能为空")
        sys.exit(1)

    version = _read_version(root)

    _git_add(root)
    committed = _git_commit(root, message)

    print("[3/4] 打版本标签...")
    if committed:
        _git_tag(root, version)
    else:
        print("跳过（无变更）")

    print("[4/4] 生成发布包...")
    _create_zip(root, version)

    _bump_version(root, version)

    print("\n打包完成。")
    input("按任意键继续...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n操作已取消。")
        sys.exit(0)
