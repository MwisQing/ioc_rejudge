"""Push the current git repo and rollback tags to GitHub."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent

_REPO = "MwisQing/ioc_rejudge"
_REMOTE_URL = f"https://github.com/{_REPO}.git"

_INIT_PATHS = [
    "ioc_rejudge/",
    "rules/",
    "tests/",
    "README.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "VERSION",
    "requirements.txt",
    "requirements-dev.txt",
    "provider-config.example.json",
    "iocProducer_api_ioc_info.py",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/HISTORY.md",
    "pack.py",
    "push.py",
    "upgrade.py",
    ".gitignore",
]


def _read_version() -> str:
    version_file = Path("VERSION")
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "0.0.0"


def _show_version() -> None:
    print(f"当前版本: v{_read_version()}")


def run_git(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        sys.exit("错误: 系统中未找到 git 命令，请确认 git 已安装并在 PATH 中")
    except subprocess.TimeoutExpired:
        sys.exit(f"错误: Git 操作超时 ({timeout}s): {' '.join(cmd)}")


def _ensure_git_repo(root: Path) -> None:
    """Init git repo if missing, for example after extracting a release zip."""
    if (root / ".git").exists():
        return
    print("未检测到 Git 仓库，正在初始化...")
    code, _, stderr = run_git(["git", "init"])
    if code != 0:
        sys.exit(f"错误: git init 失败\n{stderr.strip()}")
    print("已初始化 Git 仓库")


def _ensure_at_least_one_commit(root: Path) -> None:
    code, _, _ = run_git(["git", "rev-parse", "HEAD"])
    if code == 0:
        return

    print("仓库中没有任何提交，正在创建初始提交...")
    version = _read_version()
    existing = [path for path in _INIT_PATHS if (root / path).exists()]
    if not existing:
        sys.exit("错误: 没有可提交的项目文件")

    code, _, stderr = run_git(["git", "add", "--"] + existing)
    if code != 0:
        sys.exit(f"错误: git add 失败\n{stderr.strip()}")

    message = f"initial: v{version} from release"
    code, _, stderr = run_git(["git", "commit", "-m", message])
    if code != 0:
        sys.exit(f"错误: git commit 失败\n{stderr.strip()}")
    print(f"已创建初始提交: {message}")

    tag = f"v{version}"
    code, _, stderr = run_git(["git", "tag", tag])
    if code != 0:
        print(f"警告: 创建基线标签失败\n{stderr.strip()}")
    else:
        print(f"已创建基线标签: {tag}")


def get_remote_url(remote_name: str = "origin") -> Optional[str]:
    code, stdout, _ = run_git(["git", "remote", "get-url", remote_name])
    if code == 0:
        url = stdout.strip()
        if url:
            return url
    return None


def ensure_remote() -> None:
    existing = get_remote_url("origin")

    if existing is None:
        print(f"正在添加 origin -> {_REMOTE_URL}")
        code, _, stderr = run_git(["git", "remote", "add", "origin", _REMOTE_URL])
        if code != 0:
            sys.exit(f"错误: 添加远程仓库失败\n{stderr.strip()}")
        return

    if existing == _REMOTE_URL:
        print(f"origin: {existing}")
        return

    print("错误: origin 已指向其他远程仓库")
    print(f"  当前: {existing}")
    print(f"  目标: {_REMOTE_URL}")
    sys.exit("请确认仓库地址后再运行 push.py，避免推送到错误仓库")


def resolve_branch() -> str:
    code, stdout, _ = run_git(["git", "branch", "--show-current"])
    branch = stdout.strip() if code == 0 else ""
    if branch:
        return branch

    for name in ("main", "master"):
        code, stdout, _ = run_git(["git", "branch", "--list", name])
        if code == 0 and stdout.strip():
            code2, _, stderr2 = run_git(["git", "checkout", name])
            if code2 == 0:
                return name
            sys.exit(f"错误: 无法切换到 {name} 分支\n{stderr2.strip()}")

    code, _, stderr = run_git(["git", "checkout", "-b", "main"])
    if code != 0:
        sys.exit(f"错误: 无法创建 main 分支\n{stderr.strip()}")
    return "main"


def show_changes() -> None:
    print("本地状态:")
    code, stdout, _ = run_git(["git", "status", "--short"])
    if code == 0 and stdout.strip():
        print(stdout.strip())
    else:
        print("(干净)")


def push_branch(branch: str) -> tuple[bool, str]:
    print(f"正在推送分支 {branch} -> origin ...")
    code, stdout, stderr = run_git(["git", "push", "-u", "origin", branch], timeout=120)
    output = (stderr + stdout).strip()
    if code != 0:
        print(f"警告: 推送分支失败\n{output}")
        return False, output
    print(stdout.strip() or "分支推送成功")
    return True, output


def push_tags() -> tuple[bool, str]:
    print("正在推送 tags ...")
    code, stdout, stderr = run_git(["git", "push", "origin", "--tags"], timeout=120)
    output = (stderr + stdout).strip()
    if code != 0:
        print(f"错误: 推送 tags 失败\n{output}")
        return False, output
    print(stdout.strip() or "tags 推送成功")
    return True, output


def push_branch_and_tags(branch: str) -> None:
    branch_ok, branch_output = push_branch(branch)
    tags_ok, tags_output = push_tags()

    if not branch_ok and tags_ok:
        sys.exit(
            "分支推送失败，但 tags 已尝试推送成功。\n"
            "请先处理分支推送问题（通常需要 git pull 或解决远端已有提交），然后重新运行 push.py。\n"
            f"{branch_output}"
        )
    if branch_ok and not tags_ok:
        sys.exit(f"分支已推送，但 tags 推送失败。\n{tags_output}")
    if not branch_ok and not tags_ok:
        sys.exit(f"分支和 tags 均推送失败。\n分支错误:\n{branch_output}\n\ntags 错误:\n{tags_output}")


def _pause() -> None:
    try:
        input("按任意键继续...")
    except EOFError:
        pass


def main() -> None:
    os.chdir(SCRIPT_DIR)
    root = SCRIPT_DIR

    _show_version()
    print("版本回退依赖 pack.py 创建的 v版本-时间戳 tag")

    print("[1/3] 环境检查...")
    _ensure_git_repo(root)
    _ensure_at_least_one_commit(root)
    ensure_remote()

    show_changes()

    print("[2/3] 推送分支...")
    branch = resolve_branch()

    print("[3/3] 推送标签...")
    push_branch_and_tags(branch)

    print("\n推送完成。")
    _pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n操作已取消。")
        sys.exit(0)
