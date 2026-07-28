"""Update the project from a local release zip or GitHub."""

import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent

_REPO = "MwisQing/ioc_rejudge"
_LATEST_RELEASE_API = f"https://api.github.com/repos/{_REPO}/releases/latest"

_ZIP_PREFIX = "ioc_rejudge"
_USER_AGENT = "ioc-rejudge-updater"


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


def _select_release_asset(release: dict) -> tuple[str, str]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("GitHub Release assets 格式无效")
    candidates = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url", ""))
        if name.startswith(f"{_ZIP_PREFIX}_v") and name.endswith(".zip") and url:
            candidates.append((name, url))
    if not candidates:
        raise ValueError("最新 GitHub Release 没有可用的 ioc_rejudge ZIP 资产")
    return sorted(candidates, reverse=True)[0]


def _fetch_latest_release(timeout: int = 30) -> dict:
    request = urllib.request.Request(
        _LATEST_RELEASE_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": _USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub Release 查询失败: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub Release 查询失败: {exc.reason}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub Release 返回了无效 JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub Release 返回格式无效")
    return payload


def _download_release_asset(url: str, destination: Path, timeout: int = 120) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with partial.open("wb") as output:
                shutil.copyfileobj(response, output)
        partial.replace(destination)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"GitHub Release 下载失败: {exc}") from exc


def _check_latest_release(root: Path) -> Optional[tuple[dict, str]]:
    """Fetch GitHub latest release and compare with the local version.

    Returns ``(release, latest_version)`` when a newer version exists, and
    ``None`` when the local version is already up to date.
    """
    release = _fetch_latest_release()
    tag = str(release.get("tag_name", "")).strip()
    latest_version = tag[1:] if tag.lower().startswith("v") else tag
    if not latest_version or _parse_version(latest_version) == (0,):
        raise RuntimeError("GitHub Release 版本号无效")
    current_version = _read_version(root)
    print(f"GitHub 最新版本: v{latest_version}")
    if _parse_version(latest_version) <= _parse_version(current_version):
        print("当前已是最新版本")
        return None
    print(f"当前版本: v{current_version} -> 最新版本: v{latest_version}")
    return release, latest_version


def _download_latest_release(root: Path, release: dict, latest_version: str) -> Path:
    """Download, validate and save the latest release asset.

    The caller must have confirmed ``latest_version`` is newer than the local
    version (via :func:`_check_latest_release`).
    """
    name, url = _select_release_asset(release)
    release_dir = root / "release"
    release_dir.mkdir(exist_ok=True)
    destination = release_dir / name
    print(f"正在下载: {name}")
    _download_release_asset(url, destination)
    try:
        with zipfile.ZipFile(destination, "r") as zf:
            _validate_zip(root, zf)
            packaged_version = _read_version_from_zip(zf)
    except (OSError, zipfile.BadZipFile):
        destination.unlink(missing_ok=True)
        raise RuntimeError("下载的 GitHub Release ZIP 无效")
    if packaged_version != latest_version:
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"GitHub Release 版本不一致: tag v{latest_version}, ZIP v{packaged_version}"
        )
    print("下载完成并通过版本与路径检查")
    return destination


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
        print("正在检查 GitHub 最新版本...")
        try:
            latest_info = _check_latest_release(root)
        except (OSError, RuntimeError, ValueError) as exc:
            sys.exit(f"错误: {exc}")
        if latest_info is None:
            return
        release, latest_version = latest_info
        if not _confirm(f"发现新版本 v{latest_version}，是否下载并安装更新？"):
            print("已取消更新")
            return
        try:
            zip_path = _download_latest_release(root, release, latest_version)
        except (OSError, RuntimeError, ValueError) as exc:
            sys.exit(f"错误: {exc}")
        _offline_update(root, zip_path)

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
