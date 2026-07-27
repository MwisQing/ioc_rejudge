"""GitHub Release updater tests."""

import io
import json
import zipfile

import pytest

import upgrade


class _Response:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return self._stream.read(size)


def _release(version="2.1.2"):
    return {
        "tag_name": f"v{version}",
        "assets": [{
            "name": f"ioc_rejudge_v{version}_20260727-000000.zip",
            "browser_download_url": "https://downloads.invalid/release.zip",
        }],
    }


def _zip_bytes(version="2.1.2"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("VERSION", version)
        archive.writestr("upgrade.py", "# updated")
    return buffer.getvalue()


def test_select_release_asset_requires_project_zip():
    assert upgrade._select_release_asset(_release())[0].startswith("ioc_rejudge_v2.1.2")
    with pytest.raises(ValueError, match="没有可用"):
        upgrade._select_release_asset({"assets": []})


def test_fetch_latest_release_uses_github_api(monkeypatch):
    payload = json.dumps(_release()).encode("utf-8")
    monkeypatch.setattr(upgrade.urllib.request, "urlopen", lambda request, timeout: _Response(payload))
    assert upgrade._fetch_latest_release()["tag_name"] == "v2.1.2"


def test_download_latest_release_validates_and_saves_zip(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("2.1.0", encoding="utf-8")
    monkeypatch.setattr(upgrade, "_fetch_latest_release", lambda: _release())
    monkeypatch.setattr(
        upgrade.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(_zip_bytes()),
    )

    path = upgrade._download_latest_release(tmp_path)

    assert path is not None and path.is_file()
    assert path.parent == tmp_path / "release"


def test_download_latest_release_skips_current_version(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("2.1.2", encoding="utf-8")
    monkeypatch.setattr(upgrade, "_fetch_latest_release", lambda: _release())
    assert upgrade._download_latest_release(tmp_path) is None


def test_download_latest_release_removes_mismatched_package(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("2.1.0", encoding="utf-8")
    monkeypatch.setattr(upgrade, "_fetch_latest_release", lambda: _release())
    monkeypatch.setattr(
        upgrade.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(_zip_bytes("9.9.9")),
    )
    with pytest.raises(RuntimeError, match="版本不一致"):
        upgrade._download_latest_release(tmp_path)
    assert not list((tmp_path / "release").glob("*.zip"))
