"""R14: share UI must preserve restore capability beyond retention display limit."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ioc_rejudge.ui import build_server

from tests.test_ui_server import (
    api_post,
    cloud_response_rows,
    create,
    sample_content,
    unlock,
)


@pytest.fixture()
def make_server(tmp_path):
    """Local copy of the UI server fixture (fixtures are module-scoped)."""
    servers = []

    def _make(
        max_bundles=20,
        port=0,
        cache_dir=None,
        provider_env=None,
        transport_factory=None,
        credentials_path=None,
    ):
        key_path = tmp_path / "keys" / "key.json"
        bundles_dir = tmp_path / "bundles"
        resolved_cache = cache_dir if cache_dir is not None else (tmp_path / "provider-cache")
        server, url = build_server(
            key_path,
            bundles_dir,
            port=port,
            max_bundles=max_bundles,
            cache_dir=resolved_cache,
            provider_env=provider_env if provider_env is not None else {},
            transport_factory=transport_factory,
            credentials_path=credentials_path,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        base, _, token = url.partition("/?token=")
        return base, token, key_path, bundles_dir

    yield _make
    for server in servers:
        server.shutdown()
        server.server_close()


def _write_synthetic_bundle(
    bundles_dir: Path,
    bundle_id: str,
    created_at: str,
    *,
    with_restore: bool = False,
):
    bundle_dir = bundles_dir / bundle_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    share_text = (
        json.dumps({"ioc": f"{bundle_id}.invalid", "note": "synthetic"}, ensure_ascii=False)
        + "\n"
    )
    (bundle_dir / "share.jsonl").write_text(share_text, encoding="utf-8")
    manifest = {
        "bundle_id": bundle_id,
        "created_at": created_at,
        "rows": 1,
        "output_sha256": bundle_id + ("a" * 44),
        "token_occurrences": 0,
        "redacted_occurrences": 0,
        "source_findings": 0,
    }
    (bundle_dir / "share.jsonl.manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if with_restore:
        (bundle_dir / "restored-old.jsonl").write_text(
            json.dumps({"ioc": "restored-keep.invalid"}) + "\n",
            encoding="utf-8",
        )
        (bundle_dir / "cloud-old.jsonl").write_text(
            json.dumps({"bundle_id": bundle_id, "ioc": "cloud-keep.invalid"}) + "\n",
            encoding="utf-8",
        )
    return bundle_dir


def test_retention_overflow_keeps_oldest_manifest_and_restored_artifacts(make_server):
    url, token, _key, bundles_dir = make_server(max_bundles=2)
    unlock(url, token)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    oldest_id = "aaaaaaaaaaaaaaaaaaaa"
    oldest_dir = _write_synthetic_bundle(
        bundles_dir,
        oldest_id,
        base.isoformat().replace("+00:00", "Z"),
        with_restore=True,
    )
    created_ids = []
    for index in range(3):
        payload = {
            "content": json.dumps({"ioc": f"keep-{index}.example.invalid", "data": []}) + "\n"
        }
        created = create(url, token, payload)
        created_ids.append(created["bundle_id"])

    assert oldest_dir.is_dir()
    assert (oldest_dir / "share.jsonl.manifest.json").is_file()
    assert (oldest_dir / "restored-old.jsonl").is_file()
    assert (oldest_dir / "cloud-old.jsonl").is_file()
    for bundle_id in created_ids:
        assert (bundles_dir / bundle_id / "share.jsonl.manifest.json").is_file()

    status, body = api_post(url, token, "/api/status", {})
    assert status == 200
    listed_ids = [item["bundle_id"] for item in body["bundles"]]
    assert len(listed_ids) == 2
    assert body["bundle_history_limit"] == 2
    assert body["bundle_total"] >= 4
    # Newest history is shown; oldest synthetic is retained on disk for restore.
    assert oldest_id not in listed_ids
    assert (oldest_dir / "share.jsonl.manifest.json").is_file()


def test_restore_oldest_after_overflow_and_server_reload(make_server):
    """Create >20 bundles, restore oldest via retained manifest, reload, restore again."""
    url, token, key_path, bundles_dir = make_server(max_bundles=20)
    unlock(url, token)

    first = create(url, token, {"content": sample_content()})
    oldest_id = first["bundle_id"]
    oldest_dir = bundles_dir / oldest_id
    assert (oldest_dir / "share.jsonl.manifest.json").is_file()

    for index in range(20):
        create(
            url,
            token,
            {
                "content": json.dumps(
                    {"ioc": f"overflow-{index}.example.invalid", "data": []}
                )
                + "\n"
            },
        )

    assert (oldest_dir / "share.jsonl.manifest.json").is_file()

    cloud = cloud_response_rows(first["text"], oldest_id)
    status, body = api_post(url, token, "/api/restore", {"content": cloud})
    assert status == 200, body
    assert body["matched_bundle_id"] == oldest_id
    assert "evil.example.invalid" in body["text"]
    assert list(oldest_dir.glob("restored-*.jsonl"))
    assert list(oldest_dir.glob("cloud-*.jsonl"))

    # Simulate restart with the same key and bundle directories.
    server, url2 = build_server(
        key_path,
        bundles_dir,
        port=0,
        max_bundles=20,
        provider_env={},
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base, _, token2 = url2.partition("/?token=")
        # Key already exists from the first server; unlock without regenerating.
        status, body = api_post(
            base,
            token2,
            "/api/key",
            {"passphrase": "test-passphrase", "generate": False},
        )
        assert status == 200, body
        status, body = api_post(base, token2, "/api/restore", {"content": cloud})
        assert status == 200, body
        assert body["matched_bundle_id"] == oldest_id
        assert "evil.example.invalid" in body["text"]
        assert len(list(oldest_dir.glob("restored-*.jsonl"))) >= 2
    finally:
        server.shutdown()
        server.server_close()


def test_recreate_same_bundle_id_preserves_restored_and_cloud(make_server):
    url, token, _key, bundles_dir = make_server(max_bundles=20)
    unlock(url, token)

    content = sample_content()
    first = create(url, token, {"content": content})
    bundle_id = first["bundle_id"]
    bundle_dir = bundles_dir / bundle_id

    cloud = cloud_response_rows(first["text"], bundle_id)
    status, body = api_post(url, token, "/api/restore", {"content": cloud})
    assert status == 200, body
    restored_before = sorted(p.name for p in bundle_dir.glob("restored-*.jsonl"))
    cloud_before = sorted(p.name for p in bundle_dir.glob("cloud-*.jsonl"))
    assert restored_before
    assert cloud_before

    second = create(url, token, {"content": content})
    assert second["bundle_id"] == bundle_id
    restored_after = sorted(p.name for p in bundle_dir.glob("restored-*.jsonl"))
    cloud_after = sorted(p.name for p in bundle_dir.glob("cloud-*.jsonl"))
    assert restored_before == restored_after
    assert cloud_before == cloud_after
    assert (bundle_dir / "share.jsonl").is_file()
    assert (bundle_dir / "share.jsonl.manifest.json").is_file()

    status, body = api_post(url, token, "/api/restore", {"content": cloud})
    assert status == 200, body
    assert body["matched_bundle_id"] == bundle_id


def _seed_merge_trees(tmp_path):
    target = tmp_path / "target"
    staging = tmp_path / "staging"
    target.mkdir()
    staging.mkdir()
    preexisting = {
        "share.jsonl": b"ORIGINAL-CONTENT\n",
        "share.jsonl.manifest.json": b'{"bundle_id":"old","rows":1}\n',
        "input-old.jsonl": b"OLD-INPUT\n",
        "restored-keep.jsonl": b'{"ioc":"restored-keep.invalid"}\n',
        "cloud-keep.jsonl": b'{"ioc":"cloud-keep.invalid"}\n',
        "user-note.txt": b"operator note\n",
    }
    for name, data in preexisting.items():
        (target / name).write_bytes(data)
    (staging / "share.jsonl").write_bytes(b"NEW-SHARE\n")
    (staging / "share.jsonl.manifest.json").write_bytes(b'{"bundle_id":"new","rows":1}\n')
    (staging / "input-new.jsonl").write_bytes(b"NEW-INPUT\n")
    return target, staging, preexisting


def test_partial_backup_failure_leaves_every_original_byte_unchanged(tmp_path, monkeypatch):
    """Disk-full during backup must not restore PARTIAL over untouched originals."""
    from ioc_rejudge import ui as ui_module

    target, staging, preexisting = _seed_merge_trees(tmp_path)
    real_write = ui_module._write_complete_file
    calls = {"n": 0}

    def flaky_backup_write(path, data):
        path = Path(path)
        if ".merge-backup-" in str(path):
            calls["n"] += 1
            if calls["n"] == 1:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Simulate a truncated backup object then fail the backup phase.
                path.write_bytes(b"PARTIAL")
                raise OSError("disk full during backup")
        return real_write(path, data)

    monkeypatch.setattr(ui_module, "_write_complete_file", flaky_backup_write)

    with pytest.raises(OSError, match="disk full during backup"):
        ui_module._merge_bundle_dir(staging, target)

    for name, data in preexisting.items():
        path = target / name
        assert path.is_file(), f"missing after backup failure: {name}"
        assert path.read_bytes() == data, f"corrupted after backup failure: {name}"
    assert (target / "share.jsonl").read_bytes() == b"ORIGINAL-CONTENT\n"
    assert (target / "share.jsonl").read_bytes() != b"PARTIAL"


def test_merge_bundle_dir_failure_preserves_all_preexisting_bytes(tmp_path, monkeypatch):
    """Install failure after first success restores every original byte."""
    import os

    from ioc_rejudge import ui as ui_module

    target, staging, preexisting = _seed_merge_trees(tmp_path)
    replace_calls = {"n": 0}
    real_replace = os.replace

    def flaky_replace(src, dst, *args, **kwargs):
        src_name = Path(src).name
        if src_name.startswith(".tmp-install-"):
            replace_calls["n"] += 1
            if replace_calls["n"] >= 2:
                raise OSError("simulated replace failure after first artifact")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(ui_module.os, "replace", flaky_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        ui_module._merge_bundle_dir(staging, target)

    for name, data in preexisting.items():
        path = target / name
        assert path.is_file(), f"missing after failed merge: {name}"
        assert path.read_bytes() == data, f"bytes changed for {name}"


def test_rollback_failure_keeps_complete_backups_recoverable(tmp_path, monkeypatch):
    """If rollback replacement fails, complete backups remain and error names them."""
    import os

    from ioc_rejudge import ui as ui_module
    from ioc_rejudge.share import ShareError

    target, staging, preexisting = _seed_merge_trees(tmp_path)
    # Only replace pre-existing generated files so the first successful install
    # is a true replacement that must be rolled back (not a newly created name).
    (staging / "input-new.jsonl").unlink()
    install_n = {"n": 0}
    real_replace = os.replace

    def flaky_replace(src, dst, *args, **kwargs):
        src_name = Path(src).name
        if src_name.startswith(".tmp-install-"):
            install_n["n"] += 1
            if install_n["n"] >= 2:
                raise OSError("simulated install failure after first artifact")
        if src_name.startswith(".tmp-restore-"):
            raise OSError("simulated rollback replace failure")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(ui_module.os, "replace", flaky_replace)

    with pytest.raises(ShareError) as exc_info:
        ui_module._merge_bundle_dir(staging, target)

    message = str(exc_info.value)
    assert ".merge-backup-" in message
    assert "rollback was incomplete" in message
    backups = [
        p for p in tmp_path.iterdir() if p.is_dir() and p.name.startswith(".merge-backup-")
    ]
    assert len(backups) == 1, "complete backup directory must remain after rollback failure"
    backup_root = backups[0]
    assert str(backup_root) in message or backup_root.name in message
    # Complete originals remain recoverable from the retained backup.
    assert (backup_root / "share.jsonl").read_bytes() == b"ORIGINAL-CONTENT\n"
    assert (backup_root / "share.jsonl.manifest.json").read_bytes() == preexisting[
        "share.jsonl.manifest.json"
    ]
    # Untouched recovery/user files stay intact on the live target.
    for name in ("restored-keep.jsonl", "cloud-keep.jsonl", "user-note.txt", "input-old.jsonl"):
        assert (target / name).read_bytes() == preexisting[name]


def test_history_limit_cli_option_is_positive_int():
    from ioc_rejudge import ui as ui_module

    assert ui_module._positive_history_limit("7") == 7
    with pytest.raises(Exception):
        ui_module._positive_history_limit("0")
    with pytest.raises(Exception):
        ui_module._positive_history_limit("-3")
    with pytest.raises(SystemExit) as exc:
        ui_module.main(["--history-limit", "0"])
    assert exc.value.code == 2
