"""Workbench bare-IOC paste staging and offline unified pipeline routing."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import requests

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS, build_providers
from ioc_rejudge.workbench import LocalWorkbenchAdapter, WorkbenchValidationError
from ioc_rejudge.workbench_backend import OfflineWorkbenchAdapter


def _load_live_acceptance():
    """Load sibling test helpers without relying on tests/ package layout."""
    path = Path(__file__).with_name("test_live_acceptance.py")
    spec = importlib.util.spec_from_file_location("ioc_rejudge_test_live_acceptance", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_live = _load_live_acceptance()
DGA_MALICIOUS = _live.DGA_MALICIOUS
NOW = _live.NOW
PUBLIC_APT = _live.PUBLIC_APT
_build_transports = _live._build_transports
_remove_credentials = _live._remove_credentials


BARE_PASTE = """\
# comment line
alpha.example.invalid
beta.example.invalid
alpha.example.invalid
not a valid ioc !!!
"""

SNAPSHOT = (
    '{"ioc":"test-malware.invalid","data":[{"key":"test-malware.invalid",'
    '"level":70,"source":["sample-base"],"family":["trojan-downloader"],'
    '"hash":[{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab","level":70,'
    '"time":"2026-07-15 10:00:00"}],"updatetime":"2026-07-20 08:00:00",'
    '"context":"test-malware.invalid associated with trojan activity"}]}\n'
)


def test_stage_input_bare_paste_counts_valid_duplicate_and_rejected(tmp_path):
    adapter = LocalWorkbenchAdapter(tmp_path / "workbench")
    staged = adapter.stage_input("paste.txt", BARE_PASTE)

    assert staged["input_kind"] == "bare"
    assert staged["valid"] == 2
    assert staged["duplicated"] == 1
    assert staged["rejected"] == 1
    assert staged["rows"] == 2
    assert any("invalid IOC" in item for item in staged.get("errors", []))

    staged_path = Path(staged["path"])
    assert staged_path.is_file()
    text = staged_path.read_text(encoding="utf-8")
    assert "alpha.example.invalid" in text
    assert "beta.example.invalid" in text


def test_stage_input_bare_rejects_empty_valid_set(tmp_path):
    adapter = LocalWorkbenchAdapter(tmp_path / "workbench")
    with pytest.raises(WorkbenchValidationError, match="valid IOC"):
        adapter.stage_input("paste.txt", "# only comment\n\nnot a valid ioc !!!\n")


def test_legacy_jsonl_stage_still_requires_objects(tmp_path):
    adapter = LocalWorkbenchAdapter(tmp_path / "workbench")
    with pytest.raises(WorkbenchValidationError, match="JSONL"):
        adapter.stage_input("snapshot.jsonl", "alpha.example.invalid\n")


def test_bare_offline_task_produces_verdicts_without_network(tmp_path, monkeypatch):
    cache_dir = tmp_path / "provider-cache"
    cache_dir.mkdir()
    adapter = OfflineWorkbenchAdapter(
        tmp_path / "workbench",
        cache_dir=cache_dir,
    )

    calls = {"get": 0, "post": 0}

    class _Sentinel:
        def get(self, *args, **kwargs):
            calls["get"] += 1
            raise AssertionError("network get must not run in offline bare workbench")

        def post(self, *args, **kwargs):
            calls["post"] += 1
            raise AssertionError("network post must not run in offline bare workbench")

    monkeypatch.setattr(
        "requests.Session.get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Session.get must not run")
        ),
    )
    monkeypatch.setattr(
        "requests.Session.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Session.post must not run")
        ),
    )

    credential_reads = []

    def _block_credentials(*args, **kwargs):
        credential_reads.append((args, kwargs))
        raise AssertionError("credentials must not be loaded for offline bare tasks")

    monkeypatch.setattr(
        "ioc_rejudge.providers.factory.load_credentials_file",
        _block_credentials,
    )

    staged = adapter.stage_input("paste.txt", "one.example.invalid\ntwo.example.invalid\n")
    assert staged["input_kind"] == "bare"
    started = adapter.start_task(staged["import_id"])
    assert started["state"] == "succeeded"
    assert started["input_kind"] == "bare"
    assert started["result_count"] == 2

    results = adapter.results(started["task_id"])
    assert results["total"] == 2
    assert {row["ioc"] for row in results["rows"]} == {
        "one.example.invalid",
        "two.example.invalid",
    }
    for row in results["rows"]:
        assert "conclusion" in row
        assert "route" in row
        assert "disposition" in row
        statuses = row.get("provider_statuses") or {}
        # Offline + empty cache: fail-closed may yield error/disabled honestly.
        for status in statuses.values():
            assert str(status).casefold() in {
                "disabled",
                "error",
                "no_data",
                "success",
                "stale",
            }, statuses

    diagnostics = adapter.diagnostics(started["task_id"])
    assert diagnostics["available"] is True
    assert "processed_count" in diagnostics
    assert credential_reads == []
    assert calls["get"] == 0 and calls["post"] == 0


def test_bare_offline_replays_cached_six_source_verdicts(tmp_path, monkeypatch):
    """Online fill of provider cache, then bare workbench offline replay matches.

    Cache keys include endpoint URLs. Online fill therefore uses default provider
    URLs (credential env only) so keys match workbench bare offline env={}.
    """

    def forbid_real_network(*args, **kwargs):
        raise AssertionError("real network access is forbidden in bare cache replay")

    monkeypatch.setattr(requests.Session, "get", forbid_real_network)
    monkeypatch.setattr(requests.Session, "post", forbid_real_network)
    # Credentials only — leave default URLs so cache keys match bare offline.
    for name, value in {
        "IOC_INFO_API_KEY": "replay-ioc",
        "K01_COMPROMISE_API_KEY": "replay-k01",
        "FDP_ACCESS": "replay-fdp-access",
        "FDP_SECRET": "replay-fdp-secret",
        "WHOIS_ACCESS": "replay-whois-access",
        "WHOIS_SECRET": "replay-whois-secret",
        "PDNS_ACCESS": "replay-pdns-access",
        "PDNS_SECRET": "replay-pdns-secret",
        "ICP_UC": "replay-icp-uc",
        "ICP_KEY": "replay-icp-key",
    }.items():
        monkeypatch.setenv(name, value)
    for name in (
        "IOC_INFO_URL",
        "K01_COMPROMISE_URL",
        "FDARK_URL",
        "WHOIS_URL",
        "PDNS_URL",
        "ICP_URL",
    ):
        monkeypatch.delenv(name, raising=False)

    cache_dir = tmp_path / "provider-cache"
    online_run_dir = tmp_path / "run-online"
    targets = [DGA_MALICIOUS, PUBLIC_APT]
    paste = "\n".join(targets) + "\n"
    bundle = read_input_bundle(None, targets)
    config = Config(provider_workers=5)
    transports = _build_transports()

    online_providers = build_providers(
        list(DEFAULT_PROVIDERS),
        cache_dir=cache_dir,
        run_dir=online_run_dir,
        adjudication_config=config,
        transport_factory=transports,
    )
    online = run_unified_pipeline(
        bundle,
        online_providers,
        config,
        ProviderContext(run_dir=online_run_dir),
        now=NOW,
    )
    online_by_ioc = {row["ioc"]: row for row in online.verdicts}
    assert set(online_by_ioc) == set(targets)
    assert online_by_ioc[DGA_MALICIOUS]["conclusion"] == "存活有效"
    assert online_by_ioc[PUBLIC_APT]["conclusion"] == "失活有效"

    _remove_credentials(monkeypatch)
    credential_reads = []

    def _block_credentials(*args, **kwargs):
        credential_reads.append((args, kwargs))
        raise AssertionError("credentials must not be loaded for offline bare replay")

    monkeypatch.setattr(
        "ioc_rejudge.providers.factory.load_credentials_file",
        _block_credentials,
    )

    call_baselines = {
        name: len(transport.calls) for name, transport in transports.items()
    }

    adapter = OfflineWorkbenchAdapter(
        tmp_path / "workbench",
        cache_dir=cache_dir,
    )
    staged = adapter.stage_input("paste.txt", paste)
    assert staged["input_kind"] == "bare"
    started = adapter.start_task(staged["import_id"])
    assert started["state"] == "succeeded"
    assert started["result_count"] == 2

    results = adapter.results(started["task_id"])
    assert results["total"] == 2
    workbench_by_ioc = {row["ioc"]: row for row in results["rows"]}
    assert set(workbench_by_ioc) == set(targets)

    for ioc in targets:
        online_row = online_by_ioc[ioc]
        wb_row = workbench_by_ioc[ioc]
        assert wb_row["conclusion"] == online_row["conclusion"]
        assert wb_row["route"] == online_row["route"]
        assert wb_row["disposition"] == online_row["disposition"]
        assert wb_row.get("scope_actions") == online_row.get("scope_actions")
        online_statuses = online_row.get("provider_statuses") or {}
        wb_statuses = wb_row.get("provider_statuses") or {}
        assert set(wb_statuses) == set(online_statuses)
        for provider, status in online_statuses.items():
            assert wb_statuses[provider] == status
        assert any(
            str(status).casefold() == "success" for status in wb_statuses.values()
        ), wb_statuses

    for name, transport in transports.items():
        assert len(transport.calls) == call_baselines[name]

    assert credential_reads == []


def test_legacy_jsonl_path_keeps_input_kind_and_structure(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")
    staged = adapter.stage_input("snapshot.jsonl", SNAPSHOT)
    assert staged["input_kind"] == "jsonl"
    started = adapter.start_task(staged["import_id"])
    assert started["state"] == "succeeded"
    assert started["input_kind"] == "jsonl"
    assert started["mode"] == "offline_legacy_snapshot"
    assert started["result_count"] == 1

    results = adapter.results(started["task_id"])
    assert results["total"] == 1
    row = results["rows"][0]
    assert row["ioc"] == "test-malware.invalid"
    assert "conclusion" in row
    explanation = adapter.explanation(started["task_id"], row["result_id"])
    assert explanation["result_id"] == row["result_id"]
    export = adapter.export(started["task_id"], export_format="jsonl")
    assert export["rows"] == 1


def test_bare_and_legacy_share_consumer_endpoints(tmp_path):
    adapter = OfflineWorkbenchAdapter(tmp_path / "workbench")

    bare = adapter.stage_input("paste.txt", "shared-consumer.example.invalid\n")
    bare_task = adapter.start_task(bare["import_id"])
    legacy = adapter.stage_input("snapshot.jsonl", SNAPSHOT)
    legacy_task = adapter.start_task(legacy["import_id"])

    for task in (bare_task, legacy_task):
        task_id = task["task_id"]
        results = adapter.results(task_id)
        assert results["total"] >= 1
        result_id = results["rows"][0]["result_id"]
        explanation = adapter.explanation(task_id, result_id)
        assert explanation["task_id"] == task_id
        assert explanation["result_id"] == result_id
        reviewed = adapter.submit_review(
            task_id,
            result_id,
            decision="approved",
            reason="ok",
            reviewer="tester",
        )
        assert reviewed["review"] == "approved"
        exported = adapter.export(task_id, export_format="jsonl")
        path = adapter.export_file(exported["export_id"])
        assert path.is_file()
        diagnostics = adapter.diagnostics(task_id)
        assert diagnostics["available"] is True
        assert "input_path" not in diagnostics


def test_ui_workbench_paste_controls_present():
    page = (Path(__file__).parents[1] / "ioc_rejudge" / "ui.html").read_text(
        encoding="utf-8"
    )
    assert 'id="workbench-paste"' in page
    assert 'id="workbench-paste-preview"' in page
    assert 'id="workbench-paste-import"' in page
    assert "doWorkbenchPasteImport" in page
    assert "paste.txt" in page
    assert page.count("https://") == 0 or "https://" not in page.split("<script")[0]
