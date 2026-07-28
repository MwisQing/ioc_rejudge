"""Fully mocked live aggregation, replay, and credential-safety acceptance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import threading
from urllib.parse import unquote, urlsplit
import zipfile

import requests

from ioc_rejudge.cli import export_diagnostics
from ioc_rejudge.config import Config
from ioc_rejudge.export import export_csv, export_excel, export_jsonl
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.factory import DEFAULT_PROVIDERS, build_providers
from ioc_rejudge.providers.sidecar import SidecarProvider
from ioc_rejudge.providers.transport import TransportError


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
SENTINEL = "LIVE_ACCEPTANCE_SECRET_91b4"

DGA_WHOIS = "dga-whois.invalid"
DGA_PDNS = "dga-pdns.invalid"
DGA_ICP = "dga-icp.invalid"
DGA_MALICIOUS = "dga-malicious.invalid"
DGA_TIMEOUT = "dga-timeout.invalid"
STANDARD_ICP = "standard-icp.invalid"
PUBLIC_APT = "public-apt.invalid"
EXPIRED_PHISHING = "expired-phishing.invalid"
IP_PORT = "192.0.2.55:8443"
TARGETS = [
    DGA_WHOIS,
    DGA_PDNS,
    DGA_ICP,
    DGA_MALICIOUS,
    DGA_TIMEOUT,
    STANDARD_ICP,
    PUBLIC_APT,
    EXPIRED_PHISHING,
    IP_PORT,
]


class ScriptedTransport:
    def __init__(self, *, get=None, post=None):
        self.get_callback = get
        self.post_callback = post
        self.calls = []
        self.lock = threading.Lock()

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        with self.lock:
            self.calls.append({"method": "GET", "url": url, "params": params})
        if self.get_callback is None:
            raise AssertionError("unexpected GET")
        return self.get_callback(url, params)

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        with self.lock:
            self.calls.append({"method": "POST", "url": url, "body": body})
        if self.post_callback is None:
            raise AssertionError("unexpected POST")
        return self.post_callback(url, body)


def _host(value: str) -> str:
    return value.rsplit(":", 1)[0] if value == IP_PORT else value


def _generic_ioc_record(ioc: str) -> dict:
    return {"key": ioc, "host": _host(ioc), "level": 20}


def _ioc_records() -> dict[str, list[dict]]:
    records = {
        ioc: [_generic_ioc_record(ioc)]
        for ioc in TARGETS
        if ioc != DGA_TIMEOUT
    }
    records[PUBLIC_APT] = [{
        "key": PUBLIC_APT,
        "host": PUBLIC_APT,
        "level": 70,
        "malicious_type": ["APT"],
        "private": False,
        "confidence": 5,
        "info_level": 3,
        "context": "Public APT report: https://reports.invalid/campaign-analysis",
        "updatetime": "2024-01-01 00:00:00",
    }]
    records[EXPIRED_PHISHING] = [{
        "key": EXPIRED_PHISHING,
        "host": EXPIRED_PHISHING,
        "level": 60,
        "context": f"Historical phishing URL intelligence for {EXPIRED_PHISHING}.",
        "family": ["phishing"],
        "relate_url": [
            {"url": f"https://{EXPIRED_PHISHING}/login", "level": 60},
            {"url": f"https://{EXPIRED_PHISHING}/reset", "level": 70},
        ],
    }]
    return records


def _endpoint_host(url: str) -> str:
    return unquote(urlsplit(url).path.rstrip("/").split("/")[-1])


def _build_transports():
    dga_targets = {
        DGA_WHOIS,
        DGA_PDNS,
        DGA_ICP,
        DGA_MALICIOUS,
        DGA_TIMEOUT,
    }

    def k01_post(url, body):
        data = {}
        for ioc in body["params"]:
            tags = ["dga"] if ioc in dga_targets else ["sinkhole"]
            data[ioc] = {
                "level": "malicious",
                "data": [{"ioc_host": ioc, "tags": tags}],
            }
        return {"status": 10000, "data": data}

    ioc_call_count = 0
    records = _ioc_records()

    def ioc_post(url, body):
        nonlocal ioc_call_count
        ioc_call_count += 1
        if ioc_call_count == 1:
            return {
                "data": {
                    ioc: records[ioc]
                    for ioc in body["params"]
                    if ioc in records
                }
            }
        assert body["params"] == [DGA_TIMEOUT]
        raise TransportError(
            "timeout",
            "Request timed out for https://ioc-info.invalid/api/v1/ioc/info",
        )

    def fdark_get(url, params):
        domain = params.get("domain")
        ip = params.get("ip")
        target = f"{ip}:{params['dport']}" if ip and "dport" in params else (ip or domain)
        if target == DGA_MALICIOUS:
            return {
                "status": "ok",
                "data": [{
                    "md5": "11111111111111111111111111111111",
                    "level": 80,
                    "family": "trojan.family",
                    "type": "pe",
                    "confidence": 90,
                    "lseen": int((NOW - timedelta(days=1)).timestamp()),
                }],
                "total": 1,
            }
        if target == PUBLIC_APT:
            return {
                "status": "ok",
                "data": [{
                    "md5": "22222222222222222222222222222222",
                    "level": 99,
                    "family": "not-a-virus:Tool",
                    "type": "utility",
                    "confidence": 99,
                    "lseen": int((NOW - timedelta(days=1)).timestamp()),
                }],
                "total": 1,
            }
        return {"status": "ok", "data": [], "total": 0}

    def whois_get(url, params):
        host = _endpoint_host(url)
        if host in {DGA_WHOIS, DGA_TIMEOUT}:
            data = {
                "createdDate": ["2020-01-01"],
                "updatedDate": ["2026-01-01"],
                "expiresDate": ["2027-01-01"],
                "status": ["clientTransferProhibited"],
                "mergeStatus": True,
            }
        elif host == EXPIRED_PHISHING:
            data = {
                "createdDate": ["2018-01-01"],
                "updatedDate": ["2019-01-01"],
                "expiresDate": ["2020-01-01"],
                "status": ["redemptionPeriod"],
                "mergeStatus": True,
            }
        else:
            data = {}
        return {"code": 200, "status": "ok", "data": data}

    def pdns_get(url, params):
        host = _endpoint_host(url)
        data = []
        if host == DGA_PDNS:
            data = [{
                "rrtype": "A",
                "rdata": "192.0.2.80;",
                "count": 4,
                "time_first": int((NOW - timedelta(days=40)).timestamp()),
                "time_last": int((NOW - timedelta(days=2)).timestamp()),
            }]
        return {"code": 200, "status": "ok", "data": data}

    def icp_get(url, params):
        host = params["dm"]
        if host in {DGA_ICP, DGA_MALICIOUS}:
            return {"resultObject": {"website_icp_num": "ICP-LIVE-SYNTHETIC"}}
        if host == STANDARD_ICP:
            return {"resultObject": {}}
        return {"resultObject": {}}

    return {
        "k01_compromise": ScriptedTransport(post=k01_post),
        "ioc_info": ScriptedTransport(post=ioc_post),
        "fdark": ScriptedTransport(get=fdark_get),
        "whois": ScriptedTransport(get=whois_get),
        "pdns": ScriptedTransport(get=pdns_get),
        "icp": ScriptedTransport(get=icp_get),
    }


def _write_icp_sidecar(path: Path) -> None:
    rows = []
    for ioc in (DGA_ICP, DGA_MALICIOUS, STANDARD_ICP):
        rows.append({
            "ioc": ioc,
            "kind": "icp_registration",
            "status": "success",
            "scope": "domain",
            "fetched_at": "2026-07-24 12:00:00",
            "observed_at": "2026-07-24 12:00:00",
            "payload": {"current": True, "registration": "ICP-SYNTHETIC"},
            "raw_ref": "sidecar:icp",
        })
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def _set_online_environment(monkeypatch) -> None:
    values = {
        "IOC_INFO_API_KEY": f"{SENTINEL}-ioc",
        "IOC_INFO_URL": "https://ioc-info.invalid/api/v1/ioc/info",
        "K01_COMPROMISE_API_KEY": f"{SENTINEL}-k01",
        "K01_COMPROMISE_URL": "https://k01.invalid",
        "FDP_ACCESS": f"{SENTINEL}-fdp-access",
        "FDP_SECRET": f"{SENTINEL}-fdp-secret",
        "FDARK_URL": "https://fdark.invalid/api/v1/fdark/abstract",
        "WHOIS_ACCESS": f"{SENTINEL}-whois-access",
        "WHOIS_SECRET": f"{SENTINEL}-whois-secret",
        "WHOIS_URL": "https://whois.invalid/v3/whois/detail",
        "PDNS_ACCESS": f"{SENTINEL}-pdns-access",
        "PDNS_SECRET": f"{SENTINEL}-pdns-secret",
        "PDNS_URL": "https://pdns.invalid/api/v1/passivedns/flint/rrset",
        "ICP_UC": f"{SENTINEL}-icp-uc",
        "ICP_KEY": f"{SENTINEL}-icp-key",
        "ICP_URL": "https://icp.invalid/v2/open-api/icp-info",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _remove_credentials(monkeypatch) -> None:
    for name in (
        "IOC_INFO_API_KEY",
        "K01_COMPROMISE_API_KEY",
        "FDP_ACCESS",
        "FDP_SECRET",
        "WHOIS_ACCESS",
        "WHOIS_SECRET",
        "PDNS_ACCESS",
        "PDNS_SECRET",
        "ICP_UC",
        "ICP_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_live_nine_scenarios_offline_replay_and_credential_safety(
    tmp_path, monkeypatch
):
    def forbid_real_network(*args, **kwargs):
        raise AssertionError("real network access is forbidden in acceptance tests")

    monkeypatch.setattr(requests.Session, "get", forbid_real_network)
    monkeypatch.setattr(requests.Session, "post", forbid_real_network)
    _set_online_environment(monkeypatch)

    cache_dir = tmp_path / "cache"
    online_run_dir = tmp_path / "run-online"
    offline_run_dir = tmp_path / "run-offline"
    icp_path = tmp_path / "icp.jsonl"
    bundle = read_input_bundle(None, TARGETS)
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

    rows = {row["ioc"]: row for row in online.verdicts}
    expected = {
        DGA_WHOIS: ("误报", "dga", "false_positive", "WHOIS"),
        DGA_PDNS: ("误报", "dga", "false_positive", "pDNS"),
        DGA_ICP: ("误报", "dga", "false_positive", "ICP"),
        DGA_MALICIOUS: ("存活有效", "dga", "block", "恶意样本"),
        DGA_TIMEOUT: ("待复核", "dga", "review", "样本检查"),
        STANDARD_ICP: ("待复核", "standard", "review", ""),
        PUBLIC_APT: ("失活有效", "standard", "block", "公开APT"),
        EXPIRED_PHISHING: ("灰", "standard", "gray", "保留具体URL"),
        IP_PORT: ("待复核", "standard", "review", ""),
    }
    assert [row["ioc"] for row in online.verdicts] == TARGETS
    for ioc, (conclusion, route, disposition, reason_fragment) in expected.items():
        row = rows[ioc]
        assert row["conclusion"] == conclusion
        assert row["route"] == route
        assert row["disposition"] == disposition
        if reason_fragment:
            assert reason_fragment in row["reason"]

    assert rows[DGA_MALICIOUS]["provider_statuses"]["fdark"] == "success"
    assert rows[DGA_ICP]["provider_statuses"]["icp"] == "success"
    assert rows[STANDARD_ICP]["provider_statuses"]["icp"] == "success"
    icp_observations = {
        observation.ioc: observation
        for observation in online.observations
        if observation.provider == "icp"
    }
    assert icp_observations[DGA_ICP].payload["current"] is True
    assert icp_observations[STANDARD_ICP].payload == {
        "current": False,
        "registration": "",
    }
    assert rows[DGA_TIMEOUT]["provider_statuses"]["ioc_info"] == "error"
    assert rows[DGA_TIMEOUT]["missing_required_providers"] == ["ioc_info"]
    assert rows[PUBLIC_APT]["provider_statuses"]["fdark"] == "success"
    assert rows[EXPIRED_PHISHING]["retained_urls"] == [
        f"https://{EXPIRED_PHISHING}/login",
        f"https://{EXPIRED_PHISHING}/reset",
    ]
    assert rows[IP_PORT]["provider_statuses"]["whois"] == "disabled"
    assert rows[IP_PORT]["provider_statuses"]["pdns"] == "disabled"

    assert len(transports["whois"].calls) == 6
    assert len(transports["pdns"].calls) == 5
    assert len(transports["icp"].calls) == 8
    assert {call["params"]["dm"] for call in transports["icp"].calls} == {
        ioc for ioc in TARGETS if ioc != IP_PORT
    }
    assert all(call["params"]["dm"] != IP_PORT for call in transports["icp"].calls)
    assert all(IP_PORT not in call["url"] for call in transports["whois"].calls)
    assert all(IP_PORT not in call["url"] for call in transports["pdns"].calls)
    assert IP_PORT in transports["k01_compromise"].calls[0]["body"]["params"]
    assert IP_PORT in transports["ioc_info"].calls[0]["body"]["params"]
    assert any(
        call["params"].get("ip") == "192.0.2.55"
        and call["params"].get("dport") == 8443
        for call in transports["fdark"].calls
    )

    for name in DEFAULT_PROVIDERS:
        assert list(
            (online_run_dir / "raw" / f".cache_{name}").glob(
                "cache_*.jsonl"
            )
        )
    assert online.diagnostics.providers["ioc_info"].error == 1
    assert online.diagnostics.providers["fdark"].no_data == 7
    assert online.diagnostics.providers["whois"].disabled == 3
    assert online.diagnostics.providers["pdns"].disabled == 4
    assert all(
        observation.raw_ref.startswith("cache:")
        for observation in online.observations
        if observation.provider in DEFAULT_PROVIDERS
    )

    _remove_credentials(monkeypatch)
    offline_providers = build_providers(
        list(DEFAULT_PROVIDERS),
        cache_dir=cache_dir,
        run_dir=offline_run_dir,
        adjudication_config=config,
        offline=True,
    )
    offline = run_unified_pipeline(
        bundle,
        offline_providers,
        config,
        ProviderContext(offline=True, run_dir=offline_run_dir),
        now=NOW,
    )

    assert offline.verdicts == online.verdicts
    assert [
        (item.provider, item.ioc, item.kind, item.payload, item.raw_ref)
        for item in offline.observations
    ] == [
        (item.provider, item.ioc, item.kind, item.payload, item.raw_ref)
        for item in online.observations
    ]
    assert offline.diagnostics.providers["k01_compromise"].cache_hit == 9
    assert offline.diagnostics.providers["ioc_info"].cache_hit == 8
    assert offline.diagnostics.providers["fdark"].cache_hit == 9
    assert offline.diagnostics.providers["whois"].cache_hit == 6
    assert offline.diagnostics.providers["pdns"].cache_hit == 5
    assert offline.diagnostics.providers["icp"].cache_hit == 8

    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    jsonl_path = output_dir / "result.jsonl"
    csv_path = output_dir / "result.csv"
    xlsx_path = output_dir / "result.xlsx"
    diagnostics_path = output_dir / "diagnostics.json"
    log_path = output_dir / "run.log"
    export_jsonl(online.verdicts, str(jsonl_path))
    export_csv(online.verdicts, str(csv_path))
    export_excel(
        online.verdicts,
        str(xlsx_path),
        diagnostics=online.diagnostics.to_dict(),
    )
    export_diagnostics(online.diagnostics, str(diagnostics_path))
    log_path.write_text(
        json.dumps(online.diagnostics.to_dict(), ensure_ascii=False),
        encoding="utf-8",
    )

    sentinel_bytes = SENTINEL.encode("utf-8")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert sentinel_bytes not in path.read_bytes(), f"credential leaked to {path}"
    with zipfile.ZipFile(xlsx_path) as workbook:
        for name in workbook.namelist():
            if name.endswith(".xml") or name.endswith(".rels"):
                assert sentinel_bytes not in workbook.read(name), (
                    f"credential leaked to workbook member {name}"
                )
