"""Factory-to-pipeline and live CLI wiring tests."""

import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from ioc_rejudge.cli import main
from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.factory import build_providers
from ioc_rejudge.providers.sidecar import SidecarProvider


class FakeTransport:
    def __init__(self, response=None):
        self.response = response
        self.calls = []

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        self.calls.append(("get", url, params))
        return self.response

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        self.calls.append(("post", url, body))
        return self.response


def _whois_env(secret="pipeline-secret"):
    return {
        "WHOIS_ACCESS": f"access-{secret}",
        "WHOIS_SECRET": f"secret-{secret}",
        "WHOIS_URL": "https://whois.invalid/v3/whois/detail",
    }


def test_factory_provider_runs_through_pipeline_and_writes_audit_raw(tmp_path):
    transport = FakeTransport({
        "code": 200,
        "status": "ok",
        "data": {"expiresDate": ["2027-01-01"]},
    })
    providers = build_providers(
        ["whois"],
        env=_whois_env(),
        cache_dir=tmp_path / "cache",
        run_dir=tmp_path / "run",
        adjudication_config=Config(),
        transport_factory=lambda name: transport,
    )
    bundle = read_input_bundle(None, ["live.invalid"])
    result = run_unified_pipeline(
        bundle,
        providers,
        Config(),
        ProviderContext(run_dir=tmp_path / "run"),
    )
    assert len(transport.calls) == 1
    assert result.verdicts[0]["provider_statuses"]["whois"] == "success"
    assert result.diagnostics.providers["whois"].success == 1
    assert list(
        (tmp_path / "run" / "raw" / ".cache_whois").glob(
            "cache_*.jsonl"
        )
    )


def test_online_then_offline_cache_replay_uses_no_network(tmp_path):
    cache_dir = tmp_path / "cache"
    online_transport = FakeTransport({
        "code": 200,
        "status": "ok",
        "data": {"expiresDate": ["2027-01-01"]},
    })
    bundle = read_input_bundle(None, ["replay.invalid"])
    online_providers = build_providers(
        ["whois"],
        env=_whois_env(),
        cache_dir=cache_dir,
        adjudication_config=Config(),
        transport_factory=lambda name: online_transport,
    )
    online = run_unified_pipeline(
        bundle, online_providers, Config(), ProviderContext()
    )

    forbidden = FakeTransport()
    offline_providers = build_providers(
        ["whois"],
        env={"WHOIS_URL": _whois_env()["WHOIS_URL"]},
        cache_dir=cache_dir,
        adjudication_config=Config(),
        offline=True,
        transport_factory=lambda name: forbidden,
    )
    offline = run_unified_pipeline(
        bundle,
        offline_providers,
        Config(),
        ProviderContext(offline=True),
    )
    assert forbidden.calls == []
    assert offline.verdicts[0]["provider_statuses"] == online.verdicts[0][
        "provider_statuses"
    ]
    assert offline.diagnostics.providers["whois"].cache_hit == 1


def test_whois_and_pdns_are_applicability_disabled_for_ip_port(tmp_path):
    transports = {"whois": FakeTransport(), "pdns": FakeTransport()}
    providers = build_providers(
        ["whois", "pdns"],
        env={
            **_whois_env(),
            "PDNS_ACCESS": "pdns-access",
            "PDNS_SECRET": "pdns-secret",
            "PDNS_URL": "https://pdns.invalid/api/v1/passivedns/flint/rrset",
        },
        adjudication_config=Config(),
        transport_factory=lambda name: transports[name],
    )
    result = run_unified_pipeline(
        read_input_bundle(None, ["192.0.2.1:443"]),
        providers,
        Config(),
        ProviderContext(),
    )
    assert transports["whois"].calls == []
    assert transports["pdns"].calls == []
    assert result.verdicts[0]["provider_statuses"] == {
        "whois": "disabled",
        "pdns": "disabled",
    }


def test_missing_credentials_are_visible_without_secret_leak():
    providers = build_providers(["ioc_info"], env={}, adjudication_config=Config())
    result = run_unified_pipeline(
        read_input_bundle(None, ["disabled.invalid"]),
        providers,
        Config(),
        ProviderContext(),
    )
    serialized = json.dumps(result.diagnostics.to_dict(), ensure_ascii=False)
    assert "ioc_info" in serialized
    assert "missing required credentials" in serialized
    assert "SENTINEL" not in serialized
    assert result.verdicts[0]["provider_statuses"]["ioc_info"] == "disabled"


def test_cli_passes_explicit_live_configuration_and_context(
    tmp_path, monkeypatch
):
    output = tmp_path / "result.jsonl"
    config_path = tmp_path / "providers.json"
    config_path.write_text('{"providers": {}}', encoding="utf-8")
    captured = {}

    def fake_build(names, **kwargs):
        captured["names"] = names
        captured.update(kwargs)
        return []

    monkeypatch.setattr("ioc_rejudge.cli.build_providers", fake_build)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "cli.invalid",
            "--providers", "whois,pdns",
            "--provider-config", str(config_path),
            "--cache-dir", str(tmp_path / "cache"),
            "--run-dir", str(tmp_path / "run"),
            "--refresh",
            "--jsonl", str(output),
        ],
    )
    main()
    assert captured["names"] == ["whois", "pdns"]
    assert captured["config_path"] == config_path
    assert captured["cache_dir"] == tmp_path / "cache"
    assert captured["run_dir"] == tmp_path / "run"
    assert captured["offline"] is False
    assert output.is_file()


def test_cli_uses_reusable_provider_cache_by_default(tmp_path, monkeypatch):
    output = tmp_path / "result.jsonl"
    captured = {}

    def fake_build(names, **kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("ioc_rejudge.cli.build_providers", fake_build)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "cache-default.invalid",
            "--jsonl", str(output),
        ],
    )

    main()

    assert captured["cache_dir"].resolve() == tmp_path / "provider-cache"


def test_cli_offline_sidecar_wins_same_name_without_live_factory_call(
    tmp_path, monkeypatch
):
    sidecar = tmp_path / "whois.jsonl"
    sidecar.write_text(json.dumps({
        "ioc": "sidecar.invalid",
        "kind": "whois",
        "status": "success",
        "fetched_at": "2026-07-24 12:00:00",
        "observed_at": "2026-07-24 12:00:00",
        "payload": {"expires_at": "2027-01-01"},
    }) + "\n", encoding="utf-8")
    output = tmp_path / "result.jsonl"
    captured = {}

    def fake_build(names, **kwargs):
        captured["names"] = names
        return []

    monkeypatch.setattr("ioc_rejudge.cli.build_providers", fake_build)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "sidecar.invalid",
            "--offline",
            "--providers", "whois",
            "--provider-data", f"whois={sidecar}",
            "--jsonl", str(output),
        ],
    )
    main()
    assert captured["names"] == []
    row = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert row["provider_statuses"]["whois"] == "success"


def test_cli_online_rejects_sidecar_live_name_collision(tmp_path, monkeypatch):
    sidecar = tmp_path / "whois.jsonl"
    sidecar.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc", "collision.invalid",
            "--providers", "whois",
            "--provider-data", f"whois={sidecar}",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_cli_rejects_offline_refresh_combination(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["ioc_rejudge", "--ioc", "conflict.invalid", "--offline", "--refresh"],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


class _ConcurrentProvider:
    def __init__(self, name, *, barrier=None, delay=0, tracker=None, error=None):
        self.name = name
        self.barrier = barrier
        self.delay = delay
        self.tracker = tracker
        self.error = error
        self.contexts = []

    def supports(self, target):
        return True

    def collect(self, targets, context):
        self.contexts.append(context)
        if self.tracker is not None:
            with self.tracker["lock"]:
                self.tracker["active"] += 1
                self.tracker["peak"] = max(
                    self.tracker["peak"], self.tracker["active"]
                )
        try:
            if self.barrier is not None:
                self.barrier.wait(timeout=2)
            if self.delay:
                time.sleep(self.delay)
            if self.error:
                raise self.error
            return ProviderResult(
                name=self.name,
                statuses={
                    target.normalized: ProviderStatus.NO_DATA for target in targets
                },
                freshnesses={
                    target.normalized: Freshness.FRESH for target in targets
                },
            )
        finally:
            if self.tracker is not None:
                with self.tracker["lock"]:
                    self.tracker["active"] -= 1


def test_different_providers_actually_overlap_and_results_stay_deterministic():
    expected = None
    for _ in range(5):
        barrier = threading.Barrier(2)
        providers = [
            _ConcurrentProvider("z_provider", barrier=barrier),
            _ConcurrentProvider("a_provider", barrier=barrier),
        ]
        result = run_unified_pipeline(
            read_input_bundle(None, ["b.invalid", "a.invalid"]),
            providers,
            Config(provider_workers=2),
            ProviderContext(),
        )
        snapshot = [
            (row["ioc"], list(row["provider_statuses"].items()))
            for row in result.verdicts
        ]
        assert snapshot == [
            (
                "b.invalid",
                [("z_provider", "no_data"), ("a_provider", "no_data")],
            ),
            (
                "a.invalid",
                [("z_provider", "no_data"), ("a_provider", "no_data")],
            ),
        ]
        if expected is None:
            expected = snapshot
        assert snapshot == expected


def test_provider_workers_bounds_peak_parallelism():
    tracker = {"active": 0, "peak": 0, "lock": threading.Lock()}
    providers = [
        _ConcurrentProvider(f"provider_{index}", delay=0.04, tracker=tracker)
        for index in range(4)
    ]
    run_unified_pipeline(
        read_input_bundle(None, ["bounded.invalid"]),
        providers,
        Config(provider_workers=2),
        ProviderContext(),
    )
    assert tracker["peak"] == 2


def test_concurrent_exception_isolated_and_refresh_context_is_preserved():
    providers = [
        _ConcurrentProvider("broken", error=RuntimeError("concurrent boom")),
        _ConcurrentProvider("healthy"),
    ]
    result = run_unified_pipeline(
        read_input_bundle(None, ["refresh.invalid"]),
        providers,
        Config(provider_workers=2),
        ProviderContext(refresh=True),
    )
    assert result.verdicts[0]["provider_statuses"] == {
        "broken": "error",
        "healthy": "no_data",
    }
    assert result.diagnostics.provider_errors["broken"] == ["concurrent boom"]
    assert all(provider.contexts[0].refresh is True for provider in providers)


class _StaticProvider:
    def __init__(self, name, factory):
        self.name = name
        self.factory = factory

    def supports(self, target):
        return True

    def collect(self, targets, context):
        return self.factory(targets)


class _PlannedLiveProvider(_StaticProvider):
    is_live_provider = True

    def __init__(self, name, factory):
        super().__init__(name, factory)
        self.requested = []

    def collect(self, targets, context):
        self.requested.extend(target.normalized for target in targets)
        return super().collect(targets, context)


def _planning_provider(name, *, dga=False):
    def result(targets):
        observations = []
        statuses = {}
        for target in targets:
            statuses[target.normalized] = ProviderStatus.NO_DATA
            if name == "k01_compromise" and dga:
                statuses[target.normalized] = ProviderStatus.SUCCESS
                observations.append(Observation(
                    ioc=target.normalized,
                    scope=target.ioc_type,
                    provider=name,
                    kind="dga_classification",
                    status=ProviderStatus.SUCCESS,
                    freshness=Freshness.FRESH,
                    payload={"tags": ["dga"]},
                ))
            elif name == "icp":
                statuses[target.normalized] = ProviderStatus.SUCCESS
                observations.append(Observation(
                    ioc=target.normalized,
                    scope=target.ioc_type,
                    provider=name,
                    kind="icp_registration",
                    status=ProviderStatus.SUCCESS,
                    freshness=Freshness.FRESH,
                    payload={"current": False, "registration": ""},
                ))
        return ProviderResult(name, observations, statuses)

    return _PlannedLiveProvider(name, result)


def test_live_request_planner_skips_lifecycle_queries_not_needed_by_standard_ioc():
    providers = [
        _planning_provider("k01_compromise"),
        _planning_provider("ioc_info"),
        _planning_provider("fdark"),
        _planning_provider("whois"),
        _planning_provider("pdns"),
        _planning_provider("icp"),
    ]
    result = run_unified_pipeline(
        read_input_bundle(None, ["standard.invalid", "192.0.2.8"]),
        providers,
        Config(),
        ProviderContext(),
    )
    by_name = {provider.name: provider for provider in providers}

    assert by_name["icp"].requested == ["standard.invalid"]
    assert by_name["whois"].requested == []
    assert by_name["pdns"].requested == []
    domain_row, ip_row = result.verdicts
    assert domain_row["provider_statuses"]["icp"] == "success"
    assert domain_row["provider_statuses"]["whois"] == "disabled"
    assert ip_row["provider_statuses"]["icp"] == "disabled"


def test_live_request_planner_adds_whois_and_pdns_only_after_dga_classification():
    providers = [
        _planning_provider("k01_compromise", dga=True),
        _planning_provider("ioc_info"),
        _planning_provider("fdark"),
        _planning_provider("whois"),
        _planning_provider("pdns"),
        _planning_provider("icp"),
    ]
    run_unified_pipeline(
        read_input_bundle(None, ["dga-route.invalid"]),
        providers,
        Config(),
        ProviderContext(),
    )
    by_name = {provider.name: provider for provider in providers}

    assert by_name["whois"].requested == ["dga-route.invalid"]
    assert by_name["pdns"].requested == ["dga-route.invalid"]
    assert by_name["icp"].requested == ["dga-route.invalid"]


def _dga_gate_providers(sample_freshness):
    def classification(targets):
        target = targets[0]
        return ProviderResult(
            "k01_compromise",
            [Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="k01_compromise",
                kind="dga_classification",
                status=ProviderStatus.SUCCESS,
                freshness=Freshness.FRESH,
                payload={"tags": ["dga"]},
            )],
            {target.normalized: ProviderStatus.SUCCESS},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    def sample(name, freshness):
        def result(targets):
            target = targets[0]
            return ProviderResult(
                name=name,
                statuses={target.normalized: ProviderStatus.NO_DATA},
                freshnesses={target.normalized: freshness},
            )
        return result

    def whois(targets):
        target = targets[0]
        return ProviderResult(
            "whois",
            [Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="whois",
                kind="whois",
                status=ProviderStatus.SUCCESS,
                fetched_at=datetime(2026, 7, 24, tzinfo=timezone.utc),
                observed_at=datetime(2026, 7, 24, tzinfo=timezone.utc),
                freshness=Freshness.FRESH,
                payload={"expires_at": "2027-01-01"},
            )],
            {target.normalized: ProviderStatus.SUCCESS},
        )

    return [
        _StaticProvider("k01_compromise", classification),
        _StaticProvider("ioc_info", sample("ioc_info", Freshness.FRESH)),
        _StaticProvider("fdark", sample("fdark", sample_freshness)),
        _StaticProvider("whois", whois),
    ]


def test_dga_required_sample_gate_distinguishes_fresh_and_stale_no_data():
    bundle = read_input_bundle(None, ["gate.invalid"])
    fresh = run_unified_pipeline(
        bundle,
        _dga_gate_providers(Freshness.FRESH),
        Config(provider_workers=4),
        ProviderContext(),
        now=datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    stale = run_unified_pipeline(
        bundle,
        _dga_gate_providers(Freshness.STALE),
        Config(provider_workers=4),
        ProviderContext(offline=True),
        now=datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    assert fresh.verdicts[0]["conclusion"] == "误报"
    assert fresh.verdicts[0]["missing_required_providers"] == []
    assert stale.verdicts[0]["conclusion"] == "待复核"
    assert stale.verdicts[0]["missing_required_providers"] == ["fdark"]
    assert stale.diagnostics.providers["fdark"].stale == 1


def test_dga_default_now_accepts_recent_aware_pdns():
    recent = datetime.now(timezone.utc) - timedelta(days=1)

    def pdns(targets):
        target = targets[0]
        return ProviderResult(
            "pdns",
            [Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="pdns",
                kind="pdns_activity",
                status=ProviderStatus.SUCCESS,
                observed_at=recent,
                freshness=Freshness.FRESH,
                payload={"time_last": recent},
            )],
            {target.normalized: ProviderStatus.SUCCESS},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    providers = [
        *_dga_gate_providers(Freshness.FRESH)[:3],
        _StaticProvider("pdns", pdns),
    ]
    result = run_unified_pipeline(
        read_input_bundle(None, ["recent-aware-pdns.invalid"]),
        providers,
        Config(),
        ProviderContext(),
    )

    row = result.verdicts[0]
    assert row["conclusion"] == "误报"
    assert row["disposition"] == "false_positive"
    assert row["hit_evidence"] == "近期pDNS解析"


def test_dga_ignores_current_icp_fact_when_provider_aggregate_status_is_error():
    def failed_icp(targets):
        target = targets[0]
        return ProviderResult(
            "icp",
            [Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="icp",
                kind="icp_registration",
                status=ProviderStatus.SUCCESS,
                freshness=Freshness.FRESH,
                payload={"current": True, "registration": "ICP-STALE-SUCCESS"},
            )],
            {target.normalized: ProviderStatus.ERROR},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    providers = [
        *_dga_gate_providers(Freshness.FRESH)[:3],
        _StaticProvider("icp", failed_icp),
    ]
    result = run_unified_pipeline(
        read_input_bundle(None, ["dga-aggregate-error.invalid"]),
        providers,
        Config(),
        ProviderContext(),
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )

    row = result.verdicts[0]
    assert row["provider_statuses"]["icp"] == "error"
    assert row["conclusion"] == "失活有效"
    assert row["disposition"] == "block"


def _dga_classification_provider(record=None, *, record_status=ProviderStatus.SUCCESS):
    def collect(targets):
        target = targets[0]
        observations = [Observation(
            ioc=target.normalized,
            scope=target.ioc_type,
            provider="k01_compromise",
            kind="dga_classification",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            payload={"tags": ["dga"]},
        )]
        if record is not None:
            observations.append(Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="ioc_info",
                kind="ioc_info_record",
                status=record_status,
                freshness=Freshness.FRESH,
                payload={"record": record},
            ))
        return ProviderResult(
            "k01_compromise",
            observations,
            {target.normalized: ProviderStatus.SUCCESS},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    return collect


def test_snapshot_clue_forces_standard_before_exact_dga(tmp_path):
    snapshot = tmp_path / "clue.jsonl"
    snapshot.write_text(json.dumps({
        "ioc": "snapshot-clue.invalid",
        "data": [{
            "key": "snapshot-clue.invalid",
            "host": "snapshot-clue.invalid",
            "comment": "来源：线索群，确认恶意远控",
            "source": [],
        }],
    }, ensure_ascii=False) + "\n", encoding="utf-8")
    providers = [_StaticProvider(
        "k01_compromise",
        _dga_classification_provider(),
    )]
    result = run_unified_pipeline(
        read_input_bundle(str(snapshot)), providers, Config(), ProviderContext()
    )
    assert result.diagnostics.routes["snapshot-clue.invalid"] == "standard"
    assert result.verdicts[0]["disposition"] == "block"


def test_snapshot_context_keyword_forces_black_before_exact_dga(tmp_path):
    snapshot = tmp_path / "keyword.jsonl"
    snapshot.write_text(json.dumps({
        "ioc": "snapshot-keyword.invalid",
        "data": [{
            "key": "snapshot-keyword.invalid",
            "host": "snapshot-keyword.invalid",
            "level": 0,
            "context": "记录为黑产扩线流程",
            "source": ["spider"],
            "icp_website": "CURRENT-ICP",
        }],
    }, ensure_ascii=False) + "\n", encoding="utf-8")
    providers = [_StaticProvider(
        "k01_compromise",
        _dga_classification_provider(),
    )]

    result = run_unified_pipeline(
        read_input_bundle(str(snapshot)), providers, Config(), ProviderContext()
    )

    row = result.verdicts[0]
    assert result.diagnostics.routes["snapshot-keyword.invalid"] == "standard"
    assert row["conclusion"] == "失活有效"
    assert row["disposition"] == "block"
    assert "黑产" in row["reason"]
    assert "扩线" in row["reason"]


def test_successful_ioc_info_clue_forces_standard_before_exact_dga():
    record = {
        "key": "ioc-info-clue.invalid",
        "host": "ioc-info-clue.invalid",
        "comment": "来源：线索群，确认恶意远控",
        "source": [],
    }
    providers = [_StaticProvider(
        "k01_compromise",
        _dga_classification_provider(record),
    )]
    result = run_unified_pipeline(
        read_input_bundle(None, ["ioc-info-clue.invalid"]),
        providers,
        Config(),
        ProviderContext(),
    )
    assert result.diagnostics.routes["ioc-info-clue.invalid"] == "standard"
    assert result.verdicts[0]["disposition"] == "block"


def test_error_ioc_info_payload_does_not_create_authoritative_clue():
    record = {
        "key": "error-clue.invalid",
        "host": "error-clue.invalid",
        "comment": "来源：线索群，确认恶意远控",
        "source": [],
    }
    providers = [_StaticProvider(
        "k01_compromise",
        _dga_classification_provider(record, record_status=ProviderStatus.ERROR),
    )]
    result = run_unified_pipeline(
        read_input_bundle(None, ["error-clue.invalid"]),
        providers,
        Config(),
        ProviderContext(),
    )
    assert result.diagnostics.routes["error-clue.invalid"] == "dga"


def _icp_state_provider(*, status=ProviderStatus.SUCCESS, freshness=Freshness.FRESH, current=False, registration=None):
    def collect(targets):
        target = targets[0]
        payload = {"current": current}
        if registration is not None:
            payload["registration"] = registration
        return ProviderResult(
            "icp",
            [Observation(
                ioc=target.normalized,
                scope=target.ioc_type,
                provider="icp",
                kind="icp",
                status=status,
                freshness=freshness,
                payload=payload,
            )],
            {target.normalized: status},
            freshnesses={target.normalized: freshness},
        )

    return _StaticProvider("icp", collect)


def _historical_icp_snapshot(tmp_path, ioc="pipeline-icp-state.invalid"):
    snapshot = tmp_path / "historical-icp.jsonl"
    snapshot.write_text(json.dumps({
        "ioc": ioc,
        "data": [
            {
                "key": ioc,
                "host": ioc,
                "updatetime": "2020-01-01 00:00:00",
                "icp_website": "OLD-ICP",
            },
            {
                "key": ioc,
                "host": ioc,
                "level": 70,
                "updatetime": "2026-01-01 00:00:00",
                "source": ["manual"],
                "context": "rootkit 独狼病毒",
                "icp_website": "",
            },
        ],
    }, ensure_ascii=False) + "\n", encoding="utf-8")
    return snapshot, ioc


def test_pipeline_fresh_negative_current_icp_clears_history(tmp_path):
    snapshot, ioc = _historical_icp_snapshot(tmp_path)
    result = run_unified_pipeline(
        read_input_bundle(str(snapshot)),
        [_icp_state_provider(current=False)],
        Config(),
        ProviderContext(),
    )
    row = result.verdicts[0]
    assert row["disposition"] == "block"
    assert row["conclusion"] in {"存活有效", "失活有效"}


def test_pipeline_ignores_current_icp_fact_when_provider_aggregate_status_is_error(tmp_path):
    snapshot, ioc = _historical_icp_snapshot(tmp_path, "aggregate-error.invalid")
    sidecar = tmp_path / "icp-error.jsonl"
    sidecar.write_text(
        json.dumps({
            "ioc": ioc,
            "kind": "icp_registration",
            "status": "success",
            "fetched_at": "2026-07-26T00:00:00+00:00",
            "observed_at": "2026-07-26T00:00:00+00:00",
            "payload": {"current": False, "registration": ""},
        })
        + "\n{bad json\n",
        encoding="utf-8",
    )

    result = run_unified_pipeline(
        read_input_bundle(str(snapshot)),
        [SidecarProvider("icp", sidecar)],
        Config(),
        ProviderContext(offline=True),
    )

    row = result.verdicts[0]
    assert row["provider_statuses"]["icp"] == "error"
    assert row["conclusion"] == "待复核"
    assert row["disposition"] == "review"


@pytest.mark.parametrize(
    "provider",
    [
        _icp_state_provider(current=True, registration="ICP-CURRENT"),
        _icp_state_provider(current=False, freshness=Freshness.STALE),
        _icp_state_provider(current=False, status=ProviderStatus.ERROR),
        _icp_state_provider(current=False, status=ProviderStatus.DISABLED),
    ],
    ids=["positive", "stale-negative", "error-negative", "disabled-negative"],
)
def test_pipeline_incomplete_or_positive_current_icp_keeps_history_review(tmp_path, provider):
    snapshot, ioc = _historical_icp_snapshot(tmp_path)
    result = run_unified_pipeline(
        read_input_bundle(str(snapshot)),
        [provider],
        Config(),
        ProviderContext(),
    )
    assert result.verdicts[0]["conclusion"] == "待复核"
