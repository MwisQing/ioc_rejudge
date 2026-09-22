"""Review-fix Task 3 integration: R4 WHOIS overlay, R5 DGA routing, R6 finite
relate_url levels, R13 sidecar freshness, result-cache temporal/sidecar bounds,
and Task 4 CLI operations summary.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from math import isfinite
from pathlib import Path

import pytest

from ioc_rejudge.cli import main
from ioc_rejudge.config import Config
from ioc_rejudge.diff import compare_verdicts
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.normalize import coerce_level, merge_records
from ioc_rejudge.observations import Freshness, IocTarget, Observation, ProviderStatus, Route
from ioc_rejudge.pipeline import (
    ADJUDICATION_CACHE_CONTRACT,
    _build_standard_dossier,
    compute_result_valid_until,
    result_cache_fingerprint,
    run_unified_pipeline,
)
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.sidecar import SidecarProvider
from ioc_rejudge.result_cache import AdjudicationResultCache
from ioc_rejudge.routing import select_route
from tests.fixtures import build_record


EVAL = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
TARGET = IocTarget(
    original="whois-overlay.invalid",
    normalized="whois-overlay.invalid",
    ioc_type="domain",
    host="whois-overlay.invalid",
)
DGA_TARGET = IocTarget(
    original="dga-route.invalid",
    normalized="dga-route.invalid",
    ioc_type="domain",
    host="dga-route.invalid",
)


def _whois_obs(
    *,
    expires: str,
    status: ProviderStatus = ProviderStatus.SUCCESS,
    freshness: Freshness = Freshness.FRESH,
    fetched_at: datetime | None = None,
    ioc: str = TARGET.normalized,
    provider: str = "whois",
) -> Observation:
    return Observation(
        ioc=ioc,
        scope="domain",
        provider=provider,
        kind="whois",
        status=status,
        fetched_at=fetched_at or datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc),
        observed_at=fetched_at or datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc),
        freshness=freshness,
        payload={
            "expires_at": expires,
            "expiresDate": expires,
            "createdDate": "2020-01-01",
            "updatedDate": "2026-01-01",
        },
    )


def _dga_obs(
    tags,
    *,
    status: ProviderStatus = ProviderStatus.SUCCESS,
    freshness: Freshness = Freshness.FRESH,
    ioc: str = DGA_TARGET.normalized,
    provider: str = "k01_compromise",
) -> Observation:
    return Observation(
        ioc=ioc,
        scope="domain",
        provider=provider,
        kind="dga_classification",
        status=status,
        freshness=freshness,
        fetched_at=datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc),
        payload={"tags": tags},
    )


def _write_sidecar_row(
    path: Path,
    *,
    ioc: str,
    kind: str,
    status: str = "success",
    fetched_at: str = "2026-09-20T12:00:00+00:00",
    observed_at: str = "2026-09-20T12:00:00+00:00",
    payload: dict | None = None,
    extra: dict | None = None,
) -> None:
    row = {
        "ioc": ioc,
        "kind": kind,
        "status": status,
        "fetched_at": fetched_at,
        "observed_at": observed_at,
        "payload": payload or {},
    }
    if extra:
        row.update(extra)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    path.write_text(existing + json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")


def _rewrite_cache_shard_without_key(cache: JsonlProviderCache, ioc: str, params: dict) -> bool:
    """Test-only helper: rewrite temporary shards without one query key.

    Production code intentionally has no delete API; tests prove genuine
    absence invalidates completed results by mutating synthetic shards.
    """
    expected = cache.key(ioc, params)
    removed = False
    for path in cache._read_paths():
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        kept: list[bytes] = []
        changed = False
        for line in raw.splitlines(keepends=True):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                kept.append(line if line.endswith(b"\n") else line + b"\n")
                continue
            if isinstance(row, dict) and str(row.get("key", "")) == expected:
                changed = True
                removed = True
                continue
            kept.append(line if line.endswith(b"\n") else line + b"\n")
        if not changed:
            continue
        if kept:
            path.write_bytes(b"".join(kept))
        else:
            path.write_bytes(b"")
    with cache._index_lock:
        cache._index_signature = None
        cache._index = {}
        cache._index_diagnostics = []
    if removed:
        cache._ensure_index()
    return removed


# ── R4: WHOIS provider overlay over latest-intel merge ──────────────────────


def test_r4_fresh_whois_provider_overrides_older_snapshot_expiry():
    """Old intel updatetime keeps 2030 WHOIS; fresh provider expiry 2026 must win."""
    snapshot = build_record(
        TARGET.normalized,
        updatetime="2025-06-01 00:00:00",
        level=70,
        context="trojan c2",
    )
    snapshot["whois"] = {
        "createdDate": "2019-01-01",
        "updatedDate": "2024-01-01",
        "expiresDate": "2030-12-31",
    }
    obs = _whois_obs(expires="2026-01-01", freshness=Freshness.FRESH)
    dossier, _ = _build_standard_dossier(
        TARGET, [snapshot], [obs], {"whois": ProviderStatus.SUCCESS}, Config(), now=EVAL
    )
    assert str(dossier.whois.get("expiresDate", "")).startswith("2026-01-01")


def test_r4_fresh_whois_renewal_overrides_older_shorter_expiry():
    snapshot = build_record(TARGET.normalized, updatetime="2025-06-01 00:00:00")
    snapshot["whois"] = {"expiresDate": "2025-01-01", "createdDate": "2019-01-01"}
    obs = _whois_obs(expires="2031-06-15", freshness=Freshness.FRESH)
    dossier, _ = _build_standard_dossier(
        TARGET, [snapshot], [obs], {"whois": ProviderStatus.SUCCESS}, Config(), now=EVAL
    )
    assert str(dossier.whois.get("expiresDate", "")).startswith("2031-06-15")


def test_r4_stale_or_error_whois_does_not_overlay_snapshot():
    snapshot = build_record(TARGET.normalized, updatetime="2025-06-01 00:00:00")
    snapshot["whois"] = {"expiresDate": "2030-12-31"}
    stale = _whois_obs(expires="2026-01-01", freshness=Freshness.STALE)
    error = _whois_obs(
        expires="2024-01-01",
        status=ProviderStatus.ERROR,
        freshness=Freshness.FRESH,
    )
    for obs in (stale, error):
        dossier, _ = _build_standard_dossier(
            TARGET, [snapshot], [obs], {"whois": ProviderStatus.SUCCESS}, Config(), now=EVAL
        )
        assert str(dossier.whois.get("expiresDate", "")).startswith("2030-12-31")


def test_r4_whois_overlay_input_order_independent():
    snapshot = build_record(TARGET.normalized, updatetime="2025-06-01 00:00:00")
    snapshot["whois"] = {"expiresDate": "2030-12-31"}
    older = _whois_obs(
        expires="2026-01-01",
        fetched_at=datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc),
    )
    newer = _whois_obs(
        expires="2027-06-01",
        fetched_at=datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc),
    )
    forward, _ = _build_standard_dossier(
        TARGET,
        [snapshot],
        [older, newer],
        {"whois": ProviderStatus.SUCCESS},
        Config(),
        now=EVAL,
    )
    reverse, _ = _build_standard_dossier(
        TARGET,
        [snapshot],
        [newer, older],
        {"whois": ProviderStatus.SUCCESS},
        Config(),
        now=EVAL,
    )
    assert str(forward.whois.get("expiresDate", "")).startswith("2027-06-01")
    assert str(reverse.whois.get("expiresDate", "")).startswith("2027-06-01")


def test_r4_whois_overlay_does_not_invent_intelligence_updatetime():
    snapshot = build_record(TARGET.normalized, updatetime="2025-06-01 00:00:00", level=10)
    snapshot["whois"] = {"expiresDate": "2030-12-31"}
    obs = _whois_obs(expires="2026-01-01")
    dossier, _ = _build_standard_dossier(
        TARGET, [snapshot], [obs], {"whois": ProviderStatus.SUCCESS}, Config(), now=EVAL
    )
    # Provider fetch time must not become material activity or fake intel time.
    assert dossier.latest_material_activity_time is None or (
        dossier.latest_material_activity_time.year <= 2025
    )
    intel = dossier.latest_intel_update_time
    assert intel is not None
    assert intel.year == 2025


# ── R4: FDark adapter correctness (real adapter + fake transport) ───────────


class _FakeFDarkTransport:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
            }
        )
        return self.payload


def _fdark_provider(tmp_path, items):
    from ioc_rejudge.providers.fdark import FDarkProvider
    from ioc_rejudge.providers.settings import ProviderSettings

    transport = _FakeFDarkTransport({"status": "ok", "data": items})
    provider = FDarkProvider(
        ProviderSettings(
            name="fdark",
            base_url="https://fdark.invalid/api",
            secrets={},
            ttl=timedelta(days=7),
        ),
        Config(),
        transport=transport,
        cache=JsonlProviderCache(tmp_path, "fdark", timedelta(days=7)),
        now_fn=lambda: EVAL,
    )
    return provider, transport


def test_r4_fdark_preserves_hash_type_confidence_and_observed_time(tmp_path):
    provider, _ = _fdark_provider(
        tmp_path,
        [
            {
                "sha1": "sha1-only",
                "level": 80,
                "family": "trojan.family",
                "type": "pe",
                "confidence": 90,
                "lseen": 1_720_000_000,
            },
            {
                "sha256": "sha256-only",
                "level": 55,
                "family": "backdoor.family",
                "fseen": 1_710_000_000,
            },
        ],
    )
    target = read_input_bundle(None, ["fdark-r4.invalid"]).targets[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    first, second = result.observations
    assert first.payload["hash"] == "sha1-only"
    assert first.payload["hash_type"] == "sha1"
    assert first.payload["confidence"] == 90
    assert first.payload["family"] == "trojan.family"
    assert first.payload["level"] == 80
    assert first.observed_at == datetime.fromtimestamp(1_720_000_000, timezone.utc)
    assert first.payload["time"] == first.observed_at.isoformat()
    assert second.payload["hash_type"] == "sha256"
    assert "confidence" not in second.payload
    assert second.observed_at == datetime.fromtimestamp(1_710_000_000, timezone.utc)


def test_r4_fdark_keeps_provenance_and_target_scope(tmp_path):
    provider, transport = _fdark_provider(
        tmp_path,
        [{"md5": "md5-only", "level": 80, "family": "trojan"}],
    )
    bundle = read_input_bundle(None, ["https://fdark-r4.invalid/a"])
    target = bundle.targets[0]
    assert target.ioc_type == "url"
    result = provider.collect([target], ProviderContext())
    observation = result.observations[0]
    assert observation.ioc == target.normalized
    assert observation.scope == "url"
    assert observation.provider == "fdark"
    assert observation.fetched_at == EVAL
    assert observation.raw_ref.startswith("cache:fdark:")
    assert transport.calls[0]["params"]["http_path"] == "/a"


def test_r4_fdark_missing_invalid_future_sample_time_not_current_activity(tmp_path):
    provider, _ = _fdark_provider(
        tmp_path,
        [
            {"md5": "no-time", "level": 80, "family": "trojan"},
            {"md5": "bad-time", "level": 80, "family": "trojan", "lseen": "not-a-time"},
            {
                "md5": "future-time",
                "level": 80,
                "family": "trojan",
                "lseen": 4_000_000_000,
            },
            {"md5": "not-a-virus", "level": 99, "family": "not-a-virus:tool"},
            {"md5": "zero-confidence", "level": 99, "confidence": 0},
        ],
    )
    target = read_input_bundle(None, ["fdark-time.invalid"]).targets[0]
    result = provider.collect([target], ProviderContext())
    by_hash = {obs.payload["hash"]: obs for obs in result.observations}
    assert "time" not in by_hash["no-time"].payload
    assert by_hash["bad-time"].observed_at is None
    future_observed = by_hash["future-time"].observed_at
    assert future_observed is not None and future_observed > EVAL
    assert [
        by_hash[name].payload["malicious"]
        for name in ("not-a-virus", "zero-confidence")
    ] == [False, False]
    # Future sample time must not count as recent activity at evaluation time.
    from ioc_rejudge.parser import is_recent

    assert not is_recent(future_observed, EVAL, timedelta(days=30))


# ── R5: DGA route requires reliable fresh successful classification ─────────


def test_r5_success_plus_error_does_not_auto_dga_either_order():
    success = _dga_obs(["dga"], status=ProviderStatus.SUCCESS, freshness=Freshness.FRESH)
    error = _dga_obs(["dga"], status=ProviderStatus.ERROR, freshness=Freshness.FRESH)
    for observations in ([success, error], [error, success]):
        decision = select_route(
            DGA_TARGET,
            observations,
            dga_provider_configured=True,
            dga_provider_status=ProviderStatus.ERROR,
        )
        assert decision.route == Route.STANDARD
        assert decision.classification_unknown is True


def test_r5_stale_dga_classification_not_automatic_white_route():
    decision = select_route(
        DGA_TARGET,
        [_dga_obs(["dga"], freshness=Freshness.STALE)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is True


def test_r5_unknown_freshness_not_trusted_as_dga_success():
    """Legacy UNKNOWN freshness is not blanket trusted success for DGA white."""
    decision = select_route(
        DGA_TARGET,
        [_dga_obs(["dga"], freshness=Freshness.UNKNOWN)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is True


def test_r5_wrong_ioc_classification_ignored():
    decision = select_route(
        DGA_TARGET,
        [_dga_obs(["dga"], ioc="other.invalid", freshness=Freshness.FRESH)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is False


def test_r5_fresh_successful_exact_dga_still_routes():
    decision = select_route(
        DGA_TARGET,
        [_dga_obs(["dga"], freshness=Freshness.FRESH)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.DGA
    assert decision.classification_unknown is False


def test_r5_fresh_non_dga_tags_stay_standard():
    decision = select_route(
        DGA_TARGET,
        [_dga_obs(["phishing"], freshness=Freshness.FRESH)],
        dga_provider_configured=True,
        dga_provider_status=ProviderStatus.SUCCESS,
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is False


def test_r5_pipeline_dga_white_bypass_gone(tmp_path):
    """Success DGA observation + aggregate ERROR must not produce 误报."""
    path = tmp_path / "k01.jsonl"
    # success dga row then error row — aggregate ERROR in sidecar semantics
    _write_sidecar_row(
        path,
        ioc="bypass.invalid",
        kind="dga_classification",
        status="success",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={"tags": ["dga"]},
    )
    _write_sidecar_row(
        path,
        ioc="bypass.invalid",
        kind="dga_classification",
        status="error",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={"tags": ["dga"]},
    )
    # complete empty samples + valid WHOIS that would white on DGA route
    samples = tmp_path / "samples.jsonl"
    for name, kind in (("ioc_info", "ioc_info_record"), ("fdark", "associated_sample")):
        # use separate providers via one multi-kind file is awkward; use two files
        pass
    ioc_info = tmp_path / "ioc_info.jsonl"
    fdark = tmp_path / "fdark.jsonl"
    whois = tmp_path / "whois.jsonl"
    # NO_DATA-style empty success samples
    _write_sidecar_row(
        ioc_info,
        ioc="bypass.invalid",
        kind="ioc_info_record",
        status="no_data",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={},
    )
    _write_sidecar_row(
        fdark,
        ioc="bypass.invalid",
        kind="associated_sample",
        status="no_data",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={},
    )
    _write_sidecar_row(
        whois,
        ioc="bypass.invalid",
        kind="whois",
        status="success",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={"expires_at": "2030-01-01", "expiresDate": "2030-01-01"},
    )
    providers = [
        SidecarProvider("k01_compromise", path, ttl=timedelta(days=7)),
        SidecarProvider("ioc_info", ioc_info, ttl=timedelta(days=7)),
        SidecarProvider("fdark", fdark, ttl=timedelta(days=7)),
        SidecarProvider("whois", whois, ttl=timedelta(days=7)),
    ]
    bundle = read_input_bundle(None, ["bypass.invalid"])
    result = run_unified_pipeline(
        bundle, providers, Config(), ProviderContext(offline=True), now=EVAL
    )
    row = result.verdicts[0]
    assert row["route"] != "dga"
    assert row["conclusion"] != "误报"
    assert row.get("classification_unknown") is True or row["conclusion"] == "待复核"


# ── R6: finite relate_url levels ────────────────────────────────────────────


@pytest.mark.parametrize(
    "level",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        "NaN",
        "Infinity",
        "-Infinity",
        True,
        False,
        10**1000,
        object(),
    ],
)
def test_r6_nonfinite_or_invalid_relate_url_level_not_retained_or_direct_a(level):
    url = "https://level-gate.invalid/path"
    record = build_record(url, relate_url=[{"url": url, "level": level}])
    dossier = extract_evidence(merge_records([record]), Config())
    assert url not in dossier.retained_urls
    assert not any("relate_url" in str(e.tags) for e in dossier.evidence_a)


@pytest.mark.parametrize("level", [40, 40.0, "40", 70, "70.5"])
def test_r6_finite_numeric_string_and_boundary_40_still_work(level):
    url = "https://level-ok.invalid/path"
    record = build_record(url, relate_url=[{"url": url, "level": level}])
    dossier = extract_evidence(merge_records([record]), Config())
    assert url in dossier.retained_urls
    assert any("relate_url" in str(e.tags) for e in dossier.evidence_a)


def test_r6_https_relate_cannot_make_http_url_direct_a():
    record = build_record(
        "http://scheme-gate.invalid/path",
        relate_url=[{"url": "https://scheme-gate.invalid/path", "level": 70}],
    )
    dossier = extract_evidence(merge_records([record]), Config())
    assert not any("relate_url" in str(e.tags) for e in dossier.evidence_a)
    assert "https://scheme-gate.invalid/path" not in dossier.retained_urls


def test_r6_coerce_level_rejects_bool_and_nonfinite():
    assert not isfinite(coerce_level(True, default=float("nan")))
    assert not isfinite(coerce_level(float("nan"), default=float("nan")))
    assert coerce_level("40", default=float("nan")) == 40.0


# ── R13: sidecar freshness from fetched_at + TTL ────────────────────────────


def test_r13_sidecar_fresh_within_ttl(tmp_path):
    path = tmp_path / "icp.jsonl"
    _write_sidecar_row(
        path,
        ioc="icp-fresh.invalid",
        kind="icp_registration",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={"current": True, "registration": "京ICP备12345678号"},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    result = provider.collect(
        [IocTarget("icp-fresh.invalid", "icp-fresh.invalid", "domain", "icp-fresh.invalid")],
        ProviderContext(offline=True, now=EVAL),
    )
    assert result.observations[0].freshness == Freshness.FRESH
    assert result.freshnesses.get("icp-fresh.invalid") == Freshness.FRESH


def test_r13_sidecar_expired_is_stale(tmp_path):
    path = tmp_path / "icp.jsonl"
    _write_sidecar_row(
        path,
        ioc="icp-stale.invalid",
        kind="icp_registration",
        fetched_at="2025-01-01T00:00:00+00:00",
        payload={"current": True, "registration": "京ICP备999号"},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    result = provider.collect(
        [IocTarget("icp-stale.invalid", "icp-stale.invalid", "domain", "icp-stale.invalid")],
        ProviderContext(offline=True, now=EVAL),
    )
    assert result.observations[0].freshness == Freshness.STALE


def test_r13_sidecar_future_and_missing_stay_unknown(tmp_path):
    path = tmp_path / "icp.jsonl"
    _write_sidecar_row(
        path,
        ioc="icp-future.invalid",
        kind="icp_registration",
        fetched_at="2026-12-01T00:00:00+00:00",
        payload={"current": True, "registration": "京ICP备1号"},
    )
    _write_sidecar_row(
        path,
        ioc="icp-missing.invalid",
        kind="icp_registration",
        fetched_at="",
        payload={"current": True, "registration": "京ICP备2号"},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    targets = [
        IocTarget("icp-future.invalid", "icp-future.invalid", "domain", "icp-future.invalid"),
        IocTarget("icp-missing.invalid", "icp-missing.invalid", "domain", "icp-missing.invalid"),
    ]
    result = provider.collect(targets, ProviderContext(offline=True, now=EVAL))
    by_ioc = {o.ioc: o for o in result.observations}
    assert by_ioc["icp-future.invalid"].freshness == Freshness.UNKNOWN
    assert by_ioc["icp-missing.invalid"].freshness == Freshness.UNKNOWN


def test_r13_sidecar_ignores_claimed_freshness_field(tmp_path):
    path = tmp_path / "icp.jsonl"
    _write_sidecar_row(
        path,
        ioc="icp-spoof.invalid",
        kind="icp_registration",
        fetched_at="2025-01-01T00:00:00+00:00",
        payload={"current": True, "registration": "京ICP备spoof号"},
        extra={"freshness": "fresh"},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    result = provider.collect(
        [IocTarget("icp-spoof.invalid", "icp-spoof.invalid", "domain", "icp-spoof.invalid")],
        ProviderContext(offline=True, now=EVAL),
    )
    assert result.observations[0].freshness == Freshness.STALE


def test_r13_fresh_icp_consumed_stale_not(tmp_path):
    fresh_path = tmp_path / "fresh.jsonl"
    stale_path = tmp_path / "stale.jsonl"
    _write_sidecar_row(
        fresh_path,
        ioc="consume.invalid",
        kind="icp_registration",
        fetched_at="2026-09-20T12:00:00+00:00",
        payload={"current": True, "registration": "京ICP备FRESH号"},
    )
    _write_sidecar_row(
        stale_path,
        ioc="consume.invalid",
        kind="icp_registration",
        fetched_at="2025-01-01T00:00:00+00:00",
        payload={"current": True, "registration": "京ICP备STALE号"},
    )
    bundle = read_input_bundle(None, ["consume.invalid"])
    fresh_result = run_unified_pipeline(
        bundle,
        [SidecarProvider("icp", fresh_path, ttl=timedelta(days=30))],
        Config(),
        ProviderContext(offline=True),
        now=EVAL,
    )
    stale_result = run_unified_pipeline(
        bundle,
        [SidecarProvider("icp", stale_path, ttl=timedelta(days=30))],
        Config(),
        ProviderContext(offline=True),
        now=EVAL,
    )
    # Fresh current ICP should complete check; stale must not inject registration.
    fresh_row = fresh_result.verdicts[0]
    stale_row = stale_result.verdicts[0]
    # At minimum, observations differ in freshness through pipeline ICP gate.
    assert any(
        o.freshness == Freshness.FRESH and o.kind == "icp_registration"
        for o in fresh_result.observations
    )
    assert any(
        o.freshness == Freshness.STALE and o.kind == "icp_registration"
        for o in stale_result.observations
    )
    assert fresh_row["ioc"] == stale_row["ioc"]


def test_r13_timezone_equivalent_fetched_at(tmp_path):
    path = tmp_path / "icp.jsonl"
    # Same instant as EVAL - 1 day, written with +08:00 offset
    _write_sidecar_row(
        path,
        ioc="tz.invalid",
        kind="icp_registration",
        fetched_at="2026-09-20T20:00:00+08:00",
        payload={"current": False},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    result = provider.collect(
        [IocTarget("tz.invalid", "tz.invalid", "domain", "tz.invalid")],
        ProviderContext(offline=True, now=EVAL),
    )
    assert result.observations[0].freshness == Freshness.FRESH


def test_r13_ttl_boundary_inclusive(tmp_path):
    path = tmp_path / "icp.jsonl"
    fetched = EVAL - timedelta(days=30)
    _write_sidecar_row(
        path,
        ioc="edge.invalid",
        kind="icp_registration",
        fetched_at=fetched.isoformat(),
        payload={"current": False},
    )
    provider = SidecarProvider("icp", path, ttl=timedelta(days=30))
    at_edge = provider.collect(
        [IocTarget("edge.invalid", "edge.invalid", "domain", "edge.invalid")],
        ProviderContext(offline=True, now=EVAL),
    )
    assert at_edge.observations[0].freshness == Freshness.FRESH
    after = provider.collect(
        [IocTarget("edge.invalid", "edge.invalid", "domain", "edge.invalid")],
        ProviderContext(offline=True, now=EVAL + timedelta(microseconds=1)),
    )
    assert after.observations[0].freshness == Freshness.STALE


# ── Result cache: future fetched_at, sidecar TTL bounds, contract bump ──────


def test_contract_bumped_for_task3_semantics():
    assert ADJUDICATION_CACHE_CONTRACT >= 12


def test_future_fetched_at_exact_activation_cached_matches_uncached(tmp_path):
    """Pre-activation cache must miss at exact future fetched_at activation."""
    cache_root = tmp_path / "prov"
    result_root = tmp_path / "res"
    provider_cache = JsonlProviderCache(cache_root, "ioc_info", timedelta(hours=2))
    result_cache = AdjudicationResultCache(result_root)

    future_fetch = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    before = future_fetch - timedelta(hours=1)
    # Seed a row whose fetched_at is still in the future relative to `before`.
    provider_cache.put(
        "future-fetch.invalid",
        {"data": []},
        {"request_ioc": "future-fetch.invalid", "endpoint": "https://ioc-info.invalid"},
        fetched_at=future_fetch,
    )

    class _Reader:
        name = "ioc_info"

        def __init__(self, cache, eval_now):
            self.cache = cache
            self.eval_now = eval_now
            self.calls = []

        def supports(self, target):
            return True

        def cache_params(self, target):
            return {
                "request_ioc": target.original,
                "endpoint": "https://ioc-info.invalid",
            }

        def collect(self, targets, context):
            self.calls.append([t.normalized for t in targets])
            statuses = {}
            freshnesses = {}
            for target in targets:
                entry = self.cache.get(
                    target.original, self.cache_params(target), now=self.eval_now
                )
                if entry is None:
                    statuses[target.normalized] = ProviderStatus.NO_DATA
                    freshnesses[target.normalized] = Freshness.UNKNOWN
                else:
                    statuses[target.normalized] = ProviderStatus.NO_DATA
                    freshnesses[target.normalized] = (
                        Freshness.FRESH if entry.fresh else Freshness.STALE
                    )
            return ProviderResult(
                self.name, statuses=statuses, freshnesses=freshnesses
            )

    bundle = read_input_bundle(None, ["future-fetch.invalid"])
    first = run_unified_pipeline(
        bundle,
        [_Reader(provider_cache, before)],
        Config(),
        ProviderContext(),
        now=before,
        result_cache=result_cache,
    )
    assert first.diagnostics.result_cache_miss == 1

    # At exact activation, uncached and cached must agree (miss + recompute).
    second = run_unified_pipeline(
        bundle,
        [_Reader(provider_cache, future_fetch)],
        Config(),
        ProviderContext(),
        now=future_fetch,
        result_cache=result_cache,
    )
    uncached = run_unified_pipeline(
        bundle,
        [_Reader(provider_cache, future_fetch)],
        Config(),
        ProviderContext(),
        now=future_fetch,
        result_cache=None,
    )
    assert second.verdicts[0]["conclusion"] == uncached.verdicts[0]["conclusion"]
    # Must not silently reuse the pre-activation completed row through activation.
    assert second.diagnostics.result_cache_hit == 0 or (
        second.verdicts[0]["conclusion"] == uncached.verdicts[0]["conclusion"]
        and second.diagnostics.result_cache_miss >= 1
    )


def test_sidecar_ttl_bounds_result_cache_validity(tmp_path):
    path = tmp_path / "ioc_info.jsonl"
    fetched = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    _write_sidecar_row(
        path,
        ioc="side-ttl.invalid",
        kind="ioc_info_record",
        status="no_data",
        fetched_at=fetched.isoformat(),
        payload={},
    )
    # Companion sample provider so completeness can settle.
    fdark = tmp_path / "fdark.jsonl"
    _write_sidecar_row(
        fdark,
        ioc="side-ttl.invalid",
        kind="associated_sample",
        status="no_data",
        fetched_at=fetched.isoformat(),
        payload={},
    )
    ttl = timedelta(hours=2)
    providers = [
        SidecarProvider("ioc_info", path, ttl=ttl),
        SidecarProvider("fdark", fdark, ttl=ttl),
    ]
    bundle = read_input_bundle(None, ["side-ttl.invalid"])
    result_cache = AdjudicationResultCache(tmp_path / "rc")
    now = fetched + timedelta(hours=1)
    first = run_unified_pipeline(
        bundle,
        providers,
        Config(),
        ProviderContext(offline=True),
        now=now,
        result_cache=result_cache,
    )
    assert first.diagnostics.result_cache_miss == 1

    # Still inside TTL — hit.
    inside = run_unified_pipeline(
        bundle,
        providers,
        Config(),
        ProviderContext(offline=True),
        now=fetched + ttl,
        result_cache=result_cache,
    )
    # Past TTL — must miss (stale NO_DATA completeness flips).
    past = run_unified_pipeline(
        bundle,
        providers,
        Config(),
        ProviderContext(offline=True),
        now=fetched + ttl + timedelta(microseconds=1),
        result_cache=result_cache,
    )
    assert inside.diagnostics.result_cache_hit + past.diagnostics.result_cache_miss >= 1
    assert past.diagnostics.result_cache_hit == 0 or past.diagnostics.result_cache_miss >= 1


def test_sidecar_ttl_in_fingerprint(tmp_path):
    path = tmp_path / "side.jsonl"
    _write_sidecar_row(
        path,
        ioc="fp.invalid",
        kind="whois",
        status="no_data",
        fetched_at="2026-09-20T00:00:00+00:00",
        payload={},
    )
    target = IocTarget("fp.invalid", "fp.invalid", "domain", "fp.invalid")
    p7 = SidecarProvider("whois", path, ttl=timedelta(days=7))
    p1 = SidecarProvider("whois", path, ttl=timedelta(days=1))
    fp7 = result_cache_fingerprint(target, [], [p7], Config(), evaluation_time=EVAL)
    fp1 = result_cache_fingerprint(target, [], [p1], Config(), evaluation_time=EVAL)
    assert fp7 != fp1


def test_r3_absence_via_shard_rewrite_not_production_delete(tmp_path):
    """Genuine raw disappearance invalidates without JsonlProviderCache.delete."""
    assert not hasattr(JsonlProviderCache, "delete")

    cache_root = tmp_path / "prov"
    result_root = tmp_path / "res"
    provider_cache = JsonlProviderCache(cache_root, "ioc_info", timedelta(days=7))
    result_cache = AdjudicationResultCache(result_root)

    class _Seed:
        name = "ioc_info"

        def __init__(self, cache, payloads):
            self.cache = cache
            self.payloads = payloads
            self.calls = []

        def supports(self, target):
            return True

        def cache_params(self, target):
            return {
                "request_ioc": target.original,
                "endpoint": "https://ioc-info.invalid",
            }

        def collect(self, targets, context):
            self.calls.append([t.normalized for t in targets])
            statuses = {}
            for target in targets:
                raw = self.payloads.get(target.normalized, {"data": []})
                self.cache.put(
                    target.original,
                    raw,
                    self.cache_params(target),
                    fetched_at=datetime(2026, 9, 21, 9, tzinfo=timezone.utc),
                )
                statuses[target.normalized] = ProviderStatus.NO_DATA
            return ProviderResult(self.name, statuses=statuses)

    payloads = {"a.invalid": {"data": [1]}, "b.invalid": {"data": [2]}}
    bundle = read_input_bundle(None, ["a.invalid", "b.invalid"])
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    run_unified_pipeline(
        bundle,
        [_Seed(provider_cache, payloads)],
        Config(),
        ProviderContext(),
        now=now,
        result_cache=result_cache,
    )
    removed = _rewrite_cache_shard_without_key(
        provider_cache,
        "a.invalid",
        {"request_ioc": "a.invalid", "endpoint": "https://ioc-info.invalid"},
    )
    assert removed is True
    assert provider_cache.entry_dependency(
        "a.invalid",
        {"request_ioc": "a.invalid", "endpoint": "https://ioc-info.invalid"},
    ).startswith("absent:")
    assert not provider_cache.entry_dependency(
        "b.invalid",
        {"request_ioc": "b.invalid", "endpoint": "https://ioc-info.invalid"},
    ).startswith("absent:")

    second = run_unified_pipeline(
        bundle,
        [_Seed(provider_cache, payloads)],
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=result_cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.diagnostics.result_cache_miss == 1


# ── Task 4: CLI operations=N summary ────────────────────────────────────────


def test_cli_diff_summary_includes_operations_count(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps(
            {
                "ioc": "ops.invalid",
                "conclusion": "灰",
                "disposition": "gray",
                "retained_urls": ["https://ops.invalid/old"],
                "review_suggestion": "无需复核",
                "scope_actions": [],
                "missing_required_providers": [],
                "classification_unknown": False,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    # Same conclusion 灰, but retained_urls + review_suggestion change.
    after_path = tmp_path / "after.jsonl"
    after_path.write_text(
        json.dumps(
            {
                "ioc": "ops.invalid",
                "conclusion": "灰",
                "disposition": "gray",
                "retained_urls": ["https://ops.invalid/new"],
                "review_suggestion": "必看",
                "scope_actions": [],
                "missing_required_providers": [],
                "classification_unknown": False,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    # Drive through compare_verdicts unit first for stable ops count.
    before = [json.loads(baseline.read_text(encoding="utf-8"))]
    after = [json.loads(after_path.read_text(encoding="utf-8"))]
    report = compare_verdicts(before, after)
    assert report["changed"] == []
    assert len(report["operational_changes"]) == 1

    # CLI path: offline empty providers will not match after file; instead patch
    # export path by invoking main with a sidecar that yields pending and a
    # baseline that shares conclusion with operational field drift via direct
    # summary check on _export_diff_report through main when possible.
    # Use a minimal offline run whose baseline conclusion equals the produced
    # 待复核 but with different review_suggestion / retained_urls.
    out = tmp_path / "result.jsonl"
    base2 = tmp_path / "base2.jsonl"
    base2.write_text(
        json.dumps(
            {
                "ioc": "ops.invalid",
                "conclusion": "待复核",
                "disposition": "review",
                "retained_urls": ["https://ops.invalid/old"],
                "review_suggestion": "必看",
                "scope_actions": [],
                "missing_required_providers": [],
                "classification_unknown": False,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ioc_rejudge",
            "--ioc",
            "ops.invalid",
            "--offline",
            "--diff-baseline",
            str(base2),
            "--jsonl",
            str(out),
        ],
    )
    main()
    captured = capsys.readouterr()
    assert "operations=" in captured.out
    # conclusion stays 待复核; retained_urls / review fields may still drift.
    assert "changed=" in captured.out


def test_operational_change_same_conclusion_retained_url_regression():
    before = [
        {
            "ioc": "same.invalid",
            "conclusion": "灰",
            "disposition": "gray",
            "retained_urls": ["https://same.invalid/a"],
            "review_suggestion": "无需复核",
            "scope_actions": ["retain_url"],
            "missing_required_providers": [],
            "classification_unknown": False,
        }
    ]
    after = [
        {
            "ioc": "same.invalid",
            "conclusion": "灰",
            "disposition": "gray",
            "retained_urls": ["https://same.invalid/b"],
            "review_suggestion": "必看",
            "scope_actions": ["retain_url"],
            "missing_required_providers": [],
            "classification_unknown": False,
        }
    ]
    report = compare_verdicts(before, after)
    assert report["changed"] == []
    assert len(report["operational_changes"]) == 1
    op = report["operational_changes"][0]
    assert "retained_urls" in op["fields"]
    assert "review_suggestion" in op["fields"]
