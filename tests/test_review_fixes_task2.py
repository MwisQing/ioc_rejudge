"""Review-fix Task 2 regressions: R1 identity, R2 temporal cache, R3 dependencies."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ioc_rejudge.config import Config
from ioc_rejudge.export import export_jsonl
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.normalize import merge_records, normalize_ioc, parse_ioc_value
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
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


class _StaticProvider:
    def __init__(self, name, factory, *, cache=None):
        self.name = name
        self.factory = factory
        self.cache = cache
        self.calls = []

    def supports(self, target):
        return True

    def collect(self, targets, context):
        self.calls.append([t.normalized for t in targets])
        return self.factory(targets)


class _CacheWritingProvider:
    name = "ioc_info"

    def __init__(
        self,
        cache: JsonlProviderCache,
        payloads: dict[str, object] | None = None,
        *,
        fetched_at: datetime | None = None,
        seed_cache: bool = True,
    ):
        self.cache = cache
        self.payloads = dict(payloads or {})
        self.calls = []
        self.fetched_at = fetched_at or datetime(
            2026, 9, 21, 9, 0, tzinfo=timezone.utc
        )
        self.seed_cache = seed_cache

    def supports(self, target):
        return True

    def cache_params(self, target):
        return {"request_ioc": target.original, "endpoint": "https://ioc-info.invalid"}

    def collect(self, targets, context):
        self.calls.append([t.normalized for t in targets])
        statuses = {}
        for target in targets:
            raw = self.payloads.get(target.normalized, {"data": []})
            if self.seed_cache:
                self.cache.put(
                    target.original,
                    raw,
                    self.cache_params(target),
                    fetched_at=self.fetched_at,
                )
            statuses[target.normalized] = ProviderStatus.NO_DATA
        return ProviderResult(self.name, statuses=statuses)


class _FactProvider:
    """Cache-backed provider that emits real ioc_info_record observations."""

    name = "ioc_info"

    def __init__(
        self,
        cache: JsonlProviderCache,
        payloads: dict[str, object] | None = None,
        *,
        fetched_at: datetime | None = None,
        eval_now: datetime | None = None,
        seed_on_miss: bool = True,
    ):
        self.cache = cache
        self.payloads = dict(payloads or {})
        self.calls = []
        self.fetched_at = fetched_at or datetime(
            2026, 9, 21, 9, 0, tzinfo=timezone.utc
        )
        self.eval_now = eval_now
        self.seed_on_miss = seed_on_miss

    def supports(self, target):
        return True

    def cache_params(self, target):
        return {"request_ioc": target.original, "endpoint": "https://ioc-info.invalid"}

    def collect(self, targets, context):
        self.calls.append([t.normalized for t in targets])
        observations = []
        statuses = {}
        freshnesses = {}
        lookup_now = self.eval_now or datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        for target in targets:
            params = self.cache_params(target)
            entry = self.cache.get(target.original, params, now=lookup_now)
            if entry is None and self.seed_on_miss and target.normalized in self.payloads:
                raw = self.payloads[target.normalized]
                self.cache.put(
                    target.original,
                    raw,
                    params,
                    fetched_at=self.fetched_at,
                )
                entry = self.cache.get(target.original, params, now=lookup_now)
            if entry is None:
                statuses[target.normalized] = ProviderStatus.NO_DATA
                freshnesses[target.normalized] = Freshness.FRESH
                continue
            raw = entry.raw if isinstance(entry.raw, dict) else {}
            records = raw.get("data", [])
            if not isinstance(records, list):
                records = []
            fr = Freshness.FRESH if entry.fresh else Freshness.STALE
            freshnesses[target.normalized] = fr
            if records:
                statuses[target.normalized] = ProviderStatus.SUCCESS
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    observations.append(
                        Observation(
                            ioc=target.normalized,
                            scope=target.ioc_type,
                            provider=self.name,
                            kind="ioc_info_record",
                            status=ProviderStatus.SUCCESS,
                            fetched_at=entry.fetched_at,
                            observed_at=entry.fetched_at,
                            freshness=fr,
                            payload=dict(record),
                        )
                    )
            else:
                statuses[target.normalized] = ProviderStatus.NO_DATA
        return ProviderResult(
            self.name,
            observations,
            statuses,
            freshnesses=freshnesses,
        )


class _MultiVariantCacheProvider:
    """FDark-like provider with multiple query variants per target."""

    name = "fdark"

    def __init__(self, cache: JsonlProviderCache, payloads: dict[str, object] | None = None):
        self.cache = cache
        self.payloads = dict(payloads or {})
        self.calls = []

    def supports(self, target):
        return True

    def query_variants(self, target):
        return [
            ("fast", {"q": target.original, "mode": "fast"}),
            ("slow", {"q": target.original, "mode": "slow"}),
        ]

    def cache_params(self, target, strategy, query):
        return {
            "endpoint": "https://fdark.invalid",
            "request_ioc": target.original,
            "strategy": strategy,
            "query": dict(query),
        }

    def collect(self, targets, context):
        self.calls.append([t.normalized for t in targets])
        statuses = {}
        for target in targets:
            for strategy, query in self.query_variants(target):
                raw = self.payloads.get(
                    (target.normalized, strategy),
                    self.payloads.get(target.normalized, {"items": []}),
                )
                self.cache.put(
                    target.original,
                    raw,
                    self.cache_params(target, strategy, query),
                    fetched_at=datetime(2026, 9, 21, 9, 0, tzinfo=timezone.utc),
                )
            statuses[target.normalized] = ProviderStatus.NO_DATA
        return ProviderResult(self.name, statuses=statuses)


def _malicious_ioc_info_payload(ioc: str, *, md5: str, time: str) -> dict:
    return {
        "data": [
            {
                "key": ioc,
                "level": 90,
                "comment": f"{ioc} ransomware C2",
                "hash": [
                    {
                        "md5": md5,
                        "level": 90,
                        "family": "trojan",
                        "confidence": 5,
                        "time": time,
                    }
                ],
            }
        ]
    }


def _dga_with_pdns(pdns_last_seen: datetime):
    def classification(targets):
        target = targets[0]
        return ProviderResult(
            "k01_compromise",
            [
                Observation(
                    ioc=target.normalized,
                    scope=target.ioc_type,
                    provider="k01_compromise",
                    kind="dga_classification",
                    status=ProviderStatus.SUCCESS,
                    freshness=Freshness.FRESH,
                    payload={"tags": ["dga"]},
                )
            ],
            {target.normalized: ProviderStatus.SUCCESS},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    def empty_sample(name):
        def factory(targets):
            target = targets[0]
            return ProviderResult(
                name,
                statuses={target.normalized: ProviderStatus.NO_DATA},
                freshnesses={target.normalized: Freshness.FRESH},
            )

        return factory

    def pdns(targets):
        target = targets[0]
        return ProviderResult(
            "pdns",
            [
                Observation(
                    ioc=target.normalized,
                    scope=target.ioc_type,
                    provider="pdns",
                    kind="pdns_activity",
                    status=ProviderStatus.SUCCESS,
                    fetched_at=datetime(2026, 9, 21, 9, 0, tzinfo=timezone.utc),
                    observed_at=pdns_last_seen,
                    freshness=Freshness.FRESH,
                    payload={"time_last": pdns_last_seen, "last_seen": pdns_last_seen},
                )
            ],
            {target.normalized: ProviderStatus.SUCCESS},
            freshnesses={target.normalized: Freshness.FRESH},
        )

    return [
        _StaticProvider("k01_compromise", classification),
        _StaticProvider("ioc_info", empty_sample("ioc_info")),
        _StaticProvider("fdark", empty_sample("fdark")),
        _StaticProvider("pdns", pdns),
    ]


# ── R1: identity ───────────────────────────────────────────────────────────


def test_parse_ioc_value_keeps_scheme_legacy_normalize_strips():
    assert parse_ioc_value("https://Case.INVALID./a?Q=1") == (
        "https://case.invalid/a?Q=1",
        "url",
        [],
        "https",
    )
    assert normalize_ioc("https://Case.INVALID./a?Q=1") == (
        "case.invalid/a?Q=1",
        "url",
        [],
    )
    assert parse_ioc_value("case.invalid")[0] == "case.invalid"


def test_r1_three_scopes_both_input_orders_and_pipeline_order(tmp_path):
    providers = [_StaticProvider("counting", lambda targets: ProviderResult(
        "counting",
        statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
    ))]
    forward = read_input_bundle(
        None, ["case.invalid", "http://case.invalid", "https://case.invalid"]
    )
    reverse = read_input_bundle(
        None, ["https://case.invalid", "case.invalid", "http://case.invalid"]
    )
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    forward_result = run_unified_pipeline(
        forward, providers, Config(), ProviderContext(), now=now
    )
    reverse_result = run_unified_pipeline(
        reverse, providers, Config(), ProviderContext(), now=now
    )
    assert [row["ioc"] for row in forward_result.verdicts] == [
        "case.invalid",
        "http://case.invalid",
        "https://case.invalid",
    ]
    assert [row["ioc_type"] for row in forward_result.verdicts] == [
        "domain",
        "url",
        "url",
    ]
    assert [row["ioc"] for row in reverse_result.verdicts] == [
        "https://case.invalid",
        "case.invalid",
        "http://case.invalid",
    ]


def test_r1_sidecar_and_snapshot_do_not_spill_url_evidence_to_domain(tmp_path):
    sidecar = tmp_path / "mixed.jsonl"
    sidecar.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "ioc": "https://case.invalid",
                        "kind": "ioc_info_record",
                        "status": "success",
                        "fetched_at": "2026-09-21T09:00:00+00:00",
                        "observed_at": "2026-09-21T09:00:00+00:00",
                        "payload": {
                            "record": {
                                "key": "https://case.invalid",
                                "comment": "URL-ONLY-EVIDENCE",
                                "level": 90,
                            }
                        },
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "ioc": "case.invalid",
                        "kind": "ioc_info_record",
                        "status": "success",
                        "fetched_at": "2026-09-21T09:00:00+00:00",
                        "observed_at": "2026-09-21T09:00:00+00:00",
                        "payload": {
                            "record": {
                                "key": "case.invalid",
                                "comment": "DOMAIN-ONLY-EVIDENCE",
                                "level": 10,
                            }
                        },
                    },
                    ensure_ascii=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    provider = SidecarProvider("ioc_info", sidecar)
    bundle = read_input_bundle(None, ["case.invalid", "https://case.invalid"])
    result = provider.collect(bundle.targets, ProviderContext(offline=True))
    by_ioc = {}
    for obs in result.observations:
        by_ioc.setdefault(obs.ioc, []).append(obs)
    assert len(by_ioc["case.invalid"]) == 1
    assert "DOMAIN-ONLY" in str(by_ioc["case.invalid"][0].payload)
    assert "URL-ONLY" not in str(by_ioc["case.invalid"][0].payload)
    assert len(by_ioc["https://case.invalid"]) == 1
    assert "URL-ONLY" in str(by_ioc["https://case.invalid"][0].payload)

    snapshot = tmp_path / "snap.jsonl"
    snapshot.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "ioc": "http://case.invalid/a",
                        "data": [{"key": "http://case.invalid/a", "comment": "http-path"}],
                    }
                ),
                json.dumps(
                    {
                        "ioc": "https://case.invalid/a",
                        "data": [{"key": "https://case.invalid/a", "comment": "https-path"}],
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    snap_bundle = read_input_bundle(str(snapshot))
    assert {t.normalized for t in snap_bundle.targets} == {
        "http://case.invalid/a",
        "https://case.invalid/a",
    }
    from ioc_rejudge.pipeline import _snapshot_records

    records = _snapshot_records(snap_bundle)
    assert "http://case.invalid/a" in records
    assert "https://case.invalid/a" in records
    assert records["http://case.invalid/a"][0]["comment"] == "http-path"
    assert records["https://case.invalid/a"][0]["comment"] == "https-path"


def test_r1_result_cache_preserves_all_rows_in_order(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    provider = _StaticProvider(
        "counting",
        lambda targets: ProviderResult(
            "counting",
            statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
        ),
    )
    values = ["case.invalid", "http://case.invalid", "https://case.invalid"]
    bundle = read_input_bundle(None, values)
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    first = run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    provider.calls.clear()
    second = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=cache,
    )
    assert [row["ioc"] for row in second.verdicts] == values
    assert second.diagnostics.result_cache_hit == 3
    assert provider.calls == []
    assert first.verdicts[0]["ioc"] == "case.invalid"


def test_r1_raw_cache_isolates_http_and_https_query_params(tmp_path):
    cache = JsonlProviderCache(tmp_path, "ioc_info", timedelta(days=7))
    http_t = read_input_bundle(None, ["http://case.invalid/a"]).targets[0]
    https_t = read_input_bundle(None, ["https://case.invalid/a"]).targets[0]
    http_params = {"request_ioc": http_t.original, "endpoint": "x"}
    https_params = {"request_ioc": https_t.original, "endpoint": "x"}
    cache.put(http_t.original, {"scheme": "http"}, http_params)
    cache.put(https_t.original, {"scheme": "https"}, https_params)
    http_entry = cache.get(http_t.original, http_params)
    https_entry = cache.get(https_t.original, https_params)
    assert http_entry is not None and http_entry.raw == {"scheme": "http"}
    assert https_entry is not None and https_entry.raw == {"scheme": "https"}
    assert cache.entry_dependency(http_t.original, http_params) != cache.entry_dependency(
        https_t.original, https_params
    )


def test_r1_http_target_rejects_https_relate_url_direct_a():
    """Supervisor reproduction: HTTPS relate_url must not A-hit an HTTP target."""
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    http_t = read_input_bundle(None, ["http://case.invalid/a"]).targets[0]
    https_t = read_input_bundle(None, ["https://case.invalid/a"]).targets[0]
    cross = [
        {
            "key": "ignored",
            "level": 70,
            "relate_url": [{"url": "https://case.invalid/a", "level": 80}],
        }
    ]
    http_dossier, _ = _build_standard_dossier(
        http_t, cross, [], {}, Config(), now=now
    )
    assert http_dossier.ioc == "http://case.invalid/a"
    assert http_dossier.ioc_type == "url"
    assert http_dossier.evidence_a == []
    assert http_dossier.retained_urls == []

    # Symmetric: HTTP relate_url must not A-hit an HTTPS target.
    cross_http = [
        {
            "key": "ignored",
            "level": 70,
            "relate_url": [{"url": "http://case.invalid/a", "level": 80}],
        }
    ]
    https_dossier, _ = _build_standard_dossier(
        https_t, cross_http, [], {}, Config(), now=now
    )
    assert https_dossier.ioc == "https://case.invalid/a"
    assert https_dossier.evidence_a == []
    assert https_dossier.retained_urls == []


def test_r1_same_scheme_relate_url_still_direct_a():
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    target = read_input_bundle(None, ["https://case.invalid/a"]).targets[0]
    records = [
        {
            "key": target.normalized,
            "level": 70,
            "relate_url": [{"url": "https://case.invalid/a", "level": 80}],
        }
    ]
    dossier, _ = _build_standard_dossier(target, records, [], {}, Config(), now=now)
    assert dossier.ioc == "https://case.invalid/a"
    assert any("relate_url" in e.field for e in dossier.evidence_a)
    assert dossier.retained_urls == ["https://case.invalid/a"]


def test_r1_domain_target_never_gets_relate_url_a_but_may_retain_host_urls():
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    target = read_input_bundle(None, ["case.invalid"]).targets[0]
    records = [
        {
            "key": target.normalized,
            "level": 70,
            "relate_url": [{"url": "https://case.invalid/a", "level": 80}],
        }
    ]
    dossier, _ = _build_standard_dossier(target, records, [], {}, Config(), now=now)
    assert dossier.ioc == "case.invalid"
    assert dossier.ioc_type == "domain"
    assert dossier.evidence_a == []
    assert dossier.retained_urls == ["https://case.invalid/a"]


def test_r1_merge_records_preserves_scheme_in_dossier_ioc():
    dossier = merge_records(
        [{"key": "http://case.invalid/a", "level": 50, "host": "case.invalid"}]
    )
    assert dossier.ioc == "http://case.invalid/a"
    assert dossier.ioc_type == "url"
    # Legacy normalize still strips scheme for grouping/cache callers.
    assert normalize_ioc("http://case.invalid/a")[0] == "case.invalid/a"


def test_r1_snapshot_and_sidecar_scheme_survive_dossier_export_and_cache(tmp_path):
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    snapshot = tmp_path / "snap.jsonl"
    snapshot.write_text(
        json.dumps(
            {
                "ioc": "http://case.invalid/a",
                "data": [
                    {
                        "key": "http://case.invalid/a",
                        "level": 70,
                        "relate_url": [
                            {"url": "https://case.invalid/a", "level": 80},
                            {"url": "http://case.invalid/a", "level": 80},
                        ],
                    }
                ],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    sidecar = tmp_path / "side.jsonl"
    sidecar.write_text(
        json.dumps(
            {
                "ioc": "https://case.invalid/b",
                "kind": "ioc_info_record",
                "status": "success",
                "fetched_at": "2026-09-21T09:00:00+00:00",
                "observed_at": "2026-09-21T09:00:00+00:00",
                "payload": {
                    "record": {
                        "key": "https://case.invalid/b",
                        "level": 70,
                        "relate_url": [
                            {"url": "http://case.invalid/b", "level": 80},
                            {"url": "https://case.invalid/b", "level": 80},
                        ],
                    }
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    # Snapshot target http + sidecar-only https target via inline list mixed run.
    bundle = read_input_bundle(str(snapshot), ["https://case.invalid/b"])
    provider = SidecarProvider("ioc_info", sidecar)
    cache = AdjudicationResultCache(tmp_path / "rc")
    result = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(offline=True),
        now=now,
        result_cache=cache,
    )
    by_ioc = {row["ioc"]: row for row in result.verdicts}
    assert "http://case.invalid/a" in by_ioc
    assert "https://case.invalid/b" in by_ioc
    http_row = by_ioc["http://case.invalid/a"]
    https_row = by_ioc["https://case.invalid/b"]
    assert http_row["ioc_type"] == "url"
    assert https_row["ioc_type"] == "url"
    # Cross-scheme relate_url must not appear as direct A on either row.
    assert "relate_url[https://case.invalid/a]" not in str(http_row.get("evidence_a_detail", ""))
    assert "relate_url[http://case.invalid/b]" not in str(https_row.get("evidence_a_detail", ""))
    # Same-scheme direct evidence remains.
    assert "relate_url[http://case.invalid/a]" in str(http_row.get("evidence_a_detail", ""))
    assert "relate_url[https://case.invalid/b]" in str(https_row.get("evidence_a_detail", ""))

    out = tmp_path / "out.jsonl"
    export_jsonl(result.verdicts, str(out))
    exported = [
        json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert [row["ioc"] for row in exported] == [
        "http://case.invalid/a",
        "https://case.invalid/b",
    ]

    # Result cache hit preserves scheme-aware ioc keys.
    second = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(offline=True),
        now=now + timedelta(seconds=30),
        result_cache=cache,
    )
    assert second.diagnostics.result_cache_hit == 2
    assert [row["ioc"] for row in second.verdicts] == [
        "http://case.invalid/a",
        "https://case.invalid/b",
    ]


# ── R2: temporal validity ──────────────────────────────────────────────────


def test_r2_pdns_boundary_cached_matches_uncached(tmp_path):
    pdns_last = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
    before = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    at_boundary = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    after = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)
    bundle = read_input_bundle(None, ["dga-time.invalid"])
    config = Config()

    uncached_before = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=before
    )
    uncached_at = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=at_boundary
    )
    uncached_after = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=after
    )
    assert uncached_before.verdicts[0]["conclusion"] == "误报"
    assert uncached_at.verdicts[0]["conclusion"] == "误报"
    assert uncached_after.verdicts[0]["conclusion"] == "失活有效"

    cache = AdjudicationResultCache(tmp_path)
    providers = _dga_with_pdns(pdns_last)
    first = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=before, result_cache=cache
    )
    assert first.verdicts[0]["conclusion"] == "误报"

    # Still within inclusive bound → hit, same white conclusion.
    second = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=at_boundary,
        result_cache=cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.verdicts[0]["conclusion"] == uncached_at.verdicts[0]["conclusion"]

    # Past bound → miss and matches uncached black.
    third = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=after,
        result_cache=cache,
    )
    assert third.diagnostics.result_cache_hit == 0
    assert third.diagnostics.result_cache_miss_reasons.get("temporal_expired", 0) == 1
    assert third.verdicts[0]["conclusion"] == uncached_after.verdicts[0]["conclusion"]


def test_r2_no_time_sensitive_data_still_hits_after_30_seconds(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    provider = _StaticProvider(
        "counting",
        lambda targets: ProviderResult(
            "counting",
            statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
        ),
    )
    bundle = read_input_bundle(None, ["plain.invalid"])
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    provider.calls.clear()
    second = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert provider.calls == []


def test_r2_contract_bumped_and_valid_until_helper():
    assert ADJUDICATION_CACHE_CONTRACT >= 11
    pdns_last = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
    now = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    obs = [
        Observation(
            ioc="x.invalid",
            scope="domain",
            provider="pdns",
            kind="pdns_activity",
            status=ProviderStatus.SUCCESS,
            observed_at=pdns_last,
            freshness=Freshness.FRESH,
            payload={"last_seen": pdns_last},
        )
    ]
    bound = compute_result_valid_until(obs, Config(), now)
    assert bound == datetime(2026, 9, 21, 12, 0, 0)


def test_r2_snapshot_hash_activity_boundary_cached_matches_uncached(tmp_path):
    """Standard-route snapshot hash activity must bound result-cache validity."""
    md5 = "a" * 32
    snap_path = tmp_path / "snap.jsonl"
    snap_path.write_text(
        json.dumps(
            {
                "ioc": "192.0.2.7",
                "data": [
                    {
                        "key": "192.0.2.7",
                        "level": 70,
                        "comment": "192.0.2.7 ransomware C2",
                        "hash": [
                            {
                                "md5": md5,
                                "level": 70,
                                "family": "trojan",
                                "confidence": 5,
                                "time": "2025-09-21 12:00:00",
                            }
                        ],
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    bundle = read_input_bundle(str(snap_path), None)
    providers = [
        _StaticProvider(
            "noop",
            lambda targets: ProviderResult(
                "noop",
                statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
            ),
        )
    ]
    config = Config()
    before = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    at_boundary = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    after = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)

    uncached_before = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=before
    )
    uncached_at = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=at_boundary
    )
    uncached_after = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=after
    )
    assert uncached_before.verdicts[0]["conclusion"] == "存活有效"
    assert uncached_at.verdicts[0]["conclusion"] == "存活有效"
    assert uncached_after.verdicts[0]["conclusion"] == "失活有效"

    cache = AdjudicationResultCache(tmp_path / "rc")
    first = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=before, result_cache=cache
    )
    assert first.verdicts[0]["conclusion"] == "存活有效"
    assert first.diagnostics.result_cache_miss == 1

    second = run_unified_pipeline(
        bundle,
        providers,
        config,
        ProviderContext(),
        now=at_boundary,
        result_cache=cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.verdicts[0]["conclusion"] == uncached_at.verdicts[0]["conclusion"]

    third = run_unified_pipeline(
        bundle, providers, config, ProviderContext(), now=after, result_cache=cache
    )
    assert third.diagnostics.result_cache_hit == 0
    assert third.diagnostics.result_cache_miss_reasons.get("temporal_expired", 0) == 1
    assert third.verdicts[0]["conclusion"] == uncached_after.verdicts[0]["conclusion"]


def test_r2_future_pdns_exact_activation_cached_matches_uncached(tmp_path):
    """Future pDNS activates exclusively at the event instant (+/- 1us)."""
    pdns_last = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    before = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    at_event = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    just_before = at_event - timedelta(microseconds=1)
    just_after = at_event + timedelta(microseconds=1)
    bundle = read_input_bundle(None, ["dga-time.invalid"])
    config = Config()

    uncached_before = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=before
    )
    uncached_at = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=at_event
    )
    uncached_just_before = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=just_before
    )
    uncached_just_after = run_unified_pipeline(
        bundle, _dga_with_pdns(pdns_last), config, ProviderContext(), now=just_after
    )
    assert uncached_before.verdicts[0]["conclusion"] == "失活有效"
    assert uncached_just_before.verdicts[0]["conclusion"] == "失活有效"
    assert uncached_at.verdicts[0]["conclusion"] == "误报"
    assert uncached_just_after.verdicts[0]["conclusion"] == "误报"

    cache = AdjudicationResultCache(tmp_path / "rc")
    first = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=before,
        result_cache=cache,
    )
    assert first.verdicts[0]["conclusion"] == "失活有效"

    hit_before = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=just_before,
        result_cache=cache,
    )
    assert hit_before.diagnostics.result_cache_hit == 1
    assert hit_before.verdicts[0]["conclusion"] == uncached_just_before.verdicts[0][
        "conclusion"
    ]

    at_cached = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=at_event,
        result_cache=cache,
    )
    assert at_cached.diagnostics.result_cache_hit == 0
    assert at_cached.diagnostics.result_cache_miss_reasons.get("temporal_expired", 0) == 1
    assert at_cached.verdicts[0]["conclusion"] == uncached_at.verdicts[0]["conclusion"]

    after_cached = run_unified_pipeline(
        bundle,
        _dga_with_pdns(pdns_last),
        config,
        ProviderContext(),
        now=just_after,
        result_cache=cache,
    )
    # Recomputed row at event time is valid through the pDNS recent window.
    assert after_cached.verdicts[0]["conclusion"] == uncached_just_after.verdicts[0][
        "conclusion"
    ]


def test_r2_provider_ttl_boundary_cached_matches_uncached(tmp_path):
    """Completed verdicts expire with dependent provider raw freshness TTL."""
    cache_root = tmp_path / "prov"
    # Short TTL so the flip falls inside the evaluation day.
    provider_cache = JsonlProviderCache(cache_root, "ioc_info", timedelta(hours=2))
    fetched_at = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    before = datetime(2026, 9, 21, 11, 0, tzinfo=timezone.utc)
    at_expiry = fetched_at + timedelta(hours=2)
    after_expiry = at_expiry + timedelta(microseconds=1)
    # DGA path: NO_DATA sample completeness is FRESH before TTL and STALE after.
    payloads = {
        "ttl.invalid": {"data": []},  # NO_DATA completeness fact
    }

    def providers_at(eval_now: datetime, *, seed: bool = True):
        return [
            _StaticProvider(
                "k01_compromise",
                lambda targets: ProviderResult(
                    "k01_compromise",
                    [
                        Observation(
                            ioc=targets[0].normalized,
                            scope=targets[0].ioc_type,
                            provider="k01_compromise",
                            kind="dga_classification",
                            status=ProviderStatus.SUCCESS,
                            freshness=Freshness.FRESH,
                            payload={"tags": ["dga"]},
                        )
                    ],
                    {targets[0].normalized: ProviderStatus.SUCCESS},
                    freshnesses={targets[0].normalized: Freshness.FRESH},
                ),
            ),
            _FactProvider(
                provider_cache,
                payloads,
                fetched_at=fetched_at,
                eval_now=eval_now,
                seed_on_miss=seed,
            ),
            _StaticProvider(
                "fdark",
                lambda targets: ProviderResult(
                    "fdark",
                    statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
                    freshnesses={t.normalized: Freshness.FRESH for t in targets},
                ),
            ),
            _StaticProvider(
                "pdns",
                lambda targets: ProviderResult(
                    "pdns",
                    statuses={t.normalized: ProviderStatus.NO_DATA for t in targets},
                    freshnesses={t.normalized: Freshness.FRESH for t in targets},
                ),
            ),
        ]

    bundle = read_input_bundle(None, ["ttl.invalid"])
    config = Config()

    uncached_before = run_unified_pipeline(
        bundle, providers_at(before, seed=True), config, ProviderContext(), now=before
    )
    uncached_at = run_unified_pipeline(
        bundle, providers_at(at_expiry, seed=False), config, ProviderContext(), now=at_expiry
    )
    uncached_after = run_unified_pipeline(
        bundle,
        providers_at(after_expiry, seed=False),
        config,
        ProviderContext(),
        now=after_expiry,
    )
    assert uncached_before.verdicts[0]["conclusion"] == "失活有效"
    assert uncached_at.verdicts[0]["conclusion"] == "失活有效"
    # After provider TTL, ioc_info NO_DATA becomes STALE → sample incomplete → 待复核.
    assert uncached_after.verdicts[0]["conclusion"] == "待复核"

    result_cache = AdjudicationResultCache(tmp_path / "rc")
    first = run_unified_pipeline(
        bundle,
        providers_at(before, seed=False),
        config,
        ProviderContext(),
        now=before,
        result_cache=result_cache,
    )
    assert first.verdicts[0]["conclusion"] == "失活有效"

    second = run_unified_pipeline(
        bundle,
        providers_at(at_expiry, seed=False),
        config,
        ProviderContext(),
        now=at_expiry,
        result_cache=result_cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.verdicts[0]["conclusion"] == uncached_at.verdicts[0]["conclusion"]

    third = run_unified_pipeline(
        bundle,
        providers_at(after_expiry, seed=False),
        config,
        ProviderContext(),
        now=after_expiry,
        result_cache=result_cache,
    )
    assert third.diagnostics.result_cache_hit == 0
    assert third.diagnostics.result_cache_miss_reasons.get("temporal_expired", 0) == 1
    assert third.verdicts[0]["conclusion"] == uncached_after.verdicts[0]["conclusion"]


# ── R3: dependency digests + sidecar hash-once ──────────────────────────────


def test_r3_raw_update_invalidates_only_changed_target(tmp_path):
    cache_root = tmp_path / "prov"
    result_root = tmp_path / "res"
    provider_cache = JsonlProviderCache(cache_root, "ioc_info", timedelta(days=7))
    result_cache = AdjudicationResultCache(result_root)
    payloads = {
        "a.invalid": _malicious_ioc_info_payload(
            "a.invalid", md5="b" * 32, time="2026-09-01 12:00:00"
        ),
        "b.invalid": _malicious_ioc_info_payload(
            "b.invalid", md5="c" * 32, time="2026-09-01 12:00:00"
        ),
    }
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    provider = _FactProvider(provider_cache, payloads, eval_now=now)
    bundle = read_input_bundle(None, ["a.invalid", "b.invalid"])

    first = run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=result_cache
    )
    assert first.diagnostics.result_cache_miss == 2
    by_ioc = {row["ioc"]: row for row in first.verdicts}
    assert by_ioc["a.invalid"]["conclusion"] == "存活有效"
    assert by_ioc["b.invalid"]["conclusion"] == "存活有效"

    # External writer appends new raw facts for A only (separate cache instance).
    writer = JsonlProviderCache(cache_root, "ioc_info", timedelta(days=7))
    a_target = bundle.targets[0]
    writer.put(
        a_target.original,
        {"data": []},
        {"request_ioc": a_target.original, "endpoint": "https://ioc-info.invalid"},
        fetched_at=datetime(2026, 9, 21, 10, 30, tzinfo=timezone.utc),
    )

    provider2 = _FactProvider(
        provider_cache, payloads, eval_now=now + timedelta(seconds=30), seed_on_miss=False
    )
    second = run_unified_pipeline(
        bundle,
        [provider2],
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=result_cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.diagnostics.result_cache_miss == 1
    assert provider2.calls == [["a.invalid"]]
    by_ioc2 = {row["ioc"]: row for row in second.verdicts}
    assert by_ioc2["a.invalid"]["conclusion"] == "待复核"
    assert by_ioc2["b.invalid"]["conclusion"] == "存活有效"

    # Genuine dependent-cache disappearance (synthetic shard rewrite; the
    # production cache intentionally has no delete API) invalidates only A.
    removed = _rewrite_cache_shard_without_key(
        writer,
        a_target.original,
        {"request_ioc": a_target.original, "endpoint": "https://ioc-info.invalid"},
    )
    assert removed is True
    assert (
        writer.entry_dependency(
            a_target.original,
            {"request_ioc": a_target.original, "endpoint": "https://ioc-info.invalid"},
        ).startswith("absent:")
    )
    # B's dependency still present.
    assert not writer.entry_dependency(
        bundle.targets[1].original,
        {
            "request_ioc": bundle.targets[1].original,
            "endpoint": "https://ioc-info.invalid",
        },
    ).startswith("absent:")

    provider3 = _FactProvider(
        provider_cache,
        {"a.invalid": payloads["a.invalid"]},
        eval_now=now + timedelta(minutes=2),
        seed_on_miss=True,
    )
    third = run_unified_pipeline(
        bundle,
        [provider3],
        Config(),
        ProviderContext(),
        now=now + timedelta(minutes=2),
        result_cache=result_cache,
    )
    assert third.diagnostics.result_cache_miss >= 1
    assert "a.invalid" in (provider3.calls[0] if provider3.calls else [])
    by_ioc3 = {row["ioc"]: row for row in third.verdicts}
    assert by_ioc3["a.invalid"]["conclusion"] == "存活有效"
    assert by_ioc3["b.invalid"]["conclusion"] == "存活有效"


def _rewrite_cache_shard_without_key(cache: JsonlProviderCache, ioc: str, params: dict) -> bool:
    """Test-only helper: rewrite temporary shards without one query key."""
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


def test_r3_host_scoped_and_fdark_variant_dependencies(tmp_path):
    """Host-scoped WHOIS and multi-variant FDark digests stay per-target."""
    whois_cache = JsonlProviderCache(tmp_path / "whois", "whois", timedelta(days=7))
    fdark_cache = JsonlProviderCache(tmp_path / "fdark", "fdark", timedelta(days=7))
    result_cache = AdjudicationResultCache(tmp_path / "rc")

    class _HostWhois:
        name = "whois"

        def __init__(self, cache, payloads):
            self.cache = cache
            self.payloads = payloads
            self.calls = []

        def supports(self, target):
            return True

        def cache_params(self, target):
            return {"host": target.host, "endpoint": "https://whois.invalid"}

        def collect(self, targets, context):
            self.calls.append([t.normalized for t in targets])
            statuses = {}
            for target in targets:
                raw = self.payloads.get(target.host, {"expiresDate": "2099-01-01"})
                self.cache.put(
                    target.host,
                    raw,
                    self.cache_params(target),
                    fetched_at=datetime(2026, 9, 21, 9, tzinfo=timezone.utc),
                )
                statuses[target.normalized] = ProviderStatus.NO_DATA
            return ProviderResult(self.name, statuses=statuses)

    whois_payloads = {"host-a.invalid": {"expiresDate": "2099-01-01"}}
    fdark_payloads = {
        ("http://host-a.invalid/a", "fast"): {"items": [1]},
        ("http://host-a.invalid/a", "slow"): {"items": [2]},
        ("http://host-b.invalid/b", "fast"): {"items": [3]},
        ("http://host-b.invalid/b", "slow"): {"items": [4]},
    }
    providers = [
        _HostWhois(whois_cache, whois_payloads),
        _MultiVariantCacheProvider(fdark_cache, fdark_payloads),
    ]
    bundle = read_input_bundle(
        None, ["http://host-a.invalid/a", "http://host-b.invalid/b"]
    )
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    first = run_unified_pipeline(
        bundle, providers, Config(), ProviderContext(), now=now, result_cache=result_cache
    )
    assert first.diagnostics.result_cache_miss == 2

    # Mutate only one FDark variant for A; B must remain a hit.
    a_target = bundle.targets[0]
    writer = JsonlProviderCache(tmp_path / "fdark", "fdark", timedelta(days=7))
    writer.put(
        a_target.original,
        {"items": [99]},
        {
            "endpoint": "https://fdark.invalid",
            "request_ioc": a_target.original,
            "strategy": "slow",
            "query": {"q": a_target.original, "mode": "slow"},
        },
        fetched_at=datetime(2026, 9, 21, 10, 30, tzinfo=timezone.utc),
    )
    providers2 = [
        _HostWhois(whois_cache, whois_payloads),
        _MultiVariantCacheProvider(fdark_cache, fdark_payloads),
    ]
    second = run_unified_pipeline(
        bundle,
        providers2,
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=result_cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert second.diagnostics.result_cache_miss == 1
    assert any("http://host-a.invalid/a" in call for call in providers2[1].calls)


def test_r3_unchanged_same_target_data_still_hits(tmp_path):
    cache_root = tmp_path / "prov"
    result_root = tmp_path / "res"
    provider_cache = JsonlProviderCache(cache_root, "ioc_info", timedelta(days=7))
    result_cache = AdjudicationResultCache(result_root)
    provider = _CacheWritingProvider(provider_cache, {"solo.invalid": {"data": [1]}})
    bundle = read_input_bundle(None, ["solo.invalid"])
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=result_cache
    )
    provider2 = _CacheWritingProvider(provider_cache, {"solo.invalid": {"data": [1]}})
    # Re-put identical content with same fetched_at shape via dependency of existing row.
    second = run_unified_pipeline(
        bundle,
        [provider2],
        Config(),
        ProviderContext(),
        now=now + timedelta(seconds=30),
        result_cache=result_cache,
    )
    assert second.diagnostics.result_cache_hit == 1
    assert provider2.calls == []


def test_r3_sidecar_hash_read_once_for_three_targets(tmp_path, monkeypatch):
    path = tmp_path / "side.jsonl"
    rows = []
    for name in ("one.invalid", "two.invalid", "three.invalid"):
        rows.append(
            json.dumps(
                {
                    "ioc": name,
                    "kind": "whois",
                    "status": "no_data",
                    "fetched_at": "2026-09-21T00:00:00+00:00",
                    "observed_at": "",
                    "payload": {},
                }
            )
        )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    provider = SidecarProvider("whois", path)
    bundle = read_input_bundle(None, ["one.invalid", "two.invalid", "three.invalid"])
    cache = AdjudicationResultCache(tmp_path / "rc")
    now = datetime(2026, 9, 21, 10, tzinfo=timezone.utc)

    original = Path.read_bytes
    reads = {"n": 0}

    def counted_read_bytes(self, *args, **kwargs):
        if self == path or self.resolve() == path.resolve():
            reads["n"] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", counted_read_bytes)
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    # Fingerprint once per target at lookup + once per miss at write-back, but
    # content hash must be memoized: expect a single sidecar byte read for hashing
    # (collect() uses read_text, not read_bytes).
    assert reads["n"] == 1


def test_r3_fingerprint_differs_when_raw_changes(tmp_path):
    cache = JsonlProviderCache(tmp_path, "ioc_info", timedelta(days=7))
    target = read_input_bundle(None, ["dep.invalid"]).targets[0]
    provider = _CacheWritingProvider(cache)
    before = result_cache_fingerprint(target, [], [provider], Config())
    cache.put(
        target.original,
        {"new": True},
        provider.cache_params(target),
        fetched_at=datetime(2026, 9, 21, 12, tzinfo=timezone.utc),
    )
    after = result_cache_fingerprint(target, [], [provider], Config())
    other = read_input_bundle(None, ["other.invalid"]).targets[0]
    other_fp = result_cache_fingerprint(other, [], [provider], Config())
    assert before != after
    # Unrelated IOC fingerprint is independent of A's raw row (absence vs presence
    # of its own keys only).
    assert other_fp != after
