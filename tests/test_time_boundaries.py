"""Shared time parsing, comparison, freshness, and invalid-value boundaries."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.adjudicator import _has_expired_whois, _has_threat_residue, adjudicate
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.normalize import merge_records
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
from ioc_rejudge.parser import (
    compare_datetimes,
    is_fresh,
    is_recent,
    latest_datetime,
    normalize_datetime,
    parse_time,
)
from ioc_rejudge.pipeline import _latest_observed_time
from ioc_rejudge.profile import extract_profile
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.result_cache import AdjudicationResultCache
from ioc_rejudge.providers.fdark import _sample_time
from ioc_rejudge.providers.pdns import _activity_time
from tests.fixtures import build_hash_entry, build_record
from ioc_rejudge.config import Config


NOW = datetime(2026, 7, 24, 12, 0, 0)


def test_parse_time_accepts_iso_offsets_and_canonical_comparison_is_utc():
    aware = parse_time("2026-07-24T12:00:00+08:00")
    naive = parse_time("2026-07-24 04:00:00")

    assert aware is not None
    assert compare_datetimes(aware, naive) == 0
    assert normalize_datetime(aware) == naive
    assert latest_datetime([aware, naive]) == naive


def test_invalid_time_values_are_ignored_by_shared_helpers():
    for value in (None, "", "not-a-time", True, float("nan"), "2026-13-01"):
        assert parse_time(value) is None
        assert normalize_datetime(value) is None
        assert compare_datetimes(value, NOW) is None


def test_recent_and_fresh_require_non_future_values_and_include_exact_boundary():
    assert is_recent(NOW - timedelta(days=30), NOW, timedelta(days=30))
    assert not is_recent(NOW - timedelta(days=30, microseconds=1), NOW, timedelta(days=30))
    assert not is_recent(NOW + timedelta(seconds=1), NOW, timedelta(days=30))

    fetched = NOW - timedelta(days=7)
    assert is_fresh(fetched, NOW, timedelta(days=7))
    assert not is_fresh(fetched - timedelta(microseconds=1), NOW, timedelta(days=7))
    assert not is_fresh(NOW + timedelta(seconds=1), NOW, timedelta(days=7))
    assert not is_fresh("invalid", NOW, timedelta(days=7))


def test_merge_records_orders_mixed_aware_and_naive_record_times():
    records = [
        build_record(
            "mixed-time.invalid",
            updatetime="2026-07-24T12:00:00+08:00",
            flint={"last_seen": "2026-07-24T12:00:00+08:00", "marker": "old"},
        ),
        build_record(
            "mixed-time.invalid",
            updatetime="2026-07-24 05:00:00",
            flint={"last_seen": "2026-07-24 05:00:00", "marker": "new"},
        ),
    ]

    dossier = merge_records(records)

    assert dossier.record_snapshots[-1].raw["flint"]["marker"] == "new"
    assert dossier.flint["marker"] == "new"


def test_pipeline_latest_observed_time_is_order_independent_for_mixed_times():
    observations = [
        Observation(
            ioc="mixed-time.invalid",
            scope="domain",
            provider="one",
            kind="pdns_activity",
            status=ProviderStatus.SUCCESS,
            observed_at=datetime(2026, 7, 24, 12, tzinfo=timezone(timedelta(hours=8))),
            freshness=Freshness.FRESH,
            payload={},
        ),
        Observation(
            ioc="mixed-time.invalid",
            scope="domain",
            provider="two",
            kind="pdns_activity",
            status=ProviderStatus.SUCCESS,
            observed_at=datetime(2026, 7, 24, 5),
            freshness=Freshness.FRESH,
            payload={},
        ),
    ]

    latest = _latest_observed_time(observations, {"pdns_activity"}, ())

    assert latest == datetime(2026, 7, 24, 5)


def test_evidence_accepts_aware_activity_times_with_injected_now():
    dossier = merge_records([
        build_record(
            "aware-activity.invalid",
            level=70,
            hash_entries=[build_hash_entry(
                time="2026-07-24T11:00:00+08:00",
                level=70,
            )],
            flint={"last_seen": "2026-07-24T11:00:00+08:00"},
            dtree=[{"key": "dns.invalid", "last": "2026-07-24T11:00:00+08:00"}],
        )
    ])

    extract_evidence(dossier, Config(activity_window_days=1), now=NOW)

    assert dossier.evidence_b


def test_dga_ignores_future_activity_time():
    verdict = adjudicate_dga(
        "future-activity.invalid",
        DgaFacts(
            sample_check_complete=True,
            has_malicious_sample=True,
            malicious_sample_times=[NOW + timedelta(days=1)],
        ),
        now=NOW,
    )

    assert verdict.activity_status == "失活"


def test_adjudicator_uses_fixed_now_for_aware_whois_and_flint_boundaries():
    dossier = merge_records([build_record(
        "boundary-adjudicator.invalid",
        whois={"expiresDate": "2026-07-24T08:00:00+08:00"},
        flint={
            "last_seen": "2026-07-24T11:00:00+08:00",
            "marker": "aware",
        },
        dtree=[{"key": "related.invalid", "last": "2026-07-23 04:00:00"}],
    )])

    assert not _has_expired_whois(dossier, now=NOW)
    assert _has_threat_residue(
        dossier,
        Config(activity_window_days=1),
        now=NOW,
    )
    assert adjudicate(dossier, Config(), now=NOW).conclusion is not None


def test_future_whois_creation_date_is_not_a_new_domain():
    dossier = merge_records([build_record(
        "future-registration.invalid",
        whois={"createdDate": "2026-07-25T00:00:00+08:00"},
    )])

    extract_profile(dossier, Config(), now=NOW)

    assert "age_days" not in dossier.profile.domain
    assert dossier.profile.domain.get("is_new") is not True


def test_cache_marks_future_fetch_as_stale_and_handles_mixed_times(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", timedelta(hours=1))
    fetched = NOW.replace(tzinfo=timezone.utc)
    cache.put("cache-time.invalid", {"value": 1}, fetched_at=fetched)

    fresh = cache.get("cache-time.invalid", now=NOW + timedelta(minutes=30))
    assert fresh is not None and fresh.fresh

    cache.put(
        "future-cache-time.invalid",
        {"value": 2},
        fetched_at=(NOW + timedelta(minutes=1)).replace(tzinfo=timezone.utc),
    )
    future = cache.get("future-cache-time.invalid", now=NOW)
    assert future is not None and future.stale


def test_result_cache_marks_future_fetch_as_stale(tmp_path):
    cache = AdjudicationResultCache(tmp_path, timedelta(hours=1))
    cache.put(
        "result-cache-time.invalid",
        "fingerprint",
        {"ioc": "result-cache-time.invalid", "conclusion": "待复核"},
        fetched_at=(NOW + timedelta(minutes=1)).replace(tzinfo=timezone.utc),
    )

    entry, reason = cache.lookup(
        "result-cache-time.invalid", "fingerprint", now=NOW
    )

    assert entry is not None and not entry.fresh
    assert reason == "stale"


def test_provider_epoch_parsers_reject_negative_values():
    assert _activity_time(-1) is None
    assert _sample_time(-1) is None
