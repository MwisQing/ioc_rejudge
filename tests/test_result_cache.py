"""Completed IOC adjudication result cache tests."""

from datetime import datetime, timedelta, timezone
import json

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import ProviderStatus
from ioc_rejudge import pipeline
from ioc_rejudge.pipeline import result_cache_fingerprint, run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.result_cache import AdjudicationResultCache


class CountingProvider:
    name = "counting"

    def __init__(self):
        self.calls = []

    def supports(self, target):
        return True

    def collect(self, targets, context):
        self.calls.append([target.normalized for target in targets])
        return ProviderResult(
            self.name,
            statuses={
                target.normalized: ProviderStatus.NO_DATA for target in targets
            },
        )


class SelectiveProvider(CountingProvider):
    def supports(self, target):
        return target.normalized != "cached.invalid"


def test_adjudication_contract_version_changes_fingerprint(monkeypatch):
    target = read_input_bundle(None, ["contract.invalid"]).targets[0]
    provider = CountingProvider()
    before = result_cache_fingerprint(target, [], [provider], Config())

    monkeypatch.setattr(
        pipeline,
        "ADJUDICATION_CACHE_CONTRACT",
        pipeline.ADJUDICATION_CACHE_CONTRACT + 1,
    )
    after = result_cache_fingerprint(target, [], [provider], Config())

    assert before != after


def test_second_identical_run_reuses_complete_rows_without_provider_calls(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    bundle = read_input_bundle(None, ["one.invalid", "two.invalid"])
    provider = CountingProvider()
    now = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)

    first = run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    provider.calls.clear()
    second = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(),
        now=now + timedelta(days=1),
        result_cache=cache,
    )

    assert second.verdicts == first.verdicts
    assert provider.calls == []
    assert second.diagnostics.result_cache_hit == 2
    assert second.diagnostics.result_cache_miss == 0
    shards = list(
        (tmp_path / ".cache_adjudication_results").glob("cache_*.jsonl")
    )
    assert [path.name for path in shards] == ["cache_2026-07-28.jsonl"]
    decoded = [json.loads(line) for line in shards[0].read_text(encoding="utf-8").splitlines()]
    assert {row["result"]["ioc"] for row in decoded} == {
        "one.invalid", "two.invalid"
    }


def test_expired_refresh_and_config_change_each_recompute(tmp_path):
    cache = AdjudicationResultCache(tmp_path, ttl=timedelta(days=7))
    bundle = read_input_bundle(None, ["recompute.invalid"])
    provider = CountingProvider()
    now = datetime(2026, 7, 20, tzinfo=timezone.utc)
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    provider.calls.clear()

    expired = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(),
        now=now + timedelta(days=7, microseconds=1),
        result_cache=cache,
    )
    assert expired.diagnostics.result_cache_miss == 1
    assert provider.calls == [["recompute.invalid"]]

    provider.calls.clear()
    refreshed = run_unified_pipeline(
        bundle,
        [provider],
        Config(),
        ProviderContext(refresh=True),
        now=now + timedelta(days=1),
        result_cache=cache,
    )
    assert refreshed.diagnostics.result_cache_hit == 0
    assert provider.calls == [["recompute.invalid"]]

    provider.calls.clear()
    changed = run_unified_pipeline(
        bundle,
        [provider],
        Config(hash_malicious_level=41),
        ProviderContext(),
        now=now + timedelta(days=1),
        result_cache=cache,
    )
    assert changed.diagnostics.result_cache_miss == 1
    assert provider.calls == [["recompute.invalid"]]


def test_bad_cache_line_is_diagnostic_and_valid_latest_row_still_hits(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    result = {"ioc": "broken.invalid", "conclusion": "待复核"}
    cache.put(
        "broken.invalid",
        "fingerprint",
        result,
        fetched_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
    )
    path = next(cache.cache_dir.glob("cache_*.jsonl"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{bad json\n")

    entry = cache.get(
        "broken.invalid",
        "fingerprint",
        now=datetime(2026, 7, 29, tzinfo=timezone.utc),
    )

    assert entry is not None and entry.fresh is True
    assert entry.result == result
    assert any("bad JSON" in message for message in cache.diagnostics)


def test_normalized_ioc_hit_preserves_current_original_spelling(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    provider = CountingProvider()
    first_bundle = read_input_bundle(None, ["Case.INVALID"])
    second_bundle = read_input_bundle(None, ["case.invalid"])
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    first = run_unified_pipeline(
        first_bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    provider.calls.clear()
    second = run_unified_pipeline(
        second_bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )

    assert first.verdicts[0]["original_ioc"] == "Case.INVALID"
    assert second.verdicts[0]["original_ioc"] == "case.invalid"
    assert second.diagnostics.result_cache_hit == 1
    assert provider.calls == []


def test_partial_hit_only_collects_uncached_targets(tmp_path):
    cache = AdjudicationResultCache(tmp_path)
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    first_provider = CountingProvider()
    cached_bundle = read_input_bundle(None, ["cached.invalid"])
    run_unified_pipeline(
        cached_bundle,
        [first_provider],
        Config(),
        ProviderContext(),
        now=now,
        result_cache=cache,
    )

    provider = CountingProvider()
    mixed = run_unified_pipeline(
        read_input_bundle(None, ["cached.invalid", "new.invalid"]),
        [provider],
        Config(),
        ProviderContext(),
        now=now,
        result_cache=cache,
    )

    assert [row["ioc"] for row in mixed.verdicts] == [
        "cached.invalid", "new.invalid"
    ]
    assert mixed.diagnostics.result_cache_hit == 1
    assert mixed.diagnostics.result_cache_miss == 1
    assert provider.calls == [["new.invalid"]]


def test_provider_error_result_is_retried_instead_of_cached(tmp_path):
    class ErrorProvider(CountingProvider):
        def collect(self, targets, context):
            self.calls.append([target.normalized for target in targets])
            return ProviderResult(
                self.name,
                statuses={
                    target.normalized: ProviderStatus.ERROR for target in targets
                },
                errors=["temporary failure"],
            )

    cache = AdjudicationResultCache(tmp_path)
    provider = ErrorProvider()
    bundle = read_input_bundle(None, ["retry.invalid"])
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )
    run_unified_pipeline(
        bundle, [provider], Config(), ProviderContext(), now=now, result_cache=cache
    )

    assert provider.calls == [["retry.invalid"], ["retry.invalid"]]
    assert not list(cache.cache_dir.glob("cache_*.jsonl"))


def test_many_result_cache_lookups_read_each_shard_once(tmp_path, monkeypatch):
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    writer = AdjudicationResultCache(tmp_path)
    for index in range(200):
        ioc = f"bulk-{index}.invalid"
        writer.put(ioc, f"fingerprint-{index}", {"ioc": ioc}, fetched_at=now)

    cache = AdjudicationResultCache(tmp_path)
    cache_path = next(cache.cache_dir.glob("cache_*.jsonl"))
    original = type(cache_path).read_text
    reads = 0

    def counted_read_text(path, *args, **kwargs):
        nonlocal reads
        if path == cache_path:
            reads += 1
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(cache_path), "read_text", counted_read_text)
    for index in range(200):
        entry = cache.get(
            f"bulk-{index}.invalid",
            f"fingerprint-{index}",
            now=now + timedelta(days=1),
        )
        assert entry is not None and entry.fresh

    assert reads == 1


def test_result_cache_lookup_explains_miss_without_exposing_fingerprint(tmp_path):
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    cache = AdjudicationResultCache(tmp_path, ttl=timedelta(days=1))
    cache.put(
        "known.invalid",
        "original-secret-fingerprint",
        {"ioc": "known.invalid"},
        fetched_at=now,
    )

    missing, missing_reason = cache.lookup("missing.invalid", "any", now=now)
    changed, changed_reason = cache.lookup(
        "known.invalid", "changed-secret-fingerprint", now=now
    )
    stale, stale_reason = cache.lookup(
        "known.invalid",
        "original-secret-fingerprint",
        now=now + timedelta(days=2),
    )

    assert missing is None and missing_reason == "missing"
    assert changed is None and changed_reason == "fingerprint_mismatch"
    assert stale is not None and stale.fresh is False and stale_reason == "stale"
    assert "secret-fingerprint" not in " ".join(cache.diagnostics)


def test_interleaved_result_cache_lookup_and_put_does_not_rescan_shard(
    tmp_path, monkeypatch
):
    cache = AdjudicationResultCache(tmp_path)
    cache.get("initial-miss.invalid", "initial")
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    cache_path = cache._path_for(now)
    original = type(cache_path).read_text
    reads = 0

    def counted_read_text(path, *args, **kwargs):
        nonlocal reads
        if path == cache_path:
            reads += 1
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(cache_path), "read_text", counted_read_text)
    for index in range(100):
        ioc = f"interleaved-{index}.invalid"
        fingerprint = f"fingerprint-{index}"
        assert cache.get(ioc, fingerprint, now=now) is None
        cache.put(ioc, fingerprint, {"ioc": ioc}, fetched_at=now)

    assert reads == 0
