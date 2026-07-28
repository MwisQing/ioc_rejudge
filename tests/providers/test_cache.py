"""Append-only provider cache contract tests."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from ioc_rejudge.providers.cache import JsonlProviderCache


def test_cache_key_is_stable_normalized_and_provider_scoped(tmp_path):
    first = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    second = JsonlProviderCache(tmp_path, "pdns", ttl=timedelta(days=1))
    key = first.key("Example.INVALID", {"include": ["a", "b"], "page": 1})
    assert key == first.key(
        "example.invalid",
        {"page": 1, "include": ["a", "b"]},
    )
    assert key != second.key(
        "example.invalid",
        {"page": 1, "include": ["a", "b"]},
    )
    assert "example.invalid" not in key
    assert len(key) == 64


def test_cache_key_includes_complete_query_shape(tmp_path):
    cache = JsonlProviderCache(tmp_path, "fdark", ttl=timedelta(days=1))
    first = cache.key(
        "https://example.invalid/a",
        {"proto": "ssl", "http_path": "/a"},
    )
    second = cache.key(
        "https://example.invalid/a",
        {"domain": "example.invalid"},
    )
    third = cache.key(
        "https://example.invalid/b",
        {"proto": "ssl", "http_path": "/b"},
    )
    assert len({first, second, third}) == 3


def test_cache_put_get_latest_and_append_only(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    cache.put(
        "example.invalid",
        {"value": "first"},
        fetched_at=datetime(2026, 7, 22, 12, 0, 0),
    )
    first_text = cache.path.read_text(encoding="utf-8")
    cache.put(
        "example.invalid",
        {"value": "second"},
        fetched_at=datetime(2026, 7, 22, 13, 0, 0),
    )
    text = cache.path.read_text(encoding="utf-8")
    assert text.startswith(first_text)
    assert len(text.splitlines()) == 2
    entry = cache.get("example.invalid", now=datetime(2026, 7, 22, 13, 0, 0))
    assert entry is not None
    assert entry.raw == {"value": "second"}
    assert entry.fresh is True
    assert entry.stale is False
    assert cache.path == (
        tmp_path / ".cache_whois" / "cache_2026-07-22.jsonl"
    )
    assert not (tmp_path / "whois.jsonl").exists()


def test_cache_is_provider_scoped_and_rotates_by_fetch_date(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=7))
    cache.put(
        "example.invalid",
        {"value": "day-one"},
        fetched_at=datetime(2026, 7, 22, 23, 59, tzinfo=timezone.utc),
    )
    cache.put(
        "example.invalid",
        {"value": "day-two"},
        fetched_at=datetime(2026, 7, 23, 0, 1, tzinfo=timezone.utc),
    )

    assert sorted(path.name for path in cache.provider_dir.glob("*.jsonl")) == [
        "cache_2026-07-22.jsonl",
        "cache_2026-07-23.jsonl",
    ]
    entry = cache.get(
        "example.invalid",
        now=datetime(2026, 7, 23, 0, 2, tzinfo=timezone.utc),
    )
    assert entry is not None and entry.raw == {"value": "day-two"}


def test_cache_ttl_equality_is_fresh_and_one_microsecond_later_is_stale(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    fetched = datetime(2026, 7, 22, 12, 0, 0)
    cache.put("example.invalid", {"code": 200}, fetched_at=fetched)

    boundary = cache.get(
        "example.invalid",
        now=fetched + timedelta(days=1),
    )
    stale = cache.get(
        "example.invalid",
        now=fetched + timedelta(days=1, microseconds=1),
    )
    assert boundary is not None and boundary.fresh is True
    assert stale is not None and stale.fresh is False and stale.stale is True


def test_cache_handles_mixed_naive_and_aware_times(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(hours=1))
    cache.put(
        "example.invalid",
        {"code": 200},
        fetched_at=datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc),
    )
    entry = cache.get(
        "example.invalid",
        now=datetime(2026, 7, 24, 12, 30),
    )
    assert entry is not None and entry.fresh is True


def test_corrupt_lines_are_diagnostic_and_do_not_hide_valid_latest_entry(tmp_path):
    cache = JsonlProviderCache(tmp_path, "pdns", ttl=timedelta(days=1))
    cache.put("example.invalid", {"seq": 1}, fetched_at=datetime(2026, 7, 24))
    with cache.path.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
        handle.write(json.dumps({"key": "missing-fields"}) + "\n")
    cache.put("example.invalid", {"seq": 2}, fetched_at=datetime(2026, 7, 24, 1))

    entry = cache.get("example.invalid", now=datetime(2026, 7, 24, 2))
    assert entry is not None
    assert entry.raw == {"seq": 2}
    assert len(cache.diagnostics) == 2
    assert any("bad JSON" in message for message in cache.diagnostics)
    assert any("missing required fields" in message for message in cache.diagnostics)


def test_concurrent_appends_across_cache_instances_keep_every_line_valid(tmp_path):
    caches = [
        JsonlProviderCache(tmp_path, "fdark", ttl=timedelta(days=1))
        for _ in range(4)
    ]

    def write(index):
        caches[index % len(caches)].put(
            f"ioc-{index}.invalid",
            {"index": index},
            params={"query": index},
            fetched_at=datetime(2026, 7, 24, 12, 0),
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(write, range(200)))

    lines = caches[0].path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 200
    decoded = [json.loads(line) for line in lines]
    assert {row["raw"]["index"] for row in decoded} == set(range(200))
    for index in range(200):
        entry = caches[0].get(
            f"ioc-{index}.invalid",
            params={"query": index},
            now=datetime(2026, 7, 24, 12, 1),
        )
        assert entry is not None and entry.raw["index"] == index


def test_sensitive_mapping_values_are_redacted_before_disk(tmp_path):
    sentinel = "SENTINEL_CACHE_SECRET_91c2"
    cache = JsonlProviderCache(tmp_path, "ioc_info", ttl=timedelta(days=1))
    cache.put(
        "example.invalid",
        {"data": [], "Authorization": f"Bearer {sentinel}"},
        params={"Api-Key": sentinel, "query": "example.invalid"},
        fetched_at=datetime(2026, 7, 24),
    )
    text = cache.path.read_text(encoding="utf-8")
    assert sentinel not in text
    assert "[REDACTED]" in text


def test_cache_miss_returns_none_and_empty_diagnostics(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    assert cache.get("missing.invalid") is None
    assert cache.diagnostics == []
