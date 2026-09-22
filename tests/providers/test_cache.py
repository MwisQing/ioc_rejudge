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


def test_put_secret_values_redact_persisted_and_returned_fields(tmp_path):
    value_sentinel = "SENTINEL_CACHE_VALUE_4d7e"
    key_sentinel = "SENTINEL_CACHE_KEYNAME_2b9a"
    cache = JsonlProviderCache(tmp_path, "fdark", ttl=timedelta(days=1))
    params = {"note": value_sentinel, f"{key_sentinel}-token": "x"}
    expected_key = cache.key("example.invalid", params)
    entry = cache.put(
        "example.invalid",
        {"message": f"echo {value_sentinel}", "keep": "SAFE"},
        params,
        fetched_at=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
        secret_values=(value_sentinel,),
    )
    # Key is computed from the original params before redaction.
    assert entry.key == expected_key
    # Returned entry fields are value- and key-name-sanitized.
    assert entry.params["note"] == "[REDACTED]"
    assert entry.params[f"{key_sentinel}-token"] == "[REDACTED]"
    assert value_sentinel not in str(entry.raw)
    disk = cache.path.read_text(encoding="utf-8")
    assert value_sentinel not in disk
    # Sensitive key names keep their name but lose the value on disk.
    assert f"{key_sentinel}-token" in disk
    assert "SAFE" in disk
    # get() with the original params still finds the row.
    replay = cache.get(
        "example.invalid",
        params,
        now=datetime(2026, 9, 21, 12, 30, tzinfo=timezone.utc),
    )
    assert replay is not None
    assert replay.raw == {"message": "echo [REDACTED]", "keep": "SAFE"}


def test_concurrent_writes_with_different_sentinels_redact_persisted_bytes(tmp_path):
    sentinels = [f"SENTINEL_CONCURRENT_{index}_{0xDEAD:x}" for index in range(6)]
    caches = [
        JsonlProviderCache(tmp_path, "ioc_info", ttl=timedelta(days=1))
        for _ in range(len(sentinels))
    ]

    def write(index):
        sentinel = sentinels[index]
        entry = caches[index].put(
            f"concurrent-{index}.invalid",
            {"message": f"echo {sentinel}", "keep": "SAFE_KEEP"},
            {"note": sentinel, "index": index},
            fetched_at=datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc),
            secret_values=(sentinel,),
        )
        assert entry.params["note"] == "[REDACTED]"
        assert sentinel not in str(entry.raw)

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(write, range(len(sentinels))))

    disk = caches[0].path.read_text(encoding="utf-8")
    assert len(disk.splitlines()) == len(sentinels)
    for sentinel in sentinels:
        assert sentinel not in disk
    assert "SAFE_KEEP" in disk
    for index, sentinel in enumerate(sentinels):
        entry = caches[0].get(
            f"concurrent-{index}.invalid",
            {"note": sentinel, "index": index},
            now=datetime(2026, 7, 24, 12, 1, tzinfo=timezone.utc),
        )
        assert entry is not None
        assert entry.raw == {"message": "echo [REDACTED]", "keep": "SAFE_KEEP"}
        assert entry.params["note"] == "[REDACTED]"


def test_cache_miss_returns_none_and_empty_diagnostics(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    assert cache.get("missing.invalid") is None
    assert cache.diagnostics == []


def test_many_provider_cache_lookups_read_each_shard_once(tmp_path, monkeypatch):
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    writer = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=7))
    for index in range(200):
        writer.put(f"bulk-{index}.invalid", {"index": index}, fetched_at=now)

    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=7))
    cache_path = next(cache.provider_dir.glob("cache_*.jsonl"))
    original = JsonlProviderCache._read_shard_bytes
    reads = 0

    def counted_read_shard(self, path):
        nonlocal reads
        if path == cache_path:
            reads += 1
        return original(self, path)

    monkeypatch.setattr(JsonlProviderCache, "_read_shard_bytes", counted_read_shard)
    for index in range(200):
        entry = cache.get(f"bulk-{index}.invalid", now=now + timedelta(days=1))
        assert entry is not None and entry.raw == {"index": index}

    assert reads == 1


def test_interleaved_provider_cache_get_and_put_does_not_rescan_shard(
    tmp_path, monkeypatch
):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=7))
    cache.get("initial-miss.invalid")
    cache_path = cache._path_for(datetime(2026, 7, 28, tzinfo=timezone.utc))
    original = JsonlProviderCache._read_shard_bytes
    reads = 0

    def counted_read_shard(self, path):
        nonlocal reads
        if path == cache_path:
            reads += 1
        return original(self, path)

    monkeypatch.setattr(JsonlProviderCache, "_read_shard_bytes", counted_read_shard)
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    for index in range(100):
        ioc = f"interleaved-{index}.invalid"
        assert cache.get(ioc, now=now) is None
        cache.put(ioc, {"index": index}, fetched_at=now)

    assert reads == 0


def test_cache_index_does_not_retain_raw_payloads(tmp_path):
    cache = JsonlProviderCache(tmp_path, "whois", ttl=timedelta(days=1))
    cache.put(
        "example.invalid",
        {"blob": "x" * 100},
        fetched_at=datetime(2026, 7, 22, 12, 0, 0),
    )
    assert cache.get("example.invalid", now=datetime(2026, 7, 22, 12, 0, 0)) is not None
    assert cache._index
    for hit in cache._index.values():
        assert getattr(hit, "raw", None) is None
        assert isinstance(hit.offset, int)
