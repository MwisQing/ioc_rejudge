"""IOC Info live-provider contract tests with injected transport/cache."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.ioc_info import (
    IOCInfoProvider,
    build_payload,
    normalize_payload,
)
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        self.calls.append({
            "url": url,
            "headers": headers,
            "body": body,
            "timeout": timeout,
        })
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value


def _targets(*values):
    return read_input_bundle(None, list(values)).targets


def _provider(tmp_path, responses, *, ttl=timedelta(days=1), max_attempts=10):
    settings = ProviderSettings(
        name="ioc_info",
        base_url="https://ioc-info.invalid/api/v1/ioc/info",
        secrets={"Api-Key": "test-secret"},
        timeout=9,
        ttl=ttl,
    )
    transport = FakeTransport(responses)
    cache = JsonlProviderCache(tmp_path, "ioc_info", ttl)
    provider = IOCInfoProvider(
        settings,
        transport=transport,
        cache=cache,
        max_attempts=max_attempts,
        sleep_fn=lambda _: None,
        now_fn=lambda: NOW,
    )
    return provider, transport, cache


def test_build_payload_preserves_target_original_values():
    targets = _targets("Example.INVALID", "https://example.invalid/a")
    assert build_payload(targets) == {
        "params": ["Example.INVALID", "https://example.invalid/a"]
    }


def test_normalize_payload_supports_dict_and_list_shapes():
    requested = ["a.invalid", "b.invalid"]
    assert normalize_payload(requested, {
        "data": {"a.invalid": [{"id": 1}], "b.invalid": []},
    }) == {"a.invalid": [{"id": 1}], "b.invalid": []}
    assert normalize_payload(requested, {
        "data": [
            {"ioc": "a.invalid", "data": [{"id": 1}]},
            {"key": "b.invalid", "id": 2},
        ],
    }) == {"a.invalid": [{"id": 1}], "b.invalid": [{"key": "b.invalid", "id": 2}]}


def test_collect_success_emits_one_observation_per_source_record(tmp_path):
    provider, transport, _ = _provider(tmp_path, [{
        "data": {
            "a.invalid": [
                {"key": "a.invalid", "id": 1, "updatetime": "2026-07-20 10:00:00"},
                {"key": "a.invalid", "id": 2},
            ],
        },
    }])
    target = _targets("a.invalid")[0]
    result = provider.collect([target], ProviderContext())

    assert result.statuses == {"a.invalid": ProviderStatus.SUCCESS}
    assert len(result.observations) == 2
    assert [obs.kind for obs in result.observations] == ["ioc_info_record"] * 2
    assert [obs.payload["id"] for obs in result.observations] == [1, 2]
    assert all(obs.provider == "ioc_info" for obs in result.observations)
    assert all(obs.fetched_at == NOW for obs in result.observations)
    assert result.observations[0].observed_at == datetime(2026, 7, 20, 10, 0)
    assert all(obs.freshness == Freshness.FRESH for obs in result.observations)
    assert all(obs.raw_ref.startswith("cache:ioc_info:") for obs in result.observations)
    assert transport.calls[0]["body"] == {"params": ["a.invalid"]}


def test_partial_empty_retries_only_empty_ioc(tmp_path):
    provider, transport, _ = _provider(tmp_path, [
        {"data": {"a.invalid": [{"id": 1}], "b.invalid": []}},
        {"data": {"b.invalid": [{"id": 2}]}},
    ])
    result = provider.collect(_targets("a.invalid", "b.invalid"), ProviderContext())
    assert result.statuses == {
        "a.invalid": ProviderStatus.SUCCESS,
        "b.invalid": ProviderStatus.SUCCESS,
    }
    assert [call["body"]["params"] for call in transport.calls] == [
        ["a.invalid", "b.invalid"],
        ["b.invalid"],
    ]


def test_successful_empty_data_retries_ten_times_then_no_data(tmp_path):
    provider, transport, cache = _provider(
        tmp_path,
        [{"data": {}} for _ in range(10)],
    )
    target = _targets("empty.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert len(transport.calls) == 10
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert result.observations == []
    cached = cache.get(
        target.original,
        provider.cache_params(target),
        now=NOW,
    )
    assert cached is not None and cached.raw == {"data": {}}


def test_authentication_http_error_is_error_without_retry(tmp_path):
    error = TransportError("http", "HTTP 401 for endpoint", status_code=401)
    provider, transport, _ = _provider(tmp_path, [error])
    targets = _targets("a.invalid", "b.invalid")
    result = provider.collect(targets, ProviderContext())
    assert len(transport.calls) == 1
    assert set(result.statuses.values()) == {ProviderStatus.ERROR}
    assert result.observations == []
    assert result.errors == ["HTTP 401 for endpoint"]


def test_transport_json_error_is_error_not_no_data(tmp_path):
    provider, _, _ = _provider(
        tmp_path,
        [TransportError("json_decode", "invalid JSON", status_code=200)],
    )
    target = _targets("a.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert result.errors == ["invalid JSON"]


def test_all_fresh_cache_hits_make_no_request(tmp_path):
    provider, transport, cache = _provider(tmp_path, [])
    targets = _targets("a.invalid", "b.invalid")
    for index, target in enumerate(targets):
        cache.put(
            target.original,
            {"data": {target.original: [{"key": target.normalized, "id": index}]}},
            provider.cache_params(target),
            fetched_at=NOW,
        )
    result = provider.collect(targets, ProviderContext())
    assert transport.calls == []
    assert result.cache_hits == 2
    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}


def test_refresh_bypasses_fresh_cache_read_and_replaces_result(tmp_path):
    provider, transport, cache = _provider(
        tmp_path,
        [{"data": {"a.invalid": [{"key": "a.invalid", "id": "live"}]}}],
    )
    target = _targets("a.invalid")[0]
    cache.put(
        target.original,
        {"records": [{"key": target.normalized, "id": "cached"}]},
        provider.cache_params(target),
        fetched_at=NOW,
    )
    result = provider.collect([target], ProviderContext(refresh=True))
    assert len(transport.calls) == 1
    assert result.cache_hits == 0
    assert result.observations[0].payload["id"] == "live"


def test_offline_stale_cache_is_returned_as_stale_without_request(tmp_path):
    provider, transport, cache = _provider(tmp_path, [], ttl=timedelta(hours=1))
    target = _targets("a.invalid")[0]
    cache.put(
        target.original,
        {"data": {target.original: [{"key": target.normalized, "id": "stale"}]}},
        provider.cache_params(target),
        fetched_at=NOW - timedelta(days=2),
    )
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.cache_hits == 1
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.freshnesses[target.normalized] == Freshness.STALE
    assert result.observations[0].freshness == Freshness.STALE


def test_offline_stale_empty_cache_marks_no_data_incomplete(tmp_path):
    provider, transport, cache = _provider(tmp_path, [], ttl=timedelta(hours=1))
    target = _targets("empty.invalid")[0]
    cache.put(
        target.original,
        {"data": {target.original: []}},
        provider.cache_params(target),
        fetched_at=NOW - timedelta(days=2),
    )
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert result.freshnesses[target.normalized] == Freshness.STALE


def test_offline_cache_miss_is_error_not_no_data(tmp_path):
    provider, transport, _ = _provider(tmp_path, [])
    target = _targets("missing.invalid")[0]
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert "offline cache miss" in result.errors[0]
