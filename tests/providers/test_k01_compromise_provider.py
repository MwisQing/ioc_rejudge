"""K01 compromise classification provider and route-safety tests."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus, Route
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.k01_compromise import (
    K01CompromiseProvider,
    build_batch_payload,
)
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.routing import select_route


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


def _provider(
    tmp_path,
    responses,
    *,
    ignore_port=False,
    ignore_url=False,
    ignore_top=False,
    ttl=timedelta(days=7),
):
    settings = ProviderSettings(
        name="k01_compromise",
        base_url="https://k01.invalid",
        secrets={"Api-Key": "test-key"},
        timeout=8,
        ttl=ttl,
    )
    transport = FakeTransport(responses)
    cache = JsonlProviderCache(tmp_path, "k01_compromise", ttl)
    provider = K01CompromiseProvider(
        settings,
        transport=transport,
        cache=cache,
        ignore_port=ignore_port,
        ignore_url=ignore_url,
        ignore_top=ignore_top,
        now_fn=lambda: NOW,
    )
    return provider, transport, cache


def _response(ioc, tags, *, level="malicious", extra_hits=None):
    hits = [{"ioc_host": ioc, "tags": tags}]
    hits.extend(extra_hits or [])
    return {
        "status": 10000,
        "data": {ioc: {"level": level, "data": hits}},
    }


def test_build_batch_payload_preserves_all_five_ioc_shapes_and_exact_flags():
    targets = _targets(
        "example.invalid",
        "https://example.invalid/a",
        "example.invalid:8443",
        "192.0.2.1",
        "192.0.2.1:443",
    )
    assert build_batch_payload(
        targets,
        ignore_port=True,
        ignore_url=False,
        ignore_top=True,
    ) == {
        "params": [
            "example.invalid",
            "https://example.invalid/a",
            "example.invalid:8443",
            "192.0.2.1",
            "192.0.2.1:443",
        ],
        "ignore_port": True,
        "ignore_url": False,
        "ignore_top": True,
    }


def test_dga_only_result_normalizes_tags_and_routes_dga(tmp_path):
    target = _targets("Example.INVALID")[0]
    response = _response(target.original, [" DGA ", "dga"])
    provider, transport, _ = _provider(tmp_path, [response])
    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 1
    observation = result.observations[0]
    assert observation.kind == "dga_classification"
    assert observation.payload["tags"] == ["dga"]
    assert observation.payload["source_level"] == "malicious"
    assert observation.payload["hit_count"] == 1
    assert observation.payload["raw_classification"] == response["data"][target.original]
    assert observation.freshness == Freshness.FRESH
    decision = select_route(
        target,
        result.observations,
        dga_provider_configured=True,
        dga_provider_status=result.statuses[target.normalized],
    )
    assert decision.route == Route.DGA
    assert transport.calls[0]["url"] == "https://k01.invalid/api/v1/k01/compromises"
    assert transport.calls[0]["headers"] == {"Api-Key": "test-key"}


def test_mixed_tags_across_hits_stay_standard(tmp_path):
    target = _targets("mixed.invalid")[0]
    response = _response(
        target.original,
        ["DGA"],
        extra_hits=[{"ioc_host": target.original, "tags": [" cc ", "dga"]}],
    )
    provider, _, _ = _provider(tmp_path, [response])
    result = provider.collect([target], ProviderContext())
    assert result.observations[0].payload["tags"] == ["dga", "cc"]
    decision = select_route(
        target,
        result.observations,
        True,
        result.statuses[target.normalized],
    )
    assert decision.route == Route.STANDARD
    assert decision.classification_unknown is False


def test_sinkhole_only_is_success_but_never_dga_route(tmp_path):
    target = _targets("sink.invalid")[0]
    provider, _, _ = _provider(tmp_path, [_response(target.original, ["sinkhole"])])
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert select_route(
        target,
        result.observations,
        True,
        result.statuses[target.normalized],
    ).route == Route.STANDARD


def test_missing_or_non_list_tags_is_diagnostic_error_and_unknown_route(tmp_path):
    targets = _targets("missing.invalid", "malformed.invalid")
    response = {
        "status": 10000,
        "data": {
            targets[0].original: {"level": "malicious", "data": [{"ioc_host": targets[0].original}]},
            targets[1].original: {"level": "malicious", "data": [{"tags": "dga"}]},
        },
    }
    provider, _, _ = _provider(tmp_path, [response])
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.ERROR}
    assert result.observations == []
    assert len(result.errors) == 2
    for target in targets:
        decision = select_route(
            target,
            [],
            True,
            result.statuses[target.normalized],
        )
        assert decision.route == Route.STANDARD
        assert decision.classification_unknown is True


def test_successful_empty_result_is_no_data(tmp_path):
    target = _targets("empty.invalid")[0]
    provider, _, _ = _provider(
        tmp_path,
        [{"status": 10000, "data": {target.original: {"level": "", "data": []}}}],
    )
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert result.observations == []
    assert result.errors == []


def test_transport_and_business_errors_are_error_not_no_data(tmp_path):
    targets = _targets("transport.invalid", "business.invalid")
    transport_provider, transport, _ = _provider(
        tmp_path / "transport",
        [TransportError("http", "HTTP 503 for endpoint", 503)],
    )
    first = transport_provider.collect([targets[0]], ProviderContext())
    assert len(transport.calls) == 1
    assert first.statuses[targets[0].normalized] == ProviderStatus.ERROR

    business_provider, _, _ = _provider(
        tmp_path / "business",
        [{"status": 50001, "msg": "denied", "data": {}}],
    )
    second = business_provider.collect([targets[1]], ProviderContext())
    assert second.statuses[targets[1].normalized] == ProviderStatus.ERROR
    assert "50001" in second.errors[0]


def test_cache_key_separates_every_ignore_profile(tmp_path):
    target = _targets("https://example.invalid/a")[0]
    keys = set()
    for ignore_port in (False, True):
        for ignore_url in (False, True):
            for ignore_top in (False, True):
                provider, _, cache = _provider(
                    tmp_path,
                    [],
                    ignore_port=ignore_port,
                    ignore_url=ignore_url,
                    ignore_top=ignore_top,
                )
                keys.add(cache.key(target.original, provider.cache_params(target)))
    assert len(keys) == 8


def test_batch_response_cache_is_scoped_to_each_ioc(tmp_path):
    targets = _targets("first.invalid", "second.invalid")
    response = {
        "status": 10000,
        "msg": "ok",
        "data": {
            target.original: {
                "level": "malicious",
                "data": [{"ioc_host": target.original, "tags": ["dga"]}],
            }
            for target in targets
        },
    }
    provider, _, cache = _provider(tmp_path, [response])

    result = provider.collect(targets, ProviderContext())

    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    for target in targets:
        entry = cache.get(
            target.original,
            provider.cache_params(target),
            now=NOW,
        )
        assert entry is not None
        assert entry.raw == {
            "status": 10000,
            "msg": "ok",
            "data": {target.original: response["data"][target.original]},
        }

    replay_provider, replay_transport, _ = _provider(tmp_path, [])
    replay = replay_provider.collect(targets, ProviderContext(offline=True))
    assert replay_transport.calls == []
    assert replay.cache_hits == 2
    assert set(replay.statuses.values()) == {ProviderStatus.SUCCESS}
    assert [item.ioc for item in replay.observations] == [
        target.normalized for target in targets
    ]


def test_fresh_cache_and_offline_stale_cache_do_not_call_transport(tmp_path):
    target = _targets("cached.invalid")[0]
    response = _response(target.original, ["dga"])
    provider, transport, cache = _provider(tmp_path, [], ttl=timedelta(hours=1))
    cache.put(
        target.original,
        response,
        provider.cache_params(target),
        fetched_at=NOW - timedelta(days=1),
    )
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.cache_hits == 1
    assert result.observations[0].freshness == Freshness.STALE


def test_offline_cache_miss_is_error(tmp_path):
    target = _targets("missing.invalid")[0]
    provider, transport, _ = _provider(tmp_path, [])
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert "offline cache miss" in result.errors[0]
