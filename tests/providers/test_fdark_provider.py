"""F-Dark query normalization and provider tests."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.fdark import (
    FDarkProvider,
    _append_variant,
    _default_port_for_scheme,
    _http_proto_for_scheme,
    _http_url_query_params,
    _is_ip,
    _looks_like_uri,
    _parse_ip_port,
    _valid_port,
    build_query_param_variants,
    build_query_params,
    build_request_params,
)
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        self.calls.append({
            "url": url,
            "headers": headers,
            "params": params,
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
    include_slow_variants=False,
    include_url_param=False,
    ttl=timedelta(days=1),
    config=None,
):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api/v1/fdark/abstract",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=9,
        ttl=ttl,
    )
    transport = FakeTransport(responses)
    cache = JsonlProviderCache(tmp_path, "fdark", ttl)
    provider = FDarkProvider(
        settings,
        config or Config(),
        transport=transport,
        cache=cache,
        include_slow_variants=include_slow_variants,
        include_url_param=include_url_param,
        now_fn=lambda: NOW,
    )
    return provider, transport, cache


def _ok(*items):
    return {"message": "", "status": "ok", "data": list(items), "total": len(items)}


def test_reviewed_query_helpers_preserve_supported_and_invalid_shapes():
    assert _valid_port("1") == 1
    assert _valid_port("65535") == 65535
    assert _valid_port("0") is None
    assert _valid_port("70000") is None
    assert _valid_port("bad") is None
    assert _parse_ip_port("192.0.2.1:443") == ("192.0.2.1", 443)
    assert _parse_ip_port("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    assert _parse_ip_port("example.invalid:443") is None
    assert _parse_ip_port("192.0.2.1:70000") is None
    assert _is_ip("192.0.2.1") is True
    assert _is_ip("example.invalid") is False
    assert _looks_like_uri("https://example.invalid/a") is True
    assert _looks_like_uri("example.invalid/a") is True
    assert _looks_like_uri("example.invalid") is False
    assert _http_proto_for_scheme("HTTPS") == "ssl"
    assert _http_proto_for_scheme("http") == "http"
    assert _default_port_for_scheme("https") == 443
    assert _default_port_for_scheme("http") == 80
    assert _http_url_query_params("https://example.invalid:8443/a?q=1") == {
        "domain": "example.invalid",
        "proto": "ssl",
        "http_path": "/a",
    }


def test_build_query_params_keeps_reviewed_domain_url_and_ip_shapes():
    assert build_query_params("example.invalid") == {"domain": "example.invalid"}
    assert build_query_params("https://example.invalid/a?q=1") == {
        "domain": "example.invalid",
        "proto": "ssl",
        "http_path": "/a",
    }
    assert build_query_params("example.invalid:8443") == {
        "domain": "example.invalid:8443"
    }
    assert build_query_params("192.0.2.1") == {"ip": "192.0.2.1"}
    assert build_query_params("192.0.2.1:443") == {
        "ip": "192.0.2.1",
        "dport": 443,
    }
    assert build_query_params("192.0.2.1:70000") == {
        "domain": "192.0.2.1:70000"
    }
    assert build_request_params(
        "example.invalid", {"limit": 20, "empty": "", "none": None}
    ) == {"domain": "example.invalid", "limit": 20}


def test_fast_url_variant_is_single_and_slow_variants_are_deduplicated():
    target = "http://example.invalid:8080/login.php?a=1&b=2"
    assert build_query_param_variants(target) == [
        (
            "host_proto_path",
            {
                "domain": "example.invalid",
                "proto": "http",
                "http_path": "/login.php",
            },
        )
    ]
    variants = build_query_param_variants(target, include_slow_variants=True)
    signatures = [tuple(sorted((key, str(value)) for key, value in params.items()))
                  for _, params in variants]
    assert len(signatures) == len(set(signatures))
    by_name = dict(variants)
    assert by_name["uri_full"] == {"uri": target}
    assert by_name["host_port_path_query"] == {
        "domain": "example.invalid",
        "dport": 8080,
        "http_path": "/login.php",
        "http_query": "a=1&b=2",
    }
    assert by_name["query_kv_a"] == {
        "domain": "example.invalid",
        "http_query_kv": "a=1",
    }


def test_append_variant_eliminates_duplicate_parameter_sets():
    variants = []
    seen = set()
    _append_variant(variants, seen, "first", {"domain": "example.invalid", "x": ""})
    _append_variant(variants, seen, "second", {"domain": "example.invalid"})
    assert variants == [("first", {"domain": "example.invalid"})]


def test_collect_normalizes_samples_and_reuses_common_malicious_semantics(tmp_path):
    target = _targets("example.invalid")[0]
    response = _ok(
        {
            "md5": "md5-first",
            "sha1": "sha1-second",
            "sha256": "sha256-third",
            "level": 80,
            "family": "trojan.family",
            "type": "pe",
            "confidence": 90,
            "lseen": 1_720_000_000,
            "fseen": 1_710_000_000,
        },
        {
            "sha1": "benign-sha1",
            "level": 99,
            "family": "not-a-virus:tool",
            "type": "pe",
            "fseen": 1_700_000_000,
        },
        {
            "sha256": "zero-confidence",
            "level": 99,
            "family": "trojan.family",
            "confidence": 0,
        },
        {
            "md5": "low-level",
            "level": 39,
            "family": "trojan.family",
        },
    )
    provider, transport, _ = _provider(tmp_path, [response])
    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 4
    first = result.observations[0]
    assert first.kind == "associated_sample"
    assert first.payload == {
        "hash": "md5-first",
        "level": 80,
        "family": "trojan.family",
        "type": "pe",
        "malicious": True,
    }
    assert first.observed_at == datetime.fromtimestamp(1_720_000_000, timezone.utc)
    assert result.observations[1].observed_at == datetime.fromtimestamp(
        1_700_000_000, timezone.utc
    )
    assert [row.payload["malicious"] for row in result.observations] == [
        True,
        False,
        False,
        False,
    ]
    assert transport.calls == [{
        "url": "https://fdark.invalid/api/v1/fdark/abstract",
        "headers": {"fdp-access": "test-access", "fdp-secret": "test-secret"},
        "params": {
            "domain": "example.invalid",
            "limit": 20,
            "offset": 0,
            "order": "lseen-",
        },
        "timeout": 9,
    }]


def test_successful_empty_data_is_no_data(tmp_path):
    target = _targets("empty.invalid")[0]
    provider, _, _ = _provider(tmp_path, [_ok()])
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert result.observations == []
    assert result.errors == []


def test_transport_business_and_bad_data_are_errors(tmp_path):
    targets = _targets("transport.invalid", "business.invalid", "shape.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            TransportError("timeout", "Request timed out for endpoint"),
            {"status": "denied", "message": "no", "data": []},
            {"status": "ok", "data": {}},
        ],
    )
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.ERROR}
    assert len(result.errors) == 3
    assert result.observations == []


def test_cache_key_contains_complete_query_params(tmp_path):
    target = _targets("https://example.invalid/a")[0]
    provider, _, cache = _provider(tmp_path, [])
    first = provider.cache_params(
        target,
        "host_proto_path",
        {"domain": "example.invalid", "proto": "ssl", "http_path": "/a"},
    )
    second = provider.cache_params(
        target,
        "host_proto_path",
        {"domain": "example.invalid", "proto": "ssl", "http_path": "/b"},
    )
    assert cache.key(target.original, first) != cache.key(target.original, second)


def test_offline_stale_cache_is_used_and_refresh_bypasses_fresh_cache(tmp_path):
    target = _targets("cached.invalid")[0]
    stale_response = _ok({"md5": "stale", "level": 80, "family": "trojan"})
    live_response = _ok({"md5": "live", "level": 80, "family": "trojan"})
    provider, transport, cache = _provider(
        tmp_path, [live_response], ttl=timedelta(hours=1)
    )
    variant, query = provider.query_variants(target)[0]
    cache.put(
        target.original,
        stale_response,
        provider.cache_params(target, variant, query),
        fetched_at=NOW - timedelta(days=1),
    )

    offline = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert offline.cache_hits == 1
    assert offline.freshnesses[target.normalized] == Freshness.STALE
    assert offline.observations[0].freshness == Freshness.STALE

    refreshed = provider.collect([target], ProviderContext(refresh=True))
    assert len(transport.calls) == 1
    assert refreshed.observations[0].payload["hash"] == "live"


def test_offline_stale_empty_cache_marks_no_data_incomplete(tmp_path):
    target = _targets("empty.invalid")[0]
    provider, transport, cache = _provider(
        tmp_path, [], ttl=timedelta(hours=1)
    )
    variant, query = provider.query_variants(target)[0]
    cache.put(
        target.original,
        _ok(),
        provider.cache_params(target, variant, query),
        fetched_at=NOW - timedelta(days=1),
    )
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert result.freshnesses[target.normalized] == Freshness.STALE


def test_offline_cache_miss_is_error(tmp_path):
    target = _targets("missing.invalid")[0]
    provider, transport, _ = _provider(tmp_path, [])
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert "offline cache miss" in result.errors[0]


def test_slow_variants_require_explicit_opt_in_and_make_multiple_queries(tmp_path):
    target = _targets("https://slow.invalid/a?q=1")[0]
    fast, fast_transport, _ = _provider(tmp_path / "fast", [_ok()])
    fast.collect([target], ProviderContext())
    assert len(fast_transport.calls) == 1

    probe, _, _ = _provider(
        tmp_path / "probe", [], include_slow_variants=True
    )
    variants = probe.query_variants(target)
    assert len(variants) > 1
