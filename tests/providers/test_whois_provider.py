"""WHOIS provider applicability, date, cache, and DGA integration tests."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.config import Config
from ioc_rejudge.dga import adjudicate_dga
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.models import Conclusion
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.pipeline import _build_dga_facts
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.providers.whois import WhoisProvider


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


def _response(
    *,
    created="2020-01-02 03:04:05",
    updated="2026-01-02 03:04:05",
    expires="2027-01-02 03:04:05",
    data_extra=None,
):
    data = {
        "mergeStatus": True,
        "status": ["clientTransferProhibited"],
        "createdDate": [created] if created is not None else [],
        "updatedDate": [updated] if updated is not None else [],
        "expiresDate": [expires] if expires is not None else [],
        "registrantName": ["Example Registrant"],
    }
    data.update(data_extra or {})
    return {"code": 200, "status": "ok", "data": data}


def _provider(tmp_path, responses, *, ttl=timedelta(days=1)):
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=7,
        ttl=ttl,
    )
    transport = FakeTransport(responses)
    cache = JsonlProviderCache(tmp_path, "whois", ttl)
    provider = WhoisProvider(
        settings,
        transport=transport,
        cache=cache,
        now_fn=lambda: NOW,
    )
    return provider, transport, cache


def test_domain_url_and_domain_port_query_host_with_merge_zero(tmp_path):
    targets = _targets(
        "Example.INVALID",
        "https://url.invalid:8443/a?q=1",
        "port.invalid:9443",
    )
    provider, transport, _ = _provider(
        tmp_path, [_response(), _response(), _response()]
    )
    result = provider.collect(targets, ProviderContext())

    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    assert [call["url"] for call in transport.calls] == [
        "https://whois.invalid/v3/whois/detail/example.invalid",
        "https://whois.invalid/v3/whois/detail/url.invalid",
        "https://whois.invalid/v3/whois/detail/port.invalid",
    ]
    assert all(call["params"] == {"merge": 0} for call in transport.calls)
    assert all(
        call["headers"]
        == {"fdp-access": "test-access", "fdp-secret": "test-secret"}
        for call in transport.calls
    )


def test_plain_ip_ip_port_and_ip_url_are_disabled_without_requests(tmp_path):
    targets = _targets("192.0.2.1", "192.0.2.1:443", "https://192.0.2.2/a")
    provider, transport, _ = _provider(tmp_path, [])
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.DISABLED}
    assert transport.calls == []


def test_success_normalizes_dates_registrant_and_raw_status_fields(tmp_path):
    target = _targets("dates.invalid")[0]
    provider, _, _ = _provider(tmp_path, [_response()])
    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    observation = result.observations[0]
    assert observation.kind == "whois"
    assert observation.fetched_at == NOW
    assert observation.observed_at == NOW
    assert observation.freshness == Freshness.FRESH
    assert observation.payload["created_at"] == "2020-01-02 03:04:05"
    assert observation.payload["updated_at"] == "2026-01-02 03:04:05"
    assert observation.payload["expires_at"] == "2027-01-02 03:04:05"
    assert observation.payload["registrant"] == "Example Registrant"
    assert observation.payload["response_code"] == 200
    assert observation.payload["response_status"] == "ok"
    assert observation.payload["domain_status"] == ["clientTransferProhibited"]
    assert observation.payload["merge_status"] is True
    assert observation.payload["raw_dates"]["expiresDate"] == [
        "2027-01-02 03:04:05"
    ]


def test_date_aliases_and_multiple_values_choose_latest_parseable_fact(tmp_path):
    target = _targets("aliases.invalid")[0]
    response = {
        "code": "200",
        "status": "ok",
        "data": {
            "creationDate": ["bad", "2020-01-01"],
            "lastUpdated": "2026-01-01T00:00:00+00:00",
            "expirationDate": ["2027-01-01", "2028-01-01"],
            "registrantOrganization": ["Example Org"],
        },
    }
    provider, _, _ = _provider(tmp_path, [response])
    result = provider.collect([target], ProviderContext())
    payload = result.observations[0].payload
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert payload["created_at"] == "2020-01-01 00:00:00"
    assert payload["updated_at"] == "2026-01-01 00:00:00+00:00"
    assert payload["expires_at"] == "2028-01-01 00:00:00"
    assert payload["registrant"] == "Example Org"


def test_missing_or_invalid_expiry_is_successful_incomplete_with_diagnostic(tmp_path):
    targets = _targets("missing.invalid", "invalid.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            _response(expires=None),
            _response(expires="not-a-date"),
        ],
    )
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    assert [row.payload["expires_at"] for row in result.observations] == ["", ""]
    assert any("missing expires" in error for error in result.errors)
    assert any("invalid expires" in error for error in result.errors)


def test_code_200_without_data_is_no_data_and_bad_shapes_are_error(tmp_path):
    targets = _targets("empty.invalid", "shape.invalid", "business.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            {"code": 200, "status": "ok", "data": {}},
            {"code": 200, "status": "ok", "data": []},
            {"code": 401, "status": "unauthorized", "data": {}},
        ],
    )
    result = provider.collect(targets, ProviderContext())
    assert result.statuses[targets[0].normalized] == ProviderStatus.NO_DATA
    assert result.statuses[targets[1].normalized] == ProviderStatus.ERROR
    assert result.statuses[targets[2].normalized] == ProviderStatus.ERROR


def test_transport_timeout_and_authentication_failures_are_error(tmp_path):
    targets = _targets("timeout.invalid", "auth.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            TransportError("timeout", "Request timed out for endpoint"),
            TransportError("http", "HTTP 401 for endpoint", 401),
        ],
    )
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.ERROR}
    assert len(result.errors) == 2


def test_fresh_and_offline_stale_cache_have_distinct_freshness(tmp_path):
    targets = _targets("fresh.invalid", "stale.invalid")
    provider, transport, cache = _provider(tmp_path, [], ttl=timedelta(days=1))
    for target, age in zip(targets, (timedelta(hours=23), timedelta(hours=25))):
        cache.put(
            target.host,
            _response(),
            provider.cache_params(target),
            fetched_at=NOW - age,
        )
    result = provider.collect(targets, ProviderContext(offline=True))
    assert transport.calls == []
    assert result.cache_hits == 2
    assert [row.freshness for row in result.observations] == [
        Freshness.FRESH,
        Freshness.STALE,
    ]


def test_online_failure_attaches_stale_for_audit_but_status_remains_error(tmp_path):
    target = _targets("fallback.invalid")[0]
    provider, transport, cache = _provider(
        tmp_path,
        [TransportError("timeout", "Request timed out for endpoint")],
        ttl=timedelta(hours=1),
    )
    cache.put(
        target.host,
        _response(),
        provider.cache_params(target),
        fetched_at=NOW - timedelta(days=1),
    )
    result = provider.collect([target], ProviderContext())
    assert len(transport.calls) == 1
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.observations) == 1
    assert result.observations[0].freshness == Freshness.STALE


def test_expired_retrieved_now_does_not_become_unexpired_in_pipeline(tmp_path):
    target = _targets("expired.invalid")[0]
    provider, _, _ = _provider(
        tmp_path, [_response(expires="2025-01-01 00:00:00")]
    )
    result = provider.collect([target], ProviderContext())
    facts, missing = _build_dga_facts(
        result.observations,
        {"ioc_info": ProviderStatus.NO_DATA, "fdark": ProviderStatus.NO_DATA},
        Config(),
    )
    assert missing == []
    assert facts.whois_expires == datetime(2025, 1, 1)
    assert adjudicate_dga(target.normalized, facts, now=NOW).conclusion == (
        Conclusion.INACTIVE_VALID
    )


def test_fresh_future_expiry_whites_but_stale_and_missing_expiry_do_not(tmp_path):
    targets = _targets("future.invalid", "stale.invalid", "missing.invalid")
    provider, _, cache = _provider(
        tmp_path, [_response(expires="2027-01-01"), _response(expires=None)]
    )
    cache.put(
        targets[1].host,
        _response(expires="2027-01-01"),
        provider.cache_params(targets[1]),
        fetched_at=NOW - timedelta(days=2),
    )
    live = provider.collect(
        [targets[0], targets[2]], ProviderContext()
    )
    stale = provider.collect([targets[1]], ProviderContext(offline=True))
    statuses = {"ioc_info": ProviderStatus.NO_DATA, "fdark": ProviderStatus.NO_DATA}

    future_facts, _ = _build_dga_facts([live.observations[0]], statuses, Config())
    stale_facts, _ = _build_dga_facts(stale.observations, statuses, Config())
    missing_facts, _ = _build_dga_facts([live.observations[1]], statuses, Config())
    assert adjudicate_dga("future.invalid", future_facts, now=NOW).conclusion == (
        Conclusion.FALSE_POSITIVE
    )
    assert adjudicate_dga("stale.invalid", stale_facts, now=NOW).conclusion == (
        Conclusion.INACTIVE_VALID
    )
    assert adjudicate_dga("missing.invalid", missing_facts, now=NOW).conclusion == (
        Conclusion.INACTIVE_VALID
    )
