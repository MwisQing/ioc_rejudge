"""pDNS provider response, time, cache, and DGA integration tests."""

from datetime import datetime, timedelta, timezone

from ioc_rejudge.config import Config
from ioc_rejudge.dga import adjudicate_dga
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.models import Conclusion
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.pipeline import _build_dga_facts
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.go_transport import BatchResult
from ioc_rejudge.providers.pdns import PDNSProvider
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


class FakeGoTransport:
    available = True

    def __init__(self, results):
        self.results = list(results)
        self.requests = []
        self.workers = None
        self.rate_per_second = None

    def iter_batch(self, requests, *, workers, rate_per_second):
        self.requests = list(requests)
        self.workers = workers
        self.rate_per_second = rate_per_second
        yield from self.results


def _targets(*values):
    return read_input_bundle(None, list(values)).targets


def _record(
    *,
    rrtype="A",
    rdata="192.0.2.10;",
    count=3,
    time_first=None,
    time_last=None,
):
    return {
        "rrtype": rrtype,
        "rdata": rdata,
        "count": count,
        "time_first": time_first
        if time_first is not None
        else int((NOW - timedelta(days=40)).timestamp()),
        "time_last": time_last
        if time_last is not None
        else int((NOW - timedelta(days=1)).timestamp()),
    }


def _response(*records, code=200):
    return {"code": code, "status": "ok" if str(code) == "200" else "error", "data": list(records)}


def _provider(tmp_path, responses, *, ttl=timedelta(days=1)):
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid/api/v1/passivedns/flint/rrset",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=6,
        ttl=ttl,
    )
    transport = FakeTransport(responses)
    cache = JsonlProviderCache(tmp_path, "pdns", ttl)
    provider = PDNSProvider(
        settings,
        transport=transport,
        cache=cache,
        now_fn=lambda: NOW,
    )
    return provider, transport, cache


def test_domain_url_and_domain_port_query_host_with_trailing_slash(tmp_path):
    targets = _targets(
        "Example.INVALID",
        "https://url.invalid:8443/a?q=1",
        "port.invalid:9443",
    )
    provider, transport, _ = _provider(
        tmp_path,
        [_response(_record()), _response(_record()), _response(_record())],
    )
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    assert [call["url"] for call in transport.calls] == [
        "https://pdns.invalid/api/v1/passivedns/flint/rrset/example.invalid/",
        "https://pdns.invalid/api/v1/passivedns/flint/rrset/url.invalid/",
        "https://pdns.invalid/api/v1/passivedns/flint/rrset/port.invalid/",
    ]
    assert all(call["params"] is None for call in transport.calls)
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


def test_go_batch_path_preserves_input_order_cache_and_progress(tmp_path):
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid/api/v1/passivedns/flint/rrset",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=6,
        workers=9,
        rate_per_second=45,
        ttl=timedelta(days=1),
    )
    go_transport = FakeGoTransport([
        BatchResult("1", payload=_response(_record(rdata="192.0.2.2;"))),
        BatchResult("0", payload=_response(_record(rdata="192.0.2.1;"))),
    ])
    cache = JsonlProviderCache(tmp_path, "pdns", timedelta(days=1))
    provider = PDNSProvider(
        settings, cache=cache, go_transport=go_transport, now_fn=lambda: NOW
    )
    targets = _targets("one.invalid", "two.invalid")
    events = []

    result = provider.collect(
        targets, ProviderContext(on_progress=events.append)
    )

    assert [item.ioc for item in result.observations] == [
        targets[0].normalized, targets[1].normalized
    ]
    assert [item.payload["rdata"] for item in result.observations] == [
        "192.0.2.1;", "192.0.2.2;"
    ]
    assert [(event.done, event.total) for event in events] == [
        (0, 2), (1, 2), (2, 2)
    ]
    assert go_transport.workers == 9
    assert go_transport.rate_per_second == 45
    for target in targets:
        assert cache.get(target.host, provider.cache_params(target))


def test_every_response_record_becomes_a_complete_activity_observation(tmp_path):
    target = _targets("records.invalid")[0]
    first_time = int((NOW - timedelta(days=10)).timestamp())
    last_time = int((NOW - timedelta(days=2)).timestamp())
    records = [
        _record(time_first=first_time, time_last=last_time),
        _record(
            rrtype="AAAA",
            rdata="2001:db8::10;",
            count=1,
            time_last=str(int((NOW - timedelta(days=1)).timestamp())),
        ),
    ]
    response = _response(*records)
    provider, _, cache = _provider(tmp_path, [response])
    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 2
    first = result.observations[0]
    assert first.kind == "pdns_activity"
    assert first.payload == {
        "rrtype": "A",
        "rdata": "192.0.2.10;",
        "count": 3,
        "time_first": datetime.fromtimestamp(first_time, timezone.utc).isoformat(
            sep=" "
        ),
        "time_last": datetime.fromtimestamp(last_time, timezone.utc).isoformat(
            sep=" "
        ),
        "raw_time_first": first_time,
        "raw_time_last": last_time,
    }
    assert first.observed_at == datetime.fromtimestamp(last_time, timezone.utc)
    assert result.observations[1].payload["rrtype"] == "AAAA"
    entry = cache.get(target.host, provider.cache_params(target), now=NOW)
    assert entry.raw == response


def test_malformed_times_remain_auditable_but_never_become_now(tmp_path):
    target = _targets("bad-time.invalid")[0]
    provider, _, _ = _provider(
        tmp_path,
        [_response(_record(time_first="bad-first", time_last="bad-last"))],
    )
    result = provider.collect([target], ProviderContext())
    observation = result.observations[0]
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert observation.observed_at is None
    assert observation.payload["time_first"] == "bad-first"
    assert observation.payload["time_last"] == "bad-last"
    assert any("invalid time_first" in error for error in result.errors)
    assert any("invalid time_last" in error for error in result.errors)


def test_code_200_empty_records_is_no_data_and_bad_shapes_are_error(tmp_path):
    targets = _targets("empty.invalid", "shape.invalid", "record.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            _response(),
            {"code": 200, "status": "ok", "data": {}},
            {"code": 200, "status": "ok", "data": ["bad"]},
        ],
    )
    result = provider.collect(targets, ProviderContext())
    assert result.statuses[targets[0].normalized] == ProviderStatus.NO_DATA
    assert result.statuses[targets[1].normalized] == ProviderStatus.ERROR
    assert result.statuses[targets[2].normalized] == ProviderStatus.ERROR


def test_transport_and_business_errors_are_error(tmp_path):
    targets = _targets("timeout.invalid", "business.invalid")
    provider, _, _ = _provider(
        tmp_path,
        [
            TransportError("timeout", "Request timed out for endpoint"),
            _response(code=50001),
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
            _response(_record()),
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
        _response(_record()),
        provider.cache_params(target),
        fetched_at=NOW - timedelta(days=1),
    )
    result = provider.collect([target], ProviderContext())
    assert len(transport.calls) == 1
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.observations) == 1
    assert result.observations[0].freshness == Freshness.STALE


def test_pdns_29_30_31_day_boundary_flows_through_pipeline(tmp_path):
    targets = _targets("day29.invalid", "day30.invalid", "day31.invalid")
    responses = [
        _response(_record(time_last=int((NOW - timedelta(days=days)).timestamp())))
        for days in (29, 30, 31)
    ]
    provider, _, _ = _provider(tmp_path, responses)
    result = provider.collect(targets, ProviderContext())
    statuses = {"ioc_info": ProviderStatus.NO_DATA, "fdark": ProviderStatus.NO_DATA}
    conclusions = []
    for target, observation in zip(targets, result.observations):
        facts, missing = _build_dga_facts([observation], statuses, Config())
        assert missing == []
        conclusions.append(
            adjudicate_dga(target.normalized, facts, now=NOW).conclusion
        )
    assert conclusions == [
        Conclusion.FALSE_POSITIVE,
        Conclusion.FALSE_POSITIVE,
        Conclusion.INACTIVE_VALID,
    ]


def test_stale_and_bad_time_pdns_cannot_form_dga_white_signal(tmp_path):
    targets = _targets("stale.invalid", "bad.invalid")
    provider, _, cache = _provider(
        tmp_path, [_response(_record(time_last="bad"))]
    )
    cache.put(
        targets[0].host,
        _response(_record(time_last=int((NOW - timedelta(days=1)).timestamp()))),
        provider.cache_params(targets[0]),
        fetched_at=NOW - timedelta(days=2),
    )
    stale = provider.collect([targets[0]], ProviderContext(offline=True))
    bad = provider.collect([targets[1]], ProviderContext())
    statuses = {"ioc_info": ProviderStatus.NO_DATA, "fdark": ProviderStatus.NO_DATA}
    for target, observations in (
        (targets[0], stale.observations),
        (targets[1], bad.observations),
    ):
        facts, _ = _build_dga_facts(observations, statuses, Config())
        assert facts.pdns_last_seen is None
        assert adjudicate_dga(target.normalized, facts, now=NOW).conclusion == (
            Conclusion.INACTIVE_VALID
        )


def test_offline_cache_miss_is_error(tmp_path):
    target = _targets("missing.invalid")[0]
    provider, transport, _ = _provider(tmp_path, [])
    result = provider.collect([target], ProviderContext(offline=True))
    assert transport.calls == []
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert "offline cache miss" in result.errors[0]
