"""Contract tests for the opt-in ICP provider."""

from collections import deque
from datetime import datetime, timedelta, timezone
import threading

import pytest

from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.go_transport import BatchResult
from ioc_rejudge.providers.icp import ICPProvider
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError


NOW = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
SENTINEL_UC = "SENTINEL_ICP_UC_7f21"
SENTINEL_KEY = "SENTINEL_ICP_KEY_8a32"


class ScriptedTransport:
    def __init__(self, outcomes):
        self.outcomes = deque(outcomes)
        self.calls = []

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        self.calls.append({"url": url, "headers": headers, "params": dict(params or {}), "timeout": timeout})
        outcome = self.outcomes.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


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


def _provider(tmp_path, outcomes, *, secrets=None, ttl=timedelta(days=30)):
    transport = ScriptedTransport(outcomes)
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENTINEL_UC, "key": SENTINEL_KEY} if secrets is None else secrets,
        timeout=5,
        workers=2,
        rate_per_second=1000,
        ttl=ttl,
    )
    provider = ICPProvider(
        settings,
        transport=transport,
        cache=JsonlProviderCache(tmp_path / "cache", "icp", ttl),
        now_fn=lambda: NOW,
    )
    return provider, transport


def test_positive_response_creates_current_registration_observation(tmp_path):
    provider, transport = _provider(tmp_path, [{"resultObject": {"website_icp_num": " ICP-SYNTHETIC "}}])
    target = _targets("example.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload == {"current": True, "registration": "ICP-SYNTHETIC"}
    assert transport.calls[0]["params"] == {"uc": SENTINEL_UC, "key": SENTINEL_KEY, "dm": "example.invalid"}


def test_empty_response_creates_successful_negative_observation(tmp_path):
    provider, _ = _provider(tmp_path, [{"resultObject": {}}])
    target = _targets("empty.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload == {"current": False, "registration": ""}


def test_go_batch_path_preserves_input_order_cache_progress_and_limits(tmp_path):
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENTINEL_UC, "key": SENTINEL_KEY},
        timeout=5,
        workers=3,
        rate_per_second=7,
        ttl=timedelta(days=30),
    )
    go_transport = FakeGoTransport([
        BatchResult("1", payload={"resultObject": {}}),
        BatchResult("0", payload={"resultObject": {"icp": "ICP-GO"}}),
    ])
    cache = JsonlProviderCache(tmp_path / "cache", "icp", timedelta(days=30))
    provider = ICPProvider(
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
    assert result.observations[0].payload["registration"] == "ICP-GO"
    assert result.observations[1].payload["current"] is False
    assert [(event.done, event.total) for event in events] == [
        (0, 2), (1, 2), (2, 2)
    ]
    assert go_transport.workers == 3
    assert go_transport.rate_per_second == 7
    assert [request.params["dm"] for request in go_transport.requests] == [
        "one.invalid", "two.invalid"
    ]
    assert all(request.params["uc"] == SENTINEL_UC for request in go_transport.requests)
    assert all(request.params["key"] == SENTINEL_KEY for request in go_transport.requests)
    for target in targets:
        assert cache.get(target.host, provider.cache_params(target.host))


@pytest.mark.parametrize("response", [
    {"resultObject": {"website_icp_num": "ICP-A"}},
    {"resultObject": {"icp": "ICP-A"}},
    {"rows": [{"website_icp_num": "ICP-A"}]},
    {"rows": [{"icp": "ICP-A"}]},
])
def test_result_aliases_are_supported(tmp_path, response):
    provider, _ = _provider(tmp_path, [response])
    target = _targets("alias.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.observations[0].payload == {"current": True, "registration": "ICP-A"}


def test_high_priority_registration_ignores_malformed_lower_priority_rows(tmp_path):
    provider, _ = _provider(tmp_path, [{
        "resultObject": {"website_icp_num": "ICP-HIGH"},
        "rows": [123],
    }])
    target = _targets("priority.invalid")[0]

    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload == {
        "current": True,
        "registration": "ICP-HIGH",
    }


@pytest.mark.parametrize("response", [
    {"resultObject": []},
    {"rows": {}},
    {"resultObject": {"icp": 123}},
    {"rows": [{"website_icp_num": []}]},
])
def test_bad_shapes_are_error_not_negative(tmp_path, response):
    provider, _ = _provider(tmp_path, [response])
    target = _targets("bad.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert result.observations == []


def test_domain_url_and_domain_port_share_one_host_request(tmp_path):
    provider, transport = _provider(tmp_path, [{"resultObject": {"icp": "ICP-HOST"}}])
    targets = _targets("example.invalid", "https://example.invalid/path", "example.invalid:443")
    result = provider.collect(targets, ProviderContext())
    assert len(transport.calls) == 1
    assert [ob.ioc for ob in result.observations] == [target.normalized for target in targets]
    assert all(ob.payload["registration"] == "ICP-HOST" for ob in result.observations)


def test_ip_targets_are_disabled(tmp_path):
    provider, transport = _provider(tmp_path, [])
    targets = _targets("192.0.2.1", "192.0.2.1:443", "https://192.0.2.2/a")
    result = provider.collect(targets, ProviderContext())
    assert set(result.statuses.values()) == {ProviderStatus.DISABLED}
    assert transport.calls == []


@pytest.mark.parametrize("secrets", [{}, {"uc": SENTINEL_UC}, {"key": SENTINEL_KEY}])
def test_missing_credentials_disable_without_io(tmp_path, secrets):
    provider, transport = _provider(tmp_path, [{"resultObject": {"icp": "never"}}], secrets=secrets)
    target = _targets("missing.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.DISABLED
    assert transport.calls == []


def test_fresh_and_offline_stale_cache_replay(tmp_path):
    provider, transport = _provider(tmp_path, [])
    targets = _targets("fresh.invalid", "stale.invalid")
    provider.cache.put(targets[0].host, {"resultObject": {"icp": "ICP-FRESH"}}, provider.cache_params(targets[0].host), fetched_at=NOW)
    provider.cache.put(targets[1].host, {"resultObject": {"icp": "ICP-STALE"}}, provider.cache_params(targets[1].host), fetched_at=NOW - timedelta(days=31))
    result = provider.collect(targets, ProviderContext(offline=True))
    assert transport.calls == []
    assert [ob.freshness for ob in result.observations] == [Freshness.FRESH, Freshness.STALE]
    assert result.statuses[targets[0].normalized] == ProviderStatus.SUCCESS
    assert result.statuses[targets[1].normalized] == ProviderStatus.SUCCESS


def test_offline_cache_miss_is_error(tmp_path):
    provider, transport = _provider(tmp_path, [])
    target = _targets("offline.invalid")[0]
    result = provider.collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert transport.calls == []


def test_online_failure_attaches_stale_audit(tmp_path):
    provider, transport = _provider(tmp_path, [TransportError("timeout", "SENTINEL_ENDPOINT_TIMEOUT")], ttl=timedelta(hours=1))
    target = _targets("failure.invalid")[0]
    provider.cache.put(target.host, {"resultObject": {"icp": "ICP-OLD"}}, provider.cache_params(target.host), fetched_at=NOW - timedelta(days=1))
    result = provider.collect([target], ProviderContext())
    assert len(transport.calls) == 1
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.observations) == 1 and result.observations[0].freshness == Freshness.STALE


def test_cache_and_errors_do_not_contain_credentials(tmp_path):
    provider, _ = _provider(tmp_path, [{"resultObject": {"icp": "ICP-SAFE"}}])
    target = _targets("safe.invalid")[0]
    result = provider.collect([target], ProviderContext())
    text = str(result.errors) + provider.cache.path.read_text(encoding="utf-8")
    assert SENTINEL_UC not in text
    assert SENTINEL_KEY not in text


def test_reflected_credentials_are_redacted_from_cached_response(tmp_path):
    provider, _ = _provider(tmp_path, [{
        "resultObject": {"icp": "ICP-SAFE"},
        "debug": {
            "uc_echo": f"rejected {SENTINEL_UC}",
            "request_key": f"key={SENTINEL_KEY}",
        },
    }])
    target = _targets("reflected.invalid")[0]

    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    cached = provider.cache.path.read_text(encoding="utf-8")
    assert SENTINEL_UC not in cached
    assert SENTINEL_KEY not in cached


def test_reflected_credential_cannot_become_registration_observation(tmp_path):
    provider, _ = _provider(tmp_path, [{
        "resultObject": {"icp": f"rejected key={SENTINEL_KEY}"},
    }])
    target = _targets("reflected-registration.invalid")[0]

    result = provider.collect([target], ProviderContext())

    serialized = str(result.errors) + str(result.observations)
    cached = provider.cache.path.read_text(encoding="utf-8")
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert result.observations == []
    assert SENTINEL_KEY not in serialized
    assert SENTINEL_KEY not in cached

    offline_settings = ProviderSettings(
        name="icp",
        base_url=provider.settings.base_url,
        secrets={},
        ttl=provider.settings.ttl,
        enabled=True,
    )
    offline = ICPProvider(
        offline_settings,
        transport=ScriptedTransport([]),
        cache=provider.cache,
        now_fn=lambda: NOW,
    )
    replay = offline.collect([target], ProviderContext(offline=True))
    assert replay.statuses[target.normalized] == ProviderStatus.ERROR
    assert replay.observations == []


def test_rate_limiter_reserves_requests_at_configured_intervals():
    class FakeClock:
        def __init__(self):
            self.current = 0.0
            self.sleeps = []

        def __call__(self):
            return self.current

        def sleep(self, delay):
            self.sleeps.append(delay)
            self.current += delay

    class TimedTransport:
        def __init__(self, clock):
            self.clock = clock
            self.starts = []

        def get_json(self, *args, **kwargs):
            self.starts.append(self.clock())
            return {"resultObject": {}}

    clock = FakeClock()
    transport = TimedTransport(clock)
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENTINEL_UC, "key": SENTINEL_KEY},
        workers=1,
        rate_per_second=2,
    )
    provider = ICPProvider(
        settings,
        transport=transport,
        now_fn=lambda: NOW,
        clock=clock,
        sleep=clock.sleep,
    )

    result = provider.collect(
        _targets("rate-a.invalid", "rate-b.invalid", "rate-c.invalid"),
        ProviderContext(),
    )

    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    assert transport.starts == [0.0, 0.5, 1.0]
    assert clock.sleeps == [0.5, 0.5]


def test_internal_concurrency_never_exceeds_configured_workers():
    class PeakTransport:
        def __init__(self):
            self.active = 0
            self.peak = 0
            self.calls = 0
            self.lock = threading.Lock()
            self.pair = threading.Barrier(2)

        def get_json(self, *args, **kwargs):
            with self.lock:
                self.active += 1
                self.calls += 1
                self.peak = max(self.peak, self.active)
            try:
                self.pair.wait(timeout=2)
                return {"resultObject": {}}
            finally:
                with self.lock:
                    self.active -= 1

    transport = PeakTransport()
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENTINEL_UC, "key": SENTINEL_KEY},
        workers=2,
        rate_per_second=1000,
    )
    provider = ICPProvider(settings, transport=transport, now_fn=lambda: NOW)

    result = provider.collect(
        _targets(
            "worker-a.invalid",
            "worker-b.invalid",
            "worker-c.invalid",
            "worker-d.invalid",
        ),
        ProviderContext(),
    )

    assert set(result.statuses.values()) == {ProviderStatus.SUCCESS}
    assert transport.calls == 4
    assert transport.peak == 2
