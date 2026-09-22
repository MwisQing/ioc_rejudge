"""R9 regression: credential values must not reach exportable provider surfaces."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, ProviderStatus
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.factory import _AuditedProviderCache
from ioc_rejudge.providers.fdark import FDarkProvider
from ioc_rejudge.providers.go_transport import BatchResult
from ioc_rejudge.providers.icp import ICPProvider
from ioc_rejudge.providers.ioc_info import IOCInfoProvider
from ioc_rejudge.providers.k01_compromise import K01CompromiseProvider
from ioc_rejudge.providers.pdns import PDNSProvider
from ioc_rejudge.providers.redaction import (
    REDACTED,
    redact_secret_values,
    safe_text,
    secret_values,
)
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.transport import TransportError
from ioc_rejudge.providers.whois import WhoisProvider


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
STALE_AT = NOW - timedelta(days=10)

# Unique synthetic sentinels — never real credentials.
SENT_ACCESS = "SENTINEL_R9_ACCESS_a7c3e91f"
SENT_SECRET = "SENTINEL_R9_SECRET_b8d4f02a"
SENT_API = "SENTINEL_R9_APIKEY_c9e5a13b"
SENT_UC = "SENTINEL_R9_ICP_UC_d0f6b24c"
SENT_KEY = "SENTINEL_R9_ICP_KEY_e1a7c35d"
SAFE_MARKER = "SAFE_MARKER_KEEP_ME_9f2"
SAFE_FAMILY = "SAFE_FAMILY_KEEP"
SAFE_REGISTRANT = "SAFE_REGISTRANT_KEEP"
SAFE_RDATA = "192.0.2.55;"
SAFE_ICP = "ICP-SAFE-KEEP"


class ScriptedTransport:
    """Records outbound auth material and returns scripted outcomes."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self._index = 0

    def _next(self, *, url, headers=None, params=None, body=None, timeout=30):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}) if params is not None else None,
                "body": body,
                "timeout": timeout,
            }
        )
        if self._index >= len(self.outcomes):
            raise AssertionError("transport exhausted")
        outcome = self.outcomes[self._index]
        self._index += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        return self._next(url=url, headers=headers, params=params, timeout=timeout)

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        return self._next(url=url, headers=headers, body=body, timeout=timeout)


class FakeGoTransport:
    available = True

    def __init__(self, results):
        self.results = list(results)
        self.requests = []

    def iter_batch(self, requests, *, workers, rate_per_second):
        self.requests = list(requests)
        yield from self.results


def _targets(*values):
    return read_input_bundle(None, list(values)).targets


def _exportable_text(result, cache: JsonlProviderCache | None = None) -> str:
    parts = [
        str(result.errors),
        str(result.observations),
        str(
            [
                {"payload": obs.payload, "raw_ref": obs.raw_ref}
                for obs in result.observations
            ]
        ),
    ]
    if cache is not None:
        for path in sorted(cache.provider_dir.glob("cache_*.jsonl")):
            parts.append(path.read_text(encoding="utf-8"))
        if cache.legacy_path.is_file():
            parts.append(cache.legacy_path.read_text(encoding="utf-8"))
        if cache.path.is_file():
            parts.append(cache.path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _assert_sentinels_absent(text: str, *sentinels: str) -> None:
    for sentinel in sentinels:
        assert sentinel not in text, f"leaked sentinel {sentinel!r}"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_redaction_helper_nested_values_keys_and_safe_text():
    secrets = secret_values({"a": SENT_ACCESS, "b": SENT_SECRET, "empty": ""})
    assert set(secrets) == {SENT_ACCESS, SENT_SECRET}
    payload = {
        "message": f"echo {SENT_ACCESS}",
        SENT_SECRET: "key-is-secret",
        "details": ["x", {"nested": f"has {SENT_SECRET} end"}],
        "keep": SAFE_MARKER,
        "tuple_like": (f"{SENT_ACCESS}-tail", 1),
    }
    redacted = redact_secret_values(payload, secrets)
    rendered = str(redacted)
    _assert_sentinels_absent(rendered, SENT_ACCESS, SENT_SECRET)
    assert redacted["keep"] == SAFE_MARKER
    assert REDACTED in redacted["message"]
    assert SAFE_MARKER in rendered
    assert SENT_ACCESS not in safe_text(f"boom {SENT_ACCESS}", secrets)
    assert payload["message"] == f"echo {SENT_ACCESS}"


def test_secret_values_ignores_empty_and_does_not_mutate_settings_map():
    secrets_map = {"token": SENT_API, "blank": "", "none": None}
    assert secret_values(secrets_map) == (SENT_API,)
    assert secrets_map["token"] == SENT_API


def test_cache_put_secret_values_key_uses_original_params_and_redacts(tmp_path):
    """Cache keys use original params; persisted and returned fields are redacted."""
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    params = {
        "endpoint": "https://fdark.invalid/api",
        "query": {"domain": "safe.invalid", "note": SENT_SECRET},
        "request_ioc": "safe.invalid",
        "strategy": "domain",
    }
    expected_key = cache.key("safe.invalid", params)
    entry = cache.put(
        "safe.invalid",
        {"message": f"body {SENT_SECRET}", "keep": SAFE_MARKER},
        params,
        fetched_at=NOW,
        secret_values=(SENT_SECRET,),
    )
    assert entry.key == expected_key
    assert entry.params["query"]["note"] == REDACTED
    assert entry.params["strategy"] == "domain"
    assert SENT_SECRET not in str(entry.raw)
    assert REDACTED in str(entry.raw)
    disk = cache.path.read_text(encoding="utf-8")
    _assert_sentinels_absent(disk, SENT_SECRET)
    assert SAFE_MARKER in disk
    assert REDACTED in disk
    replay = cache.get("safe.invalid", params, now=NOW)
    assert replay is not None
    assert replay.key == expected_key
    _assert_sentinels_absent(str(replay.params) + str(replay.raw), SENT_SECRET)


def test_cache_put_redacts_ioc_and_nested_surfaces(tmp_path):
    """IOC containing a configured secret must be redacted in all persisted and
    returned metadata; original key and get(…) lookup must remain intact."""
    secret_ioc = f"https://example.invalid/path?note={SENT_SECRET}"
    nested_params = {
        "endpoint": "https://provider.invalid/",
        "query": {"note": SENT_SECRET, "safe": SAFE_MARKER},
        "headers": {"X-Api-Key": SENT_API},
    }
    nested_raw = {
        "data": {"url": secret_ioc, "keep": SAFE_MARKER},
        "items": [{"secret": SENT_SECRET, "label": SAFE_FAMILY}],
    }
    cache = JsonlProviderCache(tmp_path / "cache", "whois", timedelta(days=1))
    entry = cache.put(
        secret_ioc,
        nested_raw,
        nested_params,
        fetched_at=datetime(2026, 9, 21, tzinfo=timezone.utc),
        secret_values=(SENT_SECRET, SENT_API),
    )
    # Returned IOC must not leak the sentinel.
    assert SENT_SECRET not in entry.ioc
    assert SENT_SECRET not in str(entry.params)
    assert SENT_SECRET not in str(entry.raw)
    assert SENT_API not in str(entry.params)
    assert SAFE_MARKER in str(entry.params)
    assert SAFE_MARKER in str(entry.raw)
    # Disk bytes must not leak the sentinel.
    disk = cache.path.read_text(encoding="utf-8")
    _assert_sentinels_absent(disk, SENT_SECRET, SENT_API)
    assert SAFE_MARKER in disk
    # Original lookup key must still resolve.
    replay = cache.get(secret_ioc, nested_params, now=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc))
    assert replay is not None
    assert replay.key == entry.key
    assert SENT_SECRET not in replay.ioc
    _assert_sentinels_absent(str(replay.params) + str(replay.raw), SENT_SECRET, SENT_API)


def test_audited_cache_put_and_get_redact_ioc_and_surfaces(tmp_path):
    """Audited run/raw cache wrapper must redact IOC and nested surfaces."""
    secret_ioc = f"https://example.invalid/path?note={SENT_SECRET}"
    nested_params = {
        "endpoint": "https://provider.invalid/",
        "query": {"note": SENT_SECRET},
    }
    nested_raw = {"data": {"url": secret_ioc}, "items": [SENT_SECRET]}
    cache = _AuditedProviderCache(
        tmp_path / "cache", tmp_path / "run_raw", "whois", timedelta(days=1)
    )
    entry = cache.put(
        secret_ioc,
        nested_raw,
        nested_params,
        fetched_at=datetime(2026, 9, 21, tzinfo=timezone.utc),
        secret_values=(SENT_SECRET,),
    )
    assert SENT_SECRET not in entry.ioc
    _assert_sentinels_absent(cache.path.read_text(encoding="utf-8"), SENT_SECRET)
    _assert_sentinels_absent(cache.audit.path.read_text(encoding="utf-8"), SENT_SECRET)
    # Cache hit → audit copy must also redact (stored secret_values from put).
    hit = cache.get(
        secret_ioc,
        nested_params,
        now=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
    )
    assert hit is not None
    assert hit.key == entry.key
    assert SENT_SECRET not in hit.ioc
    _assert_sentinels_absent(cache.audit.path.read_text(encoding="utf-8"), SENT_SECRET)


def test_audited_cache_first_historical_hit_uses_constructor_secrets(tmp_path):
    """A historical unredacted row must not leak through its first audit copy."""
    sentinel = "SYNTHETIC_HIST_SECRET_9981"
    secret_ioc = f"https://example.invalid/path?note={sentinel}"
    params = {"provider": "https://whois.invalid/", "note": sentinel}
    raw = {"data": secret_ioc, "items": [sentinel]}
    source = JsonlProviderCache(tmp_path / "cache", "whois", timedelta(days=1))
    source.put(
        secret_ioc,
        raw,
        params,
        fetched_at=datetime(2026, 9, 21, tzinfo=timezone.utc),
    )
    assert sentinel in source.path.read_text(encoding="utf-8")

    cache = _AuditedProviderCache(
        tmp_path / "cache",
        tmp_path / "run_raw",
        "whois",
        timedelta(days=1),
        secret_values=(sentinel,),
    )
    entry = cache.get(
        secret_ioc,
        params,
        now=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
    )

    assert entry is not None
    assert entry.raw == raw
    _assert_sentinels_absent(
        cache.audit.path.read_text(encoding="utf-8"), sentinel
    )


# ---------------------------------------------------------------------------
# Live happy paths (strict status + surviving safe facts)
# ---------------------------------------------------------------------------


def test_fdark_python_live_redacts_echo_and_keeps_sample_facts(tmp_path):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    response = {
        "message": f"ok {SENT_SECRET}",
        "status": "ok",
        "data": [
            {
                "md5": "d" * 32,
                "level": 3,
                "family": SAFE_FAMILY,
                "type": "elf",
                "lseen": int(NOW.timestamp()),
                "note": f"family-note-{SENT_ACCESS}",
            }
        ],
        "total": 1,
        "details": f"detail-{SENT_SECRET}-detail",
        "debug": {"echo": SENT_ACCESS, "note": SAFE_MARKER},
    }
    transport = ScriptedTransport([response])
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    provider = FDarkProvider(
        settings, Config(), transport=transport, cache=cache, now_fn=lambda: NOW
    )
    secrets_before = dict(settings.secrets)
    target = _targets("echo-fdark.invalid")[0]
    result = provider.collect([target], ProviderContext())

    assert transport.calls[0]["headers"] == {
        "fdp-access": SENT_ACCESS,
        "fdp-secret": SENT_SECRET,
    }
    assert settings.secrets == secrets_before
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 1
    assert result.observations[0].payload["family"] == SAFE_FAMILY
    assert result.observations[0].payload["hash"] == "d" * 32
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_ACCESS, SENT_SECRET)
    assert SAFE_FAMILY in text
    assert SAFE_MARKER in text


def test_fdark_go_path_redacts_payload_and_keeps_auth_headers(tmp_path):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
        workers=2,
        rate_per_second=10,
    )
    payload = {
        "message": f"go-echo {SENT_SECRET}",
        "status": "ok",
        "data": [],
        "total": 0,
        "details": {"nested": [f"x{SENT_ACCESS}y", SAFE_MARKER]},
    }
    go = FakeGoTransport([BatchResult("0", payload=payload)])
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    provider = FDarkProvider(
        settings, Config(), cache=cache, go_transport=go, now_fn=lambda: NOW
    )
    target = _targets("go-fdark.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_ACCESS, SENT_SECRET)
    assert SAFE_MARKER in text
    assert SENT_SECRET in str(go.requests[0].headers.values())


def test_fdark_cacheless_sanitizes_observations_and_transport_errors():
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    target = _targets("cacheless-fdark.invalid")[0]
    response = {
        "message": f"cacheless {SENT_SECRET}",
        "status": "ok",
        "data": [
            {
                "md5": "e" * 32,
                "level": 2,
                "family": SAFE_FAMILY,
                "type": "pe",
                "lseen": int(NOW.timestamp()),
                "extra": f"fam-{SENT_ACCESS}",
            }
        ],
        "total": 1,
    }
    provider = FDarkProvider(
        settings,
        Config(),
        transport=ScriptedTransport([response]),
        cache=None,
        now_fn=lambda: NOW,
    )
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["family"] == SAFE_FAMILY
    _assert_sentinels_absent(_exportable_text(result), SENT_ACCESS, SENT_SECRET)

    err_provider = FDarkProvider(
        settings,
        Config(),
        transport=ScriptedTransport(
            [TransportError("http", f"upstream rejected {SENT_SECRET}")]
        ),
        cache=None,
        now_fn=lambda: NOW,
    )
    err_result = err_provider.collect([target], ProviderContext())
    assert err_result.statuses[target.normalized] == ProviderStatus.ERROR
    _assert_sentinels_absent(_exportable_text(err_result), SENT_ACCESS, SENT_SECRET)


def test_fdark_go_error_path_redacts_exception_text(tmp_path):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    go = FakeGoTransport(
        [BatchResult("0", error=RuntimeError(f"worker boom {SENT_SECRET}"))]
    )
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    provider = FDarkProvider(
        settings, Config(), cache=cache, go_transport=go, now_fn=lambda: NOW
    )
    target = _targets("go-err-fdark.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    _assert_sentinels_absent(_exportable_text(result, cache), SENT_ACCESS, SENT_SECRET)


def test_whois_live_redacts_echo_and_keeps_registrant(tmp_path):
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    response = {
        "code": 200,
        "status": "ok",
        "message": f"whois {SENT_SECRET}",
        "data": {
            "mergeStatus": True,
            "status": ["clientTransferProhibited"],
            "createdDate": ["2020-01-02 03:04:05"],
            "updatedDate": ["2026-01-02 03:04:05"],
            "expiresDate": ["2027-01-02 03:04:05"],
            "registrantName": [SAFE_REGISTRANT],
            "remark": f"r-{SENT_ACCESS}",
        },
    }
    transport = ScriptedTransport([response])
    cache = JsonlProviderCache(tmp_path / "cache", "whois", timedelta(days=1))
    provider = WhoisProvider(
        settings, transport=transport, cache=cache, now_fn=lambda: NOW
    )
    target = _targets("whois-echo.invalid")[0]
    result = provider.collect([target], ProviderContext())
    assert transport.calls[0]["headers"]["fdp-secret"] == SENT_SECRET
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["registrant"] == SAFE_REGISTRANT
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_ACCESS, SENT_SECRET)
    assert SAFE_REGISTRANT in text


def test_pdns_live_and_go_redact_echo(tmp_path):
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid/api/v1/passivedns/flint/rrset",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
        workers=2,
        rate_per_second=5,
    )
    record = {
        "rrtype": "A",
        "rdata": SAFE_RDATA,
        "count": 3,
        "time_first": int((NOW - timedelta(days=40)).timestamp()),
        "time_last": int((NOW - timedelta(days=1)).timestamp()),
        "note": f"pdns-{SENT_ACCESS}",
    }
    response = {
        "code": 200,
        "status": "ok",
        "message": f"pdns {SENT_SECRET}",
        "data": [record],
        "debug": {"echo": SENT_SECRET, "keep": SAFE_MARKER},
    }
    target = _targets("pdns-echo.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "pdns", timedelta(days=1))
    provider = PDNSProvider(
        settings,
        transport=ScriptedTransport([response]),
        cache=cache,
        now_fn=lambda: NOW,
    )
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["rdata"] == SAFE_RDATA
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_ACCESS, SENT_SECRET)
    assert SAFE_MARKER in text

    go_cache = JsonlProviderCache(tmp_path / "go-cache", "pdns", timedelta(days=1))
    go_provider = PDNSProvider(
        settings,
        cache=go_cache,
        go_transport=FakeGoTransport([BatchResult("0", payload=response)]),
        now_fn=lambda: NOW,
    )
    go_result = go_provider.collect([target], ProviderContext())
    assert go_result.statuses[target.normalized] == ProviderStatus.SUCCESS
    _assert_sentinels_absent(
        _exportable_text(go_result, go_cache), SENT_ACCESS, SENT_SECRET
    )


def test_ioc_info_live_redacts_echo_and_keeps_record_id(tmp_path):
    settings = ProviderSettings(
        name="ioc_info",
        base_url="https://ioc-info.invalid/api/v1/ioc/info",
        secrets={"Api-Key": SENT_API},
        ttl=timedelta(days=1),
    )
    target = _targets("ioc-info-echo.invalid")[0]
    response = {
        "message": f"info {SENT_API}",
        "data": {
            target.original: [
                {
                    "key": target.original,
                    "id": 7,
                    "updatetime": "2026-07-20 10:00:00",
                    "note": f"n-{SENT_API}",
                    "label": SAFE_MARKER,
                }
            ]
        },
        "details": ["x", {"echo": SENT_API}],
    }
    transport = ScriptedTransport([response])
    cache = JsonlProviderCache(tmp_path / "cache", "ioc_info", timedelta(days=1))
    provider = IOCInfoProvider(
        settings,
        transport=transport,
        cache=cache,
        max_attempts=1,
        sleep_fn=lambda _: None,
        now_fn=lambda: NOW,
    )
    result = provider.collect([target], ProviderContext())
    assert transport.calls[0]["headers"]["Api-Key"] == SENT_API
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["id"] == 7
    assert result.observations[0].payload["label"] == SAFE_MARKER
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_API)
    assert SAFE_MARKER in text


def test_k01_live_redacts_echo_in_raw_classification(tmp_path):
    settings = ProviderSettings(
        name="k01_compromise",
        base_url="https://k01.invalid",
        secrets={"Api-Key": SENT_API},
        ttl=timedelta(days=7),
    )
    target = _targets("k01-echo.invalid")[0]
    response = {
        "status": 10000,
        "msg": f"ok {SENT_API}",
        "data": {
            target.original: {
                "level": "malicious",
                "data": [
                    {
                        "ioc_host": target.original,
                        "tags": ["dga"],
                        "echo": SENT_API,
                        "keep": SAFE_MARKER,
                    }
                ],
            }
        },
        "debug": {"token": SENT_API},
    }
    transport = ScriptedTransport([response])
    cache = JsonlProviderCache(tmp_path / "cache", "k01_compromise", timedelta(days=7))
    provider = K01CompromiseProvider(
        settings,
        transport=transport,
        cache=cache,
        batch_size=10,
        now_fn=lambda: NOW,
    )
    result = provider.collect([target], ProviderContext())
    assert transport.calls[0]["headers"]["Api-Key"] == SENT_API
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["tags"] == ["dga"]
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_API)
    assert SAFE_MARKER in text


def test_icp_live_redacts_and_rejects_credential_registration(tmp_path):
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENT_UC, "key": SENT_KEY},
        ttl=timedelta(days=30),
        rate_per_second=1000,
        workers=2,
    )
    ok_response = {
        "resultObject": {"icp": SAFE_ICP},
        "message": f"m-{SENT_UC}",
        "debug": {"echo": SENT_KEY, "keep": SAFE_MARKER},
    }
    transport = ScriptedTransport([ok_response])
    cache = JsonlProviderCache(tmp_path / "cache", "icp", timedelta(days=30))
    provider = ICPProvider(
        settings,
        transport=transport,
        cache=cache,
        now_fn=lambda: NOW,
    )
    target = _targets("icp-echo.invalid")[0]
    secrets_before = dict(settings.secrets)
    result = provider.collect([target], ProviderContext())
    assert transport.calls[0]["params"]["uc"] == SENT_UC
    assert transport.calls[0]["params"]["key"] == SENT_KEY
    assert settings.secrets == secrets_before
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["registration"] == SAFE_ICP
    text = _exportable_text(result, cache)
    _assert_sentinels_absent(text, SENT_UC, SENT_KEY)
    assert SAFE_MARKER in text
    assert SAFE_ICP in text

    bad_cache = JsonlProviderCache(tmp_path / "bad-cache", "icp", timedelta(days=30))
    bad_provider = ICPProvider(
        settings,
        transport=ScriptedTransport(
            [{"resultObject": {"icp": f"rejected key={SENT_KEY}"}}]
        ),
        cache=bad_cache,
        now_fn=lambda: NOW,
    )
    bad_target = _targets("icp-bad-reg.invalid")[0]
    bad_result = bad_provider.collect([bad_target], ProviderContext())
    assert bad_result.statuses[bad_target.normalized] == ProviderStatus.ERROR
    assert bad_result.observations == []
    _assert_sentinels_absent(
        _exportable_text(bad_result, bad_cache), SENT_UC, SENT_KEY
    )


# ---------------------------------------------------------------------------
# Cached replay matrix (historical unredacted rows)
# ---------------------------------------------------------------------------


def _seed_raw_put(cache, ioc, raw, params, fetched_at):
    """Write historical cache bytes without provider value-redaction."""
    return cache.put(ioc, raw, params, fetched_at=fetched_at)


@pytest.mark.parametrize("freshness_mode", ["fresh", "stale_offline"])
def test_fdark_cache_replay_redacts_historical_echo(tmp_path, freshness_mode):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    target = _targets("replay-fdark.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    provider = FDarkProvider(
        settings, Config(), cache=cache, now_fn=lambda: NOW
    )
    strategy, query = provider.query_variants(target)[0]
    params = provider.cache_params(target, strategy, query)
    raw = {
        "message": f"hist {SENT_SECRET}",
        "status": "ok",
        "data": [
            {
                "md5": "a" * 32,
                "level": 1,
                "family": SAFE_FAMILY,
                "type": "elf",
                "lseen": int(NOW.timestamp()),
                "note": SENT_ACCESS,
            }
        ],
        "total": 1,
    }
    fetched = NOW if freshness_mode == "fresh" else STALE_AT
    _seed_raw_put(cache, target.original, raw, params, fetched)

    events = []
    context = ProviderContext(
        offline=True,
        on_progress=events.append,
    )
    result = provider.collect([target], context)
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["family"] == SAFE_FAMILY
    if freshness_mode == "fresh":
        assert result.observations[0].freshness == Freshness.FRESH
    else:
        assert result.observations[0].freshness == Freshness.STALE
    # Historical on-disk rows are intentionally not migrated; only replay
    # surfaces (observations/errors) must be sanitized.
    text = _exportable_text(result) + str(events)
    _assert_sentinels_absent(text, SENT_ACCESS, SENT_SECRET)
    # Historical on-disk row is intentionally not migrated:
    assert SENT_SECRET in cache.path.read_text(encoding="utf-8")


def test_whois_cache_replay_and_stale_fallback_redact(tmp_path):
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(hours=1),
    )
    target = _targets("replay-whois.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "whois", timedelta(hours=1))
    provider = WhoisProvider(settings, cache=cache, now_fn=lambda: NOW)
    raw = {
        "code": 200,
        "status": "ok",
        "message": f"cached {SENT_SECRET}",
        "data": {
            "mergeStatus": True,
            "status": ["ok"],
            "createdDate": ["2020-01-02 03:04:05"],
            "updatedDate": ["2026-01-02 03:04:05"],
            "expiresDate": ["2027-01-02 03:04:05"],
            "registrantName": [SAFE_REGISTRANT],
            "remark": SENT_ACCESS,
        },
    }
    _seed_raw_put(
        cache, target.host, raw, provider.cache_params(target), STALE_AT
    )

    offline = provider.collect([target], ProviderContext(offline=True))
    assert offline.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert offline.observations[0].payload["registrant"] == SAFE_REGISTRANT
    assert offline.observations[0].freshness == Freshness.STALE
    _assert_sentinels_absent(_exportable_text(offline), SENT_ACCESS, SENT_SECRET)

    live = WhoisProvider(
        settings,
        transport=ScriptedTransport(
            [TransportError("http", f"upstream {SENT_SECRET}")]
        ),
        cache=cache,
        now_fn=lambda: NOW,
    )
    fallback = live.collect([target], ProviderContext())
    assert fallback.statuses[target.normalized] == ProviderStatus.ERROR
    assert any(obs.freshness == Freshness.STALE for obs in fallback.observations)
    assert any(
        obs.payload.get("registrant") == SAFE_REGISTRANT for obs in fallback.observations
    )
    _assert_sentinels_absent(_exportable_text(fallback), SENT_ACCESS, SENT_SECRET)


def test_pdns_cache_replay_redacts_historical_echo(tmp_path):
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid/api/v1/passivedns/flint/rrset",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    target = _targets("replay-pdns.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "pdns", timedelta(days=1))
    provider = PDNSProvider(settings, cache=cache, now_fn=lambda: NOW)
    raw = {
        "code": 200,
        "status": "ok",
        "message": SENT_SECRET,
        "data": [
            {
                "rrtype": "A",
                "rdata": SAFE_RDATA,
                "count": 2,
                "time_first": int((NOW - timedelta(days=40)).timestamp()),
                "time_last": int((NOW - timedelta(days=1)).timestamp()),
                "note": SENT_ACCESS,
            }
        ],
    }
    _seed_raw_put(cache, target.host, raw, provider.cache_params(target), NOW)
    result = provider.collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["rdata"] == SAFE_RDATA
    # Historical disk row stays; only replay surfaces must be sanitized.
    _assert_sentinels_absent(_exportable_text(result), SENT_ACCESS, SENT_SECRET)


def test_ioc_info_cache_replay_redacts_historical_echo(tmp_path):
    settings = ProviderSettings(
        name="ioc_info",
        base_url="https://ioc-info.invalid/api/v1/ioc/info",
        secrets={"Api-Key": SENT_API},
        ttl=timedelta(days=1),
    )
    target = _targets("replay-ioc-info.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "ioc_info", timedelta(days=1))
    provider = IOCInfoProvider(
        settings,
        cache=cache,
        max_attempts=1,
        sleep_fn=lambda _: None,
        now_fn=lambda: NOW,
    )
    raw = {
        "message": SENT_API,
        "data": {
            target.original: [
                {
                    "key": target.original,
                    "id": 99,
                    "label": SAFE_MARKER,
                    "note": f"n-{SENT_API}",
                }
            ]
        },
    }
    _seed_raw_put(cache, target.original, raw, provider.cache_params(target), NOW)
    result = provider.collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["id"] == 99
    assert result.observations[0].payload["label"] == SAFE_MARKER
    _assert_sentinels_absent(_exportable_text(result), SENT_API)


def test_k01_cache_replay_redacts_raw_classification(tmp_path):
    settings = ProviderSettings(
        name="k01_compromise",
        base_url="https://k01.invalid",
        secrets={"Api-Key": SENT_API},
        ttl=timedelta(days=7),
    )
    target = _targets("replay-k01.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "k01_compromise", timedelta(days=7))
    provider = K01CompromiseProvider(
        settings, cache=cache, batch_size=10, now_fn=lambda: NOW
    )
    raw = {
        "status": 10000,
        "msg": f"ok {SENT_API}",
        "data": {
            target.original: {
                "level": "malicious",
                "data": [
                    {
                        "ioc_host": target.original,
                        "tags": ["dga"],
                        "echo": SENT_API,
                        "keep": SAFE_MARKER,
                    }
                ],
            }
        },
    }
    _seed_raw_put(cache, target.original, raw, provider.cache_params(target), NOW)
    result = provider.collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert result.observations[0].payload["tags"] == ["dga"]
    _assert_sentinels_absent(_exportable_text(result), SENT_API)
    assert SAFE_MARKER in _exportable_text(result)


def test_icp_cache_replay_rejects_secret_registration_and_redacts_echo(tmp_path):
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENT_UC, "key": SENT_KEY},
        ttl=timedelta(days=30),
        rate_per_second=1000,
    )
    good_target = _targets("replay-icp-good.invalid")[0]
    bad_target = _targets("replay-icp-bad.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "icp", timedelta(days=30))
    provider = ICPProvider(settings, cache=cache, now_fn=lambda: NOW)

    _seed_raw_put(
        cache,
        good_target.host,
        {
            "resultObject": {"icp": SAFE_ICP},
            "debug": {"echo": SENT_KEY, "keep": SAFE_MARKER},
        },
        provider.cache_params(good_target.host),
        NOW,
    )
    _seed_raw_put(
        cache,
        bad_target.host,
        {"resultObject": {"icp": f"leak-{SENT_KEY}"}},
        provider.cache_params(bad_target.host),
        NOW,
    )

    good = provider.collect([good_target], ProviderContext(offline=True))
    assert good.statuses[good_target.normalized] == ProviderStatus.SUCCESS
    assert good.observations[0].payload["registration"] == SAFE_ICP
    _assert_sentinels_absent(_exportable_text(good), SENT_UC, SENT_KEY)

    bad = provider.collect([bad_target], ProviderContext(offline=True))
    assert bad.statuses[bad_target.normalized] == ProviderStatus.ERROR
    assert bad.observations == []
    _assert_sentinels_absent(_exportable_text(bad), SENT_UC, SENT_KEY)


def test_icp_stale_fallback_after_transport_error_redacts(tmp_path):
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": SENT_UC, "key": SENT_KEY},
        ttl=timedelta(hours=1),
        rate_per_second=1000,
    )
    target = _targets("stale-icp.invalid")[0]
    cache = JsonlProviderCache(tmp_path / "cache", "icp", timedelta(hours=1))
    _seed_raw_put(
        cache,
        target.host,
        {
            "resultObject": {"icp": SAFE_ICP},
            "debug": {"echo": SENT_UC},
        },
        {"endpoint": settings.base_url, "host": target.host},
        STALE_AT,
    )
    provider = ICPProvider(
        settings,
        transport=ScriptedTransport(
            [TransportError("timeout", f"timeout {SENT_KEY}")]
        ),
        cache=cache,
        now_fn=lambda: NOW,
    )
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.observations) == 1
    assert result.observations[0].freshness == Freshness.STALE
    assert result.observations[0].payload["registration"] == SAFE_ICP
    _assert_sentinels_absent(_exportable_text(result), SENT_UC, SENT_KEY)


# ---------------------------------------------------------------------------
# Persisted query metadata + diagnostics + store paths
# ---------------------------------------------------------------------------


def test_fdark_store_redacts_credential_in_query_metadata(tmp_path):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    cache = JsonlProviderCache(tmp_path / "cache", "fdark", timedelta(days=1))
    provider = FDarkProvider(
        settings, Config(), cache=cache, now_fn=lambda: NOW
    )
    target = _targets("meta-fdark.invalid")[0]
    query = {"domain": "meta-fdark.invalid", "note": SENT_SECRET, "keep": SAFE_MARKER}
    params = provider.cache_params(target, "domain", query)
    expected_key = cache.key(target.original, params)
    raw_ref, err = provider._store_response(
        target,
        "domain",
        query,
        {"status": "ok", "data": [], "message": SAFE_MARKER},
        NOW,
    )
    assert err is None
    assert raw_ref.endswith(expected_key)
    disk = cache.path.read_text(encoding="utf-8")
    _assert_sentinels_absent(disk, SENT_SECRET, SENT_ACCESS)
    assert SAFE_MARKER in disk
    assert cache.get(target.original, params, now=NOW) is not None


def test_all_six_store_response_paths_redact_directly(tmp_path):
    cases = []

    fdark_cache = JsonlProviderCache(tmp_path / "fdark", "fdark", timedelta(days=1))
    fdark = FDarkProvider(
        ProviderSettings(
            name="fdark",
            base_url="https://fdark.invalid/api",
            secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
            ttl=timedelta(days=1),
        ),
        Config(),
        cache=fdark_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "fdark",
            fdark_cache,
            lambda: fdark._store_response(
                _targets("s.invalid")[0],
                "domain",
                {"domain": "s.invalid"},
                {"message": SENT_SECRET, "keep": SAFE_MARKER},
                NOW,
            ),
            (SENT_ACCESS, SENT_SECRET),
        )
    )

    whois_cache = JsonlProviderCache(tmp_path / "whois", "whois", timedelta(days=1))
    whois = WhoisProvider(
        ProviderSettings(
            name="whois",
            base_url="https://whois.invalid/v3/whois/detail",
            secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
            ttl=timedelta(days=1),
        ),
        cache=whois_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "whois",
            whois_cache,
            lambda: whois._store_response(
                _targets("s.invalid")[0],
                {"message": SENT_SECRET, "keep": SAFE_MARKER},
                NOW,
            ),
            (SENT_ACCESS, SENT_SECRET),
        )
    )

    pdns_cache = JsonlProviderCache(tmp_path / "pdns", "pdns", timedelta(days=1))
    pdns = PDNSProvider(
        ProviderSettings(
            name="pdns",
            base_url="https://pdns.invalid/api",
            secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
            ttl=timedelta(days=1),
        ),
        cache=pdns_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "pdns",
            pdns_cache,
            lambda: pdns._store_response(
                _targets("s.invalid")[0],
                {"message": SENT_SECRET, "keep": SAFE_MARKER},
                NOW,
            ),
            (SENT_ACCESS, SENT_SECRET),
        )
    )

    ioc_cache = JsonlProviderCache(tmp_path / "ioc_info", "ioc_info", timedelta(days=1))
    ioc = IOCInfoProvider(
        ProviderSettings(
            name="ioc_info",
            base_url="https://ioc-info.invalid/api",
            secrets={"Api-Key": SENT_API},
            ttl=timedelta(days=1),
        ),
        cache=ioc_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "ioc_info",
            ioc_cache,
            lambda: ioc._store_response(
                _targets("s.invalid")[0],
                {"message": SENT_API, "keep": SAFE_MARKER},
                NOW,
            ),
            (SENT_API,),
        )
    )

    k01_cache = JsonlProviderCache(
        tmp_path / "k01", "k01_compromise", timedelta(days=7)
    )
    k01 = K01CompromiseProvider(
        ProviderSettings(
            name="k01_compromise",
            base_url="https://k01.invalid",
            secrets={"Api-Key": SENT_API},
            ttl=timedelta(days=7),
        ),
        cache=k01_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "k01_compromise",
            k01_cache,
            lambda: k01._store_response(
                _targets("s.invalid")[0],
                {"msg": SENT_API, "keep": SAFE_MARKER, "status": 10000, "data": {}},
                NOW,
            ),
            (SENT_API,),
        )
    )

    icp_cache = JsonlProviderCache(tmp_path / "icp", "icp", timedelta(days=30))
    icp = ICPProvider(
        ProviderSettings(
            name="icp",
            base_url="https://icp.invalid/api",
            secrets={"uc": SENT_UC, "key": SENT_KEY},
            ttl=timedelta(days=30),
        ),
        cache=icp_cache,
        now_fn=lambda: NOW,
    )
    cases.append(
        (
            "icp",
            icp_cache,
            lambda: icp._store(
                "s.invalid",
                {"message": SENT_KEY, "keep": SAFE_MARKER},
                NOW,
            ),
            (SENT_UC, SENT_KEY),
        )
    )

    for name, cache, store_fn, sentinels in cases:
        raw_ref, cache_error = store_fn()
        assert cache_error is None, name
        assert raw_ref
        text = cache.path.read_text(encoding="utf-8")
        _assert_sentinels_absent(text, *sentinels)
        assert SAFE_MARKER in text


@pytest.mark.parametrize(
    "provider_name,builder",
    [
        (
            "fdark",
            lambda tmp, secrets: FDarkProvider(
                ProviderSettings(
                    name="fdark",
                    base_url="https://fdark.invalid/api",
                    secrets=secrets,
                    ttl=timedelta(days=1),
                ),
                Config(),
                cache=JsonlProviderCache(tmp, "fdark", timedelta(days=1)),
                now_fn=lambda: NOW,
            ),
        ),
        (
            "whois",
            lambda tmp, secrets: WhoisProvider(
                ProviderSettings(
                    name="whois",
                    base_url="https://whois.invalid/v3/whois/detail",
                    secrets=secrets,
                    ttl=timedelta(days=1),
                ),
                cache=JsonlProviderCache(tmp, "whois", timedelta(days=1)),
                now_fn=lambda: NOW,
            ),
        ),
        (
            "pdns",
            lambda tmp, secrets: PDNSProvider(
                ProviderSettings(
                    name="pdns",
                    base_url="https://pdns.invalid/api",
                    secrets=secrets,
                    ttl=timedelta(days=1),
                ),
                cache=JsonlProviderCache(tmp, "pdns", timedelta(days=1)),
                now_fn=lambda: NOW,
            ),
        ),
        (
            "ioc_info",
            lambda tmp, secrets: IOCInfoProvider(
                ProviderSettings(
                    name="ioc_info",
                    base_url="https://ioc-info.invalid/api",
                    secrets=secrets,
                    ttl=timedelta(days=1),
                ),
                cache=JsonlProviderCache(tmp, "ioc_info", timedelta(days=1)),
                now_fn=lambda: NOW,
            ),
        ),
        (
            "k01_compromise",
            lambda tmp, secrets: K01CompromiseProvider(
                ProviderSettings(
                    name="k01_compromise",
                    base_url="https://k01.invalid",
                    secrets=secrets,
                    ttl=timedelta(days=7),
                ),
                cache=JsonlProviderCache(tmp, "k01_compromise", timedelta(days=7)),
                now_fn=lambda: NOW,
            ),
        ),
        (
            "icp",
            lambda tmp, secrets: ICPProvider(
                ProviderSettings(
                    name="icp",
                    base_url="https://icp.invalid/api",
                    secrets=secrets,
                    ttl=timedelta(days=30),
                ),
                cache=JsonlProviderCache(tmp, "icp", timedelta(days=30)),
                now_fn=lambda: NOW,
            ),
        ),
    ],
)
def test_cache_write_failure_message_is_redacted(tmp_path, provider_name, builder, monkeypatch):
    if provider_name in {"fdark", "whois", "pdns"}:
        secrets = {"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET}
        sentinels = (SENT_ACCESS, SENT_SECRET)
    elif provider_name == "icp":
        secrets = {"uc": SENT_UC, "key": SENT_KEY}
        sentinels = (SENT_UC, SENT_KEY)
    else:
        secrets = {"Api-Key": SENT_API}
        sentinels = (SENT_API,)

    provider = builder(tmp_path / provider_name, secrets)
    sentinel = sentinels[0]

    def boom(*args, **kwargs):
        raise OSError(f"disk full while writing {sentinel}")

    monkeypatch.setattr(provider.cache, "put", boom)
    target = _targets("fail.invalid")[0]
    if provider_name == "fdark":
        raw_ref, err = provider._store_response(
            target, "domain", {"domain": "fail.invalid"}, {"ok": True}, NOW
        )
    elif provider_name == "icp":
        raw_ref, err = provider._store(target.host, {"ok": True}, NOW)
    else:
        raw_ref, err = provider._store_response(target, {"ok": True}, NOW)
    assert raw_ref == ""
    assert err is not None
    _assert_sentinels_absent(err, *sentinels)


def test_cache_diagnostics_messages_are_sanitized(tmp_path, monkeypatch):
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": SENT_ACCESS, "fdp-secret": SENT_SECRET},
        ttl=timedelta(days=1),
    )
    cache = JsonlProviderCache(tmp_path / "cache", "whois", timedelta(days=1))
    provider = WhoisProvider(
        settings,
        transport=ScriptedTransport(
            [
                {
                    "code": 200,
                    "status": "ok",
                    "data": {
                        "mergeStatus": True,
                        "status": [],
                        "createdDate": ["2020-01-02 03:04:05"],
                        "updatedDate": ["2026-01-02 03:04:05"],
                        "expiresDate": ["2027-01-02 03:04:05"],
                        "registrantName": [SAFE_REGISTRANT],
                    },
                }
            ]
        ),
        cache=cache,
        now_fn=lambda: NOW,
    )
    target = _targets("diag-whois.invalid")[0]

    original_get = cache.get

    def noisy_get(*args, **kwargs):
        result = original_get(*args, **kwargs)
        # get() itself may surface read diagnostics that echo secret material.
        cache.diagnostics = [f"index rebuild touched {SENT_SECRET}"]
        return result

    monkeypatch.setattr(cache, "get", noisy_get)
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    joined = "\n".join(result.errors)
    assert any(item.startswith("cache:") for item in result.errors)
    _assert_sentinels_absent(joined, SENT_ACCESS, SENT_SECRET)
