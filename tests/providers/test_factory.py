"""Live provider factory configuration and secret-safety tests."""

import json
from datetime import timedelta

import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import ProviderStatus
from ioc_rejudge.providers.base import ProviderContext
from ioc_rejudge.providers.factory import (
    DEFAULT_PROVIDERS,
    SUPPORTED_PROVIDERS,
    build_providers,
    load_credentials_file,
    load_local_config,
    load_result_cache_settings,
    parse_provider_names,
)


SENTINEL = "SENTINEL_FACTORY_SECRET_7f21"


class NoCallTransport:
    def __init__(self):
        self.calls = []

    def get_json(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("network transport must not be called")

    def post_json(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("network transport must not be called")


class StaticGetTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get_json(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response


def _full_env(secret=SENTINEL):
    return {
        "IOC_INFO_API_KEY": f"ioc-{secret}",
        "IOC_INFO_URL": "https://ioc-info.invalid/api/v1/ioc/info",
        "K01_COMPROMISE_API_KEY": f"k01-{secret}",
        "K01_COMPROMISE_URL": "https://k01.invalid",
        "FDP_ACCESS": f"fdp-access-{secret}",
        "FDP_SECRET": f"fdp-secret-{secret}",
        "FDARK_URL": "https://fdark.invalid/api/v1/fdark/abstract",
        "WHOIS_ACCESS": f"whois-access-{secret}",
        "WHOIS_SECRET": f"whois-secret-{secret}",
        "WHOIS_URL": "https://whois.invalid/v3/whois/detail",
        "PDNS_ACCESS": f"pdns-access-{secret}",
        "PDNS_SECRET": f"pdns-secret-{secret}",
        "PDNS_URL": "https://pdns.invalid/api/v1/passivedns/flint/rrset",
        "ICP_UC": f"icp-uc-{secret}",
        "ICP_KEY": f"icp-key-{secret}",
        "ICP_URL": "https://icp.invalid/v2/open-api/icp-info",
    }


def test_default_and_explicit_provider_name_parsing():
    assert DEFAULT_PROVIDERS == (
        "k01_compromise",
        "ioc_info",
        "fdark",
        "whois",
        "pdns",
        "icp",
    )
    assert parse_provider_names(None) == list(DEFAULT_PROVIDERS)
    assert SUPPORTED_PROVIDERS == DEFAULT_PROVIDERS
    assert parse_provider_names("icp") == ["icp"]
    assert parse_provider_names("whois,pdns") == ["whois", "pdns"]
    assert parse_provider_names(["pdns", "whois"]) == ["pdns", "whois"]
    with pytest.raises(ValueError, match="unknown provider"):
        parse_provider_names("unknown")
    with pytest.raises(ValueError, match="duplicate provider"):
        parse_provider_names("whois,whois")
    with pytest.raises(ValueError, match="must not be empty"):
        parse_provider_names("")


def test_environment_builds_all_enabled_providers_with_exact_secret_sources():
    providers = build_providers(env=_full_env(), adjudication_config=Config())
    assert [provider.name for provider in providers] == list(DEFAULT_PROVIDERS)
    by_name = {provider.name: provider for provider in providers}
    assert all(provider.settings.enabled for provider in providers)
    by_name = {provider.name: provider for provider in providers}
    assert by_name["ioc_info"].settings.secrets == {
        "Api-Key": f"ioc-{SENTINEL}"
    }
    assert by_name["k01_compromise"].settings.secrets == {
        "Api-Key": f"k01-{SENTINEL}"
    }
    assert by_name["fdark"].settings.secrets == {
        "fdp-access": f"fdp-access-{SENTINEL}",
        "fdp-secret": f"fdp-secret-{SENTINEL}",
    }
    assert by_name["whois"].settings.secrets["fdp-access"].startswith(
        "whois-access"
    )
    assert by_name["pdns"].settings.secrets["fdp-access"].startswith(
        "pdns-access"
    )
    assert SENTINEL not in repr(providers)


def test_credentials_file_is_an_explicit_secret_source_without_environment_fallback(tmp_path):
    path = tmp_path / "credentials.local.json"
    credentials = {
        "K01_COMPROMISE_API_KEY": f"k01-{SENTINEL}",
        "IOC_INFO_API_KEY": f"ioc-{SENTINEL}",
        "FDP_ACCESS": f"access-{SENTINEL}",
        "FDP_SECRET": f"secret-{SENTINEL}",
    }
    path.write_text(json.dumps(credentials), encoding="utf-8")

    loaded = load_credentials_file(path)
    assert loaded == credentials
    providers = build_providers(
        credentials_path=path,
        adjudication_config=Config(),
    )

    by_name = {provider.name: provider for provider in providers}
    assert all(
        provider.settings.enabled
        for name, provider in by_name.items()
        if name != "icp"
    )
    assert by_name["icp"].settings.enabled is False
    assert SENTINEL not in repr(providers)


@pytest.mark.parametrize(
    "payload,match",
    [
        ([], "JSON object"),
        ({"UNKNOWN_SECRET": "value"}, "unknown credentials file key"),
        ({"FDP_SECRET": 123}, "must be a string"),
    ],
)
def test_credentials_file_rejects_invalid_shapes_without_echoing_values(
    tmp_path, payload, match
):
    path = tmp_path / "credentials.local.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=match) as exc:
        load_credentials_file(path)
    assert SENTINEL not in str(exc.value)


def test_credentials_file_and_explicit_env_are_mutually_exclusive(tmp_path):
    path = tmp_path / "credentials.local.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot be used together"):
        build_providers(env={}, credentials_path=path)


def test_whois_and_pdns_fall_back_to_shared_fdp_credentials():
    env = {
        "FDP_ACCESS": f"shared-access-{SENTINEL}",
        "FDP_SECRET": f"shared-secret-{SENTINEL}",
    }
    providers = build_providers(
        ["whois", "pdns"], env=env, adjudication_config=Config()
    )
    assert all(provider.settings.enabled for provider in providers)
    for provider in providers:
        assert provider.settings.secrets == {
            "fdp-access": f"shared-access-{SENTINEL}",
            "fdp-secret": f"shared-secret-{SENTINEL}",
        }


def test_local_json_overrides_only_non_secret_options(tmp_path):
    path = tmp_path / "providers.json"
    path.write_text(json.dumps({
        "providers": {
            "fdark": {
                "url": "https://override.invalid/fdark",
                "timeout": 4,
                "ttl_hours": 12,
                "include_slow_variants": True,
                "include_url_param": True,
                "query_params": {"limit": 5, "order": "fseen-"},
            },
            "pdns": {"enabled": False},
        }
    }), encoding="utf-8")
    loaded = load_local_config(path)
    assert loaded["fdark"]["timeout"] == 4

    providers = build_providers(
        ["fdark", "pdns"],
        env=_full_env(),
        config_path=path,
        adjudication_config=Config(),
    )
    fdark, pdns = providers
    assert fdark.settings.base_url == "https://override.invalid/fdark"
    assert fdark.settings.timeout == 4
    assert fdark.settings.ttl == timedelta(hours=12)
    assert fdark.include_slow_variants is True
    assert fdark.include_url_param is True
    assert fdark.query_params["limit"] == 5
    assert pdns.settings.enabled is False


def test_result_cache_config_defaults_to_seven_days_and_can_be_overridden(tmp_path):
    defaults = load_result_cache_settings(None)
    assert defaults.enabled is True
    assert defaults.ttl == timedelta(days=7)

    path = tmp_path / "providers.json"
    path.write_text(json.dumps({
        "result_cache": {"enabled": False, "ttl_days": 3},
        "providers": {},
    }), encoding="utf-8")
    configured = load_result_cache_settings(path)
    assert configured.enabled is False
    assert configured.ttl == timedelta(days=3)


@pytest.mark.parametrize(
    "bad_config,match",
    [
        ({"providers": {"fdark": {"fdp_secret": "forbidden"}}}, "secret"),
        ({"providers": {"fdark": {"unknown": 1}}}, "unknown option"),
        ({"providers": {"unknown": {"enabled": True}}}, "unknown provider"),
        ({"unexpected": {}}, "top-level"),
        ({"providers": []}, "must be an object"),
    ],
)
def test_bad_or_secret_bearing_local_config_is_rejected(tmp_path, bad_config, match):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad_config), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_local_config(path)


def test_missing_credentials_disable_each_provider_independently():
    providers = build_providers(env={}, adjudication_config=Config())
    assert [provider.name for provider in providers] == list(DEFAULT_PROVIDERS)
    assert all(provider.settings.enabled is False for provider in providers)
    assert all("missing required credentials" in provider.disabled_reason for provider in providers)
    assert SENTINEL not in repr(providers)


def test_all_providers_default_to_seven_days_except_icp_thirty_days():
    defaults = build_providers(env=_full_env(), adjudication_config=Config())
    assert {provider.name: provider.settings.ttl for provider in defaults} == {
        "k01_compromise": timedelta(days=7),
        "ioc_info": timedelta(days=7),
        "fdark": timedelta(days=7),
        "whois": timedelta(days=7),
        "pdns": timedelta(days=7),
        "icp": timedelta(days=30),
    }
    icp = next(provider for provider in defaults if provider.name == "icp")
    assert icp.settings.enabled is True
    assert icp.settings.ttl == timedelta(days=30)
    assert icp.settings.workers == 2
    assert icp.settings.rate_per_second == 2
    assert icp.settings.secrets == {"uc": f"icp-uc-{SENTINEL}", "key": f"icp-key-{SENTINEL}"}


def test_icp_online_missing_credentials_is_disabled_without_transport():
    sentinel_transport = NoCallTransport()
    provider = build_providers(
        ["icp"], env={"ICP_UC": "only-uc"}, adjudication_config=Config(),
        transport_factory=lambda name: sentinel_transport,
    )[0]
    assert provider.settings.enabled is False
    target = read_input_bundle(None, ["missing-icp.invalid"]).targets[0]
    result = provider.collect([target], ProviderContext())
    assert result.statuses[target.normalized] == ProviderStatus.DISABLED
    assert sentinel_transport.calls == []


def test_icp_reflected_credentials_are_redacted_from_cache_and_run_raw(tmp_path):
    env = _full_env()
    transport = StaticGetTransport({
        "resultObject": {"icp": "ICP-SAFE"},
        "debug": {
            "uc_echo": env["ICP_UC"],
            "request_key": env["ICP_KEY"],
        },
    })
    provider = build_providers(
        ["icp"],
        env=env,
        cache_dir=tmp_path / "cache",
        run_dir=tmp_path / "run",
        adjudication_config=Config(),
        transport_factory=lambda name: transport,
    )[0]
    target = read_input_bundle(None, ["factory-reflected.invalid"]).targets[0]

    result = provider.collect([target], ProviderContext())

    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert env["ICP_UC"] not in persisted
    assert env["ICP_KEY"] not in persisted


def test_invalid_url_with_userinfo_or_query_is_rejected(tmp_path):
    path = tmp_path / "bad-url.json"
    path.write_text(json.dumps({
        "providers": {"whois": {"url": "https://user:pass@whois.invalid/a?key=x"}}
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="userinfo|query"):
        build_providers(
            ["whois"],
            env=_full_env(),
            config_path=path,
            adjudication_config=Config(),
        )


def test_cache_dir_and_run_dir_receive_raw_without_credentials(tmp_path):
    cache_dir = tmp_path / "cache"
    run_dir = tmp_path / "run"
    provider = build_providers(
        ["whois"],
        env=_full_env(),
        cache_dir=cache_dir,
        run_dir=run_dir,
        adjudication_config=Config(),
    )[0]
    target = read_input_bundle(None, ["audit.invalid"]).targets[0]
    raw = {"code": 200, "status": "ok", "data": {"expiresDate": ["2027-01-01"]}}
    provider.cache.put(target.host, raw, provider.cache_params(target))

    assert list((cache_dir / ".cache_whois").glob("cache_*.jsonl"))
    assert list((run_dir / "raw" / ".cache_whois").glob("cache_*.jsonl"))
    all_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert SENTINEL not in all_text


def test_offline_factory_reads_cache_without_credentials_and_never_uses_transport(tmp_path):
    cache_dir = tmp_path / "cache"
    target = read_input_bundle(None, ["offline.invalid"]).targets[0]
    online = build_providers(
        ["whois"],
        env=_full_env(),
        cache_dir=cache_dir,
        adjudication_config=Config(),
    )[0]
    online.cache.put(
        target.host,
        {"code": 200, "status": "ok", "data": {"expiresDate": ["2027-01-01"]}},
        online.cache_params(target),
    )
    sentinel_transport = NoCallTransport()
    offline = build_providers(
        ["whois"],
        env={"WHOIS_URL": _full_env()["WHOIS_URL"]},
        cache_dir=cache_dir,
        adjudication_config=Config(),
        offline=True,
        transport_factory=lambda name: sentinel_transport,
    )[0]
    assert offline.settings.enabled is True
    result = offline.collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert sentinel_transport.calls == []
