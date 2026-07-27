"""Provider settings safety and validation tests."""

from datetime import timedelta

import pytest

from ioc_rejudge.providers.settings import ProviderSettings


def test_settings_defaults_match_provider_contract():
    settings = ProviderSettings(name="whois", base_url="https://api.invalid")
    assert settings.secrets == {}
    assert settings.timeout == 30
    assert settings.workers == 10
    assert settings.rate_per_second == 20
    assert settings.ttl == timedelta(days=1)
    assert settings.enabled is True


def test_settings_repr_and_str_do_not_expose_secret_values():
    sentinel = "SENTINEL_PROVIDER_SECRET_4f93"
    settings = ProviderSettings(
        name="ioc_info",
        base_url="https://api.invalid",
        secrets={"Api-Key": sentinel, "Authorization": f"Bearer {sentinel}"},
    )
    assert sentinel not in repr(settings)
    assert sentinel not in str(settings)
    assert "secrets" not in repr(settings)
    assert "ioc_info" in repr(settings)


def test_settings_secret_defaults_are_isolated():
    first = ProviderSettings(name="first", base_url="https://first.invalid")
    second = ProviderSettings(name="second", base_url="https://second.invalid")
    first.secrets["token"] = "one"
    assert second.secrets == {}


def test_settings_public_dict_omits_secrets():
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid",
        secrets={"token": "do-not-export"},
    )
    public = settings.public_dict()
    assert "secrets" not in public
    assert "do-not-export" not in repr(public)
    assert public["ttl_seconds"] == 86400.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "base_url": "https://api.invalid"},
        {"name": "x", "base_url": ""},
        {"name": "x", "base_url": "https://api.invalid", "timeout": 0},
        {"name": "x", "base_url": "https://api.invalid", "workers": 0},
        {"name": "x", "base_url": "https://api.invalid", "rate_per_second": 0},
        {"name": "x", "base_url": "https://api.invalid", "ttl": timedelta(seconds=-1)},
    ],
)
def test_settings_reject_invalid_runtime_values(kwargs):
    with pytest.raises(ValueError):
        ProviderSettings(**kwargs)
