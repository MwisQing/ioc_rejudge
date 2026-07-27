import pytest

from ioc_rejudge.config import Config, load_config


def test_default_config():
    c = Config()
    assert c.activity_window_days == 365
    assert c.hash_malicious_level == 40
    assert c.relate_url_malicious_level == 40
    assert c.historical_malicious_level == 40
    assert c.high_level_no_a_threshold == 70


def test_load_config_defaults():
    c = load_config()
    assert c.activity_window_days == 365


def test_load_config_overrides():
    c = load_config(activity_window_days=730, hash_malicious_level=50)
    assert c.activity_window_days == 730
    assert c.hash_malicious_level == 50
    assert c.relate_url_malicious_level == 40


# ── DGA pDNS config ──

def test_dga_pdns_recent_days_default():
    c = Config()
    assert c.dga_pdns_recent_days == 30


def test_dga_pdns_recent_days_override():
    c = Config(dga_pdns_recent_days=14)
    assert c.dga_pdns_recent_days == 14


def test_load_config_dga_pdns_recent_days_default():
    c = load_config()
    assert c.dga_pdns_recent_days == 30


def test_load_config_dga_pdns_recent_days_override():
    c = load_config(dga_pdns_recent_days=14)
    assert c.dga_pdns_recent_days == 14


def test_load_config_dga_override_does_not_break_existing_fields():
    c = load_config(dga_pdns_recent_days=14, activity_window_days=730)
    assert c.dga_pdns_recent_days == 14
    assert c.activity_window_days == 730
    assert c.hash_malicious_level == 40


def test_provider_workers_default_override_and_validation():
    assert Config().provider_workers == 5
    assert Config(provider_workers=2).provider_workers == 2
    assert load_config(provider_workers=3).provider_workers == 3

    for value in (0, -1, True, "2"):
        with pytest.raises((TypeError, ValueError)):
            Config(provider_workers=value)
