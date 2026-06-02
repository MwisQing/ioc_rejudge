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
