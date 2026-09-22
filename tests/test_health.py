"""Focused health checks."""

import importlib.util
import json
from pathlib import Path

from urllib.error import HTTPError

_HEALTH_PATH = Path(__file__).resolve().parents[1] / "ioc_rejudge" / "health.py"
_HEALTH_SPEC = importlib.util.spec_from_file_location("health_under_test", _HEALTH_PATH)
health = importlib.util.module_from_spec(_HEALTH_SPEC)
_HEALTH_SPEC.loader.exec_module(health)
check_configuration = health.check_configuration
probe_provider_health = health.probe_provider_health


def test_check_configuration_reports_missing_optionals_without_network():
    result = check_configuration(["alpha"])
    provider = result["providers"]["alpha"]

    assert result["overall_status"] == "warn"
    assert provider["status"] == "warn"
    assert provider["checks"]["configuration"] == {"status": "ok"}
    assert provider["checks"]["credentials"] == {
        "status": "missing",
        "credential_name": "alpha_API_KEY",
    }
    assert provider["checks"]["endpoint"] == {"status": "missing"}
    assert provider["checks"]["cache"]["status"] == "warn"
    assert provider["checks"]["transport"] == {"status": "not_probed"}


def test_check_configuration_accepts_valid_inputs_and_creatable_cache(tmp_path):
    result = check_configuration(
        ["alpha"],
        credentials={"alpha": "secret-value"},
        endpoints={"alpha": "https://alpha.example.test"},
        cache_root=tmp_path / "cache",
    )
    checks = result["providers"]["alpha"]["checks"]

    assert result["overall_status"] == "ok"
    assert result["providers"]["alpha"]["status"] == "ok"
    assert checks["credentials"]["status"] == "present"
    assert checks["endpoint"]["status"] == "ok"
    assert checks["cache"]["status"] == "ok"
    assert checks["transport"]["status"] == "not_probed"


def test_check_configuration_rejects_endpoint_without_http_host():
    result = check_configuration(
        ["alpha"],
        endpoints={"alpha": "ftp://alpha.example.test"},
    )

    assert result["overall_status"] == "error"
    assert result["providers"]["alpha"]["status"] == "error"
    assert result["providers"]["alpha"]["checks"]["endpoint"] == {
        "status": "error",
        "reason": "invalid_endpoint",
    }


def test_probe_provider_health_calls_only_injected_transport():
    calls = []

    class Transport:
        def get_json(self, endpoint, timeout):
            calls.append((endpoint, timeout))
            return {"ok": True}

    secret = "secret-value"
    result = probe_provider_health(
        ["alpha"],
        endpoints={"alpha": "https://alpha.example.test"},
        credentials={"alpha": secret},
        transport=Transport(),
    )
    checks = result["providers"]["alpha"]["checks"]

    assert calls == [("https://alpha.example.test", 5)]
    assert result["overall_status"] == "ok"
    assert checks["transport"] == {"status": "ok"}
    assert checks["cache"] == {"status": "not_probed"}
    assert secret not in json.dumps(result)


def test_probe_provider_health_respects_offline_and_classifies_errors():
    class Transport:
        def __init__(self, exc):
            self.exc = exc

        def get_json(self, endpoint, timeout):
            raise self.exc

    offline_result = probe_provider_health(
        ["alpha"],
        endpoints={"alpha": "https://alpha.example.test"},
        transport=Transport(RuntimeError("hidden")),
        offline=True,
    )
    assert offline_result["providers"]["alpha"]["checks"]["transport"] == {
        "status": "not_probed"
    }

    cases = [
        (TimeoutError(), "timeout"),
        (ConnectionError(), "connection"),
        (HTTPError("https://alpha.example.test", 503, "hidden", None, None), "http"),
        (ValueError("hidden"), "json"),
    ]
    for exc, reason in cases:
        result = probe_provider_health(
            ["alpha"],
            endpoints={"alpha": "https://alpha.example.test"},
            transport=Transport(exc),
        )
        assert result["providers"]["alpha"]["checks"]["transport"] == {
            "status": "error",
            "reason": reason,
        }
        assert "hidden" not in json.dumps(result)
