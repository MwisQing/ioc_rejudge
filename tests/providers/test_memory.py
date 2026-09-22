"""Physical-memory concurrency cap tests."""

from ioc_rejudge.providers.memory import (
    cap_positive_int,
    detect_memory_limits,
)


_GIB = 1024 ** 3


def test_detect_memory_limits_by_installed_ram():
    low = detect_memory_limits(4 * _GIB, env={})
    assert low.http_workers == 2
    assert low.provider_workers == 2
    assert low.go_jobs_per_process == 4

    mid = detect_memory_limits(8 * _GIB, env={})
    assert mid.http_workers == 4
    assert mid.provider_workers == 3
    assert mid.go_jobs_per_process == 8

    high = detect_memory_limits(16 * _GIB, env={})
    assert high.http_workers is None
    assert high.provider_workers is None
    assert high.go_jobs_per_process is None


def test_memory_profile_env_overrides_detected_ram():
    forced_low = detect_memory_limits(
        16 * _GIB, env={"IOC_REJUDGE_MEMORY_PROFILE": "low"}
    )
    assert forced_low.http_workers == 2

    forced_full = detect_memory_limits(
        4 * _GIB, env={"IOC_REJUDGE_MEMORY_PROFILE": "full"}
    )
    assert forced_full.http_workers is None
    assert forced_full.provider_workers is None


def test_cap_positive_int_keeps_value_at_or_below_ceiling():
    assert cap_positive_int(10, None) == 10
    assert cap_positive_int(10, 2) == 2
    assert cap_positive_int(1, 8) == 1
