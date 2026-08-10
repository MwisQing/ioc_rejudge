"""Progress event plumbing and LiveProgress rendering tests."""

from datetime import timedelta
import io
import threading
import time
import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.providers.base import (
    ProgressEvent,
    ProviderContext,
    report_progress,
)
from ioc_rejudge.providers.cache import JsonlProviderCache
from ioc_rejudge.providers.fdark import FDarkProvider
from ioc_rejudge.providers.icp import ICPProvider
from ioc_rejudge.providers.ioc_info import IOCInfoProvider
from ioc_rejudge.providers.pdns import PDNSProvider
from ioc_rejudge.providers.settings import ProviderSettings
from ioc_rejudge.providers.whois import WhoisProvider
from ioc_rejudge.progress import LiveProgress


def _clock(monkeypatch, start=0.0):
    clock = {"now": start}
    monkeypatch.setattr(
        "ioc_rejudge.progress.time.perf_counter", lambda: clock["now"]
    )
    return clock


def _targets(*values):
    return read_input_bundle(None, list(values)).targets


class _WhoisTransport:
    def __init__(self, responses):
        self.responses = iter(responses)

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        return next(self.responses)


class _BlockingWhoisTransport:
    """Blocks inside get_json until release_event is set."""

    def __init__(self, entered_event: threading.Event, release_event: threading.Event):
        self.entered_event = entered_event
        self.release_event = release_event

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        self.entered_event.set()
        assert self.release_event.wait(timeout=5), "release event timed out"
        return {"code": 200, "data": {}}


class _PdnsTransport:
    def __init__(self, responses):
        self.responses = iter(responses)

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        return next(self.responses)


class _FdarkTransport:
    def __init__(self, responses):
        self.responses = iter(responses)

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        return next(self.responses)


class _UnexpectedGetErrorTransport:
    def get_json(self, *args, **kwargs):
        raise RuntimeError("unexpected transport failure")


class _IcpTransport:
    def __init__(self, responses):
        self.responses = iter(responses)

    def get_json(self, url, *, headers=None, params=None, timeout=30):
        return next(self.responses)


class _IocInfoTransport:
    def __init__(self, responses):
        self.responses = iter(responses)

    def post_json(self, url, *, headers=None, body=None, timeout=30):
        return next(self.responses)


# --- ProviderContext / report_progress plumbing ---


def test_provider_context_on_progress_defaults_to_none():
    assert ProviderContext().on_progress is None
    assert ProviderContext(offline=True).on_progress is None
    assert ProviderContext(refresh=True).on_progress is None


def test_report_progress_without_handler_is_noop():
    report_progress(ProviderContext(), "whois", 1, 5)


def test_report_progress_calls_handler_with_event_fields():
    events = []
    context = ProviderContext(on_progress=events.append)
    report_progress(context, "whois", 3, 10, "cached")
    assert len(events) == 1
    assert events[0] == ProgressEvent("whois", 3, 10, "cached")


def test_report_progress_handler_error_does_not_raise():
    def bad_handler(event):
        raise RuntimeError("progress boom")

    report_progress(ProviderContext(on_progress=bad_handler), "whois", 1, 1)


# --- LiveProgress plain (non-TTY) mode ---


def test_live_progress_plain_mode_first_update_always_prints(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=False)
    clock = _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 10))
    assert "[whois] 1/10" in stream.getvalue()


def test_live_progress_plain_mode_throttles_then_flushes(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=False)
    clock = _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 10))
    progress.event(ProgressEvent("whois", 2, 10))  # within interval: suppressed
    clock["now"] = 2.0
    progress.event(ProgressEvent("whois", 3, 10))  # past interval: printed
    progress.event(ProgressEvent("whois", 10, 10))  # final: always printed
    lines = stream.getvalue().splitlines()
    assert len(lines) == 3
    assert "[whois] 1/10" in lines[0]
    assert "[whois] 3/10" in lines[1]
    assert "[whois] 10/10" in lines[2]


def test_live_progress_plain_mode_message_writes_permanent_line():
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=False)
    progress.message("provider 'whois': completed in 1.2s (10 target(s))")
    assert "provider 'whois': completed in 1.2s (10 target(s))" in stream.getvalue()


def test_live_progress_ignores_identical_duplicate_final_event(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=False)
    _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 1))
    progress.event(ProgressEvent("whois", 1, 1))
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    assert "[whois] 1/1" in lines[0]


def test_live_progress_uses_custom_stream_isatty_when_tty_none():
    class _Stream(io.StringIO):
        def __init__(self, is_tty: bool):
            super().__init__()
            self._is_tty = is_tty

        def isatty(self) -> bool:
            return self._is_tty

    tty_stream = _Stream(True)
    plain_stream = _Stream(False)
    assert LiveProgress(stream=tty_stream, tty=None)._tty is True
    assert LiveProgress(stream=plain_stream, tty=None)._tty is False


# --- LiveProgress TTY mode ---


def test_live_progress_tty_redraws_block_with_escape_sequences(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=True)
    clock = _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 10))
    clock["now"] = 0.5
    progress.event(ProgressEvent("icp", 1, 5))
    out = stream.getvalue()
    assert "\x1b[" in out
    assert "[whois] 1/10" in out
    assert "[icp" in out and "1/5" in out


def test_live_progress_tty_seal_prints_completion_above_remaining_block(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=True)
    clock = _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 10))
    clock["now"] = 0.5
    progress.event(ProgressEvent("icp", 1, 5))
    stream.truncate(0)
    stream.seek(0)
    progress.message("provider 'whois': completed in 1.2s (10 target(s))")
    out = stream.getvalue()
    assert out.find("provider 'whois'") != -1
    assert out.find("[icp] 1/5") != -1
    assert out.find("provider 'whois'") < out.find("[icp] 1/5")


def test_live_progress_tty_close_clears_block(monkeypatch):
    stream = io.StringIO()
    progress = LiveProgress(stream=stream, tty=True)
    _clock(monkeypatch)
    progress.event(ProgressEvent("whois", 1, 10))
    progress.close()
    assert "\x1b[1A" in stream.getvalue()


# --- Provider integration: per-target / per-batch progress events ---


def _whois_provider(tmp_path, responses):
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=7,
        ttl=timedelta(days=1),
    )
    return WhoisProvider(
        settings,
        transport=_WhoisTransport(responses),
        cache=JsonlProviderCache(tmp_path, "whois", timedelta(days=1)),
    )


def test_whois_provider_reports_one_event_per_target(tmp_path):
    targets = _targets("a.invalid", "b.invalid", "c.invalid")
    provider = _whois_provider(tmp_path, [{"code": 200, "data": {}}] * 3)
    events = []
    provider.collect(targets, ProviderContext(on_progress=events.append))
    assert [(event.done, event.total) for event in events] == [
        (0, 3),
        (1, 3),
        (2, 3),
        (3, 3),
    ]
    assert all(event.provider == "whois" for event in events)


def test_whois_progress_stays_zero_until_request_returns(tmp_path):
    """Blocked transport must not advance done past 0 before the request returns."""
    targets = _targets("blocked.invalid")
    entered = threading.Event()
    release = threading.Event()
    settings = ProviderSettings(
        name="whois",
        base_url="https://whois.invalid/v3/whois/detail",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=7,
        ttl=timedelta(days=1),
    )
    provider = WhoisProvider(
        settings,
        transport=_BlockingWhoisTransport(entered, release),
        cache=JsonlProviderCache(tmp_path, "whois", timedelta(days=1)),
    )
    events_lock = threading.Lock()
    events: list[ProgressEvent] = []

    def on_progress(event: ProgressEvent) -> None:
        with events_lock:
            events.append(event)

    errors: list[BaseException] = []

    def run() -> None:
        try:
            provider.collect(targets, ProviderContext(on_progress=on_progress))
        except BaseException as exc:  # pragma: no cover - test harness
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(timeout=5), "transport was never entered"
    # Request is in flight; allow any incorrect early completion event to land.
    time.sleep(0.15)
    with events_lock:
        mid = list(events)
    assert any((event.done, event.total) == (0, 1) for event in mid), mid
    assert not any(event.done >= 1 for event in mid), mid
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert errors == []
    with events_lock:
        final = list(events)
    pairs = [(event.done, event.total) for event in final]
    assert pairs[0] == (0, 1)
    assert pairs[-1] == (1, 1)
    assert pairs.count((1, 1)) == 1
    assert all(event.provider == "whois" for event in final)


def _pdns_provider(tmp_path, responses):
    settings = ProviderSettings(
        name="pdns",
        base_url="https://pdns.invalid/api/v1/passivedns/flint/rrset",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=6,
        ttl=timedelta(days=1),
    )
    return PDNSProvider(
        settings,
        transport=_PdnsTransport(responses),
        cache=JsonlProviderCache(tmp_path, "pdns", timedelta(days=1)),
    )


def _fdark_provider(tmp_path, responses):
    settings = ProviderSettings(
        name="fdark",
        base_url="https://fdark.invalid/api/v1/fdark/abstract",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=9,
        ttl=timedelta(days=1),
    )
    return FDarkProvider(
        settings,
        Config(),
        transport=_FdarkTransport(responses),
        cache=JsonlProviderCache(tmp_path, "fdark", timedelta(days=1)),
    )


def test_whois_pdns_fdark_progress_monotonic_from_zero_unique_final(tmp_path):
    """Serial providers: start at 0/total, increase after each target, final once."""
    whois_events: list[ProgressEvent] = []
    whois = _whois_provider(tmp_path / "whois", [{"code": 200, "data": {}}] * 2)
    whois.collect(
        _targets("a.invalid", "b.invalid"),
        ProviderContext(on_progress=whois_events.append),
    )
    whois_pairs = [(event.done, event.total) for event in whois_events]
    assert whois_pairs == [(0, 2), (1, 2), (2, 2)]
    assert whois_pairs.count((2, 2)) == 1

    pdns_events: list[ProgressEvent] = []
    pdns = _pdns_provider(
        tmp_path / "pdns",
        [{"code": 200, "status": "ok", "data": []}] * 2,
    )
    pdns.collect(
        _targets("a.invalid", "b.invalid"),
        ProviderContext(on_progress=pdns_events.append),
    )
    pdns_pairs = [(event.done, event.total) for event in pdns_events]
    assert pdns_pairs == [(0, 2), (1, 2), (2, 2)]
    assert pdns_pairs.count((2, 2)) == 1

    fdark_events: list[ProgressEvent] = []
    fdark = _fdark_provider(
        tmp_path / "fdark",
        [
            {"message": "", "status": "ok", "data": [], "total": 0},
            {"message": "", "status": "ok", "data": [], "total": 0},
        ],
    )
    fdark.collect(
        _targets("a.invalid", "b.invalid"),
        ProviderContext(on_progress=fdark_events.append),
    )
    fdark_pairs = [(event.done, event.total) for event in fdark_events]
    assert fdark_pairs == [(0, 2), (1, 2), (2, 2)]
    assert fdark_pairs.count((2, 2)) == 1
    assert all(event.provider == "fdark" for event in fdark_events)


@pytest.mark.parametrize("provider_name", ["whois", "pdns", "fdark"])
def test_serial_provider_unexpected_error_does_not_report_completion(
    tmp_path, provider_name
):
    settings = ProviderSettings(
        name=provider_name,
        base_url=f"https://{provider_name}.invalid/api",
        secrets={"fdp-access": "test-access", "fdp-secret": "test-secret"},
        timeout=7,
        ttl=timedelta(days=1),
    )
    transport = _UnexpectedGetErrorTransport()
    if provider_name == "whois":
        provider = WhoisProvider(settings, transport=transport, cache=None)
    elif provider_name == "pdns":
        provider = PDNSProvider(settings, transport=transport, cache=None)
    else:
        provider = FDarkProvider(
            settings, Config(), transport=transport, cache=None
        )
    events = []

    with pytest.raises(RuntimeError, match="unexpected transport failure"):
        provider.collect(
            _targets("unexpected.invalid"),
            ProviderContext(on_progress=events.append),
        )

    assert [(event.done, event.total) for event in events] == [(0, 1)]


def _icp_provider(tmp_path, responses):
    settings = ProviderSettings(
        name="icp",
        base_url="https://icp.invalid/v2/open-api/icp-info",
        secrets={"uc": "SENTINEL_ICP_UC", "key": "SENTINEL_ICP_KEY"},
        timeout=5,
        workers=2,
        rate_per_second=1000,
        ttl=timedelta(days=30),
    )
    return ICPProvider(
        settings,
        transport=_IcpTransport(responses),
        cache=JsonlProviderCache(tmp_path / "cache", "icp", timedelta(days=30)),
    )


def test_icp_provider_reports_host_progress(tmp_path):
    targets = _targets("one.invalid", "two.invalid")
    provider = _icp_provider(
        tmp_path,
        [
            {"resultObject": {"website_icp_num": " ICP-1 "}},
            {"resultObject": {"website_icp_num": " ICP-2 "}},
        ],
    )
    events = []
    provider.collect(targets, ProviderContext(on_progress=events.append))
    assert len(events) == 3
    assert sorted(event.done for event in events) == [0, 1, 2]
    assert all(event.total == 2 for event in events)
    assert all(event.provider == "icp" for event in events)
    assert events[-1].done == 2


def _ioc_info_provider(tmp_path, responses):
    settings = ProviderSettings(
        name="ioc_info",
        base_url="https://ioc-info.invalid/api/v1/ioc/info",
        secrets={"Api-Key": "test-secret"},
        timeout=9,
        ttl=timedelta(days=1),
    )
    return IOCInfoProvider(
        settings,
        transport=_IocInfoTransport(responses),
        cache=JsonlProviderCache(tmp_path, "ioc_info", timedelta(days=1)),
    )


def test_ioc_info_provider_reports_batch_coverage_progress(tmp_path):
    targets = _targets("a.invalid", "b.invalid", "c.invalid")
    provider = _ioc_info_provider(
        tmp_path,
        [{
            "data": {
                "a.invalid": [{"id": 1}],
                "b.invalid": [{"id": 2}],
                "c.invalid": [{"id": 3}],
            }
        }],
    )
    events = []
    provider.collect(targets, ProviderContext(on_progress=events.append))
    assert [(event.done, event.total) for event in events] == [
        (0, 3),
        (3, 3),
    ]
    assert all(event.provider == "ioc_info" for event in events)
