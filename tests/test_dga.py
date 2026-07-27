"""DGA adjudication: priority matrix, time boundaries, malformed inputs, and output contracts."""
from datetime import datetime, timedelta, timezone

import pytest

from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.models import Conclusion


_NAIVE_NOW = datetime(2026, 7, 23, 12, 0, 0)
_AWARE_NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc)


def _verdict(facts, *, now=_NAIVE_NOW, pdns_days=30, activity_days=365):
    return adjudicate_dga(
        "dga.invalid", facts,
        now=now,
        pdns_recent_days=pdns_days,
        activity_window_days=activity_days,
    )


# ── Priority: malicious sample always wins (rule 1) ──

def test_has_malicious_sample_true_overrides_all_white_signals():
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        has_current_icp=True,
        whois_expires=_NAIVE_NOW + timedelta(days=90),
        pdns_last_seen=_NAIVE_NOW,
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID
    assert v.route == "dga"
    assert v.disposition == "block"


def test_malicious_sample_times_nonempty_overrides_white_signals():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        malicious_sample_times=[_NAIVE_NOW - timedelta(days=10)],
        has_current_icp=True, whois_expires=_NAIVE_NOW, pdns_last_seen=_NAIVE_NOW,
    ))
    assert v.conclusion == Conclusion.ALIVE_VALID


def test_malicious_sample_times_recent_means_alive_valid():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        malicious_sample_times=[_NAIVE_NOW - timedelta(days=100)],
    ), activity_days=365)
    assert v.conclusion == Conclusion.ALIVE_VALID


def test_malicious_sample_times_at_activity_boundary_is_alive():
    boundary = _NAIVE_NOW - timedelta(days=365)
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        malicious_sample_times=[boundary],
    ), activity_days=365, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.ALIVE_VALID


def test_malicious_sample_times_one_microsecond_past_activity_is_inactive():
    past = (_NAIVE_NOW - timedelta(days=365)) - timedelta(microseconds=1)
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        malicious_sample_times=[past],
    ), activity_days=365, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_malicious_sample_no_times_still_black():
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID
    assert v.route == "dga"


def test_malicious_sample_times_none_with_has_malicious_true_not_crash():
    """malicious_sample_times=None with has_malicious_sample=True must not crash."""
    facts = DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        has_current_icp=True,
    )
    facts.malicious_sample_times = None
    v = _verdict(facts)
    assert v.conclusion == Conclusion.INACTIVE_VALID
    assert v.disposition == "block"


def test_one_recent_naive_plus_one_incomparable_aware_is_alive():
    """One comparable naive recent time + one incomparable aware time →
    the comparable time alone is sufficient for ALIVE_VALID.  The
    incomparable entry must not poison the entire list."""
    aware = _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=1)
    naive = _NAIVE_NOW - timedelta(days=10)
    # Confirm tzinfo differs — this is the test's precondition
    assert aware.tzinfo is not None
    assert naive.tzinfo is None
    facts = DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=[aware, naive],
    )
    v = _verdict(facts, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.ALIVE_VALID, \
        f"Expected ALIVE_VALID (naive time is recent), got {v.conclusion}"


def test_order_reversal_same_result():
    """Reversing the list order must yield the same result."""
    aware = _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=1)
    naive = _NAIVE_NOW - timedelta(days=10)
    v1 = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=[aware, naive],
    ), now=_NAIVE_NOW)
    v2 = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=[naive, aware],
    ), now=_NAIVE_NOW)
    assert v1.conclusion == v2.conclusion == Conclusion.ALIVE_VALID


def test_all_aware_times_with_naive_now_are_normalized_and_still_block():
    """Aware sample times are normalized before activity comparison."""
    times = [
        _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=1),
        _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=10),
    ]
    facts = DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=times,
    )
    v = _verdict(facts, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.ALIVE_VALID
    assert v.disposition == "block"


def test_has_malicious_true_with_aware_recent_time_is_alive_and_blocked():
    """A recent aware sample time stays malicious and becomes alive."""
    facts = DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=[
            _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=5),
        ],
    )
    v = _verdict(facts, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.ALIVE_VALID
    assert v.disposition == "block"


# ── sample_check_complete must be boolean True (rule 2) ──

def test_sample_check_not_complete_returns_review():
    for bad in (False, None):
        v = _verdict(DgaFacts(
            sample_check_complete=bad, has_current_icp=True,
            whois_expires=_NAIVE_NOW + timedelta(days=90), pdns_last_seen=_NAIVE_NOW,
        ))
        assert v.conclusion == Conclusion.PENDING_REVIEW


def test_sample_check_complete_string_true_not_sufficient():
    v = _verdict(DgaFacts(
        sample_check_complete="true", has_current_icp=True,
        whois_expires=_NAIVE_NOW + timedelta(days=90),
    ))
    assert v.conclusion == Conclusion.PENDING_REVIEW


# ── ICP white signal (rule 3) ──

def test_icp_no_malware_complete_sample_check_white():
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_current_icp=True,
    ))
    assert v.conclusion == Conclusion.FALSE_POSITIVE
    assert v.disposition == "false_positive"


def test_icp_string_false_not_white():
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_current_icp="false",
    ))
    assert v.conclusion != Conclusion.FALSE_POSITIVE


# ── WHOIS white signal (rule 4) ──

def test_whois_expires_today_is_not_expired():
    v = _verdict(DgaFacts(
        sample_check_complete=True, whois_expires=_NAIVE_NOW.replace(hour=0, minute=0),
    ), now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.FALSE_POSITIVE


def test_whois_expires_yesterday_alone_not_white():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        whois_expires=_NAIVE_NOW - timedelta(days=1),
    ), now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_whois_expires_future_is_white():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        whois_expires=_NAIVE_NOW + timedelta(days=90),
    ))
    assert v.conclusion == Conclusion.FALSE_POSITIVE


# ── pDNS white signal (rule 5) ──

def test_pdns_last_seen_29_days_is_recent():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        pdns_last_seen=_NAIVE_NOW - timedelta(days=29),
    ), pdns_days=30)
    assert v.conclusion == Conclusion.FALSE_POSITIVE


def test_pdns_last_seen_at_boundary_is_recent():
    boundary = _NAIVE_NOW - timedelta(days=30)
    v = _verdict(DgaFacts(
        sample_check_complete=True, pdns_last_seen=boundary,
    ), pdns_days=30, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.FALSE_POSITIVE


def test_pdns_last_seen_one_microsecond_past_boundary_not_recent():
    past = (_NAIVE_NOW - timedelta(days=30)) - timedelta(microseconds=1)
    v = _verdict(DgaFacts(
        sample_check_complete=True, pdns_last_seen=past,
    ), pdns_days=30, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_aware_pdns_with_naive_now_is_normalized_and_recent():
    """Aware pDNS and naive now share one normalized comparison basis."""
    aware_pdns = _NAIVE_NOW.replace(tzinfo=timezone.utc) - timedelta(days=10)
    v = _verdict(DgaFacts(
        sample_check_complete=True, pdns_last_seen=aware_pdns,
    ), pdns_days=30, now=_NAIVE_NOW)
    assert v.conclusion == Conclusion.FALSE_POSITIVE
    assert v.disposition == "false_positive"


# ── No white signals → INACTIVE_VALID (rule 6) ──

def test_no_malice_complete_no_white_signals_returns_inactive_valid():
    v = _verdict(DgaFacts(sample_check_complete=True))
    assert v.conclusion == Conclusion.INACTIVE_VALID
    assert v.route == "dga"


# ── Malformed / dirty inputs must not crash ──

def test_non_datetime_sample_times_does_not_crash():
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=["not-a-time", 123],
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_non_datetime_whois_expires_not_treated_as_fresh():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        whois_expires="tomorrow",
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_non_datetime_pdns_not_treated_as_recent():
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        pdns_last_seen="yesterday",
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_int_whois_expires_not_treated_as_fresh():
    v = _verdict(DgaFacts(
        sample_check_complete=True, whois_expires=42,
    ))
    assert v.conclusion == Conclusion.INACTIVE_VALID


# ── Window parameter override genuinely changes results ──

def test_pdns_window_override_changes_boundary():
    """With pdns_recent_days=7, 8-day-old pDNS should NOT be white."""
    v = _verdict(DgaFacts(
        sample_check_complete=True,
        pdns_last_seen=_NAIVE_NOW - timedelta(days=8),
    ), pdns_days=7)
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_activity_window_override_changes_boundary():
    """With activity_window_days=30, 40-day-old sample should be INACTIVE."""
    v = _verdict(DgaFacts(
        sample_check_complete=True, has_malicious_sample=True,
        malicious_sample_times=[_NAIVE_NOW - timedelta(days=40)],
    ), activity_days=30)
    assert v.conclusion == Conclusion.INACTIVE_VALID


# ── Output contract ──

def test_route_always_dga():
    v = _verdict(DgaFacts(sample_check_complete=True, has_malicious_sample=True))
    assert v.route == "dga"


def test_disposition_block_for_black():
    v = _verdict(DgaFacts(sample_check_complete=True, has_malicious_sample=True))
    assert v.disposition == "block"


def test_disposition_false_positive_for_white():
    v = _verdict(DgaFacts(sample_check_complete=True, has_current_icp=True))
    assert v.disposition == "false_positive"


def test_disposition_review_for_pending():
    v = _verdict(DgaFacts(sample_check_complete=False))
    assert v.disposition == "review"


def test_dga_never_produces_gray():
    for facts in [
        DgaFacts(sample_check_complete=True, has_malicious_sample=True),
        DgaFacts(sample_check_complete=True, has_current_icp=True),
        DgaFacts(sample_check_complete=True, whois_expires=_NAIVE_NOW + timedelta(days=90)),
        DgaFacts(sample_check_complete=True, pdns_last_seen=_NAIVE_NOW),
        DgaFacts(sample_check_complete=False),
    ]:
        v = _verdict(facts)
        assert v.conclusion != Conclusion.GRAY, \
            f"Conclusion must not be GRAY for {facts}"


def test_provider_statuses_are_defensive_copy():
    orig = DgaFacts(
        sample_check_complete=True,
        provider_statuses={"whois": "success", "pdns": "no_data"},
    )
    v1 = _verdict(orig)
    v2 = _verdict(orig)
    v1.provider_statuses["whois"] = "corrupted"
    assert v2.provider_statuses["whois"] == "success"
    assert v1.provider_statuses["whois"] == "corrupted"


def test_dgafacts_defaults_are_isolated():
    f1 = DgaFacts(sample_check_complete=True)
    f2 = DgaFacts(sample_check_complete=True)
    f1.malicious_sample_times.append(_NAIVE_NOW)
    f1.provider_statuses["extra"] = "yes"
    assert f2.malicious_sample_times == []
    assert f2.provider_statuses == {}
