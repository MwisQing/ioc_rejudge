"""Deterministic DGA adjudication — ordered hard rules with injected time.

Consumes pre-collected DgaFacts (the upstream caller is responsible for
confirming a reliable DGA-only classification and assembling the facts).
Never uses domain-shape heuristics; never spreads WHOIS/pDNS/ICP white
rules to non-DGA routes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ioc_rejudge.models import Conclusion, Verdict


@dataclass
class DgaFacts:
    """Collected signals for a DGA-classified IOC.

    All mutable defaults use ``field(default_factory=...)`` so instances
    are independently isolated.
    """

    sample_check_complete: bool  # no default — caller must be explicit
    has_malicious_sample: bool = False
    malicious_sample_times: list[datetime] = field(default_factory=list)
    has_current_icp: bool = False
    whois_expires: datetime | None = None
    pdns_last_seen: datetime | None = None
    provider_statuses: dict[str, str] = field(default_factory=dict)


def _normalize_time(value: object) -> datetime | None:
    """Normalize aware datetimes to naive UTC and preserve naive values."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _any_recent_time(times: list[datetime] | None, cutoff: datetime) -> bool:
    """Return True when at least one valid normalized time meets *cutoff*."""
    if not times or not isinstance(times, (list, tuple)):
        return False
    normalized_cutoff = _normalize_time(cutoff)
    if normalized_cutoff is None:
        return False
    for t in times:
        normalized = _normalize_time(t)
        if normalized is not None and normalized >= normalized_cutoff:
            return True
    return False


def _has_malice(facts: DgaFacts) -> bool:
    """True when the facts indicate a known malicious sample association."""
    if facts.has_malicious_sample:
        return True
    if isinstance(facts.malicious_sample_times, (list, tuple)) and facts.malicious_sample_times:
        return True
    return False


def _is_datetime(value: object) -> bool:
    return isinstance(value, datetime)


def adjudicate_dga(
    ioc: str,
    facts: DgaFacts,
    *,
    now: datetime | None = None,
    pdns_recent_days: int = 30,
    activity_window_days: int = 365,
) -> Verdict:
    """Apply ordered DGA hard rules to *facts* and return a Verdict.

    ``now`` must be injectable for deterministic testing; when omitted,
    the current UTC time is used. All comparisons use naive UTC values.

    Rule order (first match returns):
      1. Malicious sample → BLOCK (alive / inactive based on latest time).
      2. Sample check incomplete → PENDING_REVIEW.
      3. Current ICP → FALSE_POSITIVE.
      4. WHOIS not expired → FALSE_POSITIVE.
      5. Recent pDNS → FALSE_POSITIVE.
      6. No white signals → INACTIVE_VALID.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    normalized_now = _normalize_time(now)
    if normalized_now is None:
        raise TypeError("now must be a datetime")
    now = normalized_now

    activity_cutoff = now - timedelta(days=activity_window_days)
    pdns_cutoff = now - timedelta(days=pdns_recent_days)

    # ── Rule 1: malicious sample → BLOCK ──
    if _has_malice(facts):
        if _any_recent_time(facts.malicious_sample_times, activity_cutoff):
            conclusion = Conclusion.ALIVE_VALID
            activity_status = "存活"
        else:
            conclusion = Conclusion.INACTIVE_VALID
            activity_status = "失活"
        return Verdict(
            conclusion=conclusion,
            malicious_nature="恶意",
            activity_status=activity_status,
            confidence="高",
            review_suggestion="无需复核",
            candidate_label=None,
            hit_evidence="关联恶意样本",
            forbidden_labels="",
            reason="DGA已确认恶意样本关联",
            route="dga",
            disposition="block",
            provider_statuses=dict(facts.provider_statuses),
        )

    # ── Rule 2: sample check not complete → PENDING_REVIEW ──
    if facts.sample_check_complete is not True:
        return Verdict(
            conclusion=Conclusion.PENDING_REVIEW,
            malicious_nature="不确定",
            activity_status="未知",
            confidence="低",
            review_suggestion="必看",
            candidate_label=None,
            hit_evidence="",
            forbidden_labels="",
            reason="无法确认是否有关联恶意样本（样本检查未成功完成）",
            route="dga",
            disposition="review",
            provider_statuses=dict(facts.provider_statuses),
        )

    # ── Rule 3: current ICP → FALSE_POSITIVE ──
    if facts.has_current_icp is True:
        return Verdict(
            conclusion=Conclusion.FALSE_POSITIVE,
            malicious_nature="无恶意",
            activity_status="存活",
            confidence="高",
            review_suggestion="抽检",
            candidate_label=None,
            hit_evidence="当前ICP备案",
            forbidden_labels="",
            reason="DGA域名当前存在ICP备案，已确认无关联恶意样本",
            route="dga",
            disposition="false_positive",
            provider_statuses=dict(facts.provider_statuses),
        )

    # ── Rule 4: WHOIS not expired → FALSE_POSITIVE ──
    whois_expires = _normalize_time(facts.whois_expires)
    if whois_expires is not None and whois_expires.date() >= now.date():
        return Verdict(
            conclusion=Conclusion.FALSE_POSITIVE,
            malicious_nature="无恶意",
            activity_status="存活",
            confidence="高",
            review_suggestion="抽检",
            candidate_label=None,
            hit_evidence="WHOIS未过期",
            forbidden_labels="",
            reason="DGA域名WHOIS未过期，已确认无关联恶意样本",
            route="dga",
            disposition="false_positive",
            provider_statuses=dict(facts.provider_statuses),
        )

    # ── Rule 5: recent pDNS → FALSE_POSITIVE ──
    if (_is_datetime(facts.pdns_last_seen)
            and _any_recent_time([facts.pdns_last_seen], pdns_cutoff)):
        return Verdict(
            conclusion=Conclusion.FALSE_POSITIVE,
            malicious_nature="无恶意",
            activity_status="存活",
            confidence="高",
            review_suggestion="抽检",
            candidate_label=None,
            hit_evidence="近期pDNS解析",
            forbidden_labels="",
            reason=f"DGA域名近{pdns_recent_days}天有pDNS解析，已确认无关联恶意样本",
            route="dga",
            disposition="false_positive",
            provider_statuses=dict(facts.provider_statuses),
        )

    # ── Rule 6: no white signals → INACTIVE_VALID ──
    return Verdict(
        conclusion=Conclusion.INACTIVE_VALID,
        malicious_nature="恶意",
        activity_status="失活",
        confidence="中",
        review_suggestion="抽检",
        candidate_label=None,
        hit_evidence="",
        forbidden_labels="",
        reason="DGA分类可靠，无当前白证据，保留为失活黑",
        route="dga",
        disposition="block",
        provider_statuses=dict(facts.provider_statuses),
    )
