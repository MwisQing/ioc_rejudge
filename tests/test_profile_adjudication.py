"""Integration tests for profile + adjudication with the full judgement tree."""
from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.adjudicator import adjudicate, _has_threat_residue
from ioc_rejudge.models import Conclusion
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_record, build_hash_entry


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def _recent_date_str():
    return (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")


def _old_date_str():
    return (datetime.now() - timedelta(days=500)).strftime("%Y-%m-%d")


def _run(records, config=None):
    config = config or Config()
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    verdict = adjudicate(dossier, config)
    return dossier, verdict


# ── Scenario 1: New domain + normal business + high-risk related domain ──
def test_new_domain_business_high_risk_ip():
    """official_website + recent whois + high-level relate_ip_domain → 待复核"""
    records = [build_record(
        "new-business.com",
        official_website="https://www.example.com",
        whois={"createdDate": _recent_date_str()},
        relate_ip_domain=[
            {"key": "evil-related.com", "level": 80, "last": _days_ago(10)},
            {"key": "evil2.com", "level": 90, "last": _days_ago(5)},
        ],
        level=50,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核, got {v.conclusion}. E={dossier.evidence_e}, D={dossier.evidence_d}"
    assert v.review_suggestion == "必看"


# ── Scenario 2: Mature normal business domain ──
def test_mature_business_no_threat():
    """Mature business signals with non-DGA ICP require review."""
    records = [build_record(
        "old-business.com",
        official_website="https://www.example.com",
        icp_website="https://icp.example.com",
        whois={"createdDate": _old_date_str()},
        level=30,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核, got {v.conclusion}"
    assert v.disposition == "review"
    assert "ICP" in v.reason


# ── Scenario 3: IP with high-risk PDNS + normalizing field → 待复核 ──
def test_ip_high_risk_pdns_normalizing():
    """IP with high-level relate_ip_domain + official_website → 待复核"""
    records = [build_record(
        "1.2.3.4",
        official_website="https://www.example.com",
        relate_ip_domain=[
            {"key": "evil1.com", "level": 80},
            {"key": "evil2.com", "level": 85},
        ],
        level=50,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核, got {v.conclusion}. E={dossier.evidence_e}, D={dossier.evidence_d}"
    assert v.review_suggestion in ("必看", "抽检")


# ── Scenario 4: Recent dtree activity without direct A ──
def test_recent_dtree_without_direct_a():
    """Recent dtree.last + suspicious related domain without direct context → not automatic 误报"""
    records = [build_record(
        "dns-tree.com",
        dtree=[
            {"key": "suspicious-sub.com", "level": 75, "last": _days_ago(10)},
        ],
        official_website="https://www.example.com",
        level=50,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion != Conclusion.FALSE_POSITIVE, \
        f"Should not automatically 误报 with dtree threat residue. Got {v.conclusion}"
    assert v.conclusion == Conclusion.PENDING_REVIEW


# ── Scenario 5: High-level hash without IOC closure ──
def test_high_hash_without_ioc_closure():
    """hash.level >= 70 + official_website without IOC context → 待复核"""
    records = [build_record(
        "hash-only.com",
        official_website="https://www.example.com",
        hash_entries=[build_hash_entry("abc123", level=80, time=_days_ago(100))],
        level=70,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核 with high hash, got {v.conclusion}"
    assert _has_threat_residue(dossier, Config()) is True


# ── Scenario 6: Strong A remains dominant ──
def test_strong_a_dominant():
    """Context directly mentions IOC + malicious indicator → strong A, no automatic 误报"""
    records = [build_record(
        "evil-direct.com",
        context="Sample connected to evil-direct.com via HTTP C2",
        source=["sample-base"],
        hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
        level=70,
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.ALIVE_VALID
    assert v.malicious_nature == "直接恶意"


# ── Scenario 6b: Strong A + strong E → 待复核 ──
def test_strong_a_plus_strong_e_review():
    """Non-DGA ICP outranks a strong A/E conflict candidate."""
    records = [build_record(
        "conflict-direct.com",
        context="Sample connected to conflict-direct.com C2",
        source=["sample-base"],
        hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
        official_website="https://www.normal.com",
        icp_website="https://www.normal.com",
        level=70,
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW
    assert v.candidate_label is None
    assert "ICP" in v.reason


# ── Scenario 7: WHOIS update does not become activity ──
def test_whois_update_not_activity():
    """Only recent whois.updatedDate → F evidence only, not 存活有效"""
    records = [build_record(
        "whois-update.com",
        whois={"updatedDate": _days_ago(5)},
        level=30,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion != Conclusion.ALIVE_VALID, \
        "WHOIS update alone should not produce 存活有效"
    # Should have F evidence for whois update
    assert any("whois" in e.field.lower() or "profile_update" in e.field
               for e in dossier.evidence_f), \
        "WHOIS update should produce F evidence"


# ── Scenario 8: HTTP unreachable does not become false positive ──
def test_http_unreachable_not_false_positive():
    """Only reachable=false → not automatic 误报"""
    records = [build_record(
        "unreachable.com",
        reachable=False,
        http={"status": "404"},
        level=30,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion != Conclusion.FALSE_POSITIVE, \
        f"HTTP unreachable should not automatically 误报. Got {v.conclusion}"


# ── Scenario 9: Runtime benign conflict with threat residue → 待复核 ──
def test_benign_runtime_with_threat_residue():
    """Negative risk + high-level hash → 待复核, not 误报"""
    records = [build_record(
        "benign-and-threat.com",
        risk=-60,
        hash_entries=[build_hash_entry("abc", level=80, time=_days_ago(50))],
        level=70,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核 with benign runtime + threat residue, got {v.conclusion}"
    assert _has_threat_residue(dossier, Config()) is True


# ── Scenario 10: Pure normalization → 误报 ──
def test_pure_normalization():
    """Pure normalization with non-DGA ICP still requires review."""
    records = [build_record(
        "pure-normal.com",
        icp_website="https://icp.example.com",
        official_website="https://www.example.com",
        page_title="Example Company",
        whois={"createdDate": _old_date_str()},
        level=20,
        source=["spider"],
    )]
    dossier, v = _run(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Expected 待复核 for non-DGA ICP, got {v.conclusion}"
    assert "ICP" in v.reason


# ── Threat residue detection ──
def test_threat_residue_with_malicious_family():
    """Malicious family name should trigger threat residue."""
    records = [build_record(
        "trojan-host.com",
        official_website="https://www.example.com",
        family=["TrojanDownloader"],
        level=50,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert _has_threat_residue(dossier, Config()) is True


def test_threat_residue_with_attck():
    """ATT&CK techniques should trigger threat residue."""
    records = [build_record(
        "attck-host.com",
        official_website="https://www.example.com",
        attck=["T1071", "T1041"],
        level=50,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert _has_threat_residue(dossier, Config()) is True


def test_threat_residue_negative():
    """Pure normalization without threat should NOT trigger threat residue."""
    records = [build_record(
        "clean-site.com",
        official_website="https://www.example.com",
        icp_website="https://icp.example.com",
        whois={"createdDate": _old_date_str()},
        level=20,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert _has_threat_residue(dossier, Config()) is False


def test_threat_residue_with_runtime_block():
    """Runtime block=true should trigger threat residue."""
    records = [build_record(
        "blocked.com",
        official_website="https://www.example.com",
        block=True,
        level=50,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert _has_threat_residue(dossier, Config()) is True


def test_threat_residue_with_ml_black():
    """Runtime ml_black=true should trigger threat residue."""
    records = [build_record(
        "ml-blocked.com",
        official_website="https://www.example.com",
        ml_black=True,
        level=50,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert _has_threat_residue(dossier, Config()) is True


def test_no_threat_residue_pure_e():
    """E evidence alone without threat residue should not trigger."""
    records = [build_record(
        "e-only.com",
        official_website="https://www.example.com",
        level=20,
        source=["spider"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    # Should be 误报 since no threat residue
    v = adjudicate(dossier, Config())
    assert v.conclusion == Conclusion.FALSE_POSITIVE


def test_low_hash_non_strong_source_not_threat_residue():
    """Low-level hash from a non-strong source should not block pure normalization."""
    cfg = Config()
    records = [build_record(
        "low-hash-normal.com",
        official_website="https://www.example.com",
        source=["metrix"],
        hash_entries=[build_hash_entry("lowhash", level=10, time=_days_ago(10))],
        level=20,
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, cfg)
    assert _has_threat_residue(dossier, cfg) is False
    v = adjudicate(dossier, cfg)
    assert v.conclusion == Conclusion.FALSE_POSITIVE
