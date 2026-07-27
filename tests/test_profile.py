"""Tests for profile extraction module."""
from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.models import IocDossier, IocProfile, ProfileObservation
from ioc_rejudge.profile import extract_profile, _looks_random
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_record, build_hash_entry


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def _recent_date_str():
    return (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")


def _old_date_str():
    return (datetime.now() - timedelta(days=500)).strftime("%Y-%m-%d")


def test_profile_new_domain_detected():
    """New domain (within 30 days) should produce suspicious domain_age observation."""
    records = [build_record(
        "fresh-evil.com",
        whois={"createdDate": _recent_date_str()},
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    assert dossier.profile is not None
    domain_obs = [
        o for o in dossier.profile.observations
        if o.kind == "domain_age" and o.severity == "suspicious"
    ]
    assert len(domain_obs) == 1
    assert "new_domain" in domain_obs[0].tags
    assert dossier.profile.domain.get("is_new") is True


def test_profile_mature_domain_detected():
    """Mature domain (over 1 year) should produce normal domain_age observation."""
    records = [build_record(
        "old-legit.com",
        whois={"createdDate": _old_date_str()},
        level=30,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    mature_obs = [
        o for o in dossier.profile.observations
        if o.kind == "domain_age" and o.severity == "normal"
    ]
    assert len(mature_obs) == 1
    assert "mature_domain" in mature_obs[0].tags
    assert dossier.profile.domain.get("is_mature") is True


def test_profile_ip_type_skips_domain_checks():
    """IP IOCs should skip domain profile checks."""
    records = [build_record(
        "1.2.3.4",
        whois={"createdDate": _recent_date_str()},
        level=50,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    # IP has no domain observations
    domain_obs = [
        o for o in dossier.profile.observations
        if o.kind == "domain_age"
    ]
    assert len(domain_obs) == 0


def test_profile_trusted_business_identity():
    """ICP + official_website should produce trusted_business identity observation."""
    records = [build_record(
        "normal-business.com",
        icp_website="https://icp.example.com",
        official_website="https://www.example.com",
        level=30,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    biz_obs = [
        o for o in dossier.profile.observations
        if o.kind == "business_identity"
    ]
    assert len(biz_obs) == 1
    assert "trusted_business" in biz_obs[0].tags
    assert dossier.profile.domain.get("has_trusted_business_identity") is True


def test_profile_high_risk_related_domains():
    """High-level relate_ip_domain entries produce suspicious observation."""
    records = [build_record(
        "evil.com",
        relate_ip_domain=[
            {"key": "bad1.com", "level": 80, "last": _days_ago(10)},
            {"key": "bad2.com", "level": 90, "last": _days_ago(5)},
        ],
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    high_risk = [
        o for o in dossier.profile.observations
        if o.kind == "ip_reverse_domain_risk"
    ]
    assert len(high_risk) >= 1
    assert "high_related_level" in high_risk[0].tags
    assert dossier.profile.ip.get("high_risk_related_domain_count") == 2


def test_profile_threat_runtime_flags():
    """Runtime block/black flags should produce threat observation."""
    records = [build_record(
        "evil.com",
        block=True,
        black=True,
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    threat_obs = [
        o for o in dossier.profile.observations
        if o.kind == "threat_runtime"
    ]
    assert len(threat_obs) == 1
    assert "threat_runtime" in threat_obs[0].tags
    assert dossier.profile.runtime.get("has_threat_flag") is True


def test_profile_benign_runtime_conflict():
    """Negative risk with hash entries should produce conflict observation."""
    records = [build_record(
        "conflict.com",
        risk=-60,
        hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    benign_obs = [
        o for o in dossier.profile.observations
        if o.kind == "benign_runtime"
    ]
    assert len(benign_obs) == 1
    assert benign_obs[0].severity == "conflict"
    assert dossier.profile.runtime.get("has_benign_conflict") is True


def test_profile_mixed_infrastructure():
    """Normal business with high-risk IP domains produces conflict."""
    records = [build_record(
        "shared-host.com",
        official_website="https://www.example.com",
        relate_ip_domain=[
            {"key": "evil-related.com", "level": 80},
        ],
        context="shared hosting service",
        level=50,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    conflict_obs = [
        o for o in dossier.profile.observations
        if o.kind == "mixed_infrastructure"
    ]
    assert len(conflict_obs) >= 1
    assert conflict_obs[0].severity == "conflict"


def test_profile_random_domain_detection():
    """Algorithmically generated domain names should be flagged."""
    records = [build_record(
        "x7k3m9p2q5r8t1w4.com",
        whois={"createdDate": _recent_date_str()},
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    random_obs = [
        o for o in dossier.profile.observations
        if "random_domain" in o.tags
    ]
    assert len(random_obs) >= 1
    assert dossier.profile.domain.get("looks_random") is True


def test_profile_short_lived_domain():
    """Domain with short lifespan should be flagged."""
    created = datetime.now() - timedelta(days=10)
    expires = datetime.now() + timedelta(days=20)
    records = [build_record(
        "temp-evil.com",
        whois={
            "createdDate": created.strftime("%Y-%m-%d"),
            "expiresDate": expires.strftime("%Y-%m-%d"),
        },
        level=70,
    )]
    dossier = merge_records(records)
    dossier = extract_profile(dossier, Config())

    short_obs = [
        o for o in dossier.profile.observations
        if "short_lived" in o.tags
    ]
    assert len(short_obs) == 1
    assert dossier.profile.domain.get("is_short_lived") is True


def test_looks_random():
    """_looks_random should correctly identify generated-looking names."""
    assert _looks_random("a1b2c3d4e5f6g7h8.com") is True
    assert _looks_random("x7k3m9p2q5r8t1w4.com") is True
    assert _looks_random("google.com") is False
    assert _looks_random("my-site.com") is False
    assert _looks_random("example.org") is False
    assert _looks_random("bcdfghjklmnp.com") is True  # 12+ chars, no vowels
    assert _looks_random("abc") is False  # too short
