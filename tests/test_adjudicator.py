from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.models import Conclusion
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_record, build_hash_entry


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def _test_case(records, config=None, expected_conclusion=None):
    config = config or Config()
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    verdict = adjudicate(dossier)
    if expected_conclusion:
        assert verdict.conclusion == expected_conclusion, \
            f"Expected {expected_conclusion}, got {verdict.conclusion}. Evidence: A={dossier.evidence_a}, B={dossier.evidence_b}, C={dossier.evidence_c}"
    return verdict


def test_1_alive_valid():
    records = [
        build_record(
            "evil.com",
            context="Sample directly connected to evil.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            family=["SilverFox"],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.ALIVE_VALID)
    assert v.malicious_nature == "直接恶意"
    assert v.activity_status == "近一年活跃"
    assert v.review_suggestion == "不看"


def test_2_inactive_valid():
    records = [
        build_record(
            "evil.com",
            context="Historical sample communicated with evil.com",
            source=["sample-base", "manual"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            family=["SilverFox"],
            malicious_type=["TROJAN"],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)
    assert v.activity_status == "历史活跃"


def test_3_updatetime_alone_not_alive():
    records = [
        build_record(
            "suspicious.com",
            updatetime=_days_ago(1),
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.conclusion in (Conclusion.PENDING_REVIEW, Conclusion.FALSE_POSITIVE), \
        f"Should not be alive valid with only updatetime. Got {v.conclusion}"


def test_4_false_positive():
    records = [
        build_record(
            "normal-site.com",
            official_website="https://www.google.com",
            level=30,
            family=[],
            source=["spider"],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.FALSE_POSITIVE)
    assert v.malicious_nature == "误报污染"


def test_5_a_plus_e_conflict():
    """Strong A + strong E (ICP+官网) → 待复核"""
    records = [
        build_record(
            "conflict.com",
            context="Sample directly connected to conflict.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            official_website="https://www.normal-business.com",
            icp_website="https://www.normal-business.com",
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW, \
        f"Strong A + strong E must result in 待复核, got {v.conclusion}"
    assert v.candidate_label is not None, "candidate_label must be set for A+E conflict"
    assert v.review_suggestion == "必看"
    assert "E" in v.hit_evidence
    assert "A" in v.hit_evidence
    assert "强A+强E" in v.forbidden_labels or "ICP备案+官网" in v.forbidden_labels


def test_5b_strong_a_weak_e():
    """强A + 弱E(仅官网/证书/family) → 存活有效, 置信度降为中"""
    records = [
        build_record(
            "real-evil.com",
            context="Sample directly connected to real-evil.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            official_website="https://www.normal-business.com",
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.conclusion == Conclusion.ALIVE_VALID
    assert v.confidence == "中", "Weak E should drop confidence to 中"
    assert v.review_suggestion == "抽检"


def test_6_only_d():
    records = [
        build_record(
            "unknown.com",
            relate_ip_domain=[{"key": "1.2.3.4", "level": 50, "count": 100}],
            level=50,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)


def test_7_merge_old_ac_new_b():
    records = [
        build_record(
            "evil.com",
            context="Historical sample communicated with evil.com",
            source=["sample-base"],
            hash_entries=[build_hash_entry("old_hash", level=70, time="2022-06-01 00:00:00")],
            family=["SilverFox"],
            level=70,
        ),
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            source=["sample-base"],
            hash_entries=[build_hash_entry("new_hash", level=70, time=_days_ago(10))],
            level=70,
        ),
    ]
    v = _test_case(records, expected_conclusion=Conclusion.ALIVE_VALID)


def test_8_resolv_ip_not_b():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            source=["sample-base"],
            resolv_ip="198.44.248.182",
            hash_entries=[build_hash_entry("abc", level=70, time="2020-01-01 00:00:00")],
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.conclusion == Conclusion.INACTIVE_VALID


def test_10_output_fields():
    records = [
        build_record(
            "evil.com",
            context="Sample connected to evil.com",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.hit_evidence
    assert v.forbidden_labels
    assert v.reason


def test_11_c_no_flint_access():
    records = [
        build_record(
            "evil.com",
            context="Historical sample communicated with evil.com C2 server",
            source=["sample-base", "manual"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            family=["SilverFox"],
            malicious_type=["TROJAN"],
            attck=["T1071"],
            level=70,
            flint={},
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)


def test_12_weak_c_plus_e():
    records = [
        build_record(
            "maybe-normal.com",
            official_website="https://www.legit-business.com",
            level=30,
            source=["spider"],
            family=[],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.FALSE_POSITIVE)


def test_13_custom_activity_window():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(500))],
            level=70,
        )
    ]
    config_365 = Config(activity_window_days=365)
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config_365)
    v_365 = adjudicate(dossier)
    assert v_365.conclusion == Conclusion.INACTIVE_VALID

    config_730 = Config(activity_window_days=730)
    dossier2 = merge_records(records)
    dossier2 = extract_evidence(dossier2, config_730)
    v_730 = adjudicate(dossier2)
    assert v_730.conclusion == Conclusion.ALIVE_VALID


def test_14_alone_not_c():
    records = [
        build_record(
            "suspicious.com",
            source=["sample-base"],
            family=["SilverFox"],
            tag=["CC"],
            level=70,
            context="",
        )
    ]
    v = _test_case(records)
    assert v.conclusion == Conclusion.PENDING_REVIEW


def test_15_hash_no_communication():
    records = [
        build_record(
            "innocent.com",
            context="Malware found on system, hash detected but no domain reference here",
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
        )
    ]
    v = _test_case(records)
    assert v.conclusion != Conclusion.ALIVE_VALID, \
        "Should not be alive valid when hash doesn't prove communication with IOC"
