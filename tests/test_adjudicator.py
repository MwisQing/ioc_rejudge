from datetime import datetime, timedelta
import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.dga import DgaFacts, adjudicate_dga
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.adjudicator import adjudicate, _has_meaningful_icp
from ioc_rejudge.models import (
    Conclusion, Evidence, EvidenceLevel, EvidenceStrength,
)
from ioc_rejudge.normalize import merge_records
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
from ioc_rejudge.pipeline import _apply_current_icp_state
from tests.fixtures import build_record, build_hash_entry


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def _test_case(records, config=None, expected_conclusion=None):
    config = config or Config()
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    verdict = adjudicate(dossier, config)
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


def test_5_non_dga_icp_overrides_strong_a_e():
    """Non-DGA ICP is reviewed before the strong A/E conflict tree."""
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
        f"Non-DGA ICP must result in 待复核, got {v.conclusion}"
    assert v.candidate_label is None
    assert v.review_suggestion == "必看"
    assert v.disposition == "review"
    assert "ICP" in v.reason
    assert "E" in v.hit_evidence
    assert "A" in v.hit_evidence


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


def test_clue_group_overrides_current_icp_and_is_black():
    dossier = extract_evidence(merge_records([build_record(
        "clue-priority.invalid",
        comment="来源：线索群，确认恶意远控",
        icp_website="CURRENT-ICP",
    )]), Config())
    verdict = adjudicate(dossier, Config())
    assert verdict.conclusion in {Conclusion.ALIVE_VALID, Conclusion.INACTIVE_VALID}
    assert verdict.disposition == "block"
    assert verdict.review_suggestion == "不看"


def test_operator_context_waits_when_historical_icp_is_unresolved():
    dossier = extract_evidence(merge_records([build_record(
        "operator-history.invalid",
        source=["manual", "alliocs_tpd"],
        context="rootkit 独狼病毒",
        icp_website="OLD-ICP",
    )]), Config())
    dossier.icp_website = ""
    dossier.historical_icp_values = ["OLD-ICP"]
    verdict = adjudicate(dossier, Config())
    assert verdict.conclusion == Conclusion.PENDING_REVIEW


def test_operator_context_blocks_after_current_icp_is_confirmed_absent():
    dossier = extract_evidence(merge_records([build_record(
        "operator-current-negative.invalid",
        source=["manual"],
        context="rootkit 独狼病毒",
    )]), Config())
    dossier.current_icp_check_complete = True
    verdict = adjudicate(dossier, Config())
    assert verdict.conclusion in {Conclusion.ALIVE_VALID, Conclusion.INACTIVE_VALID}
    assert verdict.disposition == "block"


def test_low_level_service_abuse_is_gray_and_retains_urls():
    config = Config()
    retained = [
        "https://business-service.invalid/assets/poisoned.js",
        "https://business-service.invalid/event/log",
    ]
    dossier = extract_evidence(merge_records([build_record(
        "business-service.invalid",
        level=30,
        source=["manual", "vt_contacted", "sample-base"],
        context=(
            "Supply-chain malware contacted business-service.invalid through "
            "a poisoned client component."
        ),
        hash_entries=[{
            "md5": "zero-confidence",
            "level": 70,
            "confidence": 0,
            "time": _days_ago(5),
        }],
        relate_url=[
            {"url": retained[0], "level": 70},
            {"url": retained[1], "level": 70},
        ],
        flint={"last_seen": _days_ago(1), "records": 8_000_000},
        risk=-70,
    )]), config)

    verdict = adjudicate(dossier, config)

    assert not any(
        evidence.field == "operator_confirmed_malicious_context"
        for evidence in dossier.evidence_a
    )
    assert verdict.conclusion == Conclusion.GRAY
    assert verdict.disposition == "gray"
    assert verdict.review_suggestion == "抽检"
    assert verdict.retained_urls == retained
    assert verdict.scope_actions == [
        {"ioc": "business-service.invalid", "scope": "domain", "action": "gray"},
        {"ioc": retained[0], "scope": "url", "action": "retain"},
        {"ioc": retained[1], "scope": "url", "action": "retain"},
    ]


def test_low_level_domain_ignores_relate_url_for_other_host():
    verdict = _test_case([build_record(
        "business-service.invalid",
        level=30,
        source=["manual"],
        context="Malware report mentions business-service.invalid.",
        relate_url=[{
            "url": "https://other-service.invalid/poisoned.js",
            "level": 70,
        }],
    )])

    assert verdict.conclusion != Conclusion.GRAY
    assert verdict.retained_urls == []


def test_high_level_operator_context_can_be_false_positive_after_asset_change():
    config = Config()
    dossier = extract_evidence(merge_records([build_record(
        "reassigned-business.invalid",
        level=70,
        source=["manual"],
        context="Historical malware used reassigned-business.invalid as C2.",
        official_website="https://reassigned-business.invalid",
        icp_website="CURRENT-ICP",
        ownership_change={
            "previous": "malicious owner",
            "current": "verified business owner",
        },
    )]), config)

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion == Conclusion.FALSE_POSITIVE
    assert verdict.disposition == "false_positive"
    assert verdict.review_suggestion == "抽检"
    assert "资产变化" in verdict.reason
    assert any(
        evidence.field == "ownership_change"
        for evidence in dossier.evidence_d
    )


def test_high_level_operator_context_without_business_closure_stays_black():
    verdict = _test_case([build_record(
        "active-c2.invalid",
        level=60,
        source=["manual"],
        context="Malware actively uses active-c2.invalid as a C2 domain.",
        hash_entries=[build_hash_entry(
            "active-malware", level=70, time=_days_ago(2)
        )],
    )])

    assert verdict.conclusion == Conclusion.ALIVE_VALID
    assert verdict.disposition == "block"


def _operator_history_dossier():
    config = Config()
    dossier = extract_evidence(merge_records([
        build_record(
            "icp-state.invalid",
            updatetime="2020-01-01 00:00:00",
            icp_website="OLD-ICP",
        ),
        build_record(
            "icp-state.invalid",
            updatetime="2026-01-01 00:00:00",
            source=["manual"],
            context="rootkit 独狼病毒",
            icp_website="",
        ),
    ]), config)
    return dossier, config


def _icp_observation(*, status=ProviderStatus.SUCCESS, freshness=Freshness.FRESH, current=False, registration=None):
    payload = {"current": current}
    if registration is not None:
        payload["registration"] = registration
    return Observation(
        ioc="icp-state.invalid",
        scope="domain",
        provider="icp",
        kind="icp",
        status=status,
        freshness=freshness,
        payload=payload,
    )


def test_fresh_negative_current_icp_clears_historical_gate_and_blocks_operator_context():
    dossier, config = _operator_history_dossier()
    _apply_current_icp_state(dossier, [_icp_observation(current=False)])
    assert dossier.current_icp_check_complete is True
    assert dossier.icp_website == ""
    assert len(dossier.historical_icp_values) == 1
    assert _has_meaningful_icp(dossier) is False
    verdict = adjudicate(dossier, config)
    assert verdict.disposition == "block"
    assert verdict.conclusion in {Conclusion.ALIVE_VALID, Conclusion.INACTIVE_VALID}


def test_fresh_positive_current_icp_keeps_operator_context_under_review():
    dossier, config = _operator_history_dossier()
    _apply_current_icp_state(
        dossier,
        [_icp_observation(current=True, registration="ICP-CURRENT")],
    )
    assert dossier.current_icp_check_complete is True
    assert dossier.icp_website == "ICP-CURRENT"
    assert _has_meaningful_icp(dossier) is True
    assert adjudicate(dossier, config).conclusion == Conclusion.PENDING_REVIEW


@pytest.mark.parametrize(
    "observation",
    [
        _icp_observation(current=False, freshness=Freshness.STALE),
        _icp_observation(current=False, status=ProviderStatus.ERROR),
        _icp_observation(current=False, status=ProviderStatus.DISABLED),
        _icp_observation(current=True, registration=""),
        _icp_observation(current="false"),
    ],
    ids=["stale-negative", "error-negative", "disabled-negative", "invalid-positive", "dirty-current"],
)
def test_incomplete_current_icp_keeps_historical_gate(observation):
    dossier, config = _operator_history_dossier()
    _apply_current_icp_state(dossier, [observation])
    assert dossier.current_icp_check_complete is False
    assert _has_meaningful_icp(dossier) is True
    assert adjudicate(dossier, config).conclusion == Conclusion.PENDING_REVIEW


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
    v_365 = adjudicate(dossier, config_365)
    assert v_365.conclusion == Conclusion.INACTIVE_VALID

    config_730 = Config(activity_window_days=730)
    dossier2 = merge_records(records)
    dossier2 = extract_evidence(dossier2, config_730)
    v_730 = adjudicate(dossier2, config_730)
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


def test_adjudicate_legacy_call_uses_default_config():
    records = [
        build_record(
            "legacy-api.com",
            official_website="https://www.example.com",
            level=20,
            source=["spider"],
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    verdict = adjudicate(dossier)
    assert verdict.conclusion == Conclusion.FALSE_POSITIVE


# ── IOC expiry vs inactive spec: acceptance scenarios ──

def test_expiry_inactive_no_biz():
    """历史恶意 + 无B + 无正常业务闭环 → 失活有效"""
    records = [
        build_record(
            "old-evil.com",
            context="Historical sample communicated with old-evil.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            family=["SilverFox"],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)
    assert v.activity_status == "历史活跃"
    assert "失活有效" in v.reason
    assert "无正常业务承接" in v.reason
    assert "IOC仍可用于拦截" in v.reason


def test_expiry_inactive_http_unreachable():
    """历史恶意 + HTTP不可达 + 无正常业务闭环 → 失活有效"""
    records = [
        build_record(
            "unreachable-evil.com",
            context="Sample communicated with unreachable-evil.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            level=70,
            http={"status": "404"},
            reachable=False,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)
    assert "失活有效" in v.reason


def test_expiry_inactive_parking():
    """历史恶意 + parking + 无正常业务闭环 → 失活有效"""
    records = [
        build_record(
            "parked-evil.com",
            context="Sample C2 communication with parked-evil.com, parking page detected",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)
    assert "失活有效" in v.reason


def test_expiry_c_plus_biz_no_threat_residue():
    """Historical C plus non-DGA ICP is reviewed before asset-change logic."""
    records = [
        build_record(
            "expired-evil.com",
            context="Historical domain associated with expired-evil.com",
            source=[],
            level=50,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert "ICP" in v.reason


def test_expiry_c_plus_biz_with_threat_residue():
    """历史恶意C + 正常业务闭环 + 威胁残留 → 待复核"""
    records = [
        build_record(
            "conflict-expired.com",
            context="Historical sample communicated with conflict-expired.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            level=70,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
            malicious_type=["TROJAN"],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert v.review_suggestion == "必看"


def test_expiry_strong_a_biz_conflict():
    """Strong A plus non-DGA ICP is reviewed by the ICP gate."""
    records = [
        build_record(
            "strong-evil-biz.com",
            context="Sample directly connected to strong-evil-biz.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert v.candidate_label is None
    assert "ICP" in v.reason


def test_expiry_no_ac_unreachable_only():
    """无A/C + 仅无解析/不可达 → 待复核（不能仅凭弱状态判误报）"""
    records = [
        build_record(
            "unreachable-unknown.com",
            level=20,
            source=["spider"],
            reachable=False,
            http={"status": "404"},
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)


def test_expiry_reason_inactive_valid():
    """验证失活有效reason文案符合spec"""
    records = [
        build_record(
            "reason-test.com",
            context="Historical sample communicated with reason-test.com",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.INACTIVE_VALID)
    assert "近期未见实质活动" in v.reason
    assert "无正常业务承接" in v.reason


def test_expiry_reason_false_positive():
    """验证误报reason文案符合spec"""
    records = [
        build_record(
            "fp-reason.com",
            official_website="https://www.example.com",
            level=20,
            source=["spider"],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.FALSE_POSITIVE)
    assert "恶意关联不成立" in v.reason or "情报已过期" in v.reason


def test_expiry_reason_pending_review():
    """验证待复核reason文案符合spec"""
    records = [
        build_record(
            "pr-reason.com",
            level=70,
            source=["spider"],
            relate_ip_domain=[{"key": "evil.com", "level": 80}],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)


def test_expiry_forbidden_contains_spec_rules():
    """验证forbidden_labels包含spec规定的禁止判定"""
    records = [
        build_record(
            "forbidden-test.com",
            context="Sample connected to forbidden-test.com",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.ALIVE_VALID)
    assert "不能仅凭无解析" in v.forbidden_labels
    assert "不能仅凭WHOIS" in v.forbidden_labels


def test_expiry_c_plus_biz_resolv_ip_only_pending():
    """Historical C plus non-DGA ICP remains review with a resolv_ip."""
    records = [
        build_record(
            "confidence-test.com",
            context="Historical domain associated with confidence-test.com",
            source=[],
            level=50,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
            resolv_ip="198.51.100.1",
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert "ICP" in v.reason


def test_expiry_c_biz_resolv_ip_only_not_false_positive():
    """Non-DGA ICP prevents automatic false-positive despite resolv_ip."""
    records = [
        build_record(
            "changed-evil.com",
            context="Historical domain associated with changed-evil.com",
            source=[],
            level=50,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
            resolv_ip="203.0.113.1",
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert "ICP" in v.reason


def test_expiry_c_biz_explicit_asset_change_with_icp_is_review():
    """Non-DGA ICP outranks an otherwise complete asset-change candidate."""
    config = Config()
    records = [
        build_record(
            "changed-evil.com",
            context="Historical domain associated with changed-evil.com",
            source=[],
            level=50,
            icp_website="https://icp.example.com",
            official_website="https://www.example.com",
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    dossier.evidence_d.append(Evidence(
        level=EvidenceLevel.D,
        field="resolv_ip_change",
        detail="previous_ip=192.0.2.1 new_value=203.0.113.1",
        tags=["asset_change"],
    ))
    v = adjudicate(dossier, config)
    assert v.conclusion == Conclusion.PENDING_REVIEW
    assert v.disposition == "review"
    assert "ICP" in v.reason


def test_expiry_c_threat_residue_no_e():
    """P2: 历史恶意C(historical_context) + 高危反查域名(威胁残留) + 无E → 待复核"""
    records = [
        build_record(
            "ip-change-evil.com",
            context="Historical domain associated with ip-change-evil.com",
            source=[],
            level=50,
            resolv_ip="10.0.0.1",
            relate_ip_domain=[{"key": "evil-related.com", "level": 80}],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert v.review_suggestion == "必看"


def test_expiry_c_resolv_ip_threat_residue_no_e():
    """P2: 历史恶意C + 解析IP变化 + 高危反查域名 + 无正常业务 → 待复核"""
    records = [
        build_record(
            "resolv-threat.com",
            context="Historical domain associated with resolv-threat.com",
            source=[],
            level=50,
            resolv_ip="198.51.100.1",
            relate_ip_domain=[
                {"key": "evil1.com", "level": 85},
                {"key": "evil2.com", "level": 75},
            ],
        )
    ]
    v = _test_case(records, expected_conclusion=Conclusion.PENDING_REVIEW)
    assert v.review_suggestion == "必看"


def test_family_malicious_word_blocks_false_positive_via_rules():
    """family/tag 含强恶意词 → 威胁残留触发，不能自动误报（词表配置驱动）。

    构造一个"仅有正常业务闭环、无其他威胁信号"的 dossier，但 family 含
    backdoor（强恶意词，来自 rules.strong_malicious_indicators）。期望结论
    不是误报（被 threat_residue 拦截），以此证明 family/tag 残留检测读 config。
    """
    config = Config()
    # safety net: the strong word must come from the configured list, not a
    # hardcoded constant — if config-driven, removing it from rules flips the verdict.
    assert "backdoor" in config.rules.strong_malicious_indicators
    records = [
        build_record(
            "backdoor-family.com",
            official_website="https://www.example.com",
            level=20,
            source=["spider"],
            family=["Backdoor"],
        )
    ]
    v = _test_case(records)
    assert v.conclusion != Conclusion.FALSE_POSITIVE, \
        "family with a strong malicious word must block automatic false-positive"


def test_family_malicious_word_disabled_when_removed_from_rules():
    """从 rules 移除强恶意词后，family 残留不再触发，恢复误报判定。

    反向验证：threat_residue 的 family/tag 检测确实由 config 驱动，而非硬编码。
    """
    from ioc_rejudge.rules import RuleConfig
    config = Config()
    # Strip every strong malicious word so the family value matches nothing.
    config.rules = RuleConfig(
        strong_sources=config.rules.strong_sources,
        weak_sources=config.rules.weak_sources,
        malicious_indicators=config.rules.malicious_indicators,
        strong_malicious_indicators=[],  # no strong words configured
        context_comment_malicious_indicators=config.rules.context_comment_malicious_indicators,
        context_comment_historical_indicators=config.rules.context_comment_historical_indicators,
        normalization_indicators=config.rules.normalization_indicators,
        review_indicators=config.rules.review_indicators,
        trusted_business_fields=config.rules.trusted_business_fields,
    )
    records = [
        build_record(
            "backdoor-family.com",
            official_website="https://www.example.com",
            level=20,
            source=["spider"],
            family=["Backdoor"],
        )
    ]
    v = _test_case(records, config=config)
    assert v.conclusion == Conclusion.FALSE_POSITIVE, \
        "with strong_malicious_indicators emptied, family residue must not fire"


_GRAY_URLS = [
    "https://gray-candidate.invalid/login",
    "https://gray-candidate.invalid/reset",
]


def _gray_candidate_dossier(*, hash_entries=None):
    config = Config()
    record = build_record(
        "gray-candidate.invalid",
        level=60,
        context="Historical phishing URL associated with gray-candidate.invalid",
        family=["phishing"],
        whois={"expiresDate": "2020-01-01"},
        relate_url=[
            {"url": _GRAY_URLS[0], "level": 60},
            {"url": _GRAY_URLS[1], "level": 70},
        ],
        hash_entries=hash_entries or [],
    )
    return extract_evidence(merge_records([record]), config)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("icp_website", " ICP-CURRENT "),
        ("historical_icp_values", ["ICP-HISTORICAL"]),
        ("historical_icp_values", ("ICP-HISTORICAL",)),
    ],
    ids=["current", "historical-list", "historical-tuple"],
)
def test_non_dga_icp_overrides_strong_a_b(field_name, value):
    config = Config()
    dossier = extract_evidence(merge_records([
        build_record(
            "icp-priority.invalid",
            context="Malware connected to icp-priority.invalid C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry(time=_days_ago(5))],
            level=70,
        )
    ]), config)
    setattr(dossier, field_name, value)

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.route == "standard"
    assert verdict.disposition == "review"
    assert "ICP" in verdict.reason


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("icp_website", "ICP-CURRENT"),
        ("historical_icp_values", ["ICP-HISTORICAL"]),
    ],
    ids=["current", "historical"],
)
def test_non_dga_icp_overrides_complete_gray_candidate(field_name, value):
    dossier = _gray_candidate_dossier()
    setattr(dossier, field_name, value)

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"
    assert "ICP" in verdict.reason


def test_non_dga_icp_overrides_false_positive_candidate():
    config = Config()
    dossier = extract_evidence(merge_records([
        build_record(
            "normal-with-icp.invalid",
            official_website="https://normal.invalid",
            level=20,
            source=["spider"],
        )
    ]), config)
    dossier.historical_icp_values = ["ICP-HISTORICAL"]

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.disposition == "review"
    assert "ICP" in verdict.reason


@pytest.mark.parametrize(
    ("current_icp", "historical_icp"),
    [
        (None, []),
        ("", []),
        ("   ", []),
        (0, []),
        (False, []),
        ({"record": "ICP"}, []),
        ([], []),
        ("", None),
        ("", "ICP-SCALAR"),
        ("", 0),
        ("", False),
        ("", {"record": "ICP"}),
        ("", [None, " ", 0, False, {}]),
    ],
)
def test_non_dga_icp_dirty_values_do_not_trigger_gate(current_icp, historical_icp):
    config = Config()
    dossier = extract_evidence(merge_records([
        build_record(
            "dirty-icp.invalid",
            official_website="https://normal.invalid",
            level=20,
            source=["spider"],
        )
    ]), config)
    dossier.icp_website = current_icp
    dossier.historical_icp_values = historical_icp

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion == Conclusion.FALSE_POSITIVE
    assert "ICP" not in verdict.reason


def test_gray_complete_candidate_has_exact_scope_contract():
    dossier = _gray_candidate_dossier()

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.GRAY
    assert verdict.route == "standard"
    assert verdict.disposition == "gray"
    assert verdict.retained_urls == _GRAY_URLS
    assert verdict.scope_actions == [
        {"ioc": "gray-candidate.invalid", "scope": "domain", "action": "gray"},
        {"ioc": _GRAY_URLS[0], "scope": "url", "action": "retain"},
        {"ioc": _GRAY_URLS[1], "scope": "url", "action": "retain"},
    ]
    assert "保留" in verdict.reason
    assert "白名单" in verdict.forbidden_labels


@pytest.mark.parametrize(
    "missing_condition",
    [
        "domain_type",
        "retained_url",
        "expired_whois",
        "no_recent_b",
        "no_malicious_sample",
        "historical_closure",
    ],
)
def test_gray_missing_each_condition_is_not_gray(missing_condition):
    dossier = _gray_candidate_dossier()
    if missing_condition == "domain_type":
        dossier.ioc_type = "url"
    elif missing_condition == "retained_url":
        dossier.retained_urls = []
    elif missing_condition == "expired_whois":
        dossier.whois = {}
    elif missing_condition == "no_recent_b":
        dossier.evidence_b.append(Evidence(
            level=EvidenceLevel.B,
            field="recent_activity",
            detail="recent material activity",
        ))
    elif missing_condition == "no_malicious_sample":
        dossier.hash_entries.append(build_hash_entry(time="2020-01-01 00:00:00"))
    elif missing_condition == "historical_closure":
        dossier.evidence_c = []
        dossier.context = ""
        dossier.comment = ""
        dossier.family = []
        dossier.tag = []
        dossier.malicious_type = []

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion != Conclusion.GRAY


@pytest.mark.parametrize(
    "whois",
    [
        None,
        "2020-01-01",
        ["2020-01-01"],
        {},
        {"expiresDate": ""},
        {"expiresDate": "not-a-date"},
        {"expiresDate": datetime.now().strftime("%Y-%m-%d")},
        {"expiresDate": "2999-01-01"},
    ],
)
def test_gray_dirty_or_unexpired_whois_is_not_gray(whois):
    dossier = _gray_candidate_dossier()
    dossier.whois = whois

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion != Conclusion.GRAY


def test_gray_historical_malicious_sample_without_recent_b_is_not_gray():
    dossier = _gray_candidate_dossier()
    assert not dossier.evidence_b
    dossier.hash_entries.append(build_hash_entry(time="2020-01-01 00:00:00"))

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion != Conclusion.GRAY


def test_gray_not_a_virus_sample_does_not_block_complete_candidate():
    dossier = _gray_candidate_dossier(hash_entries=[
        build_hash_entry(
            family="not-a-virus:AdWare",
            level=90,
            time="2020-01-01 00:00:00",
        )
    ])

    verdict = adjudicate(dossier, Config())

    assert verdict.conclusion == Conclusion.GRAY


def test_gray_scope_lists_are_defensive_copies():
    dossier = _gray_candidate_dossier()
    first = adjudicate(dossier, Config())
    assert first.conclusion == Conclusion.GRAY
    assert first.scope_actions
    first.retained_urls.append("https://mutated.invalid/path")
    first.scope_actions[0]["action"] = "block"

    second = adjudicate(dossier, Config())

    assert dossier.retained_urls == _GRAY_URLS
    assert second.retained_urls == _GRAY_URLS
    assert second.scope_actions[0]["action"] == "gray"
    assert "https://mutated.invalid/path" not in second.retained_urls


@pytest.mark.parametrize(
    ("scenario", "expected_conclusion", "expected_disposition"),
    [
        ("alive", Conclusion.ALIVE_VALID, "block"),
        ("inactive", Conclusion.INACTIVE_VALID, "block"),
        ("false_positive", Conclusion.FALSE_POSITIVE, "false_positive"),
        ("review", Conclusion.PENDING_REVIEW, "review"),
    ],
)
def test_standard_verdict_contract_maps_every_conclusion(
    scenario, expected_conclusion, expected_disposition,
):
    if scenario == "alive":
        record = build_record(
            "contract-alive.invalid",
            context="Malware connected to contract-alive.invalid C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry(time=_days_ago(5))],
            level=70,
        )
    elif scenario == "inactive":
        record = build_record(
            "contract-inactive.invalid",
            context="Historical malware at contract-inactive.invalid",
            source=["sample-base"],
            hash_entries=[build_hash_entry(time="2020-01-01 00:00:00")],
            level=70,
        )
    elif scenario == "false_positive":
        record = build_record(
            "contract-normal.invalid",
            official_website="https://normal.invalid",
            level=20,
            source=["spider"],
        )
    else:
        record = build_record("contract-review.invalid", level=20)

    verdict = _test_case([record])

    assert verdict.conclusion == expected_conclusion
    assert verdict.route == "standard"
    assert verdict.disposition == expected_disposition


def test_standard_verdict_contract_conflict_helper_maps_review():
    config = Config()
    dossier = extract_evidence(merge_records([
        build_record(
            "contract-conflict.invalid",
            context="Malware connected to contract-conflict.invalid C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry(time=_days_ago(5))],
            level=70,
        )
    ]), config)
    dossier.evidence_e.append(Evidence(
        level=EvidenceLevel.E,
        field="synthetic_business_conflict",
        detail="strong normal identity conflict",
        strength=EvidenceStrength.STRONG,
        tags=["trusted_business"],
    ))

    verdict = adjudicate(dossier, config)

    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.candidate_label == Conclusion.ALIVE_VALID.value
    assert verdict.route == "standard"
    assert verdict.disposition == "review"


def test_dga_standard_isolation_keeps_dga_icp_white():
    verdict = adjudicate_dga(
        "dga-isolation.invalid",
        DgaFacts(sample_check_complete=True, has_current_icp=True),
    )

    assert verdict.conclusion == Conclusion.FALSE_POSITIVE
    assert verdict.route == "dga"
    assert verdict.disposition == "false_positive"


@pytest.mark.parametrize(
    "record",
    [
        build_record(
            "standard-whois.invalid",
            whois={"expiresDate": "2999-01-01"},
            level=20,
        ),
        build_record(
            "standard-pdns.invalid",
            dtree=[{
                "key": "recent.standard-pdns.invalid",
                "level": 20,
                "last": _days_ago(5),
            }],
            level=20,
        ),
    ],
    ids=["whois", "pdns"],
)
def test_dga_standard_isolation_does_not_copy_white_shortcuts(record):
    verdict = _test_case([record])

    assert verdict.route == "standard"
    assert verdict.conclusion != Conclusion.FALSE_POSITIVE
