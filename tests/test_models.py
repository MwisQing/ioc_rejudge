from ioc_rejudge.models import EvidenceLevel, Evidence, IocDossier, Verdict, Conclusion


def test_evidence_level_enum():
    assert EvidenceLevel.A == "A"
    assert EvidenceLevel.F == "F"


def test_verdict_creation():
    v = Verdict(
        conclusion=Conclusion.ALIVE_VALID,
        malicious_nature="直接恶意",
        activity_status="近一年活跃",
        confidence="高",
        review_suggestion="不看",
        candidate_label=None,
        hit_evidence="A=样本直连; B=hash.time 近一年",
        forbidden_labels="不能判误报，存在A级证据",
        reason="判定为存活有效：存在直接恶意证据，且近一年存在实质活动证据。",
    )
    assert v.conclusion == Conclusion.ALIVE_VALID


def test_dossier_default_values():
    d = IocDossier(ioc="test.com", ioc_type="domain")
    assert d.evidence_a == []
    assert d.evidence_b == []
    assert d.evidence_f == []
    assert d.ports == []


def test_dossier_current_icp_check_defaults_and_isolates_instances():
    first = IocDossier(ioc="first.invalid", ioc_type="domain")
    second = IocDossier(ioc="second.invalid", ioc_type="domain")
    assert first.current_icp_check_complete is False
    assert second.current_icp_check_complete is False
    first.current_icp_check_complete = True
    assert second.current_icp_check_complete is False
