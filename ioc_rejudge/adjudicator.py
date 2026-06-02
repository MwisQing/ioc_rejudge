"""Judgment tree - A-F evidence to verdict."""
from ioc_rejudge.models import IocDossier, Verdict, Conclusion
from ioc_rejudge.evidence import _is_strong_a, _is_strong_e


def adjudicate(dossier: IocDossier) -> Verdict:
    has_a = bool(dossier.evidence_a)
    has_b = bool(dossier.evidence_b)
    has_c = bool(dossier.evidence_c)
    has_e = bool(dossier.evidence_e)
    has_d = bool(dossier.evidence_d)

    # A+E conflict only when BOTH are strong
    # Strong A + weak E → A wins, confidence drops to "中"
    # Strong A + strong E → genuine conflict, 待复核
    strong_a = _is_strong_a(dossier)
    strong_e = _is_strong_e(dossier)
    strong_conflict = strong_a and strong_e
    weak_conflict = has_a and has_e and not strong_conflict

    if has_a:
        if has_b:
            if strong_conflict:
                return _make_conflict_verdict(dossier, Conclusion.ALIVE_VALID)
            if weak_conflict:
                return _make_verdict(
                    dossier, Conclusion.ALIVE_VALID, "直接恶意", "近一年活跃", "中", "抽检",
                )
            return _make_verdict(
                dossier, Conclusion.ALIVE_VALID, "直接恶意", "近一年活跃", "高", "不看",
            )
        elif has_c:
            if strong_conflict:
                return _make_conflict_verdict(dossier, Conclusion.INACTIVE_VALID)
            if weak_conflict:
                return _make_verdict(
                    dossier, Conclusion.INACTIVE_VALID, "历史恶意", "历史活跃", "中", "抽检",
                )
            return _make_verdict(
                dossier, Conclusion.INACTIVE_VALID, "历史恶意", "历史活跃", "高", "不看",
            )
        else:
            if strong_conflict:
                return _make_conflict_verdict(dossier, Conclusion.PENDING_REVIEW)
            return _make_verdict(
                dossier, Conclusion.PENDING_REVIEW, "直接恶意", "无实质活动", "中", "必看",
                reason="判定为待复核：存在直接恶意证据但无近期活动也无历史恶意闭环，需要人工确认。",
            )

    if has_c:
        if strong_conflict:
            return _make_conflict_verdict(dossier, Conclusion.INACTIVE_VALID)
        return _make_verdict(
            dossier, Conclusion.INACTIVE_VALID, "历史恶意", "历史活跃", "中", "抽检",
        )

    if has_e:
        return _make_verdict(
            dossier, Conclusion.FALSE_POSITIVE, "误报污染", "无实质活动", "中", "不看",
        )

    return _make_verdict(
        dossier, Conclusion.PENDING_REVIEW,
        "间接关联" if has_d else "证据不足",
        "无实质活动", "低",
        "抽检" if has_d else "必看",
    )


def _make_verdict(
    dossier: IocDossier,
    conclusion: Conclusion,
    malicious_nature: str,
    activity_status: str,
    confidence: str,
    review_suggestion: str,
    reason: str | None = None,
) -> Verdict:
    hit_evidence = _build_hit_evidence(dossier)
    forbidden = _build_forbidden(dossier, conclusion)
    reason = reason or _build_reason(conclusion)

    return Verdict(
        conclusion=conclusion,
        malicious_nature=malicious_nature,
        activity_status=activity_status,
        confidence=confidence,
        review_suggestion=review_suggestion,
        candidate_label=None,
        hit_evidence=hit_evidence,
        forbidden_labels=forbidden,
        reason=reason,
    )


def _make_conflict_verdict(dossier: IocDossier, candidate: Conclusion) -> Verdict:
    hit_evidence = _build_hit_evidence(dossier)
    forbidden = _build_forbidden(dossier, Conclusion.PENDING_REVIEW)
    reason = (
        f"判定为待复核：存在直接恶意证据，但同时存在正常化证据，"
        f"证据冲突需要人工复核。候选结论: {candidate.value}。"
    )

    return Verdict(
        conclusion=Conclusion.PENDING_REVIEW,
        malicious_nature="直接恶意",
        activity_status="近一年活跃" if dossier.evidence_b else "历史活跃",
        confidence="中",
        review_suggestion="必看",
        candidate_label=candidate.value,
        hit_evidence=hit_evidence,
        forbidden_labels=forbidden,
        reason=reason,
    )


def _build_hit_evidence(dossier: IocDossier) -> str:
    parts = []
    if dossier.evidence_a:
        parts.append(f"A={'; '.join(e.field for e in dossier.evidence_a)}")
    if dossier.evidence_b:
        parts.append(f"B={'; '.join(e.field for e in dossier.evidence_b)}")
    if dossier.evidence_c:
        parts.append(f"C={'; '.join(e.field for e in dossier.evidence_c)}")
    if dossier.evidence_d:
        parts.append(f"D={'; '.join(e.field for e in dossier.evidence_d)}")
    if dossier.evidence_e:
        parts.append(f"E={'; '.join(e.field for e in dossier.evidence_e)}")
    if dossier.evidence_f:
        parts.append(f"F={'; '.join(e.field for e in dossier.evidence_f)}")
    return "; ".join(parts) if parts else "无实质证据"


def _build_forbidden(dossier: IocDossier, conclusion: Conclusion) -> str:
    reasons = []
    if dossier.evidence_a:
        reasons.append("不能判误报，因为存在A级直接恶意证据")
    if conclusion == Conclusion.ALIVE_VALID:
        if not dossier.evidence_b:
            reasons.append("不能仅凭updatetime判存活")
    elif conclusion == Conclusion.INACTIVE_VALID:
        reasons.append("不能判误报，因为存在历史恶意证据；失活不等于误报")
    elif conclusion == Conclusion.PENDING_REVIEW:
        if dossier.evidence_a and dossier.evidence_e:
            reasons.append("存在强A+强E证据冲突（ICP备案+官网匹配正常业务），不能自动提交结论，必须人工复核")
    return "；".join(reasons) if reasons else "无禁止判定"


def _build_reason(conclusion: Conclusion) -> str:
    reasons = {
        Conclusion.ALIVE_VALID: "判定为存活有效：存在直接恶意证据，且近一年存在样本、访问、解析或关联记录等实质活动证据。",
        Conclusion.INACTIVE_VALID: "判定为失活有效：历史恶意证据成立，但近一年未见样本、访问、解析或相关直接活动证据；失活不等于误报。",
        Conclusion.FALSE_POSITIVE: "判定为误报：未发现 IOC 本身的直接恶意证据，现有恶意关联主要来自弱关联、共享基础设施或标签污染，同时存在正常化或污染证据。",
        Conclusion.PENDING_REVIEW: "判定为待复核：当前快照内存在证据冲突或证据链不足，无法在不引入外部查询的情况下稳定判定。",
    }
    return reasons.get(conclusion, "未知结论")
