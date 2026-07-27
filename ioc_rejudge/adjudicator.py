"""Judgment tree - A-F evidence to verdict."""
from datetime import datetime, timedelta
import re

from ioc_rejudge.config import Config
from ioc_rejudge.models import IocDossier, Verdict, Conclusion
from ioc_rejudge.evidence import _is_strong_a, _is_strong_e, is_malicious_sample
from ioc_rejudge.normalize import coerce_level
from ioc_rejudge.parser import parse_time


_DISPOSITION_BY_CONCLUSION = {
    Conclusion.ALIVE_VALID: "block",
    Conclusion.INACTIVE_VALID: "block",
    Conclusion.GRAY: "gray",
    Conclusion.FALSE_POSITIVE: "false_positive",
    Conclusion.PENDING_REVIEW: "review",
}

_PHISHING_PATTERN = re.compile(
    r"(?<![a-z0-9])phish(?:ing|ed)?(?![a-z0-9])",
    re.IGNORECASE,
)


def _is_meaningful_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _has_meaningful_icp(dossier: IocDossier) -> bool:
    if _is_meaningful_text(dossier.icp_website):
        return True

    if dossier.current_icp_check_complete is True:
        return False

    historical = dossier.historical_icp_values
    if not isinstance(historical, (list, tuple)):
        return False
    return any(_is_meaningful_text(value) for value in historical)


def _has_expired_whois(dossier: IocDossier) -> bool:
    if not isinstance(dossier.whois, dict):
        return False
    expires = parse_time(dossier.whois.get("expiresDate"))
    return expires is not None and expires.date() < datetime.now().date()


def _has_historical_or_phishing_url_evidence(dossier: IocDossier) -> bool:
    evidence_c = dossier.evidence_c
    if isinstance(evidence_c, (list, tuple)):
        for evidence in evidence_c:
            tags = getattr(evidence, "tags", [])
            field = getattr(evidence, "field", "")
            if field in {"historical_malicious", "structured_public_apt"}:
                return True
            if isinstance(tags, (list, tuple)) and "historical" in tags:
                return True

    text_values = [dossier.context, dossier.comment]
    for values in (dossier.family, dossier.tag, dossier.malicious_type):
        if isinstance(values, (list, tuple)):
            text_values.extend(values)
    for value in text_values:
        if not isinstance(value, str):
            continue
        if "钓鱼" in value or _PHISHING_PATTERN.search(value):
            return True
    return False


def _is_gray_domain_candidate(dossier: IocDossier, config: Config) -> bool:
    if dossier.ioc_type != "domain":
        return False

    retained_urls = dossier.retained_urls
    if not isinstance(retained_urls, (list, tuple)) or not retained_urls:
        return False
    if not all(_is_meaningful_text(url) for url in retained_urls):
        return False

    if not _has_expired_whois(dossier) or dossier.evidence_b:
        return False

    hash_entries = dossier.hash_entries
    if not isinstance(hash_entries, (list, tuple)):
        return False
    if any(is_malicious_sample(entry, config) for entry in hash_entries):
        return False

    return _has_historical_or_phishing_url_evidence(dossier)


def _has_normal_business_closure(dossier: IocDossier) -> bool:
    """Check if the IOC has credible normal business identity signals.

    Normal business closure requires both ICP registration AND official website,
    indicated by E-level evidence with the 'trusted_business' tag.
    """
    for e in dossier.evidence_e:
        if "trusted_business" in e.tags:
            return True
    return False


def _has_asset_change_candidate(dossier: IocDossier) -> bool:
    """Check for concrete evidence of IOC ownership/usage change.

    Only explicit change markers qualify. Generic normalization fields
    like page_title, certificates, mature domain age, or a bare resolv_ip
    do NOT qualify as change candidates on their own.
    """
    for evidence_list in (dossier.evidence_d, dossier.evidence_e, dossier.evidence_f):
        for e in evidence_list:
            if "trusted_business" in e.tags:
                continue
            if _has_change_marker(e.field, e.detail, e.tags):
                return True
    return False


def _has_change_marker(field: str, detail: str, tags: list[str]) -> bool:
    """Return True only for explicit before/after or change markers."""
    text = " ".join([field, detail, *tags]).lower()
    explicit_markers = (
        "asset_change",
        "ownership_change",
        "whois_change",
        "registrant_change",
        "resolv_ip_change",
        "pdns_change",
        "reverse_domain_change",
        "changed",
        "previous",
        "old_value",
        "new_value",
        "from_to",
        "from-to",
        "变更",
        "变化",
    )
    if any(marker in text for marker in explicit_markers):
        return True
    if ("from " in text and " to " in text) or ("原" in text and "现" in text):
        return True
    return False


def _has_threat_residue(dossier: IocDossier, config: Config) -> bool:
    """Check for unresolved threat residue that blocks automatic 误报.

    Returns True when threat signals exist that cannot be dismissed
    by normalization evidence alone.
    """
    hml = config.historical_malicious_level
    hash_ml = config.hash_malicious_level
    window = config.activity_window_days

    # Strong or suspicious D evidence from profile observations
    for e in dossier.evidence_d:
        if "suspicious" in e.field or "threat" in e.field or "random" in e.field:
            return True

    # relate_ip_domain or dtree entries with level >= historical_malicious_level
    for entry in dossier.relate_ip_domain_entries:
        if coerce_level(entry.get("level")) >= hml:
            return True
    for entry in dossier.dtree_entries:
        if coerce_level(entry.get("level")) >= hml:
            return True

    # High-risk related domains from profile
    if dossier.profile:
        if dossier.profile.ip.get("high_risk_related_domain_count", 0) > 0:
            return True
        if dossier.profile.ip.get("random_related_domain_count", 0) > 0:
            return True

    # Flint last_seen recent with related domains
    flint_last = dossier.flint.get("last_seen", "")
    if flint_last and (dossier.relate_ip_domain_entries or dossier.dtree_entries):
        t = parse_time(str(flint_last))
        if t and t >= datetime.now() - timedelta(days=window):
            return True

    # Strong source exists but A evidence did not form
    if not dossier.evidence_a and dossier.source_set:
        strong_sources = [
            s for s in dossier.source_set
            if s in config.rules.strong_sources and s not in config.rules.weak_sources
        ]
        if strong_sources and (
            dossier.hash_entries or dossier.relate_url_entries or
            dossier.malicious_type or dossier.attck
        ):
            return True

    # Hash entries with level >= hash_malicious_level
    if dossier.hash_entries:
        max_hash_level = max((coerce_level(h.get("level")) for h in dossier.hash_entries), default=0.0)
        if max_hash_level >= hash_ml:
            return True

    # malicious_type or attck non-empty
    if dossier.malicious_type or dossier.attck:
        return True

    # family or tag contains malicious vocabulary (config-driven, same word
    # list as the strong-A path so rules stay in sync)
    combined_family_tag = " ".join(
        str(f).lower() for f in (dossier.family + dossier.tag)
    )
    if any(v in combined_family_tag for v in config.rules.strong_malicious_indicators):
        return True

    # Runtime flags: block, black, ml_black
    rf = dossier.runtime_flags
    if rf:
        if rf.get("block") is True or rf.get("black") is True or rf.get("ml_black") is True:
            return True
        alert_score = rf.get("alert_score", 0)
        if isinstance(alert_score, (int, float)) and alert_score >= 70:
            return True

    # New or random-looking domain + hash/source/relate_url/ip_domain/dtree residue
    if dossier.profile and dossier.profile.domain.get("is_new") and (
        dossier.hash_entries or dossier.relate_url_entries or
        dossier.relate_ip_domain_entries or dossier.dtree_entries or
        any(s.lower() not in ("spider", "crawler") for s in dossier.source_set)
    ):
        return True

    if dossier.profile and dossier.profile.domain.get("looks_random") and (
        dossier.hash_entries or dossier.relate_url_entries or
        dossier.relate_ip_domain_entries or dossier.dtree_entries
    ):
        return True

    # Normalization evidence conflicts with unresolved high-level hash entries
    if dossier.evidence_e and dossier.hash_entries:
        max_h = max((coerce_level(h.get("level")) for h in dossier.hash_entries), default=0.0)
        if max_h >= hash_ml:
            return True

    # Normalization evidence conflicts with unresolved infrastructure evidence
    if dossier.evidence_e and (
        dossier.relate_ip_domain_entries or dossier.dtree_entries
    ):
        # Only when entries have level at or above threshold
        has_high_rid = any(coerce_level(e.get("level")) >= hml for e in dossier.relate_ip_domain_entries)
        has_high_dt = any(coerce_level(e.get("level")) >= hml for e in dossier.dtree_entries)
        if has_high_rid or has_high_dt:
            return True

    # E evidence + profile-based D evidence → conflict
    if dossier.evidence_e and dossier.evidence_d:
        threat_d_fields = {"suspicious_domain_age", "ip_pdns_related_domains",
                          "suspicious_reverse_domains", "threat_runtime_flags",
                          "high_level_hash_without_direct_ioc",
                          "strong_source_without_direct_a",
                          "random_related_domain_shape"}
        for e in dossier.evidence_d:
            if e.field in threat_d_fields:
                return True

    return False


def _has_evidence_field(dossier: IocDossier, field: str) -> bool:
    return any(evidence.field == field for evidence in dossier.evidence_a)


def _authoritative_black_verdict(dossier: IocDossier, reason: str) -> Verdict:
    conclusion = (
        Conclusion.ALIVE_VALID if dossier.evidence_b
        else Conclusion.INACTIVE_VALID
    )
    reason = f"{reason} 结论：{conclusion.value}。"
    return _make_verdict(
        dossier,
        conclusion,
        "运营人员确定恶意",
        "近一年活跃" if dossier.evidence_b else "历史有效",
        "高",
        "不看",
        reason=reason,
    )


def adjudicate(dossier: IocDossier, config: Config | None = None) -> Verdict:
    config = config or Config()
    has_a = bool(dossier.evidence_a)
    has_b = bool(dossier.evidence_b)
    has_c = bool(dossier.evidence_c)
    has_e = bool(dossier.evidence_e)
    has_d = bool(dossier.evidence_d)
    has_structured_public_apt = any(
        evidence.field == "structured_public_apt"
        and "structured_public_apt" in evidence.tags
        for evidence in dossier.evidence_c
    )

    if _has_evidence_field(dossier, "operator_clue_group"):
        return _authoritative_black_verdict(
            dossier,
            "判定为黑：命中运营线索群确定恶意证据，无需人工复核。",
        )

    if _has_meaningful_icp(dossier):
        return _make_verdict(
            dossier,
            Conclusion.PENDING_REVIEW,
            "恶意/业务身份冲突",
            "状态不确定",
            "中",
            "必看",
            reason=(
                "判定为待复核：非DGA IOC存在ICP记录，备案可能属于历史或当前资产，"
                "必须人工确认。"
            ),
        )

    if _has_evidence_field(dossier, "operator_confirmed_malicious_context"):
        return _authoritative_black_verdict(
            dossier,
            "判定为黑：运营人员来源包含明确恶意性质上下文，且当前无未解决ICP备案冲突。",
        )

    if _is_gray_domain_candidate(dossier, config):
        verdict = _make_verdict(
            dossier,
            Conclusion.GRAY,
            "历史恶意",
            "当前domain失活",
            "中",
            "不看",
            reason=(
                "判定为灰：历史钓鱼或URL情报可信，但当前domain已过期且无近期活动；"
                "保留具体URL，不加入白名单。"
            ),
        )
        verdict.retained_urls = list(dossier.retained_urls)
        verdict.scope_actions = [
            {"ioc": dossier.ioc, "scope": "domain", "action": "gray"},
            *[
                {"ioc": url, "scope": "url", "action": "retain"}
                for url in verdict.retained_urls
            ],
        ]
        return verdict

    # A+E conflict only when BOTH are strong
    # Strong A + weak E → A wins, confidence drops to "中"
    # Strong A + strong E → genuine conflict, 待复核
    strong_a = _is_strong_a(dossier)
    strong_e = _is_strong_e(dossier)
    strong_conflict = strong_a and strong_e
    weak_conflict = has_a and has_e and not strong_conflict
    threat_residue = _has_threat_residue(dossier, config)

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
        # A complete public-APT field combination is itself the malicious
        # closure. Its APT metadata must not be reinterpreted as conflicting
        # residue when no normal-business evidence exists.
        if has_structured_public_apt and not has_e:
            if has_b:
                return _make_verdict(
                    dossier,
                    Conclusion.ALIVE_VALID,
                    "公开APT历史恶意",
                    "近一年活跃",
                    "高",
                    "抽检",
                    reason=(
                        "判定为存活有效：结构化公开APT证据闭环成立，"
                        "且近一年存在实质活动。"
                    ),
                )
            return _make_verdict(
                dossier,
                Conclusion.INACTIVE_VALID,
                "公开APT历史恶意",
                "历史活跃",
                "高",
                "抽检",
                reason=(
                    "判定为失活有效：结构化公开APT证据闭环成立，"
                    "近期未见实质活动，历史恶意仍应保留。"
                ),
            )

        normal_biz = _has_normal_business_closure(dossier)
        if normal_biz:
            # A/C成立 + B不成立 + 正常业务闭环
            # Spec: must have BOTH asset change candidate AND normal business
            # closure to auto-conclude 误报; otherwise 待复核
            if threat_residue:
                return _make_conflict_verdict(dossier, Conclusion.INACTIVE_VALID)
            if _has_asset_change_candidate(dossier):
                return _make_verdict(
                    dossier, Conclusion.FALSE_POSITIVE, "情报过期", "无实质活动", "中", "抽检",
                    reason="判定为误报：历史恶意成立但近期无实质活动，当前存在正常业务闭环及资产变化候选证据，且未发现未解决威胁残留，情报可能已过期。",
                )
            # Normal business identity without asset change evidence → ambiguous
            return _make_verdict(
                dossier, Conclusion.PENDING_REVIEW, "历史恶意", "历史活跃", "中", "必看",
                reason="判定为待复核：历史恶意成立且当前存在正常业务身份，但缺少资产变化候选证据，不足以自动判定情报过期，需要人工复核。",
            )
        # A/C成立 + B不成立 + 无正常业务闭环 → 失活有效
        if strong_e or threat_residue:
            return _make_conflict_verdict(dossier, Conclusion.INACTIVE_VALID)
        if strong_conflict:
            return _make_conflict_verdict(dossier, Conclusion.INACTIVE_VALID)
        return _make_verdict(
            dossier, Conclusion.INACTIVE_VALID, "历史恶意", "历史活跃", "中", "抽检",
        )

    if has_e:
        # False-positive protection: block automatic 误报 when threat residue exists
        if threat_residue:
            return _make_verdict(
                dossier, Conclusion.PENDING_REVIEW,
                "误报污染/威胁残留冲突", "无实质活动", "低", "必看",
                reason="判定为待复核：存在正常化证据但仍有威胁残留，不能自动判定为误报，需要人工复核。",
            )
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
        route="standard",
        disposition=_DISPOSITION_BY_CONCLUSION[conclusion],
    )


def _make_conflict_verdict(dossier: IocDossier, candidate: Conclusion) -> Verdict:
    has_direct = bool(dossier.evidence_a)
    if has_direct:
        malicious_nature = "直接恶意"
        reason = (
            f"判定为待复核：存在直接恶意证据，但同时存在正常化证据，"
            f"证据冲突需要人工复核。候选结论: {candidate.value}。"
        )
    else:
        malicious_nature = "历史恶意"
        reason = (
            f"判定为待复核：存在历史恶意证据，但同时存在正常化证据或威胁残留，"
            f"证据冲突需要人工复核。候选结论: {candidate.value}。"
        )

    verdict = _make_verdict(
        dossier,
        Conclusion.PENDING_REVIEW,
        malicious_nature,
        "近一年活跃" if dossier.evidence_b else "历史活跃",
        "中",
        "必看",
        reason=reason,
    )
    verdict.candidate_label = candidate.value
    return verdict


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
        reasons.append("不能用弱正常化证据推翻强恶意证据")
    elif conclusion == Conclusion.GRAY:
        reasons.append("domain降灰不等于加入白名单，具体恶意URL必须继续保留")
    # General forbidden rules appended for all conclusions
    general = [
        "不能仅凭无解析、不可达、parking判误报",
        "不能仅凭WHOIS、解析IP、反查域名变化判误报",
    ]
    for g in general:
        if g not in reasons:
            reasons.append(g)
    return "；".join(reasons) if reasons else "无禁止判定"


def _build_reason(conclusion: Conclusion) -> str:
    reasons = {
        Conclusion.ALIVE_VALID: "判定为存活有效：存在直接恶意证据，且近一年存在样本、访问、解析或关联记录等实质活动证据。",
        Conclusion.INACTIVE_VALID: "判定为失活有效：历史恶意或直接恶意成立，近期未见实质活动，且当前无正常业务承接；IOC仍可用于拦截。",
        Conclusion.FALSE_POSITIVE: "判定为误报：恶意关联不成立或情报已过期，当前存在正常业务闭环，且未发现未解决威胁残留。",
        Conclusion.PENDING_REVIEW: "判定为待复核：存在资产变化或正常业务信号，但与历史恶意、直接恶意或威胁残留冲突，不能自动取消情报。",
        Conclusion.GRAY: "判定为灰：domain当前不继续拦截但不能加入白名单，具体恶意URL继续保留。",
    }
    return reasons.get(conclusion, "未知结论")
