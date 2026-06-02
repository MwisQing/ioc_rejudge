"""A-F evidence extraction from merged IOC dossier."""
import re
from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.models import Evidence, EvidenceLevel, EvidenceStrength, IocDossier
from ioc_rejudge.parser import parse_time


def _is_ip(value: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))


def _ioc_aware_match(ioc: str, text: str) -> bool:
    """IOC-aware text matching. Safer than raw substring.

    - evil.com must not match not-evil.com
    - evil.com must not match evil.com.cn (unless IOC is evil.com.cn)
    - IP matching respects numeric boundaries
    - URL text is parsed to compare host
    - Case-insensitive, trailing dots normalized
    """
    if not text or not ioc:
        return False

    ioc_lower = ioc.lower().rstrip(".")
    text_lower = text.lower()

    # IP IOC: match with word boundaries
    if _is_ip(ioc_lower):
        pattern = re.compile(r'(?<!\d)' + re.escape(ioc_lower) + r'(?!\d)')
        return bool(pattern.search(text_lower))

    # Domain IOC: must match at domain boundary
    # evil.com should match "evil.com", "sub.evil.com", "evil.com:8080"
    # but NOT "not-evil.com" or "evil.com.cn"
    ioc_escaped = re.escape(ioc_lower)

    # Try URL parsing: extract hosts from URLs in text
    for url_match in re.finditer(r'https?://([^\s/"\'<>]+)', text_lower):
        host = url_match.group(1).rstrip(".")
        if host == ioc_lower or host.endswith("." + ioc_lower):
            return True

    # Domain boundary: dot before IOC = subdomain (OK), hyphen before = different domain (NOT OK)
    # Dot after IOC = different TLD like evil.com.cn (NOT OK)
    pattern = re.compile(r'(?<![a-z0-9\-])' + ioc_escaped + r'(?![a-z0-9\-])')
    match = pattern.search(text_lower)
    if not match:
        return False
    # Reject if followed by dot + more domain (evil.com.cn)
    end_pos = match.end()
    if end_pos < len(text_lower):
        next_char = text_lower[end_pos]
        if next_char == '.' and end_pos + 1 < len(text_lower) and text_lower[end_pos + 1].isalnum():
            return False
    return True


def _parse_access_end(access: dict) -> datetime | None:
    end = access.get("end", "")
    if not end:
        return None
    if len(str(end)) == 8 and str(end).isdigit():
        try:
            return datetime.strptime(str(end), "%Y%m%d")
        except ValueError:
            pass
    return parse_time(str(end))


def extract_evidence(dossier: IocDossier, config: Config) -> IocDossier:
    cutoff = datetime.now() - timedelta(days=config.activity_window_days)
    _extract_a(dossier, config)
    _extract_b(dossier, config, cutoff)
    _extract_c(dossier, config)
    _extract_d(dossier, config)
    _extract_e(dossier, config)
    _extract_f(dossier, config)
    return dossier


def _has_malicious_indicator(text: str, config: Config) -> bool:
    """Check if text contains any malicious indicator from rules."""
    text_lower = text.lower()
    indicators = config.rules.malicious_indicators + config.rules.context_comment_malicious_indicators
    return any(ind in text_lower for ind in indicators)


def _has_historical_indicator(text: str, config: Config) -> bool:
    text_lower = text.lower()
    return any(ind in text_lower for ind in config.rules.context_comment_historical_indicators)


def _has_review_indicator(dossier: IocDossier, config: Config) -> bool:
    text = "\n".join([
        dossier.context,
        dossier.comment,
        " ".join(dossier.source_set),
        " ".join(dossier.family),
        " ".join(dossier.tag),
    ]).lower()
    return any(ind.lower() in text for ind in config.rules.review_indicators)


def _has_normalization_indicator(dossier: IocDossier, config: Config) -> bool:
    text = "\n".join([
        dossier.context,
        dossier.comment,
        " ".join(dossier.source_set),
        " ".join(dossier.family),
        " ".join(dossier.tag),
        dossier.page_title,
        dossier.icp_website,
        dossier.official_website,
    ]).lower()
    return any(ind.lower() in text for ind in config.rules.normalization_indicators)


def _is_strong_source(source: str, config: Config) -> bool:
    return source in config.rules.strong_sources and source not in config.rules.weak_sources


def _trusted_business_value(dossier: IocDossier, field_name: str) -> str:
    value = getattr(dossier, field_name, "")
    if isinstance(value, bool):
        return str(value) if value else ""
    if value is None:
        return ""
    return str(value)


def _extract_a(dossier: IocDossier, config: Config):
    ioc = dossier.ioc
    combined_text = f"{dossier.context}\n{dossier.comment}"
    ioc_matched = _ioc_aware_match(ioc, combined_text)

    if ioc_matched and _has_malicious_indicator(combined_text, config):
        dossier.evidence_a.append(Evidence(
            level=EvidenceLevel.A,
            field="context/comment",
            detail=f"上下文直接提到 IOC ({ioc}) 与恶意行为关联",
            strength=EvidenceStrength.STRONG,
            tags=["direct", "context"],
        ))

    if ioc_matched:
        for h in dossier.hash_entries:
            h_level = h.get("level", 0)
            if h_level >= config.hash_malicious_level:
                dossier.evidence_a.append(Evidence(
                    level=EvidenceLevel.A,
                    field=f"hash[{h.get('md5', '')}]",
                    detail=f"样本 {h.get('md5', '')} level={h_level} >= {config.hash_malicious_level}，上下文证明通信当前IOC",
                    strength=EvidenceStrength.STRONG,
                    tags=["direct", "hash"],
                ))

        strong_sources = [s for s in dossier.source_set if _is_strong_source(s, config)]
        if strong_sources:
            dossier.evidence_a.append(Evidence(
                level=EvidenceLevel.A,
                field=f"source[{','.join(strong_sources)}]",
                detail=f"强来源 {', '.join(strong_sources)} 指向IOC",
                strength=EvidenceStrength.STRONG,
                tags=["direct", "source"],
            ))

    for url_entry in dossier.relate_url_entries:
        url = url_entry.get("url", "")
        url_level = url_entry.get("level", 0)
        if url_level >= config.relate_url_malicious_level and _ioc_aware_match(ioc, url):
            dossier.evidence_a.append(Evidence(
                level=EvidenceLevel.A,
                field=f"relate_url[{url}]",
                detail=f"relate_url直接包含IOC，level={url_level} >= {config.relate_url_malicious_level}",
                strength=EvidenceStrength.NORMAL,
                tags=["direct", "relate_url"],
            ))


def _extract_b(dossier: IocDossier, config: Config, cutoff: datetime):
    for h in dossier.hash_entries:
        t = parse_time(h.get("time", ""))
        if t and t >= cutoff:
            dossier.evidence_b.append(Evidence(
                level=EvidenceLevel.B,
                field=f"hash.time[{h.get('md5', '')}]",
                detail=f"样本时间 {h.get('time', '')} 在近{config.activity_window_days}天内",
            ))

    flint_last = parse_time(dossier.flint.get("last_seen", ""))
    if flint_last and flint_last >= cutoff:
        dossier.evidence_b.append(Evidence(
            level=EvidenceLevel.B,
            field="flint.last_seen",
            detail=f"flint最后活跃 {dossier.flint.get('last_seen', '')} 在近{config.activity_window_days}天内",
        ))

    access_end = _parse_access_end(dossier.access)
    if access_end and access_end >= cutoff:
        access_val = dossier.access.get("client_count", 0)
        if access_val and access_val > 0:
            dossier.evidence_b.append(Evidence(
                level=EvidenceLevel.B,
                field="access.end",
                detail=f"访问结束时间 {dossier.access.get('end', '')} 在近{config.activity_window_days}天内",
            ))

    for d in dossier.dtree_entries:
        t = parse_time(d.get("last", ""))
        if t and t >= cutoff:
            dossier.evidence_b.append(Evidence(
                level=EvidenceLevel.B,
                field=f"dtree.last[{d.get('key', '')}]",
                detail=f"DNS解析树最后活跃 {d.get('last', '')} 在近{config.activity_window_days}天内",
            ))


def _extract_c(dossier: IocDossier, config: Config):
    if dossier.evidence_b:
        return

    ioc = dossier.ioc
    combined_text = f"{dossier.context}\n{dossier.comment}"
    ioc_matched = _ioc_aware_match(ioc, combined_text)

    has_context_loop = ioc_matched and _has_malicious_indicator(combined_text, config)
    has_historical_context = ioc_matched and _has_historical_indicator(combined_text, config)

    strong_sources = [s for s in dossier.source_set if _is_strong_source(s, config)]
    has_source_loop = bool(
        strong_sources and
        (dossier.hash_entries or dossier.relate_url_entries or
         dossier.family or dossier.malicious_type or dossier.attck)
    ) and ioc_matched

    if not (has_context_loop or has_source_loop or has_historical_context):
        return

    if dossier.level < config.historical_malicious_level:
        return

    tags = ["historical"]
    if has_historical_context:
        tags.append("historical_context")

    dossier.evidence_c.append(Evidence(
        level=EvidenceLevel.C,
        field="historical_malicious",
        detail=f"历史恶意闭环成立，level={dossier.level} >= {config.historical_malicious_level}，近{config.activity_window_days}天无实质活动",
        strength=EvidenceStrength.NORMAL,
        tags=tags,
    ))


def _extract_d(dossier: IocDossier, config: Config):
    review_tags = ["review_indicator"] if _has_review_indicator(dossier, config) else []
    if dossier.relate_ip_domain_entries:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="relate_ip_domain",
            detail=f"关联IP/域名 {len(dossier.relate_ip_domain_entries)} 条，无直接样本命中",
        ))

    if dossier.resolv_ip:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="resolv_ip",
            detail=f"解析IP {dossier.resolv_ip}，无时间戳",
        ))

    if dossier.family or dossier.tag:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="family/tag",
            detail=f"家族/标签: {dossier.family or dossier.tag}",
        ))

    if dossier.level >= config.high_level_no_a_threshold and not dossier.evidence_a:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="level",
            detail=f"level={dossier.level} 高但无A级直接证据",
            strength=EvidenceStrength.WEAK,
            tags=["level_only"],
        ))

    if dossier.topdomain and dossier.topdomain.get("rank", -1) > 0:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="topdomain",
            detail=f"topdomain排名 {dossier.topdomain.get('rank')}",
        ))

    if review_tags:
        if not dossier.evidence_d:
            dossier.evidence_d.append(Evidence(
                level=EvidenceLevel.D,
                field="review_indicator",
                detail="review indicator matched in source, context, comment, family, or tag",
                strength=EvidenceStrength.WEAK,
            ))
        for evidence in dossier.evidence_d:
            if "review_indicator" not in evidence.tags:
                evidence.tags.append("review_indicator")


def _extract_e(dossier: IocDossier, config: Config):
    trusted_values = {
        field_name: _trusted_business_value(dossier, field_name)
        for field_name in config.rules.trusted_business_fields
    }
    has_strong_business = bool(trusted_values) and all(trusted_values.values())
    normalization_tags = ["normalization"]
    if _has_normalization_indicator(dossier, config):
        normalization_tags.append("normalization_indicator")

    for field_name, value in trusted_values.items():
        if not value:
            continue
        strength = EvidenceStrength.STRONG if has_strong_business else EvidenceStrength.WEAK
        tags = ["trusted_business"] if has_strong_business else list(normalization_tags)
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field=field_name,
            detail=f"{field_name}: {value}",
            strength=strength,
            tags=tags,
        ))

    if dossier.certificates.get("credible", False):
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="certificates",
            detail="credible certificate",
            strength=EvidenceStrength.WEAK,
            tags=list(normalization_tags),
        ))

    if dossier.page_title and "page_title" not in trusted_values:
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="page_title",
            detail=f"page_title: {dossier.page_title}",
            strength=EvidenceStrength.WEAK,
            tags=list(normalization_tags),
        ))
    return

    """E-level: false positive / contamination evidence.

    Strong E = ICP备案 + official_website both present.
    Weak E = single field (certificates, page_title, single website/icp).
    Only strong E can conflict with strong A.
    """
    has_icp = bool(dossier.icp_website)
    has_official = bool(dossier.official_website)

    if has_icp and has_official:
        # Strong E: both ICP + official website
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="icp_website",
            detail=f"存在ICP备案网站: {dossier.icp_website}",
            strength=EvidenceStrength.STRONG,
            tags=["trusted_business"],
        ))
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="official_website",
            detail=f"存在官方网站: {dossier.official_website}",
            strength=EvidenceStrength.STRONG,
            tags=["trusted_business"],
        ))
    else:
        if has_icp:
            dossier.evidence_e.append(Evidence(
                level=EvidenceLevel.E,
                field="icp_website",
                detail=f"存在ICP备案网站: {dossier.icp_website}",
                strength=EvidenceStrength.WEAK,
                tags=["normalization"],
            ))
        if has_official:
            dossier.evidence_e.append(Evidence(
                level=EvidenceLevel.E,
                field="official_website",
                detail=f"存在官方网站: {dossier.official_website}",
                strength=EvidenceStrength.WEAK,
                tags=["normalization"],
            ))

    if dossier.certificates.get("credible", False):
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="certificates",
            detail="证书可信",
            strength=EvidenceStrength.WEAK,
            tags=["normalization"],
        ))

    if dossier.page_title:
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="page_title",
            detail=f"页面标题: {dossier.page_title}",
            strength=EvidenceStrength.WEAK,
            tags=["normalization"],
        ))


def _is_strong_a(dossier: IocDossier) -> bool:
    """Strong A = any A evidence with strength=strong."""
    return any(e.strength == EvidenceStrength.STRONG for e in dossier.evidence_a)


def _is_strong_e(dossier: IocDossier) -> bool:
    """Strong E = any E evidence with strength=strong."""
    return any(e.strength == EvidenceStrength.STRONG for e in dossier.evidence_e)


def _extract_f(dossier: IocDossier, config: Config):
    if dossier.latest_intel_update_time:
        dossier.evidence_f.append(Evidence(
            level=EvidenceLevel.F,
            field="updatetime",
            detail=f"情报更新时间: {dossier.latest_intel_update_time}",
            strength=EvidenceStrength.WEAK,
            tags=["update_only"],
        ))
