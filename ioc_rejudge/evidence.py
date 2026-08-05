"""A-F evidence extraction from merged IOC dossier."""
import re
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import is_valid_host, is_valid_port
from ioc_rejudge.models import Evidence, EvidenceLevel, EvidenceStrength, IocDossier
from ioc_rejudge.normalize import coerce_level, latest_record, normalize_ioc
from ioc_rejudge.parser import parse_time
from ioc_rejudge.profile import extract_profile


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
    dossier = extract_profile(dossier, config)
    _extract_operator_evidence(dossier, config)
    _extract_a(dossier, config)
    _extract_b(dossier, config, cutoff)
    _extract_c(dossier, config)
    _extract_structured_public_apt(dossier, config)
    _extract_d(dossier, config)
    _extract_asset_change_evidence(dossier)
    _extract_e(dossier, config)
    _extract_f(dossier, config)
    _extract_profile_evidence(dossier, config)
    return dossier


_ASSET_CHANGE_FIELDS = (
    "asset_change",
    "ownership_change",
    "whois_change",
    "registrant_change",
    "resolv_ip_change",
    "pdns_change",
)


def _is_explicit_change_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized not in {"", "0", "false", "no", "none", "null", "unknown"}
    if isinstance(value, (dict, list, tuple, set)):
        return bool(value)
    return False


def _extract_asset_change_evidence(dossier: IocDossier) -> None:
    """Map only explicit structured before/after markers into D evidence."""
    seen: set[tuple[str, str]] = set()
    for snapshot in dossier.record_snapshots:
        record = snapshot.raw
        if not isinstance(record, dict):
            continue
        for field in _ASSET_CHANGE_FIELDS:
            value = record.get(field)
            if not _is_explicit_change_value(value):
                continue
            detail = str(value)
            marker = (field, detail)
            if marker in seen:
                continue
            seen.add(marker)
            dossier.evidence_d.append(Evidence(
                level=EvidenceLevel.D,
                field=field,
                detail=f"explicit structured asset change: {detail}",
                strength=EvidenceStrength.NORMAL,
                tags=["asset_change", "structured_change"],
            ))


def _indicator_match(indicator: str, text_lower: str) -> bool:
    """Match *indicator* in *text_lower* using token boundaries for English,
    contains-match for Chinese (where characters are self-delimiting).

    Regex-special characters in the indicator are safely escaped.
    Indicator is internally lowercased before matching.
    An empty indicator never matches.
    """
    if not indicator:
        return False
    ind = indicator.lower()
    if re.search(r'[一-鿿]', ind):
        return ind in text_lower
    escaped = re.escape(ind)
    pattern = re.compile(r'(?<![a-z0-9])' + escaped + r'(?![a-z0-9])')
    return bool(pattern.search(text_lower))


def _record_sources(record: dict) -> set[str]:
    raw = record.get("source", [])
    values = raw if isinstance(raw, (list, tuple, set)) else [raw]
    return {str(value).strip() for value in values if str(value).strip()}


def _record_context(record: dict) -> str:
    return "\n".join(
        str(record.get(field, "") or "")
        for field in ("context", "comment")
    )


def has_authoritative_clue(records: list[dict], config: Config) -> bool:
    record = latest_record(records)
    return bool(record) and any(
        _indicator_match(indicator, _record_context(record).lower())
        for indicator in config.rules.authoritative_clue_indicators
    )


def authoritative_context_matches(
    records: list[dict], config: Config
) -> list[str]:
    """Return configured context/comment keywords that force a black verdict."""
    record = latest_record(records)
    if not record:
        return []
    text = _record_context(record).lower()
    return [
        indicator
        for indicator in config.rules.authoritative_context_indicators
        if _indicator_match(indicator, text)
    ]


def _extract_operator_evidence(dossier: IocDossier, config: Config) -> None:
    latest = dossier.record_snapshots[-1].raw if dossier.record_snapshots else {}
    records = [latest] if isinstance(latest, dict) and latest else []
    keyword_matches = authoritative_context_matches(records, config)
    if keyword_matches:
        dossier.evidence_a.append(Evidence(
            level=EvidenceLevel.A,
            field="authoritative_context_keyword",
            detail=(
                "comment/context 命中直接判黑关键词: "
                + ", ".join(keyword_matches)
            ),
            strength=EvidenceStrength.STRONG,
            tags=["authoritative", "context_keyword"],
        ))
        return

    if has_authoritative_clue(records, config):
        dossier.evidence_a.append(Evidence(
            level=EvidenceLevel.A,
            field="operator_clue_group",
            detail="运营线索群明确确认恶意",
            strength=EvidenceStrength.STRONG,
            tags=["authoritative", "operator", "clue_group"],
        ))
        return

    operator_sources = set(config.rules.operator_sources)
    for record in records:
        if not (_record_sources(record) & operator_sources):
            continue
        if coerce_level(record.get("level")) < config.historical_malicious_level:
            continue
        if not _has_strong_malicious_indicator(_record_context(record), config):
            continue
        dossier.evidence_a.append(Evidence(
            level=EvidenceLevel.A,
            field="operator_confirmed_malicious_context",
            detail="运营人员来源包含明确恶意性质上下文",
            strength=EvidenceStrength.STRONG,
            tags=["authoritative", "operator", "malicious_context"],
        ))
        return


def is_malicious_sample(entry: dict | None, config: Config) -> bool:
    """Return True when a hash/dtree entry represents a genuine malicious sample.

    Excludes not-a-virus families, entries below hash_malicious_level, and
    entries with explicit confidence <= 0.  Missing confidence retains the
    old level-only semantics.  Malformed numeric fields return False safely.
    """
    if not entry or not isinstance(entry, dict):
        return False

    family = str(entry.get("family", "") or "").lower()
    entry_type = str(entry.get("type", "") or "").lower()
    if "not-a-virus" in family or "not-a-virus" in entry_type:
        return False

    try:
        level = float(entry.get("level", 0))
    except (ValueError, TypeError):
        return False
    if level < config.hash_malicious_level:
        return False

    if "confidence" in entry:
        try:
            confidence = float(entry["confidence"])
        except (ValueError, TypeError):
            return False
        if confidence <= 0:
            return False

    return True


def _has_malicious_indicator(text: str, config: Config) -> bool:
    """Check if text contains any malicious indicator from rules."""
    text_lower = text.lower()
    indicators = config.rules.malicious_indicators + config.rules.context_comment_malicious_indicators
    return any(_indicator_match(ind, text_lower) for ind in indicators)


def _has_strong_malicious_indicator(text: str, config: Config) -> bool:
    """Check if text contains a malicious-nature word (trojan/backdoor/rat/...).

    Strong words carry malicious nature, as opposed to neutral
    communication/behavior words (dns/http/tcp/connect/download/sample/payload)
    which only support indirect D-level evidence, never a strong-A direct hit.

    A user-declared context_comment_malicious_indicators entry is treated as a
    strong word too: by listing it there the operator explicitly asserts it is
    a malicious-nature marker for this deployment.
    """
    text_lower = text.lower()
    strong = (
        config.rules.strong_malicious_indicators
        + config.rules.context_comment_malicious_indicators
    )
    return any(_indicator_match(ind, text_lower) for ind in strong)




def _has_historical_indicator(text: str, config: Config) -> bool:
    text_lower = text.lower()
    return any(_indicator_match(ind, text_lower) for ind in config.rules.context_comment_historical_indicators)


def _has_review_indicator(dossier: IocDossier, config: Config) -> bool:
    text = "\n".join([
        dossier.context,
        dossier.comment,
        " ".join(dossier.source_set),
        " ".join(dossier.family),
        " ".join(dossier.tag),
    ]).lower()
    return any(_indicator_match(ind.lower(), text) for ind in config.rules.review_indicators)


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
    return any(_indicator_match(ind.lower(), text) for ind in config.rules.normalization_indicators)


def _is_strong_source(source: str, config: Config) -> bool:
    return source in config.rules.strong_sources and source not in config.rules.weak_sources


def _trusted_business_value(dossier: IocDossier, field_name: str) -> str:
    value = getattr(dossier, field_name, "")
    if isinstance(value, bool):
        return str(value) if value else ""
    if value is None:
        return ""
    return str(value)


def _is_valid_retained_url(url: str) -> bool:
    """Return True when *url* is a well-formed http/https URL suitable for
    retained_urls and URL IOC direct evidence.

    Uses the shared host/port validators from inputs.py so the same DNS
    label and IPv4 boundary rules apply everywhere.
    """
    if not url:
        return False
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme
        hostname = parsed.hostname
        url_port = parsed.port  # may raise ValueError for out-of-range port
    except ValueError:
        return False
    if scheme not in ("http", "https"):
        return False
    if not hostname or not is_valid_host(hostname):
        return False
    if url_port is not None and not is_valid_port(str(url_port)):
        return False
    return True


def _url_matches_domain_scope(dossier: IocDossier, url: str) -> bool:
    if dossier.ioc_type != "domain":
        return True
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return False
    return bool(hostname) and hostname.lower().rstrip(".") == dossier.ioc.lower().rstrip(".")


def _extract_a(dossier: IocDossier, config: Config):
    ioc = dossier.ioc
    combined_text = f"{dossier.context}\n{dossier.comment}"
    ioc_matched = _ioc_aware_match(ioc, combined_text)
    latest = dossier.record_snapshots[-1].raw if dossier.record_snapshots else {}
    eligible_records = [latest] if (
        isinstance(latest, dict)
        and latest
        and coerce_level(latest.get("level"))
        >= config.historical_malicious_level
    ) else []
    eligible_ioc_records = [
        record
        for record in eligible_records
        if _ioc_aware_match(ioc, _record_context(record))
    ]
    has_eligible_strong_context = any(
        _has_strong_malicious_indicator(_record_context(record), config)
        for record in eligible_ioc_records
    )

    if has_eligible_strong_context:
        dossier.evidence_a.append(Evidence(
            level=EvidenceLevel.A,
            field="context/comment",
            detail=f"上下文直接提到 IOC ({ioc}) 与恶意行为关联",
            strength=EvidenceStrength.STRONG,
            tags=["direct", "context"],
        ))
    elif ioc_matched and _has_malicious_indicator(combined_text, config):
        # Neutral communication/behavior words (dns/http/tcp/connect/sample/...)
        # do not justify a strong-A direct-malicious hit. Demote to D-level
        # indirect evidence so context is not lost but cannot overturn threat
        # residue or auto-conclude a verdict on its own.
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="context/comment",
            detail=f"上下文提及 IOC ({ioc}) 与通信/行为词关联，但无恶意性质词",
            strength=EvidenceStrength.WEAK,
            tags=["indirect", "context", "neutral_indicator"],
        ))

    if eligible_ioc_records:
        for h in dossier.hash_entries:
            if is_malicious_sample(h, config):
                dossier.evidence_a.append(Evidence(
                    level=EvidenceLevel.A,
                    field=f"hash[{h.get('md5', '')}]",
                    detail=f"样本 {h.get('md5', '')} 上下文证明通信当前IOC",
                    strength=EvidenceStrength.STRONG,
                    tags=["direct", "hash"],
                ))

        strong_sources = sorted({
            source
            for record in eligible_ioc_records
            for source in _record_sources(record)
            if _is_strong_source(source, config)
        })
        if strong_sources:
            dossier.evidence_a.append(Evidence(
                level=EvidenceLevel.A,
                field=f"source[{','.join(strong_sources)}]",
                detail=f"强来源 {', '.join(strong_sources)} 指向IOC",
                strength=EvidenceStrength.STRONG,
                tags=["direct", "source"],
            ))

    # Collect qualifying relate_url entries into retained_urls.
    for url_entry in dossier.relate_url_entries:
        url = str(url_entry.get("url", ""))
        if (
            not _is_valid_retained_url(url)
            or not _url_matches_domain_scope(dossier, url)
        ):
            continue
        try:
            url_level = float(url_entry.get("level", 0))
        except (ValueError, TypeError):
            continue
        if url_level >= config.relate_url_malicious_level:
            if url not in dossier.retained_urls:
                dossier.retained_urls.append(url)

    # For URL IOC targets: exact normalized match with a relate_url entry
    # produces direct evidence.  Domain targets never get A from relate_url.
    if dossier.ioc_type == "url":
        ioc_normalized = normalize_ioc(dossier.ioc)[0]
        for url_entry in dossier.relate_url_entries:
            url = str(url_entry.get("url", ""))
            if not _is_valid_retained_url(url):
                continue
            try:
                url_level = float(url_entry.get("level", 0))
            except (ValueError, TypeError):
                continue
            if url_level < config.relate_url_malicious_level:
                continue
            url_normalized = normalize_ioc(url)[0]
            if url_normalized == ioc_normalized:
                dossier.evidence_a.append(Evidence(
                    level=EvidenceLevel.A,
                    field=f"relate_url[{url}]",
                    detail=f"relate_url matches URL IOC, level={url_level}",
                    strength=EvidenceStrength.NORMAL,
                    tags=["direct", "relate_url"],
                ))


def _extract_b(dossier: IocDossier, config: Config, cutoff: datetime):
    for h in dossier.hash_entries:
        if not is_malicious_sample(h, config):
            continue
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
    latest = dossier.record_snapshots[-1].raw if dossier.record_snapshots else {}
    eligible_ioc_records = [latest] if (
        isinstance(latest, dict)
        and latest
        and coerce_level(latest.get("level"))
        >= config.historical_malicious_level
        and _ioc_aware_match(ioc, _record_context(latest))
    ) else []
    combined_text = "\n".join(
        _record_context(record) for record in eligible_ioc_records
    )
    ioc_matched = bool(eligible_ioc_records)

    has_context_loop = ioc_matched and _has_malicious_indicator(combined_text, config)
    has_historical_context = ioc_matched and _has_historical_indicator(combined_text, config)

    strong_sources = sorted({
        source
        for record in eligible_ioc_records
        for source in _record_sources(record)
        if _is_strong_source(source, config)
    })
    has_source_loop = bool(
        strong_sources and
        (dossier.hash_entries or dossier.relate_url_entries or
         dossier.family or dossier.malicious_type or dossier.attck)
    ) and ioc_matched

    if not (has_context_loop or has_source_loop or has_historical_context):
        return

    tags = ["historical"]
    if has_historical_context:
        tags.append("historical_context")

    dossier.evidence_c.append(Evidence(
        level=EvidenceLevel.C,
        field="historical_malicious",
        detail=(
            "历史恶意闭环成立，承载恶意上下文的记录达到"
            f"level >= {config.historical_malicious_level}，情报曾经有效"
        ),
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

    # page_title as standalone weak E (profile maps it to F, but it still
    # carries weak normalization weight when not already a trusted field)
    if dossier.page_title and "page_title" not in config.rules.trusted_business_fields:
        dossier.evidence_e.append(Evidence(
            level=EvidenceLevel.E,
            field="page_title",
            detail=f"page_title: {dossier.page_title}",
            strength=EvidenceStrength.WEAK,
            tags=list(normalization_tags),
        ))


def _extract_profile_evidence(dossier: IocDossier, config: Config):
    """Map profile observations into D/E/F evidence."""
    if not dossier.profile:
        return

    for obs in dossier.profile.observations:
        if obs.severity == "suspicious":
            _map_suspicious_to_d(dossier, obs, config)
        elif obs.severity == "normal":
            _map_normal_to_e(dossier, obs)
        elif obs.severity == "conflict":
            _map_conflict_to_e(dossier, obs)
        elif obs.severity == "neutral":
            _map_neutral_to_f(dossier, obs)

    # Additional D evidence: high-level hash without direct IOC match
    _add_hash_without_ioc_d(dossier, config)

    # Additional D evidence: strong source without direct A
    _add_source_without_a_d(dossier, config)


def _map_suspicious_to_d(dossier: IocDossier, obs, config: Config):
    kind_map = {
        "domain_age": "suspicious_domain_age",
        "domain_lifespan": "suspicious_domain_age",
        "ip_reverse_domain_risk": "ip_pdns_related_domains",
        "threat_runtime": "threat_runtime_flags",
        "random_domain": "random_related_domain_shape",
        "random_related_domains": "random_related_domain_shape",
        "recent_pdns_activity": "suspicious_reverse_domains",
        "recent_infrastructure": "suspicious_reverse_domains",
    }
    evidence_field = kind_map.get(obs.kind, obs.kind)
    dossier.evidence_d.append(Evidence(
        level=EvidenceLevel.D,
        field=evidence_field,
        detail=f"{obs.field} [{','.join(obs.tags)}]: {obs.detail}",
        strength=EvidenceStrength.NORMAL,
        tags=list(obs.tags),
    ))


def _map_normal_to_e(dossier: IocDossier, obs):
    kind_map = {
        "business_identity": "trusted_business_identity",
        "popular_domain": "popular_normal_domain",
        "shared_infrastructure": "shared_infrastructure",
        "benign_runtime": "normal_runtime_signals",
        "domain_age": "stable_business_domain",
    }
    evidence_field = kind_map.get(obs.kind, obs.kind)
    dossier.evidence_e.append(Evidence(
        level=EvidenceLevel.E,
        field=evidence_field,
        detail=f"{obs.field} [{','.join(obs.tags)}]: {obs.detail}",
        strength=EvidenceStrength.WEAK,
        tags=list(obs.tags),
    ))


def _map_conflict_to_e(dossier: IocDossier, obs):
    dossier.evidence_e.append(Evidence(
        level=EvidenceLevel.E,
        field="benign_family_or_risk_conflict",
        detail=f"{obs.field} [{','.join(obs.tags)}]: {obs.detail}",
        strength=EvidenceStrength.NORMAL,
        tags=["conflict"] + obs.tags,
    ))


def _map_neutral_to_f(dossier: IocDossier, obs):
    kind_map = {
        "whois_update": "profile_update_only",
        "domain_expiry": "whois_expiry_without_threat_context",
        "http_state": "http.status",
        "reachable": "reachable",
        "current_status": "current_status",
        "near_expiry": "whois_expiry_without_threat_context",
        "parking": "parking_state",
    }
    evidence_field = kind_map.get(obs.kind, obs.kind)
    dossier.evidence_f.append(Evidence(
        level=EvidenceLevel.F,
        field=evidence_field,
        detail=f"{obs.field} [{','.join(obs.tags)}]: {obs.detail}",
        strength=EvidenceStrength.WEAK,
        tags=list(obs.tags),
    ))


def _add_hash_without_ioc_d(dossier: IocDossier, config: Config):
    """High-level hash entries without direct IOC evidence → D."""
    if dossier.evidence_a:
        return
    high_hashes = [
        h for h in dossier.hash_entries
        if is_malicious_sample(h, config)
    ]
    if high_hashes:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="high_level_hash_without_direct_ioc",
            detail=f"{len(high_hashes)} hash entries level >= {config.hash_malicious_level} without IOC closure",
            strength=EvidenceStrength.NORMAL,
            tags=["hash", "no_ioc_closure"],
        ))


def _add_source_without_a_d(dossier: IocDossier, config: Config):
    """Strong sources without direct A evidence → D."""
    if dossier.evidence_a:
        return
    strong_sources = [
        s for s in dossier.source_set
        if s in config.rules.strong_sources and s not in config.rules.weak_sources
    ]
    if strong_sources:
        dossier.evidence_d.append(Evidence(
            level=EvidenceLevel.D,
            field="strong_source_without_direct_a",
            detail=f"strong sources {', '.join(strong_sources)} without direct IOC closure",
            strength=EvidenceStrength.WEAK,
            tags=["source", "no_ioc_closure"],
        ))


def _is_strong_a(dossier: IocDossier) -> bool:
    """Strong A = any A evidence with strength=strong."""
    return any(e.strength == EvidenceStrength.STRONG for e in dossier.evidence_a)


def _is_strong_e(dossier: IocDossier) -> bool:
    """Strong E = any E evidence with strength=strong."""
    return any(e.strength == EvidenceStrength.STRONG for e in dossier.evidence_e)


def _extract_structured_public_apt(dossier: IocDossier, config: Config):
    """Create a single normal-strength C evidence entry when every public-APT
    criterion is met by at least one record snapshot.

    Required: malicious_type contains case-insensitive exact ``"APT"`` (scalar
    or list); private is boolean False; confidence >= 4; info_level >= 2;
    level >= 70; a URL extracted from context, comment, or a ``reference``
    field.  A bare top-level ``url`` field is not sufficient.
    Malformed numeric fields do not crash — they exclude the record instead.
    """
    latest_snapshot = (
        dossier.record_snapshots[-1] if dossier.record_snapshots else None
    )
    for snap in dossier.record_snapshots:
        raw = snap.raw
        mt = raw.get("malicious_type")
        if isinstance(mt, str):
            mt = [mt]
        if not isinstance(mt, list):
            continue
        if not any(str(x).strip().upper() == "APT" for x in mt):
            continue

        if raw.get("private") is not False:
            continue

        try:
            confidence = float(raw.get("confidence", 0))
        except (ValueError, TypeError):
            continue
        if confidence < 4:
            continue

        try:
            info_level = float(raw.get("info_level", 0))
        except (ValueError, TypeError):
            continue
        if info_level < 2:
            continue

        try:
            level = float(raw.get("level", 0))
        except (ValueError, TypeError):
            continue
        if level < 70:
            continue

        reference_fields = ["reference"]
        if snap is latest_snapshot:
            reference_fields.extend(["context", "comment"])
        reference_text = "\n".join(
            str(raw.get(field, ""))
            for field in reference_fields
            if raw.get(field)
        )
        urls = re.findall(r'https?://[^\s"\'<>]+', reference_text)
        if not urls:
            continue
        ref_url = urls[0]

        dossier.evidence_c.append(Evidence(
            level=EvidenceLevel.C,
            field="structured_public_apt",
            detail=f"公开APT报告: {ref_url}",
            strength=EvidenceStrength.NORMAL,
            tags=["historical", "structured_public_apt"],
        ))
        return  # At most one entry


def _extract_f(dossier: IocDossier, config: Config):
    if dossier.latest_intel_update_time:
        dossier.evidence_f.append(Evidence(
            level=EvidenceLevel.F,
            field="updatetime",
            detail=f"情报更新时间: {dossier.latest_intel_update_time}",
            strength=EvidenceStrength.WEAK,
            tags=["update_only"],
        ))
