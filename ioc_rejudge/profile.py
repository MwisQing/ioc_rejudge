"""IOC profile extraction - converts raw fields into explainable observations."""
import re
from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.models import IocDossier, IocProfile, ProfileObservation
from ioc_rejudge.normalize import coerce_level
from ioc_rejudge.parser import parse_time


def _is_domain(value: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', value))


def _looks_random(text: str) -> bool:
    """Check if a domain label looks algorithmically generated."""
    if not text:
        return False
    label = text.split(".")[0]
    if len(label) < 8:
        return False
    digits = sum(1 for c in label if c.isdigit())
    consonants = sum(1 for c in label if c.lower() in "bcdfghjklmnpqrstvwxyz")
    vowels = sum(1 for c in label if c.lower() in "aeiou")
    if len(label) >= 12 and vowels == 0:
        return True
    if digits >= len(label) * 0.4:
        return True
    if consonants >= len(label) * 0.8 and len(label) >= 10:
        return True
    return False


def extract_profile(dossier: IocDossier, config: Config) -> IocDossier:
    """Extract domain, IP, and runtime profile observations from raw fields."""
    now = datetime.now()
    observations: list[ProfileObservation] = []
    domain_summary: dict = {}
    ip_summary: dict = {}
    runtime_summary: dict = {}

    _extract_domain_profile(dossier, config, now, observations, domain_summary)
    _extract_ip_profile(dossier, config, observations, ip_summary)
    _extract_runtime_profile(dossier, observations, runtime_summary)
    _detect_parking_state(dossier, observations)

    dossier.profile = IocProfile(
        observations=observations,
        domain=domain_summary,
        ip=ip_summary,
        runtime=runtime_summary,
    )
    return dossier


def _extract_domain_profile(
    dossier: IocDossier, config: Config, now: datetime,
    observations: list[ProfileObservation], summary: dict,
):
    if dossier.ioc_type not in ("domain", "domain_port", "url"):
        return

    whois = dossier.whois
    created_str = whois.get("createdDate", "")
    expires_str = whois.get("expiresDate", "")
    updated_str = whois.get("updatedDate", "")
    registrant_email = whois.get("registrantEmail", "")
    registrant_name = whois.get("registrantName", "")
    privacy = whois.get("privacyprotect_whois", "")

    created = parse_time(created_str) if created_str else None
    expires = parse_time(expires_str) if expires_str else None
    updated = parse_time(updated_str) if updated_str else None

    # Domain age
    age_days = None
    if created:
        age_days = (now - created).days
        summary["age_days"] = age_days

        # New domain: within 30 days
        if age_days <= 30:
            summary["is_new"] = True
            observations.append(ProfileObservation(
                field="whois.createdDate",
                kind="domain_age",
                value=created_str,
                severity="suspicious",
                detail=f"domain registered within {age_days} days",
                tags=["new_domain"],
            ))
        # Mature domain: older than 1 year
        elif age_days > 365:
            summary["is_mature"] = True
            observations.append(ProfileObservation(
                field="whois.createdDate",
                kind="domain_age",
                value=created_str,
                severity="normal",
                detail=f"domain registered over {age_days // 365} years ago",
                tags=["mature_domain"],
            ))

        # Short-lived domain
        if expires and created:
            lifespan = (expires - created).days
            if 0 < lifespan <= 90:
                summary["is_short_lived"] = True
                observations.append(ProfileObservation(
                    field="whois.expiresDate",
                    kind="domain_lifespan",
                    value=expires_str,
                    severity="suspicious",
                    detail=f"domain lifespan only {lifespan} days (created to expiry)",
                    tags=["short_lived"],
                ))

    # Near expiry / expired (auxiliary only)
    if expires:
        days_to_expiry = (expires - now).days
        if days_to_expiry < 0:
            observations.append(ProfileObservation(
                field="whois.expiresDate",
                kind="domain_expiry",
                value=expires_str,
                severity="neutral",
                detail="domain registration has expired",
                tags=["expired"],
            ))
        elif days_to_expiry <= 30:
            observations.append(ProfileObservation(
                field="whois.expiresDate",
                kind="domain_expiry",
                value=expires_str,
                severity="neutral",
                detail=f"domain expires in {days_to_expiry} days",
                tags=["near_expiry"],
            ))

    # WHOIS update (F-level only)
    if updated:
        observations.append(ProfileObservation(
            field="whois.updatedDate",
            kind="profile_update",
            value=updated_str,
            severity="neutral",
            detail=f"WHOIS updated {updated_str}",
            tags=["whois_update"],
        ))

    # Missing registration identity / privacy protection
    has_registrant = bool(registrant_email or registrant_name)
    has_privacy = bool(privacy)
    if has_privacy and not has_registrant:
        observations.append(ProfileObservation(
            field="whois.privacyprotect_whois",
            kind="domain_privacy",
            value=str(privacy),
            severity="neutral",
            detail="WHOIS privacy protection enabled, no registrant identity",
            tags=["privacy_protection"],
        ))

    # Trusted business identity
    has_icp = bool(dossier.icp_website)
    has_official = bool(dossier.official_website)
    if has_icp and has_official:
        summary["has_trusted_business_identity"] = True
        observations.append(ProfileObservation(
            field="icp_website+official_website",
            kind="business_identity",
            value=f"{dossier.icp_website}, {dossier.official_website}",
            severity="normal",
            detail="both ICP registration and official website present",
            tags=["trusted_business"],
        ))
    elif has_icp:
        observations.append(ProfileObservation(
            field="icp_website",
            kind="business_identity",
            value=dossier.icp_website,
            severity="normal",
            detail="ICP registration present",
            tags=["icp_only"],
        ))
    elif has_official:
        observations.append(ProfileObservation(
            field="official_website",
            kind="business_identity",
            value=dossier.official_website,
            severity="normal",
            detail="official website present",
            tags=["official_only"],
        ))

    # Page title
    if dossier.page_title:
        observations.append(ProfileObservation(
            field="page_title",
            kind="page_title",
            value=dossier.page_title,
            severity="neutral",
            detail=f"page title: {dossier.page_title}",
            tags=["page_title"],
        ))

    # Popular / normal top domain
    topdomain = dossier.topdomain
    if topdomain and topdomain.get("rank", -1) > 0:
        observations.append(ProfileObservation(
            field="topdomain",
            kind="popular_domain",
            value=f"rank={topdomain.get('rank')}",
            severity="normal",
            detail=f"top domain rank {topdomain.get('rank')}",
            tags=["popular_domain"],
        ))

    # Random-looking domain
    if _looks_random(dossier.ioc):
        summary["looks_random"] = True
        observations.append(ProfileObservation(
            field="ioc",
            kind="domain_shape",
            value=dossier.ioc,
            severity="suspicious",
            detail="domain name looks algorithmically generated",
            tags=["random_domain"],
        ))


def _extract_ip_profile(
    dossier: IocDossier, config: Config,
    observations: list[ProfileObservation], summary: dict,
):
    relate_entries = dossier.relate_ip_domain_entries
    dtree_entries = dossier.dtree_entries

    # Combine related domains from both sources
    related_domains: list[dict] = []
    seen_keys: set[str] = set()
    for entry in relate_entries:
        key = str(entry.get("key", entry.get("domain", entry)))
        if key not in seen_keys:
            seen_keys.add(key)
            related_domains.append(entry)
    for entry in dtree_entries:
        key = str(entry.get("key", entry.get("domain", "")))
        if key and key not in seen_keys:
            seen_keys.add(key)
            related_domains.append(entry)

    total = len(related_domains)
    summary["related_domain_count"] = total

    # High-risk related domains
    high_risk = [
        d for d in related_domains
        if coerce_level(d.get("level")) >= config.historical_malicious_level
    ]
    summary["high_risk_related_domain_count"] = len(high_risk)

    # Recent related domains (within activity window)
    cutoff = datetime.now() - timedelta(days=config.activity_window_days)
    recent_related = [
        d for d in related_domains
        if parse_time(d.get("last", "")) and parse_time(d.get("last", "")) >= cutoff
    ]
    summary["recent_related_domain_count"] = len(recent_related)

    # Random-looking related domains
    random_related = [
        d for d in related_domains
        if _looks_random(str(d.get("key", d.get("domain", ""))))
    ]
    summary["random_related_domain_count"] = len(random_related)

    # High-risk related domains observation
    if high_risk:
        observations.append(ProfileObservation(
            field="relate_ip_domain",
            kind="ip_reverse_domain_risk",
            value=f"{len(high_risk)} high-risk related domains",
            severity="suspicious",
            detail=f"IP has {len(high_risk)} related domains with level >= {config.historical_malicious_level}",
            tags=["pdns", "high_related_level"],
        ))

    # Multiple related domains (infrastructure context)
    if total >= 3:
        observations.append(ProfileObservation(
            field="relate_ip_domain+dtree",
            kind="ip_related_domain_count",
            value=f"{total} related domains",
            severity="neutral",
            detail=f"IP hosts {total} related domains",
            tags=["pdns", "infrastructure"],
        ))

    # Random-looking related domains
    if random_related:
        observations.append(ProfileObservation(
            field="relate_ip_domain+dtree",
            kind="random_related_domains",
            value=f"{len(random_related)} random-looking domains",
            severity="suspicious",
            detail=f"IP has {len(random_related)} random-looking related domains",
            tags=["random_domain", "pdns"],
        ))

    # Recent PDNS activity
    if recent_related:
        observations.append(ProfileObservation(
            field="dtree.last",
            kind="recent_pdns_activity",
            value=f"{len(recent_related)} recently active domains",
            severity="suspicious",
            detail=f"IP has {len(recent_related)} related domains with recent activity",
            tags=["pdns", "recent"],
        ))

    # Flint infrastructure relations
    flint = dossier.flint
    if flint:
        flint_last = parse_time(flint.get("last_seen", ""))
        if flint_last and flint_last >= cutoff:
            observations.append(ProfileObservation(
                field="flint.last_seen",
                kind="recent_infrastructure",
                value=str(flint.get("last_seen", "")),
                severity="suspicious",
                detail="flint shows recent infrastructure activity",
                tags=["flint", "recent"],
            ))

    # Shared infrastructure check (CDN, cloud, IDC, shared hosting)
    combined_text = f"{dossier.context}\n{dossier.comment}\n" + \
        " ".join(str(d.get("key", "")) for d in related_domains)
    _SHARED_INFRA = ["cdn", "cloud", "idc", "shared hosting", "cdn节点", "云服务", "共享"]
    if any(ind in combined_text.lower() for ind in _SHARED_INFRA):
        summary["shared_infrastructure"] = True
        observations.append(ProfileObservation(
            field="context/comment",
            kind="shared_infrastructure",
            value="shared hosting / CDN / cloud indicators",
            severity="normal",
            detail="infrastructure shared with normal services (CDN/cloud/hosting)",
            tags=["shared_infra"],
        ))

    # Mixed infrastructure: normal-business fields + high-risk related domains
    has_normal = (
        bool(dossier.icp_website) or bool(dossier.official_website) or
        summary.get("shared_infrastructure") or
        any(ind in combined_text.lower() for ind in _SHARED_INFRA)
    )
    if has_normal and high_risk:
        summary["mixed_infrastructure"] = True
        observations.append(ProfileObservation(
            field="relate_ip_domain",
            kind="mixed_infrastructure",
            value=f"normal business + {len(high_risk)} high-risk domains",
            severity="conflict",
            detail="normal business indicators coexist with high-risk related domains on same IP",
            tags=["pdns", "conflict", "mixed_infra"],
        ))


def _extract_runtime_profile(
    dossier: IocDossier,
    observations: list[ProfileObservation], summary: dict,
):
    rf = dossier.runtime_flags

    # Threat runtime flags
    threat_flags: list[str] = []
    if rf.get("block") is True:
        threat_flags.append("block")
    if rf.get("black") is True:
        threat_flags.append("black")
    if rf.get("ml_black") is True:
        threat_flags.append("ml_black")
    alert_score = rf.get("alert_score", 0)
    if isinstance(alert_score, (int, float)) and alert_score >= 70:
        threat_flags.append(f"alert_score={alert_score}")
    if rf.get("fdark"):
        fdark_val = str(rf["fdark"]).lower()
        if any(w in fdark_val for w in ["trojan", "malware", "backdoor", "rat", "木马", "恶意", "后门"]):
            threat_flags.append("fdark_malicious")

    if threat_flags:
        summary["has_threat_flag"] = True
        observations.append(ProfileObservation(
            field="runtime_flags",
            kind="threat_runtime",
            value=", ".join(threat_flags),
            severity="suspicious",
            detail=f"runtime threat flags: {', '.join(threat_flags)}",
            tags=["threat_runtime"],
        ))

    # Benign conflict markers
    benign_markers: list[str] = []
    risk_val = rf.get("risk")
    if isinstance(risk_val, (int, float)) and risk_val < 0:
        benign_markers.append(f"risk={risk_val}")
    if rf.get("ml_cls") and str(rf["ml_cls"]).upper() in ("NOT_A_VIRUS", "BENIGN", "CLEAN"):
        benign_markers.append(f"ml_cls={rf['ml_cls']}")

    if benign_markers:
        summary["has_benign_conflict"] = True
        severity = "conflict" if (summary.get("has_threat_flag") or dossier.hash_entries) else "normal"
        observations.append(ProfileObservation(
            field="runtime_flags",
            kind="benign_runtime",
            value=", ".join(benign_markers),
            severity=severity,
            detail=f"benign runtime markers: {', '.join(benign_markers)}",
            tags=["benign_runtime"],
        ))

    # HTTP state (F-level only)
    http = dossier.http
    if http:
        http_status = http.get("status", "")
        if http_status:
            observations.append(ProfileObservation(
                field="http.status",
                kind="http_state",
                value=str(http_status),
                severity="neutral",
                detail=f"HTTP status: {http_status}",
                tags=["http_state"],
            ))

    reachable = rf.get("reachable")
    if reachable is not None:
        observations.append(ProfileObservation(
            field="reachable",
            kind="reachable",
            value=str(reachable),
            severity="neutral",
            detail=f"reachable: {reachable}",
            tags=["reachable"],
        ))

    current_status = rf.get("current_status")
    if current_status:
        observations.append(ProfileObservation(
            field="current_status",
            kind="current_status",
            value=str(current_status),
            severity="neutral",
            detail=f"current_status: {current_status}",
            tags=["current_status"],
        ))


def _detect_parking_state(
    dossier: IocDossier,
    observations: list[ProfileObservation],
):
    """Detect parking / empty / placeholder page state → F-level observation.

    Parking is a weak state signal, not a normal business indicator.
    It supports 失活有效 but cannot independently justify 误报.
    """
    _PARKING_INDICATORS = ["parking", "parked", "empty page", "placeholder",
                           "停靠", "停放", "空置"]
    combined_text = f"{dossier.context}\n{dossier.comment}".lower()
    matched = [ind for ind in _PARKING_INDICATORS if ind in combined_text]
    if matched:
        observations.append(ProfileObservation(
            field="context/comment",
            kind="parking",
            value=", ".join(matched),
            severity="neutral",
            detail=f"parking or placeholder indicators: {', '.join(matched)}",
            tags=["parking", "weak_state"],
        ))
