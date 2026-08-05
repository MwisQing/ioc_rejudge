"""IOC normalization and grouping."""
import re
from datetime import datetime
from urllib.parse import urlparse
from ioc_rejudge.models import IocDossier, RecordSnapshot
from ioc_rejudge.parser import parse_time


def _record_time(record: dict) -> datetime | None:
    """Extract the best-effort record timestamp."""
    for field in ("updatetime", "inserttime", "disposaltime"):
        parsed = parse_time(str(record.get(field, "")))
        if parsed:
            return parsed
    return None


def _ordered_snapshots(records: list[dict]) -> list[RecordSnapshot]:
    """Build provenance snapshots sorted by (record_time, original index).

    Records without a parseable time sort before those with one
    (datetime.min is used as the sort key for None).
    """
    snapshots = [
        RecordSnapshot(
            index=idx,
            record_time=_record_time(rec),
            sources=_merge_all_values([rec], "source"),
            raw=rec,
        )
        for idx, rec in enumerate(records)
    ]
    return sorted(
        snapshots,
        key=lambda s: (s.record_time or datetime.min, s.index),
    )


def latest_record(records: list[dict]) -> dict:
    """Return the latest record by timestamp, then original input order."""
    snapshots = _ordered_snapshots(records)
    return snapshots[-1].raw if snapshots else {}


def normalize_ioc(value: str, port: str = "0") -> tuple[str, str, list[str]]:
    value = value.strip()
    if not value:
        return ("", "unknown", [])

    ports = []
    if port and port != "0" and port != "":
        ports = [port]

    # URL input: http://host/path or https://host:port/path
    url_match = re.match(r'^https?://', value, re.IGNORECASE)
    if url_match:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        url_port = str(parsed.port) if parsed.port else ""
        path = parsed.path or ""
        if parsed.query:
            path += "?" + parsed.query
        host = host.rstrip(".").lower()
        if url_port:
            ports = [url_port]
            normalized = f"{host}:{url_port}{path}" if path else f"{host}:{url_port}"
        else:
            normalized = f"{host}{path}" if path else host
        return (normalized, "url", ports)

    # IP:port pattern
    ip_port_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', value)
    if ip_port_match:
        ip = ip_port_match.group(1)
        p = ip_port_match.group(2)
        return (f"{ip}:{p}", "ip_port", [p])

    # Plain IP
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return (value, "ip", ports)

    # domain:port pattern (when port not already set from record)
    if not ports:
        domain_port_match = re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*):(\d+)$', value)
        if domain_port_match:
            domain = domain_port_match.group(1).rstrip(".").lower()
            p = domain_port_match.group(5)
            return (f"{domain}:{p}", "domain_port", [p])

    domain = value.rstrip(".").lower()
    if ports:
        return (f"{domain}:{ports[0]}", "domain_port", ports)
    return (domain, "domain", ports)


def _get_group_key(record: dict) -> str:
    ioc = record.get("key") or record.get("host") or record.get("ioc", "")
    port = str(record.get("port", "0"))
    normalized, ioc_type, ports = normalize_ioc(ioc, port)
    return normalized


def group_by_ioc(records: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for rec in records:
        key = _get_group_key(rec)
        if key not in groups:
            groups[key] = []
        groups[key].append(rec)
    return groups


def _merge_all_values(records: list[dict], field: str, default=None) -> list:
    result = []
    seen = set()
    for rec in records:
        val = rec.get(field, [])
        if val is None:
            continue
        if not isinstance(val, list):
            val = [val]
        for item in val:
            key = str(item)
            if key not in seen:
                seen.add(key)
                result.append(item)
    return result


def _pick_latest(records: list[dict], field: str) -> str | None:
    latest_dt = None
    latest_val = None
    for rec in records:
        val = rec.get(field)
        if not val:
            continue
        dt = parse_time(str(val))
        if dt and (latest_dt is None or dt > latest_dt):
            latest_dt = dt
            latest_val = str(val)
    return latest_val


def _collect_all_nested(records: list[dict], nested_field: str) -> list[dict]:
    result = []
    seen = set()
    for rec in records:
        entries = rec.get(nested_field, [])
        if not entries or not isinstance(entries, list):
            continue
        for entry in entries:
            dedup_key = str(entry.get("md5", entry.get("key", entry)))
            if dedup_key not in seen:
                seen.add(dedup_key)
                result.append(entry)
    return result


def _safe_current_dict(record: dict, field: str) -> dict:
    """Return a shallow copy of *record[field]* if it is a dict, else {}.

    Guards against malformed records where whois/http may be a string,
    list, or other non-dict value that would crash ``dict(...)``.
    """
    val = record.get(field)
    if isinstance(val, dict):
        return dict(val)
    return {}


def _pick_latest_dict(records: list[dict], field: str) -> dict:
    """Pick the dict whose internal time value is most recent.

    Scans all records for dicts with the given field, compares their
    time-like values, and returns the one with the latest timestamp.
    Falls back to last non-empty if no timestamps found.
    """
    TIME_KEYS = ("last_seen", "end", "last", "updatedDate", "not_after",
                 "createdDate", "expiresDate")
    best_dt = None
    best_val = {}
    fallback = {}

    for rec in records:
        val = rec.get(field)
        if not val or not isinstance(val, dict):
            continue
        fallback = val  # keep last as fallback
        # Try to find a time field inside this dict
        for key in TIME_KEYS:
            dt = parse_time(val.get(key, ""))
            if dt and (best_dt is None or dt > best_dt):
                best_dt = dt
                best_val = val
                break

    return best_val if best_val else fallback


def coerce_level(value: object, default: float = 0.0) -> float:
    """Coerce a possibly dirty level field (None, bool, str, junk) to a float."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def merge_records(records: list[dict]) -> IocDossier:
    if not records:
        return IocDossier(ioc="", ioc_type="unknown")

    first = records[0]
    ioc_val = first.get("key") or first.get("host") or first.get("ioc", "")
    port = str(first.get("port", "0"))
    normalized, ioc_type, ports = normalize_ioc(ioc_val, port)

    max_level = 0.0
    for rec in records:
        lvl = coerce_level(rec.get("level"))
        if lvl > max_level:
            max_level = lvl

    hash_entries = _collect_all_nested(records, "hash")
    dtree_entries = _collect_all_nested(records, "dtree")
    relate_url_entries = _collect_all_nested(records, "relate_url")
    relate_ip_domain_entries = _collect_all_nested(records, "relate_ip_domain")

    source_set = _merge_all_values(records, "source")
    family = _merge_all_values(records, "family")
    tag = _merge_all_values(records, "tag")
    malicious_type = _merge_all_values(records, "malicious_type")
    attck = _merge_all_values(records, "attck")
    record_categories = list({rec.get("category", "") for rec in records if rec.get("category")})

    latest_flint = _pick_latest_dict(records, "flint")
    latest_access = _pick_latest_dict(records, "access")
    latest_certificates = _pick_latest_dict(records, "certificates")
    latest_topdomain = _pick_latest_dict(records, "topdomain")

    # ---- Current-state fields from the single latest record ----
    snapshots = _ordered_snapshots(records)
    latest_rec = snapshots[-1].raw if snapshots else {}
    latest_whois = _safe_current_dict(latest_rec, "whois")
    latest_http = _safe_current_dict(latest_rec, "http")

    # historical_icp_values: all non-empty ICP from older snapshots
    historical_icp: list[str] = []
    icp_current = str(latest_rec.get("icp_website", "") or "")
    for snap in snapshots[:-1]:  # all except the latest
        val = str(snap.raw.get("icp_website", "") or "")
        if val:
            historical_icp.append(val)

    official_website = str(latest_rec.get("official_website", "") or "")
    page_title = str(latest_rec.get("page_title", "") or "")
    resolv_ip = str(latest_rec.get("resolv_ip", "") or "")

    # Aggregate runtime flags across all records
    aggregated_runtime: dict[str, str | bool | int | float] = {}
    _RUNTIME_FIELDS = [
        "risk", "fdark", "alert", "alert_score", "block", "black",
        "ml_black", "ml_cls", "ml_confidence", "current_status",
        "reachable", "processed", "task_status",
    ]
    for rec in records:
        for f in _RUNTIME_FIELDS:
            val = rec.get(f)
            if val is not None and f not in aggregated_runtime:
                aggregated_runtime[f] = val
            elif val is not None and f in aggregated_runtime:
                # Take max for numeric, latest non-empty for strings, True wins for bools
                existing = aggregated_runtime[f]
                if isinstance(val, bool) and isinstance(existing, bool):
                    aggregated_runtime[f] = existing or val
                elif isinstance(val, (int, float)) and isinstance(existing, (int, float)):
                    # risk: preserve most negative (benign) value
                    if f == "risk":
                        aggregated_runtime[f] = min(existing, val)
                    else:
                        aggregated_runtime[f] = max(existing, val)
                elif isinstance(val, str) and val and not existing:
                    aggregated_runtime[f] = val

    dossier = IocDossier(
        ioc=normalized,
        ioc_type=ioc_type,
        ports=ports,
        level=max_level,
        hash_entries=hash_entries,
        flint=latest_flint,
        access=latest_access,
        dtree_entries=dtree_entries,
        relate_url_entries=relate_url_entries,
        relate_ip_domain_entries=relate_ip_domain_entries,
        source_set=source_set,
        family=[f for f in family if f],
        tag=tag,
        malicious_type=malicious_type,
        attck=attck,
        record_categories=record_categories,
        context=str(latest_rec.get("context", "") or ""),
        comment=str(latest_rec.get("comment", "") or ""),
        certificates=latest_certificates,
        topdomain=latest_topdomain,
        icp_website=icp_current,
        official_website=official_website,
        page_title=page_title,
        resolv_ip=resolv_ip,
        whois=latest_whois,
        http=latest_http,
        runtime_flags=aggregated_runtime,
        record_snapshots=snapshots,
        historical_icp_values=historical_icp,
    )

    activity_times = []
    for h in hash_entries:
        t = parse_time(h.get("time", ""))
        if t:
            activity_times.append(t)
    flint_last = parse_time(latest_flint.get("last_seen", ""))
    if flint_last:
        activity_times.append(flint_last)
    access_end = parse_time(latest_access.get("end", ""))
    if access_end:
        activity_times.append(access_end)
    for d in dtree_entries:
        t = parse_time(d.get("last", ""))
        if t:
            activity_times.append(t)

    if activity_times:
        dossier.latest_material_activity_time = max(activity_times)

    whois_updated = parse_time(latest_whois.get("updatedDate", ""))
    if whois_updated:
        dossier.latest_profile_update_time = whois_updated

    latest_intel = _pick_latest(records, "updatetime")
    if latest_intel:
        dossier.latest_intel_update_time = parse_time(latest_intel)

    return dossier
