"""Test fixture builders."""
from datetime import datetime, timedelta


def build_record(
    ioc: str = "test.com",
    level: float = 70.0,
    category: str = "DOMAIN_PORT",
    source: list[str] | None = None,
    hash_entries: list[dict] | None = None,
    context: str = "",
    comment: str = "",
    family: list[str] | None = None,
    tag: list[str] | None = None,
    flint: dict | None = None,
    access: dict | None = None,
    dtree: list[dict] | None = None,
    relate_url: list[dict] | None = None,
    relate_ip_domain: list[dict] | None = None,
    certificates: dict | None = None,
    port: str = "0",
    **extra,
) -> dict:
    record = {
        "key": ioc,
        "host": ioc,
        "level": level,
        "category": category,
        "source": source or [],
        "hash": hash_entries or [],
        "context": context,
        "comment": comment,
        "family": family or [],
        "tag": tag or [],
        "flint": flint or {},
        "access": access or {},
        "dtree": dtree or [],
        "relate_url": relate_url or [],
        "relate_ip_domain": relate_ip_domain or [],
        "certificates": certificates or {},
        "port": port,
        "malicious_type": [],
        "attck": [],
        "resolv_ip": "",
        "icp_website": "",
        "official_website": "",
        "page_title": "",
        "topdomain": {},
    }
    record.update(extra)
    return record


def build_hash_entry(
    md5: str = "abc123",
    level: int = 70,
    time: str = "2026-03-20 17:10:41",
    family: str = "SilverFox",
    source: list[str] | None = None,
) -> dict:
    return {
        "md5": md5,
        "level": level,
        "time": time,
        "family": family,
        "source": source or ["fdark"],
    }
