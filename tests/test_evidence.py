from datetime import datetime, timedelta
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.models import EvidenceLevel, IocDossier
from tests.fixtures import build_record, build_hash_entry
from ioc_rejudge.normalize import merge_records


def _today_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


def test_evidence_a_sample_direct_connection():
    records = [
        build_record(
            "evil.com",
            context="DNS: evil.com\nTCP: 1.2.3.4:8080\nHTTP: http://1.2.3.4:8080/payload",
            source=["sample-base", "zion_sandbox"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            family=["SilverFox"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert len(dossier.evidence_a) > 0, "Should have A-level evidence from context"


def test_evidence_a_hash_level_above_threshold():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected to C2",
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            source=["sample-base"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert any(e.level == EvidenceLevel.A for e in dossier.evidence_a)


def test_evidence_a_hash_without_ioc_connection_not_a_level():
    records = [
        build_record(
            "innocent.com",
            context="Malware detected but no mention of innocent.com",
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    a_evidence = [e for e in dossier.evidence_a if "hash" in e.field.lower()]


def test_evidence_b_recent_activity():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            source=["sample-base"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert any(e.level == EvidenceLevel.B for e in dossier.evidence_b)


def test_evidence_b_old_activity_not_b():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            hash_entries=[build_hash_entry("abc", level=70, time="2020-01-01 00:00:00")],
            source=["sample-base"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config(activity_window_days=365))
    b_from_hash = [e for e in dossier.evidence_b if "hash" in e.field.lower()]
    assert len(b_from_hash) == 0


def test_evidence_c_historical_malicious():
    records = [
        build_record(
            "evil.com",
            context="Historical sample communicated with evil.com",
            source=["sample-base", "manual"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            family=["SilverFox"],
            malicious_type=["TROJAN"],
            attck=["T1071"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config(activity_window_days=365))
    assert len(dossier.evidence_c) > 0


def test_evidence_c_alone_not_sufficient():
    records = [
        build_record(
            "suspicious.com",
            source=["sample-base"],
            family=["SilverFox"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert len(dossier.evidence_c) == 0


def test_evidence_d_only_relate_ip():
    records = [
        build_record(
            "suspicious.com",
            relate_ip_domain=[{"key": "1.2.3.4", "level": 50, "count": 100}],
            level=50,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert len(dossier.evidence_d) > 0


def test_evidence_e_shared_infrastructure():
    records = [
        build_record(
            "suspicious.com",
            official_website="https://www.normal-business.com",
            level=30,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    assert len(dossier.evidence_e) > 0


def test_evidence_f_updatetime_alone():
    records = [
        build_record(
            "suspicious.com",
            updatetime=_today_str(),
            level=30,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    f_fields = [e.field for e in dossier.evidence_f]
    assert any("updatetime" in f for f in f_fields)
    b_fields = [e.field for e in dossier.evidence_b]
    assert not any("updatetime" in f for f in b_fields)


def test_evidence_resolv_ip_no_timestamp_not_b():
    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            source=["sample-base"],
            resolv_ip="198.44.248.182",
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    b_from_resolv = [e for e in dossier.evidence_b if "resolv" in e.field.lower()]
    assert len(b_from_resolv) == 0


def test_missing_fields_no_error():
    dossier = IocDossier(ioc="test.com", ioc_type="domain")
    dossier = extract_evidence(dossier, Config())
    assert isinstance(dossier.evidence_a, list)
