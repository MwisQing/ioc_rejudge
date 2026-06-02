from ioc_rejudge.normalize import normalize_ioc, group_by_ioc, merge_records
from tests.fixtures import build_record, build_hash_entry


def test_normalize_domain():
    assert normalize_ioc("Example.COM") == ("example.com", "domain", [])
    assert normalize_ioc("example.com.") == ("example.com", "domain", [])


def test_normalize_ip():
    assert normalize_ioc("192.168.1.1") == ("192.168.1.1", "ip", [])


def test_normalize_domain_port():
    assert normalize_ioc("test.com", port="8080") == ("test.com:8080", "domain_port", ["8080"])
    assert normalize_ioc("test.com", port="0") == ("test.com", "domain", [])


def test_group_by_ioc():
    records = [
        {"key": "Test.COM.", "host": "test.com.", "port": "0"},
        {"key": "test.com", "host": "test.com", "port": "0"},
    ]
    groups = group_by_ioc(records)
    assert len(groups) == 1
    assert "test.com" in groups


def test_group_by_ioc_different_ports():
    records = [
        {"key": "test.com", "host": "test.com", "port": "80"},
        {"key": "test.com", "host": "test.com", "port": "443"},
    ]
    groups = group_by_ioc(records)
    assert len(groups) == 2


def test_merge_records_basic():
    records = [
        build_record("test.com", level=40, hash_entries=[
            build_hash_entry("aaa", level=40, time="2024-01-01 00:00:00"),
        ]),
        build_record("test.com", level=70, hash_entries=[
            build_hash_entry("bbb", level=70, time="2026-03-20 17:10:41"),
        ]),
    ]
    dossier = merge_records(records)
    assert dossier.ioc == "test.com"
    assert dossier.level == 70.0
    assert len(dossier.hash_entries) == 2
    assert len(dossier.source_set) >= 0


def test_merge_records_time_fields():
    records = [
        build_record("test.com", flint={"last_seen": "2024-01-01 00:00:00"}),
        build_record("test.com", flint={"last_seen": "2026-01-01 00:00:00"}),
    ]
    dossier = merge_records(records)
    assert dossier.flint["last_seen"] == "2026-01-01 00:00:00"


def test_merge_records_missing_fields():
    records = [
        {"key": "test.com", "host": "test.com"},
        build_record("test.com", level=70),
    ]
    dossier = merge_records(records)
    assert dossier.ioc == "test.com"
