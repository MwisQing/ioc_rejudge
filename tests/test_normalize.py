from datetime import datetime

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


# ── Temporal aggregation: stop cross-record backfill ──

def test_latest_record_does_not_backfill_old_icp_or_whois():
    """Latest record with empty ICP and partial WHOIS must not pull values
    from older records.  Old ICP goes to historical_icp_values only."""
    records = [
        build_record(
            "example.invalid", updatetime="2021-01-01 00:00:00",
            icp_website="OLD-ICP",
            whois={"createdDate": "2016-01-01"},
        ),
        build_record(
            "example.invalid", updatetime="2026-01-01 00:00:00",
            icp_website="",
            whois={"expiresDate": "2026-07-04"},
        ),
    ]
    dossier = merge_records(records)
    assert dossier.icp_website == "", \
        f"Expected empty icp_website, got {dossier.icp_website!r}"
    assert dossier.whois == {"expiresDate": "2026-07-04"}, \
        f"Expected latest-record whois only, got {dossier.whois}"
    assert dossier.historical_icp_values == ["OLD-ICP"]
    assert len(dossier.record_snapshots) == 2


def test_whois_not_cross_merged_across_records():
    """WHOIS fields from different records must not be stitched together."""
    records = [
        build_record(
            "merge.invalid", updatetime="2020-01-01 00:00:00",
            whois={"createdDate": "2019-01-01", "registrar": "OldReg"},
        ),
        build_record(
            "merge.invalid", updatetime="2024-01-01 00:00:00",
            whois={"expiresDate": "2025-01-01"},
        ),
    ]
    dossier = merge_records(records)
    # Latest record's whois is the truth.  Old createdDate/registrar must not leak in.
    assert dossier.whois == {"expiresDate": "2025-01-01"}, \
        f"Expected latest whois only, got {dossier.whois}"


def test_current_state_fields_from_latest_record_only():
    """icp_website, official_website, page_title, resolv_ip, http
    must all come from the single latest record."""
    records = [
        build_record(
            "state.invalid", updatetime="2020-01-01 00:00:00",
            official_website="https://old.example",
            page_title="Old Title",
            resolv_ip="10.0.0.1",
            http={"status": "200"},
        ),
        build_record(
            "state.invalid", updatetime="2024-06-01 00:00:00",
            official_website="",
            page_title="",
            resolv_ip="",
            http={},
        ),
    ]
    dossier = merge_records(records)
    assert dossier.official_website == ""
    assert dossier.page_title == ""
    assert dossier.resolv_ip == ""
    assert dossier.http == {}


def test_same_time_records_stable_by_index():
    """Records with identical timestamps must sort by original index."""
    records = [
        build_record("stable.invalid", updatetime="2024-01-01 00:00:00",
                      whois={"expiresDate": "first"}),
        build_record("stable.invalid", updatetime="2024-01-01 00:00:00",
                      whois={"expiresDate": "second"}),
    ]
    dossier = merge_records(records)
    # Index 1 is later → its whois wins
    assert dossier.whois == {"expiresDate": "second"}


def test_comment_and_context_come_from_latest_record_only():
    records = [
        build_record(
            "remarks.invalid",
            updatetime="2024-01-01 00:00:00",
            comment="old comment",
            context="old context",
        ),
        build_record(
            "remarks.invalid",
            updatetime="2026-01-01 00:00:00",
            comment="latest comment",
            context="latest context",
        ),
    ]

    dossier = merge_records(records)

    assert dossier.comment == "latest comment"
    assert dossier.context == "latest context"


def test_empty_latest_comment_and_context_do_not_backfill_history():
    records = [
        build_record(
            "cleared-remarks.invalid",
            updatetime="2024-01-01 00:00:00",
            comment="old comment",
            context="old context",
        ),
        build_record(
            "cleared-remarks.invalid",
            updatetime="2026-01-01 00:00:00",
            comment="",
            context="",
        ),
    ]

    dossier = merge_records(records)

    assert dossier.comment == ""
    assert dossier.context == ""


def test_same_time_latest_comment_uses_later_input_record():
    records = [
        build_record(
            "same-time-remarks.invalid",
            updatetime="2026-01-01 00:00:00",
            comment="first comment",
        ),
        build_record(
            "same-time-remarks.invalid",
            updatetime="2026-01-01 00:00:00",
            comment="second comment",
        ),
    ]

    dossier = merge_records(records)

    assert dossier.comment == "second comment"


def test_record_snapshots_preserve_raw_and_sources():
    """Every record produces a RecordSnapshot with index, time, sources, raw."""
    records = [
        build_record("snap.invalid", updatetime="2023-01-01 00:00:00",
                      source=["src-a"]),
        build_record("snap.invalid", updatetime="2025-01-01 00:00:00",
                      source=["src-b"]),
    ]
    dossier = merge_records(records)
    assert len(dossier.record_snapshots) == 2
    assert dossier.record_snapshots[0].index == 0
    assert dossier.record_snapshots[0].sources == ["src-a"]
    assert dossier.record_snapshots[0].record_time == datetime(2023, 1, 1)
    assert dossier.record_snapshots[1].index == 1
    assert dossier.record_snapshots[1].sources == ["src-b"]


def test_multiple_old_icp_values_collected():
    """All non-empty ICP values from older records go to historical_icp_values."""
    records = [
        build_record("multi-icp.invalid", updatetime="2021-01-01 00:00:00",
                      icp_website="ICP-2021"),
        build_record("multi-icp.invalid", updatetime="2022-01-01 00:00:00",
                      icp_website="ICP-2022"),
        build_record("multi-icp.invalid", updatetime="2026-01-01 00:00:00",
                      icp_website=""),
    ]
    dossier = merge_records(records)
    assert dossier.icp_website == ""
    assert dossier.historical_icp_values == ["ICP-2021", "ICP-2022"]


def test_historical_aggregations_still_work():
    """hash_entries, dtree, relate_url, family, tag, source_set
    must still aggregate across records."""
    records = [
        build_record("agg.invalid", updatetime="2020-01-01 00:00:00",
                      hash_entries=[build_hash_entry("aaa", level=50)],
                      family=["Trojan"], source=["src1"]),
        build_record("agg.invalid", updatetime="2025-01-01 00:00:00",
                      hash_entries=[build_hash_entry("bbb", level=70)],
                      family=["Downloader"], source=["src2"]),
    ]
    dossier = merge_records(records)
    assert len(dossier.hash_entries) == 2
    assert set(dossier.family) == {"Trojan", "Downloader"}
    assert set(dossier.source_set) == {"src1", "src2"}


# ── Malformed current-state fields must not crash ──

def test_whois_string_in_latest_record_does_not_crash():
    """Latest record whois is a string → whois defaults to {}, no backfill."""
    records = [
        build_record("s.invalid", updatetime="2020-01-01 00:00:00",
                      whois={"createdDate": "old"}),
        build_record("s.invalid", updatetime="2026-01-01 00:00:00",
                      whois="not-a-dict"),
    ]
    dossier = merge_records(records)
    assert dossier.whois == {}


def test_http_list_in_latest_record_does_not_crash():
    """Latest record http is a list → http defaults to {}, no backfill."""
    records = [
        build_record("s.invalid", updatetime="2020-01-01 00:00:00",
                      http={"status": "200"}),
        build_record("s.invalid", updatetime="2026-01-01 00:00:00",
                      http=["not", "a", "dict"]),
    ]
    dossier = merge_records(records)
    assert dossier.http == {}
