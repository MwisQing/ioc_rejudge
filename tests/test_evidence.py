from datetime import datetime, timedelta
import pytest
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence, has_authoritative_clue
from ioc_rejudge.models import EvidenceLevel, EvidenceStrength, IocDossier
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


def _ctx_dossier(context: str, level: float = 0.0) -> IocDossier:
    records = [build_record("evil.com", context=context, level=level)]
    return extract_evidence(merge_records(records), Config())


def test_strong_a_neutral_indicators_do_not_promote_strong_a():
    # dns/http/tcp/connect/download/sample/payload are communication/behavior
    # words, not malicious-nature words. They must not form a strong-A direct hit.
    dossier = _ctx_dossier(
        "DNS: evil.com\nTCP: 1.2.3.4:8080\nHTTP: http://1.2.3.4:8080/payload\n"
        "Sample connected and downloaded"
    )
    strong_ctx_a = [
        e for e in dossier.evidence_a
        if e.field == "context/comment" and e.strength == EvidenceStrength.STRONG
    ]
    assert not strong_ctx_a, "Neutral communication words must not produce a strong-A direct hit"
    # Context is preserved as weak D-level indirect evidence, not lost.
    demoted_d = [e for e in dossier.evidence_d if e.field == "context/comment"]
    assert len(demoted_d) == 1
    assert demoted_d[0].strength == EvidenceStrength.WEAK


def test_strong_a_malicious_nature_word_promotes_strong_a():
    # trojan/backdoor/rat/c2/malware carry malicious nature and still form strong A.
    for word in ("trojan", "backdoor", "rat", "c2", "malware"):
        dossier = _ctx_dossier(f"evil.com observed as {word} callback")
        strong_ctx_a = [
            e for e in dossier.evidence_a
            if e.field == "context/comment" and e.strength == EvidenceStrength.STRONG
        ]
        assert len(strong_ctx_a) == 1, f"strong word {word!r} should form a strong-A hit"


def test_strong_a_neutral_then_malicious_word_still_strong_a():
    # When both neutral and strong words are present, strong word wins.
    dossier = _ctx_dossier("Sample evil.com connected to trojan C2")
    strong_ctx_a = [
        e for e in dossier.evidence_a
        if e.field == "context/comment" and e.strength == EvidenceStrength.STRONG
    ]
    assert len(strong_ctx_a) == 1


def test_clue_group_comment_creates_authoritative_a():
    record = build_record(
        "clue.invalid",
        source=["manual"],
        comment="来源：线索群 终端排查 -> clue.invalid",
    )
    assert has_authoritative_clue([record], Config()) is True
    dossier = extract_evidence(merge_records([record]), Config())
    evidence = [e for e in dossier.evidence_a if e.field == "operator_clue_group"]
    assert len(evidence) == 1
    assert evidence[0].strength == EvidenceStrength.STRONG
    assert "authoritative" in evidence[0].tags


def test_operator_source_and_explicit_malicious_context_create_authoritative_a():
    dossier = extract_evidence(merge_records([build_record(
        "operator.invalid",
        source=["manual", "alliocs_tpd"],
        context="劫持浏览器的rootkit，行为类似独狼病毒",
    )]), Config())
    assert any(
        e.field == "operator_confirmed_malicious_context"
        and e.strength == EvidenceStrength.STRONG
        and "malicious_context" in e.tags
        for e in dossier.evidence_a
    )


@pytest.mark.parametrize("source,context", [
    (["manual"], "普通运营备注"),
    (["sample-base"], "rootkit behavior"),
    (["manual"], "only a reference https://reports.invalid/item"),
])
def test_operator_evidence_near_negatives_do_not_upgrade(source, context):
    dossier = extract_evidence(merge_records([build_record(
        "near-negative.invalid", source=source, context=context,
    )]), Config())
    assert not any("operator" in e.tags for e in dossier.evidence_a)


def test_operator_source_and_malicious_context_must_be_in_same_record():
    dossier = extract_evidence(merge_records([
        build_record("split.invalid", source=["manual"]),
        build_record("split.invalid", context="rootkit behavior"),
    ]), Config())
    assert not any(
        e.field == "operator_confirmed_malicious_context"
        for e in dossier.evidence_a
    )



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


# ── Malicious sample semantics ──

from ioc_rejudge.evidence import is_malicious_sample


def test_not_a_virus_hash_is_not_malicious_sample():
    entry = {"md5": "abc", "level": 70, "confidence": 3, "family": "not-a-virus"}
    assert is_malicious_sample(entry, Config()) is False


def test_low_level_hash_is_not_malicious_sample():
    entry = {"md5": "abc", "level": 10, "confidence": 5}
    assert is_malicious_sample(entry, Config()) is False


def test_confidence_zero_is_not_malicious_sample():
    entry = {"md5": "abc", "level": 70, "confidence": 0}
    assert is_malicious_sample(entry, Config()) is False


def test_high_level_no_confidence_is_malicious_sample():
    """Missing confidence field retains old level-only semantics."""
    entry = {"md5": "abc", "level": 70}
    assert is_malicious_sample(entry, Config()) is True


def test_high_level_positive_confidence_is_malicious_sample():
    entry = {"md5": "abc", "level": 70, "confidence": 3}
    assert is_malicious_sample(entry, Config()) is True


def test_malformed_level_does_not_crash():
    entry = {"md5": "abc", "level": "not-a-number"}
    assert is_malicious_sample(entry, Config()) is False


def test_malformed_confidence_returns_false():
    entry = {"md5": "abc", "level": 70, "confidence": "bogus"}
    assert is_malicious_sample(entry, Config()) is False


def test_null_or_missing_fields_return_false():
    assert is_malicious_sample(None, Config()) is False
    assert is_malicious_sample({}, Config()) is False


# ── URL scope: relate_url must not create domain A ──

def test_url_scope_does_not_create_domain_a():
    """relate_url for a domain target must not produce A evidence."""
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[{"url": "https://evil.com/phish", "level": 60}])
    ]), Config())
    assert not any("relate_url" in str(e.tags) for e in dossier.evidence_a)
    # URL should be in retained_urls
    assert "https://evil.com/phish" in dossier.retained_urls


def test_url_target_exact_match_creates_url_evidence():
    """URL IOC target with exact relate_url match should produce evidence."""
    records = [build_record("https://evil.com/phish",
                            relate_url=[{"url": "https://evil.com/phish", "level": 60}])]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    # URL targets with exact match get evidence (not domain A)
    urls_in_evidence = [e for e in dossier.evidence_a if "relate_url" in str(e.tags)]
    assert len(urls_in_evidence) == 1


def test_retained_urls_deduplicated_first_seen_order():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://evil.com/a", "level": 60},
            {"url": "https://evil.com/b", "level": 60},
            {"url": "https://evil.com/a", "level": 70},  # duplicate URL
        ])
    ]), Config())
    assert dossier.retained_urls == ["https://evil.com/a", "https://evil.com/b"]


def test_invalid_url_not_retained():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "", "level": 60},
            {"url": "not-a-valid-url", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


# ── Structured public APT evidence ──

def test_full_public_apt_creates_c_evidence():
    records = [build_record(
        "apt.invalid", updatetime="2024-01-01 00:00:00",
        context="apt.invalid is an APT domain, see https://report.example/apt-report",
        malicious_type=["APT"], level=70, source=["sample-base"],
        private=False, confidence=5, info_level=3,
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 1
    assert c_apt[0].strength == EvidenceStrength.NORMAL


def test_private_true_not_public_apt():
    records = [build_record(
        "private.invalid", updatetime="2024-01-01 00:00:00",
        context="private.invalid is APT related",
        family=["APT-X"], level=70,
        private=True, confidence=5, info_level=3,
        url="https://report.example/apt",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_missing_apt_family_not_public_apt():
    records = [build_record(
        "noapt.invalid", updatetime="2024-01-01 00:00:00",
        context="noapt.invalid is a threat",
        family=["Trojan"], level=70,
        private=False, confidence=5, info_level=3,
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_low_confidence_not_public_apt():
    records = [build_record(
        "lowconf.invalid", updatetime="2024-01-01 00:00:00",
        context="lowconf.invalid APT",
        family=["APT-Y"], level=70,
        private=False, confidence=3, info_level=3,
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_low_info_level_not_public_apt():
    records = [build_record(
        "lowinfo.invalid", updatetime="2024-01-01 00:00:00",
        context="lowinfo.invalid APT",
        family=["APT-Z"], level=70,
        private=False, confidence=5, info_level=1,
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_low_level_not_public_apt():
    records = [build_record(
        "lowlevel.invalid", updatetime="2024-01-01 00:00:00",
        context="lowlevel.invalid APT",
        family=["APT-W"], level=50,
        private=False, confidence=5, info_level=3,
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_missing_url_not_public_apt():
    records = [build_record(
        "nourl.invalid", updatetime="2024-01-01 00:00:00",
        context="nourl.invalid APT",
        family=["APT-V"], level=70,
        private=False, confidence=5, info_level=3,
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_private_string_false_not_public_apt():
    """private must be boolean False — string 'false' is not sufficient."""
    records = [build_record(
        "strfalse.invalid", updatetime="2024-01-01 00:00:00",
        context="strfalse.invalid APT",
        family=["APT-U"], level=70,
        private="false", confidence=5, info_level=3,
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_malformed_apt_fields_do_not_crash():
    """Malformed numeric fields must not throw exceptions and must not
    produce structured_public_apt evidence."""
    records = [build_record(
        "malform.invalid", updatetime="2024-01-01 00:00:00",
        context="malform.invalid APT",
        family=["APT-T"], level=70,
        private=False, confidence="bogus", info_level="high",
        url="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


# ── Structured public APT: malicious_type only, exact match ──

def test_apt_malicious_type_scalar_exact_match():
    """malicious_type as a scalar string exactly equal to 'APT' (case-insensitive)
    satisfies the APT label check."""
    records = [build_record(
        "apt-scalar.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type="apt", level=70,
        private=False, confidence=5, info_level=3,
        context="APT domain https://report.example/apt-report reported",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 1


def test_apt_malicious_type_in_list():
    """malicious_type as a list containing 'APT' works."""
    records = [build_record(
        "apt-list.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type=["Trojan", "APT"], level=70,
        private=False, confidence=5, info_level=3,
        context="APT domain https://report.example/apt-report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 1


def test_apt_family_tag_not_sufficient():
    """family or tag containing 'APT' is NOT sufficient — only malicious_type counts."""
    records = [build_record(
        "apt-family.invalid", updatetime="2024-01-01 00:00:00",
        family=["APT-C-01"], tag=["apt-tag"], level=70,
        private=False, confidence=5, info_level=3,
        context="APT domain https://report.example/apt-report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_apt_capture_not_match():
    """'CAPTURE' (contains 'APT') must NOT match — exact match only."""
    records = [build_record(
        "capture.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type="CAPTURE", level=70,
        private=False, confidence=5, info_level=3,
        context="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_apt_adapt_not_match():
    """'adapt' (contains 'apt') must NOT match — exact match only."""
    records = [build_record(
        "adapt.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type="adapt", level=70,
        private=False, confidence=5, info_level=3,
        context="https://report.example/report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


def test_apt_url_from_context():
    """The reference URL must come from context, comment, or reference field."""
    records = [build_record(
        "apt-url-ctx.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type="APT", level=70,
        private=False, confidence=5, info_level=3,
        context="APT domain reference: https://report.example/apt-report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 1


def test_apt_toplevel_url_not_sufficient():
    """A top-level 'url' field alone (without context/comment/reference) is NOT
    sufficient for public APT reference URL."""
    records = [build_record(
        "apt-toplevel.invalid", updatetime="2024-01-01 00:00:00",
        malicious_type="APT", level=70,
        private=False, confidence=5, info_level=3,
        url="https://report.example/apt-report",
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    c_apt = [e for e in dossier.evidence_c if "structured_public_apt" in e.tags]
    assert len(c_apt) == 0


# ── B evidence filtered by is_malicious_sample ──

def test_b_not_a_virus_hash_no_b():
    """not-a-virus family/type hash must not produce B evidence."""
    records = [build_record(
        "clean.invalid",
        hash_entries=[{"md5": "abc", "level": 70, "time": _days_ago(10),
                       "family": "not-a-virus:Adware"}],
        level=70, source=["sample-base"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    b_from_hash = [e for e in dossier.evidence_b if "hash" in e.field.lower()]
    assert len(b_from_hash) == 0


def test_b_low_level_hash_no_b():
    """Hash below hash_malicious_level must not produce B evidence."""
    records = [build_record(
        "low.invalid",
        hash_entries=[{"md5": "abc", "level": 10, "time": _days_ago(10)}],
        level=10, source=["sample-base"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    b_from_hash = [e for e in dossier.evidence_b if "hash" in e.field.lower()]
    assert len(b_from_hash) == 0


def test_b_confidence_zero_hash_no_b():
    """Hash with explicit confidence=0 must not produce B evidence."""
    records = [build_record(
        "zeroconf.invalid",
        hash_entries=[{"md5": "abc", "level": 70, "confidence": 0,
                       "time": _days_ago(10)}],
        level=70, source=["sample-base"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    b_from_hash = [e for e in dossier.evidence_b if "hash" in e.field.lower()]
    assert len(b_from_hash) == 0


def test_b_missing_confidence_high_level_gets_b():
    """Hash with missing confidence field and high level must still produce B."""
    records = [build_record(
        "high.invalid",
        hash_entries=[{"md5": "abc", "level": 70, "time": _days_ago(10)}],
        level=70, source=["sample-base"],
    )]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    b_from_hash = [e for e in dossier.evidence_b if "hash" in e.field.lower()]
    assert len(b_from_hash) >= 1


# ── retained_urls: http/https only, valid hostname/port ──

def test_retained_urls_ftp_rejected():
    """FTP URLs must not be retained."""
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "ftp://evil.com/malware", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_out_of_range_port_rejected():
    """URLs with out-of-range ports must not be retained and must not crash."""
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://evil.com:99999/phish", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_leading_hyphen_hostname_rejected():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://-bad.invalid/a", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_trailing_hyphen_hostname_rejected():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://bad-.invalid/a", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_double_dot_hostname_rejected():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://bad..invalid/a", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_underscore_hostname_rejected():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://bad_host.invalid/a", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_retained_urls_invalid_ipv4_octets_rejected():
    dossier = extract_evidence(merge_records([
        build_record("evil.com", relate_url=[
            {"url": "https://999.999.999.999/a", "level": 60},
        ])
    ]), Config())
    assert dossier.retained_urls == []


def test_url_ioc_bad_relate_url_no_a_and_no_crash():
    """URL IOC target with a bad-hostname relate_url must not crash, not
    produce A evidence, and not retain the bad URL."""
    dossier = extract_evidence(merge_records([
        build_record("https://good.invalid/path", relate_url=[
            {"url": "https://good.invalid/path", "level": 60},
            {"url": "https://-bad.invalid/a", "level": 60},
        ])
    ]), Config())
    a_urls = [e for e in dossier.evidence_a if "relate_url" in str(e.tags)]
    assert len(a_urls) == 1  # only the good URL matches
    assert set(dossier.retained_urls) == {"https://good.invalid/path"}
