"""Boundary tests for IOC-aware matching, normalization, rules, strength, diagnostics."""
import json
import tempfile
import os
from datetime import datetime, timedelta
from ioc_rejudge.config import Config, load_config
from ioc_rejudge.evidence import extract_evidence, _ioc_aware_match, _indicator_match
from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.normalize import normalize_ioc, merge_records
from ioc_rejudge.models import Conclusion, EvidenceStrength, IocDossier
from ioc_rejudge.rules import load_rules
from ioc_rejudge.cli import run_pipeline_with_diagnostics
from tests.fixtures import build_record, build_hash_entry


def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


# --- IOC-aware matching ---

def test_evil_com_not_match_not_evil_com():
    assert _ioc_aware_match("evil.com", "not-evil.com is different") is False


def test_evil_com_not_match_evil_com_cn():
    assert _ioc_aware_match("evil.com", "evil.com.cn is a different domain") is False


def test_evil_com_matches_subdomain():
    assert _ioc_aware_match("evil.com", "sub.evil.com is a subdomain") is True


def test_evil_com_matches_with_port():
    assert _ioc_aware_match("evil.com", "evil.com:8080 has a port") is True


def test_evil_com_matches_in_url():
    assert _ioc_aware_match("evil.com", "http://evil.com/path") is True


def test_evil_com_matches_in_https_url():
    assert _ioc_aware_match("evil.com", "https://evil.com:443/api") is True


def test_evil_com_case_insensitive():
    assert _ioc_aware_match("Evil.COM", "evil.com is here") is True


def test_evil_com_trailing_dot():
    assert _ioc_aware_match("evil.com.", "evil.com is here") is True


def test_ip_boundary_no_false_positive():
    assert _ioc_aware_match("1.2.3.4", "11.2.3.45 is different") is False


def test_ip_boundary_exact_match():
    assert _ioc_aware_match("1.2.3.4", "connect to 1.2.3.4:8080") is True


def test_ip_boundary_with_port_in_text():
    assert _ioc_aware_match("1.2.3.4", "1.2.3.4:443 is the target") is True


def test_empty_ioc_no_match():
    assert _ioc_aware_match("", "some text") is False


def test_empty_text_no_match():
    assert _ioc_aware_match("evil.com", "") is False


# --- URL normalization ---

def test_normalize_url_http():
    normalized, ioc_type, ports = normalize_ioc("http://evil.com/path")
    assert ioc_type == "url"
    assert "evil.com" in normalized
    assert "/path" in normalized


def test_normalize_url_https_with_port():
    normalized, ioc_type, ports = normalize_ioc("https://evil.com:8443/api")
    assert ioc_type == "url"
    assert "evil.com" in normalized
    assert "8443" in normalized
    assert ports == ["8443"]


def test_normalize_url_preserves_path():
    normalized, ioc_type, ports = normalize_ioc("http://evil.com/a/b/c")
    assert "/a/b/c" in normalized
    assert ioc_type == "url"


def test_normalize_url_and_domain_separate():
    url_norm, url_type, _ = normalize_ioc("http://evil.com/path")
    dom_norm, dom_type, _ = normalize_ioc("evil.com")
    assert url_norm != dom_norm
    assert url_type != dom_type


# --- IP:port normalization ---

def test_normalize_ip_port():
    normalized, ioc_type, ports = normalize_ioc("1.2.3.4:443")
    assert normalized == "1.2.3.4:443"
    assert ioc_type == "ip_port"
    assert ports == ["443"]


def test_normalize_ip_port_separate_from_plain_ip():
    ip_norm, ip_type, _ = normalize_ioc("1.2.3.4")
    ip_port_norm, ip_port_type, _ = normalize_ioc("1.2.3.4:443")
    assert ip_norm != ip_port_norm
    assert ip_type != ip_port_type


def test_normalize_domain_port_in_value():
    normalized, ioc_type, ports = normalize_ioc("example.com:8080")
    assert normalized == "example.com:8080"
    assert ioc_type == "domain_port"
    assert ports == ["8080"]


# --- Custom rules affect evidence ---

def test_custom_strong_source_affects_a():
    """Custom rules adding a strong source should affect A evidence."""
    rules_data = {"strong_sources": ["my-custom-source"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [
        build_record(
            "evil.com",
            context="Sample evil.com connected",
            source=["my-custom-source"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert any(e.strength == EvidenceStrength.STRONG for e in dossier.evidence_a)


def test_custom_context_malicious_indicator_affects_a():
    """Custom context_comment_malicious_indicators should affect A evidence."""
    rules_data = {"context_comment_malicious_indicators": ["custom-threat"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [
        build_record(
            "evil.com",
            context="evil.com is a custom-threat actor",
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert len(dossier.evidence_a) > 0


def test_custom_historical_indicator_affects_c():
    """Custom historical indicators should affect C evidence."""
    rules_data = {"context_comment_historical_indicators": ["曾经的威胁"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [
        build_record(
            "evil.com",
            context="evil.com 曾经的威胁 样本通信",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time="2022-01-01 00:00:00")],
            family=["SilverFox"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert len(dossier.evidence_c) > 0


def test_custom_trusted_business_fields_drive_strong_e():
    """trusted_business_fields should control which fields form strong E."""
    rules_data = {"trusted_business_fields": ["icp_website", "page_title"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [
        build_record(
            "business.com",
            icp_website="https://business.com",
            page_title="Business Portal",
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert any(e.field == "page_title" and e.strength == EvidenceStrength.STRONG for e in dossier.evidence_e)


def test_review_indicators_add_review_tag_to_evidence():
    """review_indicators should mark related evidence for analyst review."""
    rules_data = {"review_indicators": ["shared-hosting"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [build_record("shared.com", tag=["shared-hosting"])]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert any("review_indicator" in e.tags for e in dossier.evidence_d)


def test_weak_source_does_not_support_source_a():
    """weak_sources should not independently support A evidence."""
    rules_data = {
        "strong_sources": ["weak-feed"],
        "weak_sources": ["weak-feed"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)

    records = [
        build_record(
            "weak-source.com",
            context="weak-source.com observed in connection logs",
            source=["weak-feed"],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    assert not any(e.field.startswith("source[") for e in dossier.evidence_a)


# --- Evidence strength drives conflict ---

def test_strong_a_strong_e_conflict():
    """Non-DGA ICP should outrank the strong A/E conflict candidate."""
    records = [
        build_record(
            "conflict.com",
            context="Sample connected to conflict.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            official_website="https://www.normal-business.com",
            icp_website="https://www.normal-business.com",
            level=70,
        )
    ]
    cfg = Config()
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, cfg)
    verdict = adjudicate(dossier, cfg)
    assert verdict.conclusion == Conclusion.PENDING_REVIEW
    assert verdict.candidate_label is None
    assert verdict.disposition == "review"
    assert "ICP" in verdict.reason


def test_weak_e_strong_a_no_overturn():
    """Weak E with strong A should not overturn A; confidence drops to 中."""
    records = [
        build_record(
            "real-evil.com",
            context="Sample connected to real-evil.com C2",
            source=["sample-base"],
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            official_website="https://www.normal-business.com",
            level=70,
        )
    ]
    cfg = Config()
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, cfg)
    verdict = adjudicate(dossier, cfg)
    assert verdict.conclusion == Conclusion.ALIVE_VALID
    assert verdict.confidence == "中"
    assert verdict.review_suggestion == "抽检"


# --- Diagnostics ---

def test_diagnostics_json_counts():
    """Diagnostics should include parse/skipped/missing/empty/no-IOC counts."""
    lines = [
        {"ioc": "test.com", "data": [{"key": "test.com", "level": 70}]},
        {"ioc": "no-data.com"},  # missing data
        {"ioc": "empty.com", "data": []},  # empty data
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
        f.flush()
        result = run_pipeline_with_diagnostics(f.name, Config())
        diag = result.diagnostics
        assert diag.processed_count == 1
        assert diag.missing_data_count == 1
        assert diag.empty_data_count == 1
        assert diag.skipped_total == 2
    os.unlink(f.name)


def test_diagnostics_parse_error_samples_are_bounded():
    """Parse error diagnostics should include bounded invalid-line samples."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        f.write(json.dumps({"ioc": "ok.com", "data": [{"key": "ok.com"}]}, ensure_ascii=False) + "\n")
        for i in range(25):
            f.write(f"bad json line {i}\n")
        f.flush()
        result = run_pipeline_with_diagnostics(f.name, Config())
        diag = result.diagnostics
        assert diag.parse_error_count == 25
        assert len(diag.parse_error_samples) == 20
        assert diag.parse_error_samples[0].startswith("line 2:")
        assert "bad json line 0" in diag.parse_error_samples[0]
    os.unlink(f.name)


def test_diagnostics_json_structure():
    """Diagnostics JSON should have required fields."""
    from ioc_rejudge.cli import Diagnostics, export_diagnostics
    diag = Diagnostics(
        input_path="test.jsonl",
        processed_count=10,
        parse_error_count=1,
        missing_data_count=2,
        empty_data_count=0,
        non_list_data_count=0,
        no_ioc_count=1,
        skipped_total=4,
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        export_diagnostics(diag, f.name)
        with open(f.name, encoding="utf-8") as rf:
            data = json.load(rf)
        assert data["input_path"] == "test.jsonl"
        assert data["processed_count"] == 10
        assert data["parse_error_count"] == 1
        assert data["skipped_total"] == 4
        assert "parse_error_samples" in data
        assert "skipped_row_samples" in data
    os.unlink(f.name)


# --- Fix weak test: hash-without-IOC A evidence ---

def test_hash_without_ioc_not_a_level():
    """Hash without IOC in context should not produce A evidence."""
    records = [
        build_record(
            "innocent.com",
            context="Malware found on system but no IOC reference",
            hash_entries=[build_hash_entry("abc", level=70, time=_days_ago(30))],
            level=70,
        )
    ]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, Config())
    a_evidence = [e for e in dossier.evidence_a if "hash" in e.field.lower()]
    assert len(a_evidence) == 0, f"Hash without IOC context should not be A-level: {a_evidence}"


# --- Existing tests still pass (regression) ---

# ── Shared helper ──

def _ctx_dossier(context: str, level: float = 0.0) -> IocDossier:
    records = [build_record("evil.com", context=context, level=level)]
    return extract_evidence(merge_records(records), Config())


# ── Token-aware English word boundaries ──

def test_rat_does_not_match_rate1():
    """`rat` must match only as a complete English token, not inside `rate1`."""
    dossier = _ctx_dossier("evil.com observed rate1:9e-05 rate2:7e-05")
    assert not any(e.field == "context/comment" for e in dossier.evidence_a)


def test_c2_does_not_match_hash_fragment():
    """`c2` must not match inside hexadecimal hash fragments like ...157c2ab..."""
    dossier = _ctx_dossier("evil.com sha1=aaaa157c2abbbb")
    assert not any(e.field == "context/comment" for e in dossier.evidence_a)


def test_rat_matches_with_punctuation_boundary():
    """`rat` must match when adjacent to punctuation or whitespace."""
    dossier = _ctx_dossier(
        "evil.com is a RAT with (backdoor)", level=70
    )
    a_ctx = [e for e in dossier.evidence_a if e.field == "context/comment"]
    assert len(a_ctx) >= 1


def test_c2_matches_with_punctuation_boundary():
    """`c2` with surrounding punctuation must still match."""
    dossier = _ctx_dossier("evil.com used as C2-server", level=70)
    a_ctx = [e for e in dossier.evidence_a if e.field == "context/comment"]
    assert len(a_ctx) >= 1


def test_chinese_malicious_indicator_still_works():
    """Chinese indicators must still use contains matching (no token boundary)."""
    dossier = _ctx_dossier("evil.com 恶意样本通信", level=70)
    a_ctx = [e for e in dossier.evidence_a if e.field == "context/comment"]
    assert len(a_ctx) >= 1


def test_regex_special_indicator_does_not_break_matching():
    """Indicators with regex-special characters must be safely escaped."""
    # Use a custom config with a special-char indicator
    import json, tempfile, os
    rules_data = {"context_comment_malicious_indicators": ["evil.com"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(rules_data, f)
        f.flush()
        config = load_config(rules_path=f.name)
    os.unlink(f.name)
    records = [build_record("evil.com", context="evil.com callback detected", level=70)]
    dossier = merge_records(records)
    dossier = extract_evidence(dossier, config)
    a_ctx = [e for e in dossier.evidence_a if e.field == "context/comment"]
    assert len(a_ctx) >= 1


def test_empty_indicator_never_matches():
    """An empty-string indicator must never trigger a match."""
    assert _indicator_match("", "any text rat") is False
    assert _indicator_match("", "") is False


def test_indicator_uppercase_matches_lowercase_text():
    """Indicators are internally lowercased before matching so 'RAT' matches 'rat'."""
    assert _indicator_match("RAT", "evil.com observed as rat callback") is True
    assert _indicator_match("C2", "evil.com used as c2-server") is True

def test_parser_regression():
    """Parser should still handle JSONL correctly."""
    from ioc_rejudge.parser import read_jsonl_snapshot
    lines = [
        {"ioc": "test.com", "data": [{"key": "test.com", "level": 70}]},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 0
    os.unlink(f.name)
