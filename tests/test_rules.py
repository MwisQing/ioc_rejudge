"""Tests for rule configuration loading."""
import json
import tempfile
import os
import pytest
from ioc_rejudge.rules import load_rules, RuleConfig


def test_load_rules_default():
    rules = load_rules()
    assert "sample-base" in rules.strong_sources
    assert "sample" in rules.malicious_indicators
    assert "historical" in rules.context_comment_historical_indicators
    assert "icp_website" in rules.trusted_business_fields
    assert "trojan" in rules.strong_malicious_indicators
    assert "backdoor" in rules.strong_malicious_indicators
    # neutral words belong to the broad list, not the strong list
    assert "dns" in rules.malicious_indicators
    assert "dns" not in rules.strong_malicious_indicators
    assert "sample" not in rules.strong_malicious_indicators
    assert rules.authoritative_clue_indicators == ["线索群"]
    assert rules.authoritative_context_indicators == ["黑产", "扩展", "扩线"]
    assert "恶意" in rules.context_comment_malicious_indicators
    assert rules.operator_sources == ["manual", "alliocs_tpd"]


def test_load_rules_deployment_defaults_match_builtin():
    rules = load_rules("rules/default_rules.json")
    assert rules.authoritative_clue_indicators == ["线索群"]
    assert rules.authoritative_context_indicators == ["黑产", "扩展", "扩线"]
    assert "恶意" in rules.context_comment_malicious_indicators
    assert rules.operator_sources == ["manual", "alliocs_tpd"]


def test_load_rules_new_fields_override_independently_and_fill_legacy_defaults():
    data = {
        "authoritative_clue_indicators": ["custom-clue"],
        "operator_sources": ["custom-source"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
        f.flush()
        rules = load_rules(f.name)
    os.unlink(f.name)
    assert rules.authoritative_clue_indicators == ["custom-clue"]
    assert rules.operator_sources == ["custom-source"]
    assert "sample" in rules.malicious_indicators


def test_load_rules_list_defaults_are_isolated():
    first = load_rules()
    second = load_rules()
    first.authoritative_clue_indicators.append("changed")
    first.operator_sources.clear()
    assert second.authoritative_clue_indicators == ["线索群"]
    assert second.operator_sources == ["manual", "alliocs_tpd"]


def test_load_rules_strong_indicators_missing_key_filled():
    # A custom JSON without strong_malicious_indicators must fall back to defaults,
    # not raise, so existing rule files stay forward-compatible.
    data = {"malicious_indicators": ["evil"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        rules = load_rules(f.name)
        assert rules.malicious_indicators == ["evil"]
        assert "trojan" in rules.strong_malicious_indicators
    os.unlink(f.name)



def test_load_rules_custom_json():
    data = {
        "strong_sources": ["custom-source"],
        "malicious_indicators": ["evil"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        rules = load_rules(f.name)
        assert rules.strong_sources == ["custom-source"]
        assert rules.malicious_indicators == ["evil"]
        # Missing keys filled from defaults
        assert "historical" in rules.context_comment_historical_indicators
    os.unlink(f.name)


def test_load_rules_malformed_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write("{bad json}")
        f.flush()
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_rules(f.name)
    os.unlink(f.name)


def test_load_rules_invalid_field_type():
    data = {"strong_sources": "not-a-list"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        with pytest.raises(ValueError, match="must be a list"):
            load_rules(f.name)
    os.unlink(f.name)


def test_load_rules_invalid_item_type():
    data = {"strong_sources": [123]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        with pytest.raises(ValueError, match="must contain only strings"):
            load_rules(f.name)
    os.unlink(f.name)


def test_load_rules_unknown_field():
    data = {"unknown_field": ["value"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        with pytest.raises(ValueError, match="Unknown rule field"):
            load_rules(f.name)
    os.unlink(f.name)


def test_load_rules_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_rules("/nonexistent/rules.json")
