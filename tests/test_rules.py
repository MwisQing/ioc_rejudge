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
