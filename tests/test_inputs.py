"""Input contract tests for bare IOC, inline IOC, and legacy snapshot parsing."""
import json
import tempfile
import os

from ioc_rejudge.inputs import InputKind, InputBundle, read_input_bundle


# --- Bare IOC file ---

def test_reads_bare_ioc_file_and_preserves_order(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("# comment\nExample.INVALID\nhttps://Example.INVALID/a\nExample.INVALID\n", encoding="utf-8")
    bundle = read_input_bundle(str(path), inline_iocs=["10.0.0.1:443"])
    assert bundle.kind == InputKind.IOC_LIST
    assert [target.normalized for target in bundle.targets] == [
        "example.invalid", "example.invalid/a", "10.0.0.1:443",
    ]


def test_bare_ioc_file_domain_normalization(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("Evil.COM.\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.IOC_LIST
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "evil.com"
    assert bundle.targets[0].original == "Evil.COM."
    assert bundle.targets[0].ioc_type == "domain"


def test_bare_ioc_file_ip_address(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("1.2.3.4\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "1.2.3.4"
    assert bundle.targets[0].ioc_type == "ip"


def test_bare_ioc_file_ip_port(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("1.2.3.4:443\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "1.2.3.4:443"
    assert bundle.targets[0].ioc_type == "ip_port"
    assert bundle.targets[0].ports == ("443",)


def test_bare_ioc_file_domain_port(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("example.invalid:8080\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "example.invalid:8080"
    assert bundle.targets[0].ioc_type == "domain_port"


def test_bare_ioc_file_url_with_port(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("https://example.invalid:8443/b\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    target = bundle.targets[0]
    assert target.ioc_type == "url"
    assert "8443" in target.normalized
    assert target.ports == ("8443",)


def test_domain_and_url_are_different_targets(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("example.invalid\nhttps://example.invalid/path\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 2
    assert bundle.targets[0].normalized == "example.invalid"
    assert bundle.targets[1].normalized == "example.invalid/path"


def test_ip_and_ip_port_are_different_targets(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("1.2.3.4\n1.2.3.4:443\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 2
    assert bundle.targets[0].normalized == "1.2.3.4"
    assert bundle.targets[1].normalized == "1.2.3.4:443"


# --- Deduplication ---

def test_duplicate_normalized_values_keep_first_occurrence(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("Example.INVALID\nexample.invalid\nEXAMPLE.INVALID\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].original == "Example.INVALID"


def test_file_values_before_inline_values(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("file-first.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path), inline_iocs=["file-first.invalid", "inline-only.invalid"])
    assert len(bundle.targets) == 2
    assert bundle.targets[0].normalized == "file-first.invalid"
    assert bundle.targets[1].normalized == "inline-only.invalid"


# --- Comments and empty lines ---

def test_comments_and_empty_lines_are_ignored(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("# this is a comment\n\n# another comment\n  \nevil.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "evil.invalid"


def test_only_comments_returns_empty_targets(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("# comment only\n# another\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.IOC_LIST
    assert bundle.targets == []


def test_empty_file_returns_empty_targets(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.IOC_LIST
    assert bundle.targets == []
    assert bundle.errors == []


# --- Invalid IOCs ---

def test_invalid_ioc_is_reported_not_silently_converted(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("not a valid host\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "invalid IOC" in bundle.errors[0]
    assert "not a valid host" in bundle.errors[0]


def test_multiple_invalid_lines_all_reported(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("invalid one\nvalid.invalid\ninvalid two\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "valid.invalid"
    assert len(bundle.errors) == 2


def test_leading_hyphen_domain_is_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("-bad.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "-bad.invalid" in bundle.errors[0]


def test_double_dot_domain_is_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("bad..invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "bad..invalid" in bundle.errors[0]


def test_trailing_hyphen_label_is_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("bad-.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "bad-.invalid" in bundle.errors[0]


def test_invalid_ip_octets_are_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("999.999.999.999\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "999.999.999.999" in bundle.errors[0]


def test_ip_port_with_out_of_range_port_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("1.2.3.4:99999\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "1.2.3.4:99999" in bundle.errors[0]


def test_domain_port_with_zero_port_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("evil.invalid:0\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1
    assert "evil.invalid:0" in bundle.errors[0]


def test_malformed_url_empty_host_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("http://\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1


def test_malformed_url_bad_host_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("https://-bad.invalid/path\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1


def test_url_with_out_of_range_port_rejected(tmp_path):
    path = tmp_path / "iocs.txt"
    path.write_text("http://evil.invalid:99999/\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1


def test_not_a_host_with_underscore_rejected(tmp_path):
    """Underscore is not valid in hostnames — reject as invalid IOC."""
    path = tmp_path / "iocs.txt"
    path.write_text("not_a_host.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.targets == []
    assert len(bundle.errors) == 1


# --- Legacy snapshot ---

def test_reads_legacy_snapshot(tmp_path):
    path = tmp_path / "snapshot.jsonl"
    path.write_text(json.dumps({"ioc": "example.invalid", "data": [{"key": "example.invalid"}]}) + "\n")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.SNAPSHOT
    assert len(bundle.snapshots) == 1
    assert bundle.snapshots[0]["ioc"] == "example.invalid"


def test_legacy_snapshot_preserves_records(tmp_path):
    path = tmp_path / "snapshot.jsonl"
    records = [
        {"ioc": "a.invalid", "data": [{"key": "a.invalid", "level": 70}]},
        {"ioc": "b.invalid", "data": [{"key": "b.invalid", "level": 50}]},
    ]
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.SNAPSHOT
    assert len(bundle.snapshots) == 2
    assert [s["ioc"] for s in bundle.snapshots] == ["a.invalid", "b.invalid"]


def test_legacy_snapshot_with_parse_errors(tmp_path):
    path = tmp_path / "snapshot.jsonl"
    path.write_text(
        json.dumps({"ioc": "ok.invalid", "data": [{"key": "ok.invalid"}]}) + "\n"
        "not valid json\n"
        + json.dumps({"ioc": "also-ok.invalid", "data": [{"key": "also-ok.invalid"}]}) + "\n",
        encoding="utf-8",
    )
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.SNAPSHOT
    assert len(bundle.snapshots) == 2
    assert len(bundle.errors) >= 1


def test_snapshot_detection_not_fooled_by_bare_json_object(tmp_path):
    """A bare JSON object without ioc+data keys should not be treated as a snapshot."""
    path = tmp_path / "not_snapshot.txt"
    path.write_text('{"some": "json", "value": 1}\n', encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.IOC_LIST


def test_snapshot_detection_not_fooled_by_curly_brace_in_text(tmp_path):
    """A line containing { but not valid JSON with ioc+data should not trigger snapshot mode."""
    path = tmp_path / "log.txt"
    path.write_text("{some log prefix} evil.invalid\n", encoding="utf-8")
    bundle = read_input_bundle(str(path))
    assert bundle.kind == InputKind.IOC_LIST


# --- Inline only ---

def test_inline_only_no_file(tmp_path):
    bundle = read_input_bundle(None, inline_iocs=["evil.invalid", "1.2.3.4"])
    assert bundle.kind == InputKind.IOC_LIST
    assert len(bundle.targets) == 2
    assert bundle.targets[0].normalized == "evil.invalid"
    assert bundle.targets[1].normalized == "1.2.3.4"


def test_inline_dedup_within_itself(tmp_path):
    bundle = read_input_bundle(None, inline_iocs=["dup.invalid", "dup.invalid", "unique.invalid"])
    assert len(bundle.targets) == 2
    assert bundle.targets[0].original == "dup.invalid"
    assert bundle.targets[1].original == "unique.invalid"


def test_no_path_and_no_inline_returns_empty_bundle():
    bundle = read_input_bundle(None)
    assert bundle.kind == InputKind.IOC_LIST
    assert bundle.targets == []
    assert bundle.snapshots == []
    assert bundle.errors == []


# --- Encoding ---

def test_utf8_sig_encoding(tmp_path):
    path = tmp_path / "bom.txt"
    path.write_bytes(b"\xef\xbb\xbfevil.invalid\n")
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "evil.invalid"


def test_gbk_encoding(tmp_path):
    path = tmp_path / "gbk.txt"
    # "测试.invalid" in GBK
    path.write_bytes("evil.invalid\n".encode("gbk"))
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "evil.invalid"


def test_gbk_with_chinese_comments(tmp_path):
    """GBK-encoded file with Chinese characters in comments must decode and
    skip comment lines correctly, extracting only the IOC value."""
    path = tmp_path / "gbk_cn.txt"
    content = "# 这是中文注释\nevil.invalid\n# 另一行注释\n".encode("gbk")
    path.write_bytes(content)
    bundle = read_input_bundle(str(path))
    assert len(bundle.targets) == 1
    assert bundle.targets[0].normalized == "evil.invalid"


# --- Undecodable file ---

def test_undecodable_file_raises_value_error(tmp_path):
    path = tmp_path / "binary.bin"
    path.write_bytes(b"\x80\x81\x82\x83")
    try:
        read_input_bundle(str(path))
        assert False, "Expected ValueError"
    except ValueError as e:
        assert "Cannot decode" in str(e)


# --- InputBundle structure ---

def test_input_bundle_defaults():
    bundle = InputBundle(kind=InputKind.IOC_LIST)
    assert bundle.kind == InputKind.IOC_LIST
    assert bundle.targets == []
    assert bundle.snapshots == []
    assert bundle.errors == []


def test_input_kind_values():
    assert InputKind.IOC_LIST.value == "ioc_list"
    assert InputKind.SNAPSHOT.value == "snapshot"
