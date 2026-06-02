import json
import tempfile
import os
from ioc_rejudge.parser import read_jsonl_snapshot


def test_read_valid_jsonl():
    lines = [
        {"ioc": "test.com", "data": [{"key": "test.com", "level": 70}]},
        {"ioc": "evil.com", "data": [{"key": "evil.com", "level": 80}]},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 2
        assert skipped == 0
        assert result[0]["ioc"] == "test.com"
        assert result[1]["ioc"] == "evil.com"
    os.unlink(f.name)


def test_read_jsonl_with_prefix_text():
    content = 'some prefix text\n{"ioc": "test.com", "data": [{"key": "test.com"}]}\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        f.write(content)
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 1
        assert result[0]["ioc"] == "test.com"
    os.unlink(f.name)


def test_read_jsonl_missing_file():
    try:
        read_jsonl_snapshot("/nonexistent/path/file.jsonl")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError:
        pass


def test_read_jsonl_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        f.write("")
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert result == []
        assert skipped == 0
    os.unlink(f.name)


def test_read_jsonl_missing_fields_no_error():
    lines = [
        {"ioc": "test.com", "data": [{"key": "test.com"}]},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 0
        assert result[0]["ioc"] == "test.com"
        rec = result[0]["data"][0]
        assert rec.get("level") is None
    os.unlink(f.name)


def test_read_jsonl_malformed_line_among_valid():
    content = 'garbage line\n{"ioc": "good.com", "data": [{"key": "good.com"}]}\nanother garbage\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        f.write(content)
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 2
        assert result[0]["ioc"] == "good.com"
    os.unlink(f.name)


def test_read_jsonl_regex_fallback_invalid_json():
    content = '{not valid json at all}\n{"ioc": "ok.com", "data": [{"key": "ok.com"}]}\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
        f.write(content)
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 1
    os.unlink(f.name)


def test_read_jsonl_gbk_encoded_file():
    gbk_content = json.dumps({"ioc": "测试.com", "data": [{"key": "测试.com", "level": 70}]}, ensure_ascii=False)
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".jsonl", delete=False) as f:
        f.write((gbk_content + "\n").encode("gbk"))
        f.flush()
        result, skipped = read_jsonl_snapshot(f.name)
        assert len(result) == 1
        assert skipped == 0
    os.unlink(f.name)
