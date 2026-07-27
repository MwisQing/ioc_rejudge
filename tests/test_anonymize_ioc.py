import json
from pathlib import Path

import pytest
from ioc_rejudge import anonymize_ioc


def load_anonymizer():
    return anonymize_ioc


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_cli_writes_valid_jsonl_and_minimally_redacts_sensitive_values(tmp_path):
    module = load_anonymizer()
    raw_hash = "0123456789abcdef0123456789abcdef"
    input_rows = [
        {
            "ioc": "evil.example.com",
            "data": [
                {
                    "key": "evil.example.com",
                    "host": "evil.example.com",
                    "level": 70,
                    "source": ["sample-base"],
                    "family": ["SilverFox"],
                    "url": "http://evil.example.com/a/b?token=abc",
                    "response_url": "https://evil.example.com/login?x=1",
                    "resolv_ip": "8.8.8.8|1.2.3.4",
                    "submitter": "张三",
                    "api_token": "super-secret",
                    "hash": [{"md5": raw_hash, "level": 70, "time": "2026-01-02 03:04:05"}],
                    "comment": "张三 checked evil.example.com from 8.8.8.8 with admin@example.com and 0123456789abcdef0123456789abcdef",
                }
            ],
        },
        {
            "ioc": "http://evil.example.com/a/b?token=abc",
            "data": [
                {
                    "key": "1.2.3.4",
                    "ip": "1.2.3.4",
                    "processed": "张三",
                    "authorization": "Bearer secret",
                    "context": "same domain evil.example.com and same ip 1.2.3.4",
                }
            ],
        },
    ]
    input_path = tmp_path / "cache.jsonl"
    output_path = tmp_path / "cache_anonymized.jsonl"
    names_path = tmp_path / "names.txt"
    input_path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in input_rows) + "\n",
        encoding="utf-8",
    )
    names_path.write_text("张三\n", encoding="utf-8")

    assert module.main(["-i", str(input_path), "-o", str(output_path), "--names-file", str(names_path)]) == 0

    rows = read_jsonl(output_path)
    assert len(rows) == 2
    first_record = rows[0]["data"][0]
    assert set(first_record.keys()) == set(input_rows[0]["data"][0].keys())
    assert first_record["level"] == 70
    assert first_record["source"] == ["sample-base"]
    assert first_record["family"] == ["SilverFox"]
    assert first_record["api_token"] == "[REDACTED]"
    assert rows[1]["data"][0]["authorization"] == "[REDACTED]"
    assert first_record["submitter"] == "PERSON_0001"
    assert rows[1]["data"][0]["processed"] == "PERSON_0001"
    assert first_record["hash"][0]["level"] == 70
    assert first_record["hash"][0]["time"] == "2026-01-02 03:04:05"
    assert len(first_record["hash"][0]["md5"]) == 32
    int(first_record["hash"][0]["md5"], 16)

    output_text = output_path.read_text(encoding="utf-8")
    for sensitive in [
        "evil.example.com",
        "8.8.8.8",
        "1.2.3.4",
        raw_hash,
        "admin@example.com",
        "张三",
        "super-secret",
        "Bearer secret",
        "/a/b",
        "token=abc",
    ]:
        assert sensitive not in output_text

    assert rows[0]["ioc"] in rows[0]["data"][0]["key"]
    assert rows[0]["ioc"] in rows[0]["data"][0]["host"]
    assert rows[0]["ioc"] in rows[1]["data"][0]["context"]


def test_pretty_json_array_outputs_one_json_object_per_line(tmp_path):
    module = load_anonymizer()
    input_path = tmp_path / "pretty.json"
    output_path = tmp_path / "out.jsonl"
    input_path.write_text(
        json.dumps(
            [
                {"ioc": "one.example.net", "data": [{"key": "one.example.net"}]},
                {"ioc": "two.example.net", "data": [{"key": "two.example.net"}]},
            ],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    assert module.main(["-i", str(input_path), "-o", str(output_path)]) == 0

    rows = read_jsonl(output_path)
    assert len(rows) == 2
    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 2
    assert all(isinstance(row, dict) for row in rows)


def test_refuses_to_overwrite_existing_output_without_force(tmp_path):
    module = load_anonymizer()
    input_path = tmp_path / "cache.jsonl"
    output_path = tmp_path / "cache_anonymized.jsonl"
    input_path.write_text(json.dumps({"ioc": "a.example", "data": [{"key": "a.example"}]}) + "\n", encoding="utf-8")
    output_path.write_text("keep me\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        module.main(["-i", str(input_path), "-o", str(output_path)])

    assert exc.value.code == 1
    assert output_path.read_text(encoding="utf-8") == "keep me\n"
    assert module.main(["-i", str(input_path), "-o", str(output_path), "--force"]) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))
