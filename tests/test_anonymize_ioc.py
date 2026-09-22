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
            "ioc": "evil.example.invalid",
            "data": [
                {
                    "key": "evil.example.invalid",
                    "host": "evil.example.invalid",
                    "level": 70,
                    "source": ["sample-base"],
                    "family": ["SilverFox"],
                    "url": "http://evil.example.invalid/a/b?token=abc",
                    "response_url": "https://evil.example.invalid/login?x=1",
                    "resolv_ip": "10.8.8.8|10.1.2.3",
                    "submitter": "张三",
                    "api_token": "super-secret",
                    "hash": [{"md5": raw_hash, "level": 70, "time": "2026-01-02 03:04:05"}],
                    "comment": "张三 checked evil.example.invalid from 10.8.8.8 with admin@example.invalid and 0123456789abcdef0123456789abcdef",
                }
            ],
        },
        {
            "ioc": "http://evil.example.invalid/a/b?token=abc",
            "data": [
                {
                    "key": "10.1.2.3",
                    "ip": "10.1.2.3",
                    "processed": "张三",
                    "authorization": "Bearer secret",
                    "context": "same domain evil.example.invalid and same ip 10.1.2.3",
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
        "evil.example.invalid",
        "10.8.8.8",
        "10.1.2.3",
        raw_hash,
        "admin@example.invalid",
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


def test_share_bundle_round_trips_identity_values_and_redacts_credentials(tmp_path):
    from ioc_rejudge.share import create_bundle, restore_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    manifest = tmp_path / "shared.manifest.json"
    original = {
        "ioc": "evil.example.invalid",
        "data": [{
            "url": "https://alice:secret-password@evil.example.invalid/login?token=secret-value",
            "ip": "10.8.8.8",
            "md5": "0123456789abcdef0123456789abcdef",
            "ioc_hash": "0123456789abcdef",
            "submitter": "张三",
            "comment": (
                "evil.example.invalid contacted 10.8.8.8 from C:\\Users\\张三\\x.exe "
                "phone 13900000000 id 00000019000101000X"
            ),
            "api_token": "secret-value",
        }],
    }
    source.write_text(json.dumps(original, ensure_ascii=False) + "\n", encoding="utf-8")

    result = create_bundle(
        source,
        shared,
        key,
        manifest_path=manifest,
        generate_key=True,
        passphrase="test-passphrase",
    )
    assert result["rows"] == 1
    assert result["output_findings"] == 0
    assert "input_sha256" not in result
    assert len(result["manifest_mac"]) == 64
    assert scan_bundle(shared)["finding_count"] == 0
    shared_text = shared.read_text(encoding="utf-8")
    assert "evil.example.invalid" not in shared_text
    assert "10.8.8.8" not in shared_text
    assert "0123456789abcdef" not in shared_text
    assert "secret-value" not in shared_text
    assert "secret-password" not in shared_text
    assert "13900000000" not in shared_text
    assert "00000019000101000X" not in shared_text
    assert "[REDACTED]" in shared_text

    assert restore_bundle(
        shared,
        restored,
        key,
        manifest_path=manifest,
        passphrase="test-passphrase",
    ) == 1
    restored_row = json.loads(restored.read_text(encoding="utf-8"))
    assert restored_row["ioc"] == original["ioc"]
    assert restored_row["data"][0]["ip"] == original["data"][0]["ip"]
    assert restored_row["data"][0]["md5"] == original["data"][0]["md5"]
    assert restored_row["data"][0]["ioc_hash"] == original["data"][0]["ioc_hash"]
    assert restored_row["data"][0]["submitter"] == original["data"][0]["submitter"]
    assert restored_row["data"][0]["api_token"] == "[REDACTED]"
    assert "secret-value" not in restored_row["data"][0]["url"]
    assert "secret-password" not in restored_row["data"][0]["url"]
    assert "13900000000" in restored_row["data"][0]["comment"]
    assert "00000019000101000X" in restored_row["data"][0]["comment"]
    key_data = json.loads(key.read_text(encoding="utf-8"))
    assert "key" not in key_data
    assert "test-passphrase" not in key.read_text(encoding="utf-8")


def test_share_tokens_are_deterministic_within_a_key_and_wrong_key_fails(tmp_path):
    from ioc_rejudge.share import ShareError, create_bundle, restore_bundle

    source = tmp_path / "source.jsonl"
    shared_a = tmp_path / "shared-a.jsonl"
    shared_b = tmp_path / "shared-b.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    wrong_key = tmp_path / "wrong-key.json"
    source.write_text(
        json.dumps({"ioc": "same.example.invalid", "context": "same.example.invalid and same.example.invalid"}) + "\n",
        encoding="utf-8",
    )

    create_bundle(
        source,
        shared_a,
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    create_bundle(source, shared_b, key, passphrase="test-passphrase")
    assert shared_a.read_bytes() == shared_b.read_bytes()
    create_bundle(
        source,
        tmp_path / "unused.jsonl",
        wrong_key,
        generate_key=True,
        passphrase="wrong-passphrase",
    )
    with pytest.raises(ShareError):
        restore_bundle(
            shared_a,
            restored,
            wrong_key,
            passphrase="wrong-passphrase",
        )

    with pytest.raises(ShareError):
        restore_bundle(
            shared_a,
            restored,
            key,
            passphrase="incorrect-passphrase",
        )


def test_cloud_response_requires_bundle_id_and_authentic_tokens(tmp_path):
    from ioc_rejudge.share import ShareError, create_bundle, restore_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    response = tmp_path / "response.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    manifest_path = tmp_path / "manifest.json"
    source.write_text(json.dumps({"ioc": "review.example.invalid"}) + "\n", encoding="utf-8")
    manifest = create_bundle(
        source,
        shared,
        key,
        manifest_path=manifest_path,
        generate_key=True,
        passphrase="test-passphrase",
    )
    token = json.loads(shared.read_text(encoding="utf-8"))["ioc"]

    response.write_text(
        json.dumps({
            "bundle_id": manifest["bundle_id"],
            "case": {"ioc": token, "proposed_label": "review"},
        }) + "\n",
        encoding="utf-8",
    )
    assert restore_bundle(
        response,
        restored,
        key,
        manifest_path=manifest_path,
        passphrase="test-passphrase",
    ) == 1
    assert json.loads(restored.read_text(encoding="utf-8"))["case"]["ioc"] == "review.example.invalid"

    response.write_text(json.dumps({"case": {"ioc": token}}) + "\n", encoding="utf-8")
    with pytest.raises(ShareError, match="bundle_id"):
        restore_bundle(
            response,
            restored,
            key,
            manifest_path=manifest_path,
            passphrase="test-passphrase",
            force=True,
        )

    replacement = "A" if token[-1] != "A" else "B"
    response.write_text(
        json.dumps({"bundle_id": manifest["bundle_id"], "ioc": token[:-1] + replacement}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ShareError, match="authentication"):
        restore_bundle(
            response,
            restored,
            key,
            manifest_path=manifest_path,
            passphrase="test-passphrase",
            force=True,
        )


def test_manifest_is_authenticated_with_the_local_key(tmp_path):
    from ioc_rejudge.share import ShareError, create_bundle, restore_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    manifest_path = tmp_path / "manifest.json"
    source.write_text(json.dumps({"ioc": "manifest.example.invalid"}) + "\n", encoding="utf-8")
    create_bundle(
        source,
        shared,
        key,
        manifest_path=manifest_path,
        generate_key=True,
        passphrase="test-passphrase",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rows"] = 2
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with pytest.raises(ShareError, match="authentication"):
        restore_bundle(
            shared,
            restored,
            key,
            manifest_path=manifest_path,
            passphrase="test-passphrase",
        )


def test_share_handles_ipv6_uuid_numeric_identity_and_nested_credentials(tmp_path):
    from ioc_rejudge.share import create_bundle, restore_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    original = {
        "ioc": "2001:db8::7",
        "user_id": 13900000000,
        "employee_id": 42.5,
        "analyst": "Alice Example",
        "上传人": "李四",
        "cmdline": "curl Authorization: Bearer cmd-secret https://example.invalid",
        "metadata": {
            "authorization": {"bearer": "never-upload-this"},
            "note": (
                "host 2001:db8::7 case 550e8400-e29b-41d4-a716-446655440000 "
                f"sha512 {'a' * 128} domain test.xn--invalid.invalid"
            ),
        },
        "mapping": {
            "https://alice:password@example.invalid/a?api_key=secret&case=1": "evidence"
        },
    }
    source.write_text(json.dumps(original) + "\n", encoding="utf-8")

    create_bundle(
        source,
        shared,
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    shared_text = shared.read_text(encoding="utf-8")
    assert "2001:db8::7" not in shared_text
    assert "550e8400-e29b-41d4-a716-446655440000" not in shared_text
    assert "Alice Example" not in shared_text
    assert "李四" not in shared_text
    assert "test.xn--invalid.invalid" not in shared_text
    assert "a" * 128 not in shared_text
    assert "never-upload-this" not in shared_text
    assert "cmd-secret" not in shared_text
    assert "alice:password" not in shared_text
    assert "api_key=secret" not in shared_text
    assert scan_bundle(shared)["finding_count"] == 0

    restore_bundle(shared, restored, key, passphrase="test-passphrase")
    restored_row = json.loads(restored.read_text(encoding="utf-8"))
    assert restored_row["ioc"] == original["ioc"]
    assert restored_row["user_id"] == original["user_id"]
    assert restored_row["employee_id"] == original["employee_id"]
    assert restored_row["analyst"] == original["analyst"]
    assert restored_row["上传人"] == original["上传人"]
    assert restored_row["metadata"]["authorization"] == "[REDACTED]"
    assert "cmd-secret" not in restored_row["cmdline"]
    assert "[REDACTED]" in restored_row["cmdline"]
    assert original["metadata"]["note"] == restored_row["metadata"]["note"]
    restored_url = next(iter(restored_row["mapping"]))
    assert "alice:password" not in restored_url
    assert "api_key=%5BREDACTED%5D" in restored_url


def test_restore_rejects_keys_that_collide_after_token_restoration(tmp_path):
    from ioc_rejudge.share import ShareError, create_bundle, restore_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    response = tmp_path / "response.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    manifest_path = tmp_path / "manifest.json"
    source.write_text(
        json.dumps({"mapping": {"collision.example.invalid": "original"}}) + "\n",
        encoding="utf-8",
    )
    manifest = create_bundle(
        source,
        shared,
        key,
        manifest_path=manifest_path,
        generate_key=True,
        passphrase="test-passphrase",
    )
    token = next(iter(json.loads(shared.read_text(encoding="utf-8"))["mapping"]))
    response.write_text(
        json.dumps({
            "bundle_id": manifest["bundle_id"],
            "mapping": {token: "one", "collision.example.invalid": "two"},
        }) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ShareError, match="duplicate keys"):
        restore_bundle(
            response,
            restored,
            key,
            manifest_path=manifest_path,
            passphrase="test-passphrase",
        )


def test_dynamic_ioc_keys_are_tokenized_and_restored(tmp_path):
    from ioc_rejudge.share import create_bundle, restore_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    source.write_text(
        json.dumps({"mapping": {"keyed.example.invalid": "evidence"}}) + "\n",
        encoding="utf-8",
    )
    create_bundle(
        source,
        shared,
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    assert "keyed.example.invalid" not in shared.read_text(encoding="utf-8")
    assert scan_bundle(shared)["finding_count"] == 0
    restore_bundle(shared, restored, key, passphrase="test-passphrase")
    assert "keyed.example.invalid" in json.loads(restored.read_text(encoding="utf-8"))["mapping"]


def test_names_file_replacements_do_not_modify_existing_tokens(tmp_path):
    from ioc_rejudge.share import create_bundle, restore_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    original = {"ioc": "names.example.invalid", "comment": "analyst domain reviewed it"}
    source.write_text(json.dumps(original) + "\n", encoding="utf-8")

    create_bundle(
        source,
        shared,
        key,
        names=["domain"],
        generate_key=True,
        passphrase="test-passphrase",
    )
    restore_bundle(shared, restored, key, passphrase="test-passphrase")

    assert json.loads(restored.read_text(encoding="utf-8")) == original


def test_create_rejects_preexisting_share_tokens(tmp_path):
    from ioc_rejudge.share import ShareError, create_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    key_source = tmp_path / "key-source.jsonl"
    key = tmp_path / "share-key.json"
    key_source.write_text(json.dumps({"ioc": "key-source.invalid"}) + "\n", encoding="utf-8")
    create_bundle(
        key_source,
        tmp_path / "initial.jsonl",
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    source.write_text(json.dumps({"context": "ss1:domain:not-a-real-token"}) + "\n", encoding="utf-8")
    assert scan_bundle(source)["finding_counts"]["malformed_token"] >= 1
    with pytest.raises(ShareError, match="already contains"):
        create_bundle(
            source,
            tmp_path / "shared.jsonl",
            key,
            passphrase="test-passphrase",
        )

    source.write_text('{"ioc":"one.invalid","ioc":"two.invalid"}\n', encoding="utf-8")
    with pytest.raises(ShareError, match="invalid JSONL"):
        create_bundle(
            source,
            tmp_path / "duplicate.jsonl",
            key,
            passphrase="test-passphrase",
        )


def test_share_v07_leak_heuristics_token_redact_and_round_trip(tmp_path):
    import base64

    from ioc_rejudge.share import create_bundle, restore_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
    sample_hash = "a" * 64
    nested = {"ioc": "nested.example.invalid"}
    nested_b64 = base64.b64encode(
        json.dumps(nested, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    original = {
        "ioc": "cover.example.invalid",
        "producer": "producer.example.invalid",
        "comment": (
            f"jwt {jwt} "
            "Update By huangjiahong "
            "请联系 alice.example "
            "defang aaa.bbb[.]invalid "
            f"sample {sample_hash}exe "
            "host EC2AMAZ-ABCDEFG "
            "hxxp://phish.example.invalid/a"
        ),
        "payload": nested_b64,
    }
    source.write_text(json.dumps(original, ensure_ascii=False) + "\n", encoding="utf-8")

    result = create_bundle(
        source,
        shared,
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    assert result["output_findings"] == 0
    assert result["redacted_occurrences"] >= 1
    assert scan_bundle(shared)["finding_count"] == 0

    shared_row = json.loads(shared.read_text(encoding="utf-8"))
    shared_text = shared.read_text(encoding="utf-8")
    assert jwt not in shared_text
    assert "[REDACTED]" in shared_row["comment"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in shared_row["comment"]
    assert "huangjiahong" not in shared_text
    assert "alice.example" not in shared_text
    assert "aaa.bbb" not in shared_text
    assert "aaa.bbb[.]invalid" not in shared_text
    assert sample_hash not in shared_text
    assert "EC2AMAZ-ABCDEFG" not in shared_text
    assert "phish.example.invalid" not in shared_text
    assert "nested.example.invalid" not in shared_text
    assert "producer.example.invalid" not in shared_text
    assert "hxxp://" not in shared_text

    restore_bundle(shared, restored, key, passphrase="test-passphrase")
    restored_row = json.loads(restored.read_text(encoding="utf-8"))
    assert restored_row["ioc"] == original["ioc"]
    assert restored_row["producer"] == original["producer"]
    assert "[REDACTED]" in restored_row["comment"]
    assert jwt not in restored_row["comment"]
    assert "huangjiahong" in restored_row["comment"]
    assert "alice.example" in restored_row["comment"]
    assert "aaa.bbb.invalid" in restored_row["comment"]
    assert sample_hash in restored_row["comment"]
    assert "EC2AMAZ-ABCDEFG" in restored_row["comment"]
    assert "http://phish.example.invalid/a" in restored_row["comment"]
    restored_nested = json.loads(
        base64.b64decode(restored_row["payload"]).decode("utf-8")
    )
    assert restored_nested == nested


def test_share_scan_skips_empty_final_unix_path_segment():
    from ioc_rejudge.share import scan_value

    assert scan_value("/lib/") == []
    assert scan_value("dropped dynamic/appdata/token/lib/") == []
    codes = {item["code"] for item in scan_value("/home/analyst/samples/payload.bin")}
    assert "path" in codes


def test_share_package_lib_fragment_does_not_fail_strict(tmp_path):
    from ioc_rejudge.share import create_bundle, restore_bundle, scan_bundle

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    original = {
        "ioc": "dropped.example.invalid",
        "context": (
            "dropped: dynamic/appdata/com.example.invalid/lib/libsample.so "
            "dynamic/appdata/com.example.invalid/lib/libhelper.so"
        ),
        "comment": "also /home/analyst/samples/payload.bin",
    }
    source.write_text(json.dumps(original, ensure_ascii=False) + "\n", encoding="utf-8")

    result = create_bundle(
        source,
        shared,
        key,
        generate_key=True,
        passphrase="test-passphrase",
    )
    assert result["output_findings"] == 0
    assert scan_bundle(shared)["finding_count"] == 0
    shared_text = shared.read_text(encoding="utf-8")
    assert "com.example.invalid" not in shared_text
    assert "libsample.so" not in shared_text
    assert "/home/analyst/samples/payload.bin" not in shared_text

    restore_bundle(shared, restored, key, passphrase="test-passphrase")
    restored_row = json.loads(restored.read_text(encoding="utf-8"))
    assert restored_row["context"] == original["context"]
    assert restored_row["comment"] == original["comment"]


def test_share_commands_are_available_from_package_entrypoint():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "ioc_rejudge", "share", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "create" in result.stdout
    assert "restore" in result.stdout
    assert "scan" in result.stdout


def test_share_cli_create_scan_and_restore_with_environment_passphrase(tmp_path):
    import os
    import subprocess
    import sys

    source = tmp_path / "source.jsonl"
    shared = tmp_path / "shared.jsonl"
    restored = tmp_path / "restored.jsonl"
    key = tmp_path / "share-key.json"
    manifest = tmp_path / "shared.jsonl.manifest.json"
    source.write_text(json.dumps({"ioc": "cli.example.invalid"}) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["IOC_SHARE_PASSPHRASE"] = "test-passphrase"

    create = subprocess.run(
        [
            sys.executable,
            "-m",
            "ioc_rejudge",
            "share",
            "create",
            "-i",
            str(source),
            "-o",
            str(shared),
            "--key-file",
            str(key),
            "--generate-key",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert create.returncode == 0, create.stderr
    assert "test-passphrase" not in create.stdout + create.stderr

    scan = subprocess.run(
        [sys.executable, "-m", "ioc_rejudge", "share", "scan", "-i", str(shared)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert scan.returncode == 0, scan.stderr
    assert json.loads(scan.stdout)["finding_count"] == 0

    restore = subprocess.run(
        [
            sys.executable,
            "-m",
            "ioc_rejudge",
            "share",
            "restore",
            "-i",
            str(shared),
            "-o",
            str(restored),
            "--key-file",
            str(key),
            "--manifest",
            str(manifest),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert restore.returncode == 0, restore.stderr
    assert "test-passphrase" not in restore.stdout + restore.stderr
    assert json.loads(restored.read_text(encoding="utf-8"))["ioc"] == "cli.example.invalid"


def test_same_seed_produces_identical_output_bytes(tmp_path):
    module = load_anonymizer()
    raw_hash = "ffffffffffffffffffffffffffffffff"
    input_path = tmp_path / "input.jsonl"
    input_path.write_text(
        json.dumps(
            {
                "domain": "seed-source.example.invalid",
                "ip": "192.0.2.10",
                "hash": raw_hash,
                "email": "sender@example.invalid",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    first_output = tmp_path / "first.jsonl"
    second_output = tmp_path / "second.jsonl"
    different_seed_output = tmp_path / "different-seed.jsonl"

    assert module.main(["-i", str(input_path), "-o", str(first_output), "--seed", "1234"]) == 0
    assert module.main(["-i", str(input_path), "-o", str(second_output), "--seed", "1234"]) == 0
    assert module.main(["-i", str(input_path), "-o", str(different_seed_output), "--seed", "4321"]) == 0

    assert first_output.read_bytes() == second_output.read_bytes()
    assert first_output.read_bytes() != different_seed_output.read_bytes()
