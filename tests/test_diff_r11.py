"""R11: same-label operational changes must be visible in diff."""

from ioc_rejudge.diff import compare_verdicts


def _row(ioc, conclusion, **extra):
    row = {"ioc": ioc, "conclusion": conclusion, "reason": extra.pop("reason", "")}
    row.update(extra)
    return row


def test_same_gray_retained_urls_change_is_reported():
    before = [
        _row(
            "gray.invalid",
            "灰",
            disposition="gray",
            retained_urls=["https://gray.invalid/old"],
            scope_actions=[
                {"ioc": "gray.invalid", "scope": "domain", "action": "gray"},
                {"ioc": "https://gray.invalid/old", "scope": "url", "action": "retain"},
            ],
            review_suggestion="抽检",
        )
    ]
    after = [
        _row(
            "gray.invalid",
            "灰",
            disposition="gray",
            retained_urls=["https://gray.invalid/new"],
            scope_actions=[
                {"ioc": "gray.invalid", "scope": "domain", "action": "gray"},
                {"ioc": "https://gray.invalid/new", "scope": "url", "action": "retain"},
            ],
            review_suggestion="抽检",
        )
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    assert result["transitions"] == {"灰->灰": 1}
    ops = result["operational_changes"]
    assert len(ops) == 1
    assert ops[0]["ioc"] == "gray.invalid"
    assert "retained_urls" in ops[0]["fields"]
    assert ops[0]["before"]["retained_urls"] == ["https://gray.invalid/old"]
    assert ops[0]["after"]["retained_urls"] == ["https://gray.invalid/new"]
    assert "scope_actions" in ops[0]["fields"]


def test_same_label_scope_action_change_is_reported():
    before = [
        _row(
            "block.invalid",
            "存活有效",
            disposition="block",
            scope_actions=[{"ioc": "block.invalid", "scope": "domain", "action": "block"}],
            review_suggestion="不看",
        )
    ]
    after = [
        _row(
            "block.invalid",
            "存活有效",
            disposition="block",
            scope_actions=[{"ioc": "block.invalid", "scope": "host", "action": "monitor"}],
            review_suggestion="不看",
        )
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    op = result["operational_changes"][0]
    assert op["fields"] == ["scope_actions"]
    assert op["before"]["scope_actions"] == [
        {"ioc": "block.invalid", "scope": "domain", "action": "block"}
    ]
    assert op["after"]["scope_actions"] == [
        {"ioc": "block.invalid", "scope": "host", "action": "monitor"}
    ]


def test_same_label_newly_mandatory_review_is_reported():
    before = [
        _row(
            "black.invalid",
            "存活有效",
            disposition="block",
            review_suggestion="无需复核",
        )
    ]
    after = [
        _row(
            "black.invalid",
            "存活有效",
            disposition="block",
            review_suggestion="必看",
            missing_required_providers=["whois"],
            classification_unknown=True,
        )
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    op = result["operational_changes"][0]
    assert "review_suggestion" in op["fields"]
    assert op["before"]["review_suggestion"] == "无需复核"
    assert op["after"]["review_suggestion"] == "必看"
    assert "missing_required_providers" in op["fields"]
    assert op["after"]["missing_required_providers"] == ["whois"]
    assert "classification_unknown" in op["fields"]
    assert op["after"]["classification_unknown"] is True


def test_unchanged_rows_and_reorder_only_equality_produce_no_ops():
    before = [
        _row(
            "stable.invalid",
            "灰",
            disposition="gray",
            retained_urls=["https://a.invalid/1", "https://a.invalid/2"],
            scope_actions=[
                {"ioc": "stable.invalid", "scope": "domain", "action": "gray"},
                {"ioc": "https://a.invalid/1", "scope": "url", "action": "retain"},
                {"ioc": "https://a.invalid/2", "scope": "url", "action": "retain"},
            ],
            review_suggestion="抽检",
            missing_required_providers=["pdns", "whois"],
        )
    ]
    after = [
        _row(
            "stable.invalid",
            "灰",
            disposition="gray",
            # order + duplicate noise only
            retained_urls=[
                "https://a.invalid/2",
                "https://a.invalid/1",
                "https://a.invalid/1",
            ],
            scope_actions=[
                {"ioc": "https://a.invalid/2", "scope": "url", "action": "retain"},
                {"ioc": "stable.invalid", "scope": "domain", "action": "gray"},
                {"ioc": "https://a.invalid/1", "scope": "url", "action": "retain"},
                {"ioc": "https://a.invalid/1", "scope": "url", "action": "retain"},
            ],
            review_suggestion="抽检",
            missing_required_providers=["whois", "pdns", "whois"],
        )
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    assert result["operational_changes"] == []


def test_http_https_and_mixed_identities_remain_separate():
    before = [
        _row("example.invalid", "灰", disposition="gray", retained_urls=["http://example.invalid/a"]),
        _row("http://example.invalid/path", "灰", disposition="gray", retained_urls=[]),
        _row("https://example.invalid/path", "灰", disposition="gray", retained_urls=[]),
    ]
    after = [
        _row("https://example.invalid/path", "灰", disposition="gray", retained_urls=[]),
        _row("http://example.invalid/path", "灰", disposition="gray", retained_urls=[]),
        _row(
            "example.invalid",
            "灰",
            disposition="gray",
            retained_urls=["https://example.invalid/a"],
        ),
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    assert set(result["transitions"].keys()) == {"灰->灰"}
    assert sum(result["transitions"].values()) == 3
    # domain IOC operational change only; HTTP/HTTPS identities stay distinct keys
    assert [op["ioc"] for op in result["operational_changes"]] == ["example.invalid"]
    assert result["only_before"] == []
    assert result["only_after"] == []


def test_legacy_transitions_and_duplicates_still_work():
    before = [
        _row("to-white.invalid", "失活有效"),
        _row("to-black.invalid", "误报"),
        _row("to-gray.invalid", "存活有效"),
        _row("to-review.invalid", "误报"),
        _row("dup.invalid", "误报"),
        _row("dup.invalid", "待复核"),
    ]
    after = [
        _row("to-white.invalid", "误报", reason="ok"),
        _row("to-black.invalid", "存活有效", reason="hit"),
        _row("to-gray.invalid", "灰", reason="scope"),
        _row("to-review.invalid", "待复核", reason="need"),
        _row("dup.invalid", "待复核"),
    ]
    result = compare_verdicts(before, after)
    assert [item["ioc"] for item in result["black_to_white"]] == ["to-white.invalid"]
    assert [item["ioc"] for item in result["white_to_black"]] == ["to-black.invalid"]
    assert [item["ioc"] for item in result["to_gray"]] == ["to-gray.invalid"]
    assert [item["ioc"] for item in result["to_review"]] == ["to-review.invalid"]
    assert result["duplicate_before"] == {"dup.invalid": 2}
    # conclusion transitions remain the meaning of `changed`
    assert "kind" not in result["changed"][0]
    assert result.get("operational_changes") == [] or isinstance(
        result["operational_changes"], list
    )


def test_legacy_missing_operational_fields_use_neutral_defaults():
    before = [_row("legacy.invalid", "灰")]
    after = [
        _row(
            "legacy.invalid",
            "灰",
            disposition="gray",
            retained_urls=["https://legacy.invalid/x"],
            review_suggestion="必看",
        )
    ]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    op = result["operational_changes"][0]
    assert op["before"]["retained_urls"] == []
    assert op["before"]["disposition"] == ""
    assert op["before"]["review_suggestion"] == ""
    assert op["before"]["scope_actions"] == []
    assert op["before"]["missing_required_providers"] == []
    assert op["before"]["classification_unknown"] is False


def test_malformed_collection_values_are_distinguished_safely():
    before = [
        _row(
            "bad.invalid",
            "灰",
            retained_urls="not-a-list",
            scope_actions=None,
            missing_required_providers=42,
        )
    ]
    after = [
        _row(
            "bad.invalid",
            "灰",
            retained_urls=["https://bad.invalid/ok"],
            scope_actions=[{"ioc": "bad.invalid", "scope": "domain", "action": "gray"}],
            missing_required_providers=["whois"],
        )
    ]
    result = compare_verdicts(before, after)
    op = result["operational_changes"][0]
    assert "retained_urls" in op["fields"]
    assert "scope_actions" in op["fields"]
    assert "missing_required_providers" in op["fields"]
    # Public before/after must show actual raw malformed values, not empty lists.
    assert op["before"]["retained_urls"] == "not-a-list"
    assert op["before"]["missing_required_providers"] == 42
    assert op["after"]["retained_urls"] == ["https://bad.invalid/ok"]
    assert op["after"]["missing_required_providers"] == ["whois"]


def test_malformed_to_malformed_reports_raw_before_and_after():
    before = [_row("mm.invalid", "灰", retained_urls="bad-old")]
    after = [_row("mm.invalid", "灰", retained_urls="bad-new")]
    result = compare_verdicts(before, after)
    assert result["changed"] == []
    assert len(result["operational_changes"]) == 1
    op = result["operational_changes"][0]
    assert "retained_urls" in op["fields"]
    assert op["before"]["retained_urls"] == "bad-old"
    assert op["after"]["retained_urls"] == "bad-new"


def test_empty_list_to_malformed_reports_raw_after():
    before = [_row("em.invalid", "灰", retained_urls=[])]
    after = [_row("em.invalid", "灰", retained_urls="bad-new")]
    result = compare_verdicts(before, after)
    op = result["operational_changes"][0]
    assert "retained_urls" in op["fields"]
    assert op["before"]["retained_urls"] == []
    assert op["after"]["retained_urls"] == "bad-new"


def test_malformed_to_valid_and_valid_reorder_still_quiet():
    before = [_row("mv.invalid", "灰", retained_urls="broken")]
    after = [_row("mv.invalid", "灰", retained_urls=["https://mv.invalid/a", "https://mv.invalid/b"])]
    result = compare_verdicts(before, after)
    op = result["operational_changes"][0]
    assert op["before"]["retained_urls"] == "broken"
    assert op["after"]["retained_urls"] == ["https://mv.invalid/a", "https://mv.invalid/b"]

    quiet = compare_verdicts(
        [_row("q.invalid", "灰", retained_urls=["https://q.invalid/2", "https://q.invalid/1"])],
        [_row("q.invalid", "灰", retained_urls=["https://q.invalid/1", "https://q.invalid/2", "https://q.invalid/1"])],
    )
    assert quiet["operational_changes"] == []
