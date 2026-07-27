"""Deterministic verdict-diff contract tests."""

import pytest

from ioc_rejudge.diff import compare_verdicts


def _row(ioc, conclusion, reason=""):
    return {"ioc": ioc, "conclusion": conclusion, "reason": reason}


def test_compare_verdicts_reports_transitions_changes_and_membership():
    before = [
        _row("stable.invalid", "存活有效"),
        _row("to-white.invalid", "失活有效"),
        _row("to-black.invalid", "误报"),
        _row("to-gray.invalid", "存活有效"),
        _row("to-review.invalid", "误报"),
        _row("removed.invalid", "待复核"),
    ]
    after = [
        _row("added.invalid", "待复核", "new"),
        _row("to-review.invalid", "待复核", "needs review"),
        _row("to-gray.invalid", "灰", "scope changed"),
        _row("to-black.invalid", "存活有效", "new sample"),
        _row("to-white.invalid", "误报", "normal closure"),
        _row("stable.invalid", "存活有效"),
    ]

    result = compare_verdicts(before, after)

    assert result["transitions"] == {
        "存活有效->存活有效": 1,
        "误报->存活有效": 1,
        "存活有效->灰": 1,
        "误报->待复核": 1,
        "失活有效->误报": 1,
    }
    assert [item["ioc"] for item in result["changed"]] == [
        "to-black.invalid",
        "to-gray.invalid",
        "to-review.invalid",
        "to-white.invalid",
    ]
    assert result["only_before"] == ["removed.invalid"]
    assert result["only_after"] == ["added.invalid"]
    assert [item["ioc"] for item in result["black_to_white"]] == ["to-white.invalid"]
    assert [item["ioc"] for item in result["white_to_black"]] == ["to-black.invalid"]
    assert [item["ioc"] for item in result["to_gray"]] == ["to-gray.invalid"]
    assert [item["ioc"] for item in result["to_review"]] == ["to-review.invalid"]


def test_compare_verdicts_is_deterministic_for_reversed_input():
    before = [_row("b.invalid", "误报"), _row("a.invalid", "存活有效")]
    after = [_row("a.invalid", "误报", "a"), _row("b.invalid", "失活有效", "b")]
    assert compare_verdicts(before, after) == compare_verdicts(
        list(reversed(before)),
        list(reversed(after)),
    )


@pytest.mark.parametrize(
    ("before", "after", "message"),
    [
        ([{"conclusion": "误报"}], [], "before[0] missing required field 'ioc'"),
        ([{"ioc": "x.invalid"}], [], "before[0] missing required field 'conclusion'"),
        ([], [{"conclusion": "误报"}], "after[0] missing required field 'ioc'"),
        ([], [{"ioc": "x.invalid"}], "after[0] missing required field 'conclusion'"),
    ],
)
def test_compare_verdicts_rejects_missing_required_fields(before, after, message):
    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        compare_verdicts(before, after)


def test_compare_verdicts_uses_last_duplicate_and_reports_count():
    duplicate = [_row("same.invalid", "误报"), _row("same.invalid", "待复核")]
    result = compare_verdicts(duplicate, [_row("same.invalid", "待复核")])
    assert result["transitions"] == {"待复核->待复核": 1}
    assert result["changed"] == []
    assert result["duplicate_before"] == {"same.invalid": 2}
    assert result["duplicate_after"] == {}
