import hashlib
import json
import os

import pytest

from ioc_rejudge.explanations import explain_verdict
from ioc_rejudge.run_history import RunHistory


def test_explain_verdict_has_stable_required_fields_and_sha256_fingerprint():
    verdict = {
        "ioc": "example.test",
        "conclusion": "needs_review",
        "reason": "changed score",
        "rule_path": "rules/score.yaml",
        "freshness": "current",
        "evidence": [
            {"field": "score", "detail": "0.8", "level": "high", "tags": ["score"]},
            {"field": "sandbox", "missing": True},
        ],
    }

    first = explain_verdict(verdict)
    second = explain_verdict(dict(verdict))

    assert first == second
    assert first["conclusion"] == "needs_review"
    assert first["accepted_evidence"] == [
        {"field": "score", "detail": "0.8", "level": "high", "tags": ["score"]}
    ]
    assert first["rejected_evidence"] == [{"field": "sandbox", "missing": True}]

    canonical = json.dumps(
        {
            "accepted_evidence": first["accepted_evidence"],
            "rejected_evidence": first["rejected_evidence"],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert first["evidence_fingerprint"] == hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    assert len(first["evidence_fingerprint"]) == 64
    assert all(character in "0123456789abcdef" for character in first["evidence_fingerprint"])


def test_explain_verdict_uses_required_provider_diagnostics_and_priorities():
    verdict = {"conclusion": "pass", "reason": "verdict reason"}
    dossier = {
        "ioc": "from-dossier",
        "reason": "dossier reason",
        "next_actions": ["do-not-use"],
        "missing_required_providers": ["sandbox"],
        "evidence": [{"field": "sandbox", "missing": True}],
    }
    diagnostics = {
        "reason": "diagnostic reason",
        "rule": {"path": "rules/check.yml"},
        "next_actions": ["rerun-sandbox"],
        "missing_required_providers": ["sandbox"],
    }

    result = explain_verdict(verdict, dossier, diagnostics)

    assert result["ioc"] == "from-dossier"
    assert result["conclusion"] == "pass"
    assert result["reason"] == "diagnostic reason"
    assert result["rule_path"] == "rules/check.yml"
    assert result["accepted_evidence"] == []
    assert result["rejected_evidence"] == [{"field": "sandbox", "missing": True}]
    assert result["missing_required_providers"] == ["sandbox"]
    assert result["next_actions"] == ["rerun-sandbox"]


def test_run_history_records_are_sorted_deduplicated_and_bounded(tmp_path):
    history = RunHistory(tmp_path, max_runs=2)

    assert history.load() == []
    assert history.select_baseline() is None
    assert history.record({"run_id": "b", "created_at": "2"}) == {
        "run_id": "b",
        "created_at": "2",
    }
    history.record({"run_id": "a", "created_at": "1"})
    with pytest.raises(ValueError, match="already exists"):
        history.record({"run_id": "b", "created_at": "3"})

    assert history.list_runs() == [
        {"run_id": "a", "created_at": "1"},
        {"run_id": "b", "created_at": "2"},
    ]
    assert history.path.read_text(encoding="utf-8").endswith("\n")

    history.record({"run_id": "c", "created_at": "3"})
    assert [record["run_id"] for record in history.list_runs()] == ["b", "c"]


def test_run_history_selects_deterministic_baseline(tmp_path):
    history = RunHistory(tmp_path)
    history.record({"run_id": "old", "created_at": "1"})
    history.record({"run_id": "current", "created_at": "2"})

    assert history.select_baseline() == {"run_id": "current", "created_at": "2"}
    assert history.select_baseline("current") == {"run_id": "old", "created_at": "1"}
    assert history.select_baseline("old") is None
    with pytest.raises(ValueError, match="not in history"):
        history.select_baseline("missing")


def test_run_history_is_atomic_and_preserves_existing_data_on_failure(
    tmp_path, monkeypatch
):
    history = RunHistory(tmp_path)
    history.record({"run_id": "old", "created_at": "1"})
    before = history.path.read_bytes()

    def failed_replace(self, target):
        raise OSError("replacement failed")

    monkeypatch.setattr(os, "replace", failed_replace)
    with pytest.raises(OSError, match="replacement failed"):
        history.record({"run_id": "new", "created_at": "2"})

    assert history.path.read_bytes() == before
    assert list(tmp_path.glob(".history-*.tmp")) == []
    assert history.get("old") == {"run_id": "old", "created_at": "1"}
    assert history.get("new") is None


def test_run_history_loads_valid_objects_and_rejects_unsafe_ids(tmp_path):
    history = RunHistory(tmp_path)
    history.path.write_text(
        '{"run_id":"good"}\nnot-json\n[1,2,3]\n{"other":true}\n',
        encoding="utf-8",
    )

    assert history.load() == [{"run_id": "good"}]
    assert history.get("good") == {"run_id": "good"}
    with pytest.raises(ValueError, match="traversal"):
        history.record({"run_id": "../escape"})
