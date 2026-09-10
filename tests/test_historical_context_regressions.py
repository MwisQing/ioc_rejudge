import pytest

from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_hash_entry, build_record


def _extract(records):
    if isinstance(records, dict):
        records = [records]
    return extract_evidence(
        merge_records(records),
        Config(activity_window_days=30),
    )


def _c_evidence(dossier):
    return list(dossier.evidence_c)


@pytest.mark.parametrize("indicator", ["DNS", "HTTP", "sample", "payload"])
def test_neutral_context_does_not_create_historical_c(indicator):
    ioc = "neutral-context.invalid"
    dossier = _extract(build_record(
        ioc,
        level=70,
        context=f"{indicator} observed for {ioc}",
    ))

    assert _c_evidence(dossier) == []
    verdict = adjudicate(dossier, Config())
    assert verdict.disposition == "review"
    assert "间接关联" in verdict.reason
    assert "存在资产变化" not in verdict.reason


def test_historical_word_alone_does_not_create_c():
    ioc = "historical-only.invalid"
    dossier = _extract(build_record(
        ioc,
        level=70,
        context=f"Historical intelligence for {ioc}",
    ))

    assert _c_evidence(dossier) == []


@pytest.mark.parametrize(
    "hash_entry",
    [
        build_hash_entry("low-level", level=10, time="2020-01-01 00:00:00"),
        build_hash_entry(
            "not-a-virus",
            level=70,
            family="not-a-virus:AdWare",
            time="2020-01-01 00:00:00",
        ),
    ],
    ids=["low_level", "not_a_virus"],
)
def test_ineligible_same_record_sample_does_not_create_c(hash_entry):
    ioc = "ineligible-sample.invalid"
    dossier = _extract(build_record(
        ioc,
        level=70,
        source=["sample-base"],
        context=f"Observed {ioc}",
        hash_entries=[hash_entry],
    ))

    assert _c_evidence(dossier) == []


def test_sample_from_different_record_does_not_create_c():
    ioc = "split-sample.invalid"
    records = [
        build_record(
            ioc,
            level=70,
            source=["sample-base"],
            context=f"Archived observation for {ioc}",
            hash_entries=[build_hash_entry(
                "historical-malware",
                level=70,
                time="2020-01-01 00:00:00",
            )],
        ),
        build_record(
            ioc,
            level=70,
            source=["sample-base"],
            context=f"Current observation for {ioc}",
        ),
    ]

    assert _c_evidence(_extract(records)) == []


@pytest.mark.parametrize(
    "raw_hash",
    [
        build_hash_entry("same-record-dict", level=70, time="2020-01-01 00:00:00"),
        [
            None,
            "malformed hash entry",
            build_hash_entry("same-record-list", level=70, time="2020-01-01 00:00:00"),
        ],
    ],
    ids=["dict", "list_filters_non_dicts"],
)
def test_malicious_sample_in_same_record_creates_c(raw_hash):
    ioc = "same-record-sample.invalid"
    record = build_record(
        ioc,
        level=70,
        context=f"Observed {ioc}",
    )
    dossier = merge_records([record])
    dossier.record_snapshots[-1].raw["hash"] = raw_hash

    assert _c_evidence(extract_evidence(dossier, Config(activity_window_days=30)))


@pytest.mark.parametrize("word", ["trojan", "malware"])
def test_explicit_malicious_text_creates_c(word):
    ioc = "explicit-malicious.invalid"
    dossier = _extract(build_record(
        ioc,
        level=70,
        context=f"{word} report for {ioc}",
    ))

    assert _c_evidence(dossier)


def test_historical_context_only_tags_an_already_admitted_c():
    ioc = "historical-tag.invalid"
    dossier = _extract(build_record(
        ioc,
        level=70,
        context=f"Historical malware report for {ioc}",
    ))

    evidence = _c_evidence(dossier)
    assert len(evidence) == 1
    assert evidence[0].tags == ["historical", "historical_context"]
