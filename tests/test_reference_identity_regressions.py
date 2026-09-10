"""Public report references must belong to the record's IOC subject."""

import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_record


def _apt_record(ioc="reported.invalid", reference="https://reports.invalid/report", **extra):
    return build_record(
        ioc,
        level=70,
        malicious_type=["APT"],
        private=False,
        confidence=5,
        info_level=3,
        reference=reference,
        **extra,
    )


def _public_references(records):
    dossier = extract_evidence(merge_records(records), Config())
    return [item for item in dossier.evidence_c if item.field == "structured_public_apt"]


def test_external_report_can_rely_on_matching_structured_record_subject():
    assert _public_references([_apt_record("REPORTED.invalid.")])


def test_report_on_another_record_subject_cannot_create_target_evidence():
    records = [build_record("target.invalid", level=20), _apt_record("other.invalid")]
    assert _public_references(records) == []


@pytest.mark.parametrize("reference", [
    "https://reports.invalid:99999/report",
    "https://user:password@reports.invalid/report",
    "https://not_legal.invalid/report",
    "https://reports.invalid:/report",
])
def test_malformed_or_credential_bearing_report_is_not_evidence(reference):
    assert _public_references([_apt_record(reference=reference)]) == []


def test_invalid_first_reference_does_not_hide_later_valid_reference():
    references = "https://bad.invalid:99999/report https://reports.invalid/valid"
    evidence = _public_references([_apt_record(reference=references)])
    assert len(evidence) == 1
    assert evidence[0].detail.endswith("https://reports.invalid/valid")


def test_domain_port_record_matches_its_normalized_subject():
    assert _public_references([_apt_record(port="443")])


def test_report_for_another_url_path_does_not_match_target_url():
    records = [
        build_record("https://reported.invalid/target", level=20),
        _apt_record("https://reported.invalid/other"),
    ]
    assert _public_references(records) == []
