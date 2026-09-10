"""Non-finite provider values cannot satisfy evidence thresholds."""

import pytest

from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence, is_malicious_sample
from ioc_rejudge.normalize import coerce_level, merge_records
from tests.fixtures import build_record


_NONFINITE = [
    "NaN", "Infinity", "-Infinity", float("nan"), float("inf"),
    pytest.param(10 ** 1000, id="overflow"),
]


@pytest.mark.parametrize("value", _NONFINITE)
def test_nonfinite_record_level_uses_fallback(value):
    assert coerce_level(value, default=0) == 0


@pytest.mark.parametrize("value", _NONFINITE)
@pytest.mark.parametrize("field", ["level", "confidence"])
def test_nonfinite_sample_number_cannot_prove_malice(value, field):
    sample = {"level": 70, "confidence": 5, field: value}
    assert is_malicious_sample(sample, Config()) is False


@pytest.mark.parametrize("field", ["level", "confidence", "info_level"])
@pytest.mark.parametrize("value", ["NaN", "Infinity"])
def test_nonfinite_public_apt_number_cannot_create_c(field, value):
    values = {"level": 70, "confidence": 5, "info_level": 3, field: value}
    record = build_record(
        "numbers.invalid",
        malicious_type=["APT"],
        private=False,
        reference="https://reports.invalid/report",
        **values,
    )
    dossier = extract_evidence(merge_records([record]), Config())
    assert not any(item.field == "structured_public_apt" for item in dossier.evidence_c)
