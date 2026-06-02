"""Integration test using the real json_temp.txt data."""
import os
from ioc_rejudge.cli import run_pipeline
from ioc_rejudge.config import Config


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT_PATH = os.path.join(PROJECT_DIR, "json_temp.txt")


def test_real_snapshot_no_crash():
    config = Config()
    verdicts = run_pipeline(SNAPSHOT_PATH, config)
    assert len(verdicts) == 1


def test_real_snapshot_has_required_fields():
    config = Config()
    verdicts = run_pipeline(SNAPSHOT_PATH, config)
    required = [
        "ioc", "conclusion", "malicious_nature", "activity_status",
        "confidence", "review_suggestion", "candidate_label",
        "hit_evidence", "forbidden_labels", "reason",
    ]
    for v in verdicts:
        for field in required:
            assert field in v, f"Missing field: {field} for IOC {v.get('ioc', 'unknown')}"


def test_real_snapshot_valid_conclusions():
    config = Config()
    verdicts = run_pipeline(SNAPSHOT_PATH, config)
    valid = {"存活有效", "失活有效", "误报", "待复核"}
    for v in verdicts:
        assert v["conclusion"] in valid, \
            f"Invalid conclusion '{v['conclusion']}' for {v['ioc']}"
