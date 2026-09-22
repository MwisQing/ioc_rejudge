"""R10: mandatory-review black verdicts belong in the default queue."""

from datetime import datetime

from ioc_rejudge.config import Config
from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import Freshness, Observation, ProviderStatus
from ioc_rejudge.pipeline import run_unified_pipeline
from ioc_rejudge.providers.base import ProviderContext, ProviderResult
from ioc_rejudge.review_queue import append_label, build_queue, load_queue, summarize

NOW = datetime(2026, 7, 23, 12, 0, 0)


def _row(**kwargs):
    base = {
        "ioc": "sample.invalid",
        "conclusion": "存活有效",
        "disposition": "block",
        "review_suggestion": "无需复核",
        "label": "",
        "note": "",
    }
    base.update(kwargs)
    return base


class _StaticProvider:
    def __init__(self, name, observations=(), status=ProviderStatus.SUCCESS):
        self.name = name
        self.observations = list(observations)
        self.status = status

    def supports(self, target):
        return True

    def collect(self, targets, context):
        return ProviderResult(
            self.name,
            observations=self.observations,
            statuses={target.normalized: self.status for target in targets},
            freshnesses={target.normalized: Freshness.FRESH for target in targets},
        )


def test_build_queue_includes_block_with_mandatory_review():
    rows = build_queue(
        [
            _row(ioc="must.invalid", disposition="block", review_suggestion="必看", conclusion="存活有效"),
            _row(ioc="ordinary-block.invalid", disposition="block", review_suggestion="无需复核"),
            _row(ioc="pending.invalid", disposition="review", conclusion="待复核", review_suggestion="必看"),
            _row(ioc="business.invalid", disposition="review", conclusion="灰", review_suggestion="抽检"),
        ],
        pending_only=True,
    )
    assert [r["ioc"] for r in rows] == [
        "business.invalid",
        "must.invalid",
        "pending.invalid",
    ]
    must = next(r for r in rows if r["ioc"] == "must.invalid")
    assert must["disposition"] == "block"
    assert must["conclusion"] == "存活有效"
    assert must["review_suggestion"] == "必看"


def test_build_queue_pending_only_false_returns_all_with_ioc():
    rows = build_queue(
        [
            _row(ioc="z.invalid", disposition="block", review_suggestion="无需复核"),
            _row(ioc="a.invalid", disposition="review", conclusion="待复核"),
            {"conclusion": "误报"},  # no ioc -> skipped
        ],
        pending_only=False,
    )
    assert [r["ioc"] for r in rows] == ["a.invalid", "z.invalid"]


def test_build_queue_preserves_labels_notes_and_sort_order(tmp_path):
    pending = build_queue(
        [
            _row(ioc="b.invalid", disposition="block", review_suggestion="必看"),
            _row(ioc="a.invalid", disposition="review", conclusion="待复核"),
        ]
    )
    assert [r["ioc"] for r in pending] == ["a.invalid", "b.invalid"]
    path = tmp_path / "q.jsonl"
    append_label(path, "a.invalid", label="确认恶意", note="ops", reviewer="A", reviewed_at="2026-01-01T00:00:00Z")
    loaded = load_queue(path)
    assert loaded[0]["label"] == "确认恶意"
    assert loaded[0]["note"] == "ops"
    assert summarize(pending)["unreviewed"] == 2


def test_pipeline_icp_conflict_direct_malicious_enters_default_queue():
    """ICP conflict + strong hash direct evidence keeps black and must enter queue."""
    ioc = "hash-conflict.invalid"
    observations = [
        Observation(
            ioc=ioc,
            scope="domain",
            provider="icp",
            kind="icp",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            payload={"current": True, "registration": "ICP-A"},
        ),
        Observation(
            ioc=ioc,
            scope="domain",
            provider="icp",
            kind="icp",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            payload={"current": False},
        ),
        Observation(
            ioc=ioc,
            scope="domain",
            provider="ioc_info",
            kind="ioc_info_record",
            status=ProviderStatus.SUCCESS,
            freshness=Freshness.FRESH,
            payload={
                "key": ioc,
                "level": 70,
                "source": ["manual"],
                "context": f"{ioc} trojan backdoor communication",
                "comment": f"{ioc} malware sample download",
                "hash": [
                    {
                        "md5": "deadbeefdeadbeefdeadbeefdeadbeef",
                        "level": 70,
                        "time": "2026-07-20 10:00:00",
                        "confidence": 80,
                        "family": "trojan",
                        "type": "TROJAN",
                    }
                ],
            },
        ),
    ]
    providers = [
        _StaticProvider("icp", [o for o in observations if o.provider == "icp"]),
        _StaticProvider("ioc_info", [o for o in observations if o.provider == "ioc_info"]),
        _StaticProvider("fdark", status=ProviderStatus.NO_DATA),
    ]
    result = run_unified_pipeline(
        read_input_bundle(None, [ioc]),
        providers,
        Config(),
        ProviderContext(offline=True),
        now=NOW,
    )
    row = result.verdicts[0]
    assert row["disposition"] == "block"
    assert row["review_suggestion"] == "必看"
    assert row["conclusion"] in {"存活有效", "失活有效"}

    queue = build_queue(result.verdicts, pending_only=True)
    assert [item["ioc"] for item in queue] == [ioc]
    assert queue[0]["disposition"] == "block"
    assert queue[0]["review_suggestion"] == "必看"

    ordinary = build_queue(
        result.verdicts
        + [
            _row(
                ioc="plain-block.invalid",
                disposition="block",
                review_suggestion="无需复核",
                conclusion="存活有效",
            )
        ],
        pending_only=True,
    )
    assert [item["ioc"] for item in ordinary] == [ioc]
