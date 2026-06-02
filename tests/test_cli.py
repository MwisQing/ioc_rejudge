import json
import tempfile
import os
from ioc_rejudge.cli import run_pipeline
from ioc_rejudge.config import Config


def test_full_pipeline_with_real_data():
    lines = [
        {
            "ioc": "test.com",
            "data": [
                {
                    "key": "test.com",
                    "host": "test.com",
                    "level": 70,
                    "category": "DOMAIN_PORT",
                    "source": ["sample-base"],
                    "context": "Sample connected to test.com C2",
                    "hash": [{"md5": "abc", "level": 70, "time": "2026-03-20 17:10:41"}],
                    "family": ["SilverFox"],
                }
            ],
        },
        {
            "ioc": "normal.com",
            "data": [
                {
                    "key": "normal.com",
                    "host": "normal.com",
                    "level": 30,
                    "source": ["spider"],
                    "official_website": "https://www.google.com",
                }
            ],
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as sf:
        for line in lines:
            sf.write(json.dumps(line, ensure_ascii=False) + "\n")
        sf.flush()

        verdicts = run_pipeline(sf.name, Config())
        assert len(verdicts) == 2
        iocs = {v["ioc"] for v in verdicts}
        assert "test.com" in iocs
        assert "normal.com" in iocs

    os.unlink(sf.name)
