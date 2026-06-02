import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import requests

import sys

# Import the module functions
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import iocProducer_api_ioc_info as mod


class TestQueryBatch:
    """T001: query_batch parses API responses correctly"""

    def test_normal_dict_response(self):
        """Normal case: {"data": {"ioc1": [...], "ioc2": [...]}}"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"evil.com": [{"id": 1}], "10.0.0.1": [{"id": 2}]}
        }
        with patch("requests.post", return_value=mock_resp):
            result = mod.query_batch(["evil.com", "10.0.0.1"], "test-key")
        assert result == {"evil.com": [{"id": 1}], "10.0.0.1": [{"id": 2}]}

    def test_empty_dict_response(self):
        """API returns {"data": {}} — some IOC data missing"""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {}}
        with patch("requests.post", return_value=mock_resp):
            result = mod.query_batch(["evil.com"], "test-key")
        assert result == {}

    def test_http_error_raises(self):
        """HTTP 500 raises HTTPError"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "500 Server Error"
        )
        with patch("requests.post", return_value=mock_resp):
            with pytest.raises(requests.exceptions.HTTPError):
                mod.query_batch(["evil.com"], "test-key")


class TestRetryMechanism:
    """T002-T007: Retry logic for empty data"""

    def _run_main(self, ioc_list, api_responses, cache_data=None):
        """Helper: run main() with mocked IOCs, API, and cache."""
        tmpdir = Path(tempfile.mkdtemp())
        api_key_file = tmpdir / "Api-Key.txt"
        api_key_file.write_text("test-key-123")
        ioc_file = tmpdir / "ioc.txt"
        ioc_file.write_text("\n".join(ioc_list))

        cache_dir = tmpdir / "ioc_info_cache"

        call_count = [0]
        response_iter = iter(api_responses)

        def mock_post(*args, **kwargs):
            call_count[0] += 1
            mock_resp = MagicMock()
            try:
                resp_data = next(response_iter)
            except StopIteration:
                mock_resp.json.return_value = {"data": {}}
                return mock_resp
            mock_resp.json.return_value = resp_data
            return mock_resp

        with patch.object(mod, "ROOT", tmpdir), \
             patch.object(mod, "CACHE_DIR", cache_dir), \
             patch("requests.post", mock_post), \
             patch("time.sleep", lambda x: None):

            # Run main via import
            mod.main()

        # Read result
        result_path = tmpdir / "ioc_info_result.jsonl"
        if result_path.exists():
            results = []
            for line in result_path.read_text().splitlines():
                if line.strip():
                    results.append(json.loads(line))
        else:
            results = []

        return results, call_count[0]

    def test_no_retry_when_data_present(self):
        """T002: All IOCs return data on first request — no retry"""
        iocs = ["ioc1.com", "ioc2.com", "ioc3.com"]
        responses = [{"data": {
            "ioc1.com": [{"id": 1}],
            "ioc2.com": [{"id": 2}],
            "ioc3.com": [{"id": 3}],
        }}]
        results, calls = self._run_main(iocs, responses)
        assert len(results) == 3
        assert calls == 1  # only one request

    def test_retry_on_empty_data(self):
        """T003: IOC with empty data triggers retry"""
        iocs = ["good.com", "bad.com"]
        # First call: good.com has data, bad.com empty
        # Second call: bad.com now has data
        responses = [
            {"data": {"good.com": [{"id": 1}], "bad.com": []}},
            {"data": {"bad.com": [{"id": 2}]}},
        ]
        results, calls = self._run_main(iocs, responses)
        assert len(results) == 2  # both IOCs have data
        assert calls == 2  # retry happened

    def test_max_retries_exceeded(self):
        """T004: IOC exceeds 10 retries — excluded from result"""
        iocs = ["good.com", "flaky.com"]
        # First call: good.com OK, flaky.com empty
        # Next 9 calls: flaky.com still empty (total 10 calls, then permanently failed)
        responses = [{"data": {"good.com": [{"id": 1}], "flaky.com": []}}] * 10
        results, calls = self._run_main(iocs, responses)
        assert len(results) == 1  # only good.com
        assert results[0]["ioc"] == "good.com"
        assert calls == 10  # 1 initial + 9 retries = 10 total

    def test_empty_data_not_cached(self):
        """T005: IOC with empty data after all retries is NOT written to cache"""
        iocs = ["good.com", "flaky.com"]
        responses = [{"data": {"good.com": [{"id": 1}], "flaky.com": []}}] * 11
        results, calls = self._run_main(iocs, responses)
        # flaky.com should NOT appear
        iocs_in_result = {r["ioc"] for r in results}
        assert "flaky.com" not in iocs_in_result

    def test_cache_hit_skips_query(self):
        """T006: Cached IOCs are not queried again"""
        tmpdir = Path(tempfile.mkdtemp())
        api_key_file = tmpdir / "Api-Key.txt"
        api_key_file.write_text("test-key-123")
        ioc_file = tmpdir / "ioc.txt"
        ioc_file.write_text("cached.com\nnew.com")
        cache_dir = tmpdir / "ioc_info_cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "2026-06-01.jsonl"
        cache_file.write_text('{"ioc": "cached.com", "data": [{"id": 1}]}\n')

        call_count = [0]

        def mock_post(*args, **kwargs):
            call_count[0] += 1
            assert kwargs["json"]["params"] == ["new.com"]
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"data": {"new.com": [{"id": 2}]}}
            return mock_resp

        with patch.object(mod, "ROOT", tmpdir), \
             patch.object(mod, "CACHE_DIR", cache_dir), \
             patch.object(mod, "cache_path_for_today", return_value=cache_file), \
             patch("requests.post", mock_post), \
             patch("time.sleep", lambda x: None):
            mod.main()

        result_path = tmpdir / "ioc_info_result.jsonl"
        results = [json.loads(line) for line in result_path.read_text().splitlines()]
        iocs_in_result = {r["ioc"] for r in results}
        assert iocs_in_result == {"cached.com", "new.com"}
        assert call_count[0] == 1

    def test_all_cached_no_query(self):
        """T007: All IOCs cached — no API calls, no UnboundLocalError"""
        tmpdir = Path(tempfile.mkdtemp())
        api_key_file = tmpdir / "Api-Key.txt"
        api_key_file.write_text("test-key")
        ioc_file = tmpdir / "ioc.txt"
        ioc_file.write_text("cached1.com\ncached2.com")
        cache_dir = tmpdir / "ioc_info_cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "2026-06-01.jsonl"
        cache_file.write_text(
            '{"ioc": "cached1.com", "data": [{"id": 1}]}\n'
            '{"ioc": "cached2.com", "data": [{"id": 2}]}\n'
        )

        call_count = [0]

        def mock_post(*args, **kwargs):
            call_count[0] += 1
            raise AssertionError("Should not be called when all IOCs cached")

        with patch.object(mod, "ROOT", tmpdir), \
             patch.object(mod, "CACHE_DIR", cache_dir), \
             patch.object(mod, "cache_path_for_today", return_value=cache_file), \
             patch("requests.post", mock_post):
            mod.main()

        assert call_count[0] == 0
