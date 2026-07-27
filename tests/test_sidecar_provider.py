"""Contract tests for provider protocol and deterministic sidecar provider."""
import json
from dataclasses import FrozenInstanceError
from datetime import datetime
from pathlib import Path

import pytest

from ioc_rejudge.inputs import read_input_bundle
from ioc_rejudge.observations import IocTarget, Observation, ProviderStatus, Freshness
from ioc_rejudge.providers.base import Provider, ProviderContext, ProviderResult
from ioc_rejudge.providers.sidecar import SidecarProvider


# --- Provider status semantics ---

def test_sidecar_provider_distinguishes_no_data_and_error(tmp_path):
    """A valid sidecar row with status=success produces SUCCESS and an Observation."""
    path = tmp_path / "whois.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "example.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {"expires_at": "2027-01-01"},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 1
    assert result.observations[0].provider == "whois"


def test_sidecar_bad_line_is_reported(tmp_path):
    """An unparseable line marks all targets as ERROR and populates errors."""
    path = tmp_path / "bad.jsonl"
    path.write_text("not-json\n", encoding="utf-8")
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("icp", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.errors) > 0


def test_sidecar_no_data_for_missing_target(tmp_path):
    """A target not present in the sidecar file stays NO_DATA."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "other.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA


def test_sidecar_disabled_status_preserved(tmp_path):
    """An explicitly disabled row yields DISABLED, not NO_DATA."""
    path = tmp_path / "disabled.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "example.invalid", "kind": "icp", "status": "disabled",
            "fetched_at": "", "observed_at": "", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("icp", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.DISABLED


def test_sidecar_error_status_preserved(tmp_path):
    """An explicitly error row yields ERROR."""
    path = tmp_path / "error.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "example.invalid", "kind": "icp", "status": "error",
            "fetched_at": "", "observed_at": "", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("icp", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.errors) == 0  # explicit error row is not a parse error


def test_sidecar_unknown_enum_defaults_to_error(tmp_path):
    """An unrecognized status string produces ERROR for that target."""
    path = tmp_path / "unknown.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "example.invalid", "kind": "icp", "status": "bogus_status",
            "fetched_at": "", "observed_at": "", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("icp", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.errors) > 0


def test_sidecar_file_not_found(tmp_path):
    """A missing sidecar file sets all targets to ERROR."""
    path = tmp_path / "nonexistent.jsonl"
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.errors) > 0


def test_sidecar_empty_file(tmp_path):
    """An empty sidecar file yields NO_DATA for all targets."""
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA


# --- IOC matching ---

def test_sidecar_domain_and_url_not_conflated(tmp_path):
    """A sidecar row for a URL should not match a domain-only target with the same host."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "https://evil.invalid/path", "kind": "http", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {"status": 200},
        }) + "\n",
        encoding="utf-8",
    )
    domain_target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    url_target = read_input_bundle(None, ["https://evil.invalid/path"]).targets[0]
    result = SidecarProvider("http", path).collect([domain_target, url_target], ProviderContext(offline=True))
    # Domain target: no matching row → NO_DATA
    assert result.statuses[domain_target.normalized] == ProviderStatus.NO_DATA
    # URL target: matching row → SUCCESS
    assert result.statuses[url_target.normalized] == ProviderStatus.SUCCESS


def test_sidecar_wrong_ioc_not_matched(tmp_path):
    """Sidecar rows for non-requested IOCs must not pollute result."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "pollution.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["example.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.NO_DATA
    assert len(result.observations) == 0


def test_invalid_ioc_in_sidecar_does_not_crash(tmp_path):
    """Sidecar rows whose IOC crashes normalize_ioc (e.g. URL with out-of-range
    port) must not propagate the exception — report ERROR with error detail."""
    path = tmp_path / "bad_iocs.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "http://evil.invalid:99999/", "kind": "http", "status": "success",
            "fetched_at": "", "observed_at": "", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("test", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.ERROR
    assert len(result.errors) > 0


# --- Multiple targets and observations ---

def test_observations_grouped_by_target_order_not_sidecar_row_order(tmp_path):
    """Targets [a,b] with interleaved sidecar rows [b1,a1,b2,a2] → [a1,a2,b1,b2].

    Observations must be grouped by target request order; within each target
    the original sidecar row order is preserved.
    """
    path = tmp_path / "interleaved.jsonl"
    rows = [
        {"ioc": "b.invalid", "kind": "p1", "status": "success",
         "fetched_at": "2026-07-23 10:00:00", "observed_at": "2027-01-01",
         "payload": {"seq": "b1"}},
        {"ioc": "a.invalid", "kind": "p1", "status": "success",
         "fetched_at": "2026-07-23 10:00:00", "observed_at": "2027-01-01",
         "payload": {"seq": "a1"}},
        {"ioc": "b.invalid", "kind": "p2", "status": "success",
         "fetched_at": "2026-07-23 10:00:00", "observed_at": "2027-01-01",
         "payload": {"seq": "b2"}},
        {"ioc": "a.invalid", "kind": "p2", "status": "success",
         "fetched_at": "2026-07-23 10:00:00", "observed_at": "2027-01-01",
         "payload": {"seq": "a2"}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    targets = read_input_bundle(None, ["a.invalid", "b.invalid"]).targets
    result = SidecarProvider("test", path).collect(targets, ProviderContext(offline=True))
    seqs = [obs.payload["seq"] for obs in result.observations]
    assert seqs == ["a1", "a2", "b1", "b2"]
    assert result.statuses["a.invalid"] == ProviderStatus.SUCCESS
    assert result.statuses["b.invalid"] == ProviderStatus.SUCCESS


def test_sidecar_multiple_targets_preserve_order(tmp_path):
    """Statuses and observations must follow request target order."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "b.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    targets = read_input_bundle(None, ["a.invalid", "b.invalid", "c.invalid"]).targets
    result = SidecarProvider("whois", path).collect(targets, ProviderContext(offline=True))
    assert list(result.statuses.keys()) == ["a.invalid", "b.invalid", "c.invalid"]
    assert result.statuses["a.invalid"] == ProviderStatus.NO_DATA
    assert result.statuses["b.invalid"] == ProviderStatus.SUCCESS
    assert result.statuses["c.invalid"] == ProviderStatus.NO_DATA


def test_sidecar_multiple_observations_same_ioc(tmp_path):
    """Multiple sidecar rows for the same IOC all become observations."""
    path = tmp_path / "data.jsonl"
    rows = [
        {"ioc": "evil.invalid", "kind": "whois", "status": "success",
         "fetched_at": "2026-07-23 10:00:00", "observed_at": "2027-01-01",
         "payload": {"key": "a"}},
        {"ioc": "evil.invalid", "kind": "pdns", "status": "success",
         "fetched_at": "2026-07-23 11:00:00", "observed_at": "2027-01-02",
         "payload": {"key": "b"}},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("multi", path).collect([target], ProviderContext(offline=True))
    assert result.statuses[target.normalized] == ProviderStatus.SUCCESS
    assert len(result.observations) == 2
    assert result.observations[0].payload["key"] == "a"
    assert result.observations[1].payload["key"] == "b"


# --- Optional fields ---

def test_sidecar_scope_field_preserved(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "scope": "domain",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.observations[0].scope == "domain"


def test_sidecar_scope_defaults_to_kind(tmp_path):
    """When scope is omitted, it falls back to kind."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.observations[0].scope == "whois"


def test_sidecar_strength_and_raw_ref_preserved(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01",
            "strength": "strong", "raw_ref": "row-001",
            "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.observations[0].strength == "strong"
    assert result.observations[0].raw_ref == "row-001"


# --- Time parsing ---

def test_sidecar_fetched_at_parsed(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "20270101",
            "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert isinstance(result.observations[0].fetched_at, datetime)
    assert isinstance(result.observations[0].observed_at, datetime)


def test_sidecar_empty_times_become_none(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "fetched_at": "", "observed_at": "",
            "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.observations[0].fetched_at is None
    assert result.observations[0].observed_at is None


# --- Provider protocol compliance ---

def test_sidecar_provider_implements_provider_protocol():
    provider = SidecarProvider("test", Path("/tmp/test.jsonl"))
    assert isinstance(provider, Provider)
    assert provider.name == "test"
    assert provider.supports(IocTarget("evil.invalid", "evil.invalid", "domain", "evil.invalid"))


def test_sidecar_provider_cache_hits_zero(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "ioc": "evil.invalid", "kind": "whois", "status": "success",
            "fetched_at": "2026-07-23 10:00:00",
            "observed_at": "2027-01-01", "payload": {},
        }) + "\n",
        encoding="utf-8",
    )
    target = read_input_bundle(None, ["evil.invalid"]).targets[0]
    result = SidecarProvider("whois", path).collect([target], ProviderContext(offline=True))
    assert result.cache_hits == 0


# --- ProviderContext immutability ---

def test_provider_context_is_frozen():
    ctx = ProviderContext(offline=True, refresh=False)
    assert ctx.offline is True
    assert ctx.refresh is False
    assert ctx.run_dir is None
    with pytest.raises(FrozenInstanceError):
        ctx.offline = False


# --- Result structure ---

def test_provider_result_has_required_fields():
    result = ProviderResult(name="test")
    assert result.name == "test"
    assert result.observations == []
    assert result.statuses == {}
    assert result.errors == []
    assert result.cache_hits == 0
