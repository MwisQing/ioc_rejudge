"""Deterministic local JSONL sidecar provider.

Reads observations from a JSONL file keyed by normalized IOC.  Rows that do
not match a requested target are silently skipped; every requested target
receives an explicit ProviderStatus.

Freshness is derived from ``fetched_at``, the evaluation clock
(``ProviderContext.now`` or wall clock), and the configured TTL.  A row's
claimed ``freshness`` field is never trusted.  Missing, invalid, or future
``fetched_at`` values stay ``unknown``; ages beyond TTL become ``stale``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ioc_rejudge.normalize import parse_ioc_value
from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
)
from ioc_rejudge.parser import is_fresh, normalize_datetime, parse_time
from ioc_rejudge.providers.base import ProviderContext, ProviderResult

# Match live factory defaults: ICP 30 days, other sources 7 days.
_DEFAULT_TTL = timedelta(days=7)
_ICP_TTL = timedelta(days=30)


def _default_ttl_for_name(name: str) -> timedelta:
    if name == "icp":
        return _ICP_TTL
    return _DEFAULT_TTL


def derive_sidecar_freshness(
    fetched_at: datetime | None,
    now: datetime,
    ttl: timedelta,
) -> Freshness:
    """Map fetch time + TTL onto Freshness without trusting row claims.

    - fresh: valid fetched_at within inclusive TTL window
    - stale: valid fetched_at older than TTL
    - unknown: missing, invalid, or future fetched_at
    """
    if not isinstance(ttl, timedelta) or ttl < timedelta(0):
        return Freshness.UNKNOWN
    normalized_now = normalize_datetime(now)
    normalized_fetched = normalize_datetime(fetched_at)
    if normalized_now is None or normalized_fetched is None:
        return Freshness.UNKNOWN
    if normalized_fetched > normalized_now:
        return Freshness.UNKNOWN
    if is_fresh(normalized_fetched, normalized_now, ttl):
        return Freshness.FRESH
    return Freshness.STALE


def _aggregate_target_freshness(values: list[Freshness]) -> Freshness | None:
    if not values:
        return None
    if any(value == Freshness.STALE for value in values):
        return Freshness.STALE
    if any(value == Freshness.UNKNOWN for value in values):
        return Freshness.UNKNOWN
    if all(value == Freshness.FRESH for value in values):
        return Freshness.FRESH
    return Freshness.UNKNOWN


class SidecarProvider:
    """A provider backed by a local JSONL file of pre-fetched observations.

    Each line must be a JSON object with at least ``ioc``, ``kind``,
    ``status``, ``fetched_at``, ``observed_at``, and ``payload``.
    Optional fields: ``scope`` (defaults to *kind*), ``strength``
    (defaults to ``"normal"``), ``raw_ref`` (defaults to ``""``).
    A claimed ``freshness`` field on the row is ignored.

    ``ttl`` defaults to the live-provider TTL for the same name (ICP 30 days,
    others 7 days). Tests and CLI callers may inject an explicit TTL.
    """

    def __init__(
        self,
        name: str,
        path: Path,
        *,
        ttl: timedelta | None = None,
    ):
        self._name = name
        self._path = path
        self.ttl = _default_ttl_for_name(name) if ttl is None else ttl

    @property
    def name(self) -> str:
        return self._name

    def supports(self, target: IocTarget) -> bool:
        """Sidecar can serve any target whose IOC appears in the backing file."""
        return True

    def collect(
        self, targets: list[IocTarget], context: ProviderContext
    ) -> ProviderResult:
        """Read the sidecar file and return observations for matching targets.

        File-not-found and un-decodable files produce ERROR for all targets.
        Unparseable lines produce ERROR for all targets and add an error detail.
        Each requested target that has no matching sidecar row stays NO_DATA.
        """
        observations_by_target: dict[str, list[Observation]] = {
            t.normalized: [] for t in targets
        }
        statuses: dict[str, ProviderStatus] = {
            t.normalized: ProviderStatus.NO_DATA for t in targets
        }
        freshness_values: dict[str, list[Freshness]] = {
            t.normalized: [] for t in targets
        }
        errors: list[str] = []
        target_by_norm: dict[str, IocTarget] = {
            t.normalized: t for t in targets
        }
        eval_now = normalize_datetime(context.now) if context.now is not None else None
        if eval_now is None:
            eval_now = datetime.now(timezone.utc)

        if not self._path.exists():
            for t in targets:
                statuses[t.normalized] = ProviderStatus.ERROR
            errors.append(f"Sidecar file not found: {self._path}")
            return ProviderResult(self._name, [], statuses, errors, 0)

        try:
            text = self._path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            for t in targets:
                statuses[t.normalized] = ProviderStatus.ERROR
            errors.append(f"Cannot decode sidecar file: {self._path}")
            return ProviderResult(self._name, [], statuses, errors, 0)

        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: bad JSON — {exc}")
                for t in targets:
                    statuses[t.normalized] = ProviderStatus.ERROR
                continue

            if not isinstance(row, dict):
                errors.append(f"line {line_no}: expected JSON object, got {type(row).__name__}")
                for t in targets:
                    statuses[t.normalized] = ProviderStatus.ERROR
                continue

            ioc_value = str(row.get("ioc", ""))
            kind = str(row.get("kind", ""))
            if not ioc_value or not kind:
                errors.append(f"line {line_no}: missing required field ioc or kind")
                for t in targets:
                    statuses[t.normalized] = ProviderStatus.ERROR
                continue

            # parse_ioc_value may raise ValueError for malformed URLs
            # (e.g. out-of-range port via urllib.parse).  Treat as ERROR.
            # Canonical identity keeps URL scheme so bare domain / http / https
            # rows never cross-match.
            try:
                normalized_ioc = parse_ioc_value(ioc_value)[0]
            except ValueError as exc:
                errors.append(
                    f"line {line_no}: cannot normalize IOC {ioc_value!r} — {exc}"
                )
                for t in targets:
                    statuses[t.normalized] = ProviderStatus.ERROR
                continue
            if normalized_ioc not in target_by_norm:
                continue  # row for an IOC not in this request — ignore

            target = target_by_norm[normalized_ioc]

            # Parse status enum; unknown values are errors.
            status_str = str(row.get("status", ""))
            try:
                status = ProviderStatus(status_str)
            except ValueError:
                errors.append(
                    f"line {line_no}: unknown ProviderStatus {status_str!r}"
                )
                statuses[target.normalized] = ProviderStatus.ERROR
                continue

            # Parse timestamps via the project-wide parse_time helper.
            fetched_at = parse_time(row.get("fetched_at"))
            observed_at = parse_time(row.get("observed_at"))
            freshness = derive_sidecar_freshness(fetched_at, eval_now, self.ttl)

            # Apply status to the aggregate mapping.
            current = statuses[target.normalized]
            if current != ProviderStatus.ERROR:
                if status == ProviderStatus.ERROR:
                    statuses[target.normalized] = ProviderStatus.ERROR
                elif status == ProviderStatus.DISABLED:
                    if current not in (ProviderStatus.ERROR,):
                        statuses[target.normalized] = ProviderStatus.DISABLED
                elif status == ProviderStatus.SUCCESS:
                    if current not in (ProviderStatus.ERROR, ProviderStatus.DISABLED):
                        statuses[target.normalized] = ProviderStatus.SUCCESS
                elif status == ProviderStatus.NO_DATA:
                    if current == ProviderStatus.NO_DATA:
                        statuses[target.normalized] = ProviderStatus.NO_DATA

            scope = str(row.get("scope", kind))
            strength = str(row.get("strength", "normal"))
            raw_ref = str(row.get("raw_ref", ""))
            payload = row.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}

            observations_by_target[target.normalized].append(Observation(
                ioc=target.normalized,
                scope=scope,
                provider=self._name,
                kind=kind,
                status=status,
                fetched_at=fetched_at,
                observed_at=observed_at,
                freshness=freshness,
                strength=strength,
                payload=payload,
                raw_ref=raw_ref,
            ))
            freshness_values[target.normalized].append(freshness)

        observations = [
            obs for t in targets for obs in observations_by_target[t.normalized]
        ]
        freshnesses: dict[str, Freshness] = {}
        for key, values in freshness_values.items():
            aggregate = _aggregate_target_freshness(values)
            if aggregate is not None:
                freshnesses[key] = aggregate
        return ProviderResult(
            self._name, observations, statuses, errors, 0, freshnesses=freshnesses
        )
