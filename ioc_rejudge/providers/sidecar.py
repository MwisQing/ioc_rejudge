"""Deterministic local JSONL sidecar provider.

Reads observations from a JSONL file keyed by normalized IOC.  Rows that do
not match a requested target are silently skipped; every requested target
receives an explicit ProviderStatus.
"""

import json
from pathlib import Path

from ioc_rejudge.normalize import normalize_ioc
from ioc_rejudge.observations import (
    Freshness,
    IocTarget,
    Observation,
    ProviderStatus,
)
from ioc_rejudge.parser import parse_time
from ioc_rejudge.providers.base import ProviderContext, ProviderResult


class SidecarProvider:
    """A provider backed by a local JSONL file of pre-fetched observations.

    Each line must be a JSON object with at least ``ioc``, ``kind``,
    ``status``, ``fetched_at``, ``observed_at``, and ``payload``.
    Optional fields: ``scope`` (defaults to *kind*), ``strength``
    (defaults to ``"normal"``), ``raw_ref`` (defaults to ``""``).
    """

    def __init__(self, name: str, path: Path):
        self._name = name
        self._path = path

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
        errors: list[str] = []
        target_by_norm: dict[str, IocTarget] = {
            t.normalized: t for t in targets
        }

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

            # normalize_ioc may raise ValueError for malformed URLs
            # (e.g. out-of-range port via urllib.parse).  Treat as ERROR.
            try:
                normalized_ioc = normalize_ioc(ioc_value)[0]
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
            fetched_at = parse_time(str(row.get("fetched_at", "")))
            observed_at = parse_time(str(row.get("observed_at", "")))

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
                freshness=Freshness.UNKNOWN,
                strength=strength,
                payload=payload,
                raw_ref=raw_ref,
            ))

        observations = [
            obs for t in targets for obs in observations_by_target[t.normalized]
        ]
        return ProviderResult(self._name, observations, statuses, errors, 0)
