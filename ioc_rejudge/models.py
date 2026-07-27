"""Data structures for IOC rejudgement."""
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Conclusion(str, Enum):
    ALIVE_VALID = "存活有效"
    INACTIVE_VALID = "失活有效"
    GRAY = "灰"
    FALSE_POSITIVE = "误报"
    PENDING_REVIEW = "待复核"


class EvidenceLevel(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class EvidenceStrength(str, Enum):
    STRONG = "strong"
    NORMAL = "normal"
    WEAK = "weak"


@dataclass
class Evidence:
    level: EvidenceLevel
    field: str
    detail: str
    strength: EvidenceStrength = EvidenceStrength.NORMAL
    tags: list[str] = field(default_factory=list)
    provider: str = ""
    observed_at: datetime | None = None
    record_index: int | None = None


@dataclass
class ProfileObservation:
    field: str
    kind: str
    value: str
    severity: str  # suspicious / normal / neutral / conflict
    detail: str
    tags: list[str] = field(default_factory=list)


@dataclass
class RecordSnapshot:
    """A single record's provenance preserved for traceability.

    index: original position in the input record list.
    record_time: best-effort record timestamp (updatetime/inserttime/disposaltime).
    sources: deduplicated source list from this record.
    raw: the original record dict (may be mutated later — copy if needed).
    """

    index: int
    record_time: datetime | None
    sources: list[str]
    raw: dict


@dataclass
class IocProfile:
    observations: list[ProfileObservation] = field(default_factory=list)
    domain: dict = field(default_factory=dict)
    ip: dict = field(default_factory=dict)
    runtime: dict = field(default_factory=dict)


@dataclass
class IocDossier:
    ioc: str
    ioc_type: str
    ports: list[str] = field(default_factory=list)
    evidence_a: list[Evidence] = field(default_factory=list)
    evidence_b: list[Evidence] = field(default_factory=list)
    evidence_c: list[Evidence] = field(default_factory=list)
    evidence_d: list[Evidence] = field(default_factory=list)
    evidence_e: list[Evidence] = field(default_factory=list)
    evidence_f: list[Evidence] = field(default_factory=list)
    latest_material_activity_time: datetime | None = None
    latest_intel_update_time: datetime | None = None
    latest_profile_update_time: datetime | None = None
    source_set: list[str] = field(default_factory=list)
    record_categories: list[str] = field(default_factory=list)
    level: float = 0.0
    hash_entries: list[dict] = field(default_factory=list)
    flint: dict = field(default_factory=dict)
    access: dict = field(default_factory=dict)
    dtree_entries: list[dict] = field(default_factory=list)
    relate_url_entries: list[dict] = field(default_factory=list)
    relate_ip_domain_entries: list[dict] = field(default_factory=list)
    context: str = ""
    comment: str = ""
    family: list[str] = field(default_factory=list)
    tag: list[str] = field(default_factory=list)
    malicious_type: list[str] = field(default_factory=list)
    attck: list[str] = field(default_factory=list)
    certificates: dict = field(default_factory=dict)
    topdomain: dict = field(default_factory=dict)
    icp_website: str = ""
    official_website: str = ""
    page_title: str = ""
    resolv_ip: str = ""
    whois: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    runtime_flags: dict = field(default_factory=dict)
    profile: IocProfile | None = None
    candidate_label: str | None = None
    reason: str = ""
    forbidden_labels: str = ""
    record_snapshots: list[RecordSnapshot] = field(default_factory=list)
    historical_icp_values: list[str] = field(default_factory=list)
    retained_urls: list[str] = field(default_factory=list)
    current_icp_check_complete: bool = False


@dataclass
class Verdict:
    conclusion: Conclusion
    malicious_nature: str
    activity_status: str
    confidence: str
    review_suggestion: str
    candidate_label: str | None
    hit_evidence: str
    forbidden_labels: str
    reason: str
    route: str = "standard"
    disposition: str = "review"
    scope_actions: list[dict] = field(default_factory=list)
    retained_urls: list[str] = field(default_factory=list)
    provider_statuses: dict[str, str] = field(default_factory=dict)
    evidence_origins: list[dict] = field(default_factory=list)
    missing_required_providers: list[str] = field(default_factory=list)
