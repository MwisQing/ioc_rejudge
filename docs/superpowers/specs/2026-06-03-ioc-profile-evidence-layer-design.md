# IOC Profile Evidence Layer Design

## Purpose

This design expands the APT IOC snapshot rejudgement tool with a profile evidence layer. The goal is to reduce false negatives where real threats are classified as `误报` because the current judgement tree uses too few fields from the API snapshot.

The current implementation already has the A-F evidence model and four final conclusions:

```text
存活有效 / 失活有效 / 误报 / 待复核
```

This work keeps those labels and the existing evidence-tree discipline. It does not introduce scoring, averaging, voting, or external lookup.

The main change is to add a structured profile extraction layer before evidence extraction:

```text
parser.read_jsonl_snapshot()
  -> normalize.merge_records()
  -> profile.extract_profile()
  -> evidence.extract_evidence()
  -> adjudicator.adjudicate()
  -> export.export_jsonl/csv/excel()
```

The profile layer converts raw fields such as WHOIS, passive DNS, reverse domains, runtime flags, and HTTP state into explainable observations. Evidence extraction then maps those observations into A-F evidence. The adjudicator only consumes evidence, not raw profile fields.

## Problem

The API snapshot contains richer information than the current tool uses. Several fields are merged weakly or not used at all:

- `whois` is not preserved in `IocDossier`.
- IP reverse or passive DNS context from `relate_ip_domain`, `dtree`, and `flint.ip` is treated too shallowly.
- `dtree` is only used for recent activity time; it does not consider related domain shape, malicious level, or freshness.
- `flint.ip` is not used as an infrastructure relationship.
- Runtime signals such as `risk`, `fdark`, `alert`, `block`, `black`, `ml_*`, `reachable`, `http.status`, and `current_status` do not participate in judgement.
- Normalization evidence can trigger `误报` when direct A/C evidence is absent, even if weaker threat residue still exists.

The highest-risk path is:

```text
no A
no C
has E
=> 误报
```

This can hide real threats when E-level normal-business evidence exists but the IOC still has unresolved threat residue such as high-level hashes, strong sources, malicious reverse domains, suspicious new registration, or runtime threat flags.

## Non-Goals

This work does not:

- Query external DNS, WHOIS, HTTP, TIP, sandbox, or search services.
- Change the four conclusion labels.
- Replace the A-F evidence model.
- Introduce score-based or weighted judgement.
- Treat `whois.updatedDate`, `updatetime`, `reachable`, or `http.status` as standalone activity evidence.
- Treat HTTP unreachable, expired certificates, or expired WHOIS as standalone false-positive evidence.
- Merge IOC evidence across JSONL rows.
- Change API collection scripts.

## Architecture

### New Module

Add:

```text
ioc_rejudge/profile.py
```

Responsibilities:

- Build an `IocProfile` from an `IocDossier`.
- Convert raw profile fields into `ProfileObservation` objects.
- Keep observations explainable and field-addressable.
- Avoid final judgement decisions.

The profile module must not call the adjudicator and must not mutate verdicts.

### Existing Module Changes

`models.py`:

- Add raw fields currently missing from `IocDossier`.
- Add profile dataclasses.
- Keep existing `Evidence`, `IocDossier`, and `Verdict` APIs compatible.

`normalize.py`:

- Preserve merged profile-relevant raw fields.
- Keep all evidence-bearing values rather than overwriting older useful values with newer empty values.

`evidence.py`:

- Run profile extraction before or inside `extract_evidence`.
- Map `ProfileObservation` objects into D/E/F evidence and, only where justified, auxiliary B/C support.
- Do not let profile observations directly become final labels.

`adjudicator.py`:

- Add a false-positive protection gate.
- Block automatic `误报` when threat residue exists.

`cli.py` and `export.py`:

- Include profile details in output so analysts can see why an IOC was blocked from automatic `误报`.

## Data Model

### IocDossier Additions

Add these fields to `IocDossier`:

```text
whois: dict
http: dict
runtime_flags: dict
profile: IocProfile | None
```

`runtime_flags` stores normalized copies of fields such as:

```text
risk
fdark
alert
alert_score
block
black
ml_black
ml_cls
ml_confidence
current_status
reachable
processed
task_status
```

The exact field list can be conservative in the first implementation, but the fields above should be considered the intended input surface.

### ProfileObservation

Use a small dataclass:

```text
ProfileObservation
- field: str
- kind: str
- value: str
- severity: str
- detail: str
- tags: list[str]
```

Allowed `severity` values:

```text
suspicious
normal
neutral
conflict
```

Examples:

```text
field="whois.createdDate"
kind="domain_age"
value="2026-05-20"
severity="suspicious"
detail="domain registered within 30 days"
tags=["new_domain"]
```

```text
field="relate_ip_domain"
kind="ip_reverse_domain_risk"
value="3 high-risk related domains"
severity="suspicious"
detail="IP has multiple related domains with level >= 70"
tags=["pdns", "high_related_level"]
```

### IocProfile

Use one profile container:

```text
IocProfile
- observations: list[ProfileObservation]
- domain: dict
- ip: dict
- runtime: dict
```

The `domain`, `ip`, and `runtime` dicts may hold summarized values useful for export, such as:

```text
domain.age_days
domain.is_new
domain.is_short_lived
domain.has_trusted_business_identity
domain.looks_random
ip.related_domain_count
ip.high_risk_related_domain_count
ip.recent_related_domain_count
ip.random_related_domain_count
runtime.has_threat_flag
runtime.has_benign_conflict
```

These summaries are not scores. They are named facts.

## Field Mapping

### Domain Profile

Input fields:

```text
whois.createdDate
whois.updatedDate
whois.expiresDate
whois.registrantEmail
whois.registrantName
privacyprotect_whois
icp_website
official_website
page_title
topdomain
```

Observations:

- New domain: `createdDate` within the configured activity window or a stricter first-version threshold such as 30 days.
- Mature domain: `createdDate` older than one year.
- Short-lived domain: `expiresDate - createdDate` is unusually short when both dates exist.
- Near expiry or expired: auxiliary only; never a standalone verdict driver.
- Missing registration identity or privacy protection: auxiliary D/E context only.
- Trusted business identity: `icp_website + official_website` both present, optionally with consistent `page_title`.
- Popular or normal top domain: normal E support only when no threat residue exists.
- Random-looking domain: suspicious D support when combined with threat residue or recent registration.

### IP Profile

Input fields:

```text
flint
dtree[]
relate_ip_domain[]
resolv_ip
topdomain
```

Observations:

- Recent passive DNS activity: `dtree[].last` or `flint.last_seen` within `activity_window_days`.
- High-risk related domains: `relate_ip_domain[].level` or `dtree[].level` at or above the malicious threshold.
- Multiple related domains: useful for infrastructure context.
- Random-looking related domains: suspicious when many related domains have generated-looking labels.
- Shared infrastructure: normalizing E support when tags or text indicate CDN, cloud, IDC, shared hosting, parking, or normal business mixing.
- Mixed infrastructure: conflict when normal-business fields and high-risk related domains both exist.

Rules:

- Related domains without timestamps do not become B evidence.
- Recent related-domain activity can support B only when an A/C malicious chain already exists.
- High-risk related domains without A/C become strong D and block automatic `误报`.

### Runtime Profile

Input fields:

```text
access
reachable
http.status
current_status
risk
fdark
alert
alert_score
block
black
ml_black
ml_cls
ml_confidence
processed
task_status
```

Observations:

- Access activity: `access.end` with positive `client_count` remains B evidence as today.
- Threat runtime flags: `block=true`, `black=true`, `ml_black=true`, high `alert_score`, or explicit malicious markers in `fdark`.
- Benign conflict markers: negative `risk`, `NOT_A_VIRUS`, normal-port explanations, or benign family labels.
- HTTP state: `http.status`, `reachable`, and `current_status` are F-level or conflict context, not standalone final evidence.

Rules:

- Threat runtime flags can block automatic `误报`.
- Benign runtime markers cannot override direct A evidence.
- Benign runtime markers plus unresolved high-risk evidence should produce `待复核`, not `误报`.

## Evidence Mapping

Profile observations map into evidence as follows.

### D-Level Additions

Add D evidence for:

```text
ip_pdns_related_domains
suspicious_domain_age
suspicious_reverse_domains
threat_runtime_flags
high_level_hash_without_direct_ioc
strong_source_without_direct_a
random_related_domain_shape
```

These show threat residue or suspicious infrastructure but are not enough by themselves to produce `存活有效`.

### E-Level Additions

Add E evidence for:

```text
stable_business_domain
trusted_business_identity
shared_infrastructure
normal_runtime_signals
benign_family_or_risk_conflict
popular_normal_domain
```

E evidence still cannot overturn strong A. E evidence only supports `误报` when A/C are absent and threat residue is absent.

### F-Level Additions

Add F evidence for:

```text
whois.updatedDate
http.status
reachable
current_status
profile_update_only
whois_expiry_without_threat_context
```

F remains explanatory only.

### Auxiliary B/C Support

Profile observations may support B/C only under strict conditions:

- Recent `dtree.last` or `flint.last_seen` can support B when a malicious chain already exists.
- Recent related domains can support B only when linked to existing A/C context.
- Old WHOIS or mature domain age does not create C.
- New domain age does not create A alone.

## False-Positive Protection Gate

Add an adjudicator helper:

```text
_has_threat_residue(dossier) -> bool
```

It returns true when any of these exist:

- Strong or suspicious D evidence from profile observations.
- `relate_ip_domain` or `dtree` contains entries with level at or above `historical_malicious_level`.
- IP profile has multiple high-risk or random-looking related domains.
- `flint.last_seen` is recent and infrastructure relations exist.
- `source_set` contains a strong source but A evidence did not form.
- `hash_entries` exist with max hash level at or above `hash_malicious_level`.
- `malicious_type` or `attck` is non-empty.
- `family` or `tag` contains explicit malicious vocabulary such as trojan, malware, backdoor, rat, c2, malicious, spyware, botnet, or their Chinese equivalents.
- Runtime flags indicate threat, blocking, blacklisting, or ML malicious state.
- New or random-looking domain also has hash, source, relate_url, relate_ip_domain, or dtree residue.
- Normalization evidence conflicts with unresolved high-risk hash, source, context, or infrastructure evidence.

This helper is a boolean protection gate, not a score.

## Adjudicator Changes

Current risky path:

```text
no A
no C
has E
=> 误报
```

New path:

```text
no A
no C
has E
has threat residue
=> 待复核

no A
no C
has E
no threat residue
=> 误报
```

Full intended tree:

```text
1. If A exists:
   - A + B -> candidate 存活有效.
   - A + C or A without B -> candidate 失活有效 or 待复核 according to existing rules.
   - Strong A + strong E -> 待复核 with candidate_label.
   - Weak E may lower confidence or raise review, but cannot produce 误报.

2. If no A but C exists:
   - If strong E or profile conflict exists -> 待复核.
   - Otherwise -> 失活有效.

3. If no A/C but E exists:
   - If _has_threat_residue(dossier) -> 待复核.
   - Otherwise -> 误报.

4. If no A/C/E but D exists:
   - 待复核.
   - Strong or recent profile D -> 必看.
   - Weak D -> 抽检.

5. If no material evidence exists:
   - 待复核 / 低置信 / 必看.
```

Expected behavior changes:

```text
official_website + high-risk IP PDNS reverse domains -> 待复核, not 误报
official_website + high-level hash without IOC closure -> 待复核, not 误报
official_website + new random-looking domain -> 待复核, not 误报
official_website + no threat residue -> 误报
```

## Export Changes

Add optional output fields:

```text
profile_observation_detail
profile_domain_summary
profile_ip_summary
profile_runtime_summary
threat_residue
threat_residue_detail
```

The detail format should be compact and reviewable:

```text
relate_ip_domain [suspicious,pdns,high_related_level]: 3 related domains level >= 70
whois.createdDate [suspicious,new_domain]: domain registered within 30 days
risk [conflict,benign_runtime]: risk=-60 but high-level hash remains unresolved
```

Excel output should keep these fields near the evidence detail columns.

## Testing Requirements

Add tests in:

```text
tests/test_profile.py
tests/test_profile_adjudication.py
```

Required scenarios:

1. New domain with normal-business field and high-risk related domain:
   - Input: `official_website`, recent `whois.createdDate`, high-level `relate_ip_domain`.
   - Expected: `待复核`, not `误报`.

2. Mature normal business domain:
   - Input: old `whois.createdDate`, `icp_website`, `official_website`, normal `page_title`, no threat residue.
   - Expected: `误报`.

3. IP with recent high-risk passive DNS reverse domains:
   - Input: IP IOC, multiple `relate_ip_domain` or `dtree` entries with level >= 70, plus normalizing field.
   - Expected: `待复核` and `必看` or `抽检`, not `误报`.

4. Recent `dtree` activity without direct A:
   - Input: recent `dtree.last`, suspicious related domain, no direct context match.
   - Expected: strong D or B auxiliary only when malicious chain exists; final should not be automatic `误报`.

5. High-level hash without IOC closure:
   - Input: `hash.level >= 70`, `official_website`, context does not mention IOC.
   - Expected: `待复核`, not `误报`.

6. Strong A remains dominant:
   - Input: context directly mentions IOC in TCP/HTTP/DNS plus normal WHOIS/topdomain fields.
   - Expected: no automatic `误报`; strong A + strong E still becomes `待复核`.

7. WHOIS update does not become activity:
   - Input: only recent `whois.updatedDate`.
   - Expected: F evidence only; no `存活有效`.

8. HTTP unreachable does not become false positive:
   - Input: only `reachable=false` or `http.status=404`.
   - Expected: not automatic `误报`.

9. Runtime benign conflict with threat residue:
   - Input: negative `risk` or `NOT_A_VIRUS` plus high-level hash or strong source.
   - Expected: `待复核`, not `误报`.

10. Pure normalization:
    - Input: ICP, official website, page title, mature domain, no threat residue.
    - Expected: `误报`.

Regression command:

```bash
python -m pytest tests/ -v
```

All existing tests must still pass. Tests touching `evidence.py` or `adjudicator.py` must verify both evidence details and final verdicts.

## Acceptance Criteria

The work is acceptable when:

- `IocDossier` preserves WHOIS, HTTP, runtime, and profile-relevant infrastructure fields.
- `profile.extract_profile()` produces explainable observations without final judgement decisions.
- WHOIS registration age, passive DNS/reverse domains, runtime flags, and normal-business fields map into A-F evidence through explicit rules.
- Automatic `误报` is blocked when threat residue exists.
- Pure normal-business cases can still become `误报`.
- `whois.updatedDate`, `updatetime`, `reachable`, and `http.status` cannot independently support `存活有效`.
- HTTP unreachable, expired WHOIS, and benign runtime markers cannot independently prove `误报`.
- Strong A behavior remains preserved.
- Strong A + strong E still becomes `待复核` with `candidate_label`.
- Excel, CSV, and JSONL outputs expose profile details enough for analyst review.
- Full regression passes with `python -m pytest tests/ -v`.

## Implementation Order

1. Add profile dataclasses to `models.py`.
2. Extend `IocDossier` and `normalize.merge_records()` to preserve WHOIS, HTTP, and runtime fields.
3. Add `profile.py` with observation extraction and focused tests.
4. Map profile observations into D/E/F evidence in `evidence.py`.
5. Add `_has_threat_residue()` and false-positive protection in `adjudicator.py`.
6. Add export detail fields.
7. Add the required profile adjudication tests.
8. Run full regression.

This order keeps the first steps mostly data-preserving, then introduces behavior changes with targeted tests.
