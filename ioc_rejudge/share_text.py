"""Free-text leak heuristics for share transform/scan (AES-SIV tokens / REDACTED).

Ported from desensitize_json-v0.7 detection shapes only — no fake substitutes
or value_map.json. Public create/restore/scan APIs remain on share.py.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any, Callable

REDACTED = "[REDACTED]"

_TOKEN_RE = re.compile(r"ss1:([a-z][a-z0-9_-]{0,31}):([A-Za-z0-9_-]+)")
_URL_RE = re.compile(r"(?i)https?://[^\s<>'\"]+")
_IP_RE = re.compile(
    r"(?<![0-9])"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?![0-9.])"
)
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![0-9A-Fa-f:.])"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9.\-])"
)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
_CN_ID_RE = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})"
    r"(?![0-9A-Za-z])"
)
_HASH_EXE_RE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})"
    r"(\.exe\b|exe\b)"
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"(?![Tt]\d{4}(?![0-9A-Za-z]))"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:xn--[A-Za-z0-9-]{1,59}|[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9_\-])"
)
_DOMAIN_GLUED_RE = re.compile(
    r"(^|[0-9A-Za-z\-])"
    r"((?:[A-Za-z][A-Za-z0-9\-]{0,61}\.)+"
    r"(?:com|net|org|cn|io|info|xyz|top|ru|uk|de|jp|kr|tv|cc|me|biz|co|in|us"
    r"|ca|au|br|pl|it|es|nl|se|vip|wang|club|site|online|store|shop|tech|app"
    r"|dev|live|news|blog|world|space|link|click|fun|icu|pro|gov|edu|mil"
    r"|mobi|name|asia|jobs|tel|travel|ai|gg|ly|to|sh|ws|la|mn|ph|pk|bd|ir"
    r"|sa|ae|za|mx|ar|cl|pe|ve|invalid)(?:\.[A-Za-z]{2,})?)\b"
)
_WINDOWS_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\|\\\\)[^\s\"'|<>]+")
_UNIX_PATH_RE = re.compile(
    r"(?<!https:)(?<!http:)(?<![A-Za-z0-9])/(?:[^\s\"'|<>/]+/){1,}[^\s\"'|<>]*"
)
_BANG_PATH_RE = re.compile(r"[A-Za-z]:(?:![^!\s\"'<>|;,。\r\n]+)+")
_IPV4_TRUNC_RE = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){2}\d{1,3})(\.{2,}|…)")
_IPV4_UNDERSCORE_FULL = re.compile(
    r"\A(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)_){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\Z"
)
_IPV4_UNDERSCORE_RE = re.compile(
    r"(?<![0-9A-Za-z_])"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)_){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?![0-9A-Za-z_])"
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
_EC2_HOST_RE = re.compile(r"\bEC2AMAZ-[A-Z0-9]{6,}\b")
_ECS_HOST_RE = re.compile(r"\bECS\d{3,}\b")
_ALIYUN_INSTANCE_RE = re.compile(r"\biZ[A-Za-z0-9]{6,}Z\b")
_ATTCK_RE = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z", re.IGNORECASE)
_LABELED_NAME_RE = re.compile(
    r"(?i)(?:"
    r"Producer|Author|Reporter|Owner|Creator|Operator|Analyst|Engineer|Submitter"
    r"|Submit|Submitted|Report|Reported|Create|Created|Provide|Provided"
    r"|Discover|Discovered|Maintain|Maintained|Publish|Published"
    r"|Update|Updated|Write|Written|Design|Designed"
    r"|Detect|Detected|Found|Analyze|Analyzed"
    r"|Investigate|Investigated|Research|Researched"
    r")"
    r"(?:\s*[:：]\s*|\s+by\s*[:：]?\s*)"
    r"([A-Za-z][A-Za-z0-9\-]{1,29})(?![A-Za-z0-9_\-])"
)
_CN_CONTACT_RE = re.compile(
    r"(?:请联系|联系)"
    r"(?:\s*(?:QQ|微信|邮箱|电话|[Tt][Ee][Ll]))?"
    r"(?:\s*[:：]?|\s+)\s*"
    r"([A-Za-z0-9][A-Za-z0-9._\-@]{2,39})"
    r"(?![A-Za-z0-9._\-])"
)
_INLINE_SECRET_RE = re.compile(
    r"\b(?:authorization|api[-_]?key|access[-_]?key|token|secret|password)"
    r"\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^\s,;]+"
    r"|\bbearer\s+[A-Za-z0-9._~+/=-]+"
    r"|\b(?:cookie|set-cookie)\s*[:=]\s*[^\r\n,]+",
    re.IGNORECASE,
)
_DEFANG_PATTERNS = [
    (re.compile(r"\[\s*\]\s*\[\s*\]\s*\."), "."),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\[\s*\]\s*\.\s*\[\s*\]"), "."),
    (re.compile(r"\[\s*\]"), "."),
    (re.compile(r"\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"hxxps?://", re.I), "http://"),
    (re.compile(r"\bxttps?://", re.I), "http://"),
    (re.compile(r"\bmeow://", re.I), "http://"),
]
_BASE64_JSON_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")


def defang_normalize(value: str) -> str:
    if not value:
        return value
    out = value
    for pattern, replacement in _DEFANG_PATTERNS:
        out = pattern.sub(replacement, out)
    out = out.replace("%2F", "/").replace("%2f", "/")
    out = out.replace("%3A", ":").replace("%3a", ":")
    return out


def is_underscore_ipv4(value: str) -> bool:
    return bool(_IPV4_UNDERSCORE_FULL.match(value.strip()))


def is_cloud_host(value: str) -> bool:
    text = value.strip()
    if not text or " " in text or "/" in text or "." in text:
        return False
    return bool(
        _EC2_HOST_RE.fullmatch(text)
        or _ECS_HOST_RE.fullmatch(text)
        or _ALIYUN_INSTANCE_RE.fullmatch(text)
    )


def is_attck_id(value: str) -> bool:
    return bool(_ATTCK_RE.match(value.strip()))


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def _email_fullmatch(value: str) -> bool:
    return bool(re.fullmatch(
        r"[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,63}",
        value.strip(),
    ))


def try_parse_base64_json(value: str) -> Any | None:
    text = value.strip()
    if len(text) < 32 or len(text) % 4 != 0:
        return None
    if " " in text or "\n" in text or "\t" in text:
        return None
    if not _BASE64_JSON_RE.fullmatch(text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
        payload = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not payload or payload[0] not in "{[":
        return None
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, (dict, list)):
        return None
    return parsed


def encode_base64_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def transform_free_text(
    value: str,
    *,
    encode: Callable[[str, str], str],
    redact: Callable[[str], str],
    safe_url: Callable[[str], str],
    names: list[str],
) -> str:
    """Defang, then greedily replace non-overlapping entities (longest first)."""
    if not value:
        return value
    text = defang_normalize(value)
    candidates: list[tuple[int, int, str]] = []

    def add(start: int, end: int, replacement: str) -> None:
        if start < end:
            candidates.append((start, end, replacement))

    for match in _JWT_RE.finditer(text):
        add(match.start(), match.end(), redact(match.group(0)))

    for match in _URL_RE.finditer(text):
        add(match.start(), match.end(), encode("url", safe_url(match.group(0))))

    for match in _INLINE_SECRET_RE.finditer(text):
        add(match.start(), match.end(), redact(match.group(0)))

    for match in _EMAIL_RE.finditer(text):
        add(match.start(), match.end(), encode("email", match.group(0)))

    for match in _IP_RE.finditer(text):
        raw = match.group(0)
        if not _is_ipv4(raw):
            continue
        start = match.start()
        if start >= 2 and text[start - 1] == "." and text[start - 2].isdigit():
            continue
        add(start, match.end(), encode("ip", raw))

    for match in _IPV6_CANDIDATE_RE.finditer(text):
        raw = match.group(0)
        if _is_ipv6(raw):
            add(match.start(), match.end(), encode("ip", raw))

    for match in _IPV4_TRUNC_RE.finditer(text):
        add(
            match.start(),
            match.end(),
            encode("ip", match.group(1)) + match.group(2),
        )

    for match in _IPV4_UNDERSCORE_RE.finditer(text):
        add(match.start(), match.end(), encode("ip", match.group(0)))

    for match in _BANG_PATH_RE.finditer(text):
        add(match.start(), match.end(), encode("path", match.group(0)))

    for match in _WINDOWS_PATH_RE.finditer(text):
        add(match.start(), match.end(), encode("path", match.group(0)))

    for match in _UNIX_PATH_RE.finditer(text):
        add(match.start(), match.end(), encode("path", match.group(0)))

    for match in _HASH_EXE_RE.finditer(text):
        add(match.start(1), match.end(1), encode("hash", match.group(1)))

    for match in _HASH_RE.finditer(text):
        add(match.start(), match.end(), encode("hash", match.group(0)))

    for match in _UUID_RE.finditer(text):
        add(match.start(), match.end(), encode("id", match.group(0)))

    for match in _PHONE_RE.finditer(text):
        add(match.start(), match.end(), encode("person", match.group(0)))

    for match in _CN_ID_RE.finditer(text):
        add(match.start(), match.end(), encode("id", match.group(0)))

    for match in _DOMAIN_RE.finditer(text):
        raw = match.group(0)
        if is_attck_id(raw) or not raw or " " in raw:
            continue
        add(match.start(), match.end(), encode("domain", raw))

    for match in _DOMAIN_GLUED_RE.finditer(text):
        seg = match.group(2)
        if is_attck_id(seg) or "." not in seg:
            continue
        add(match.start(2), match.end(2), encode("domain", seg))

    for pattern in (_EC2_HOST_RE, _ECS_HOST_RE, _ALIYUN_INSTANCE_RE):
        for match in pattern.finditer(text):
            add(match.start(), match.end(), encode("host", match.group(0)))

    for match in _LABELED_NAME_RE.finditer(text):
        add(match.start(1), match.end(1), encode("person", match.group(1)))

    for match in _CN_CONTACT_RE.finditer(text):
        token = match.group(1)
        if _email_fullmatch(token):
            kind = "email"
        elif token.isdigit() and 5 <= len(token) <= 12:
            kind = "person"
        else:
            kind = "person"
        add(match.start(1), match.end(1), encode(kind, token))

    for name in names:
        if not name:
            continue
        start = 0
        while True:
            index = text.find(name, start)
            if index < 0:
                break
            add(index, index + len(name), encode("person", name))
            start = index + len(name)

    if not candidates:
        return text

    candidates.sort(key=lambda item: (-(item[1] - item[0]), item[0]))
    chosen: list[tuple[int, int, str]] = []
    for start, end, replacement in candidates:
        if any(not (end <= left or start >= right) for left, right, _ in chosen):
            continue
        chosen.append((start, end, replacement))
    chosen.sort(key=lambda item: item[0])

    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in chosen:
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def residual_finding_codes(scrubbed: str) -> list[str]:
    """Finding codes for leftovers the strict scanner must still catch."""
    codes: list[str] = []
    if _JWT_RE.search(scrubbed):
        codes.append("jwt")
    if (
        _EC2_HOST_RE.search(scrubbed)
        or _ECS_HOST_RE.search(scrubbed)
        or _ALIYUN_INSTANCE_RE.search(scrubbed)
    ):
        codes.append("cloud_host")
    if _HASH_EXE_RE.search(scrubbed):
        codes.append("hash")
    if _IPV4_UNDERSCORE_RE.search(scrubbed):
        codes.append("underscore_ip")
    return codes


__all__ = [
    "REDACTED",
    "defang_normalize",
    "encode_base64_json",
    "is_attck_id",
    "is_cloud_host",
    "is_underscore_ipv4",
    "residual_finding_codes",
    "transform_free_text",
    "try_parse_base64_json",
]
