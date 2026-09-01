"""Create and restore encrypted, local-only IOC sharing bundles.

The share format is deliberately separate from the adjudication input format.
It is a safe context-transfer format for an analyst or an AI service, not a
replacement for the local pipeline.  Identity-bearing values become
deterministic AES-SIV tokens so equality and relationships survive while the
key remains local.  Credential-like values are irreversibly redacted.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any, Callable, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESSIV


SCHEMA = "ioc-share/v1"
KEY_SCHEMA = "ioc-share-key/v1"
ALGORITHM = "AES-256-SIV"
KEY_BYTES = 64
KDF = "scrypt"
KDF_N = 2**14
KDF_R = 8
KDF_P = 1
REDACTED = "[REDACTED]"

_TOKEN_RE = re.compile(r"ss1:([a-z][a-z0-9_-]{0,31}):([A-Za-z0-9_-]+)")
_URL_RE = re.compile(r"(?i)https?://[^\s<>'\"]+")
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![0-9A-Fa-f:.])"
)
_EMAIL_RE = re.compile(r"\b[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,63}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
_CN_ID_RE = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")
_HASH_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b"
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:xn--[A-Za-z0-9-]{1,59}|[A-Za-z]{2,63})\b"
)
_WINDOWS_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\|\\\\)[^\s\"']+")
_UNIX_PATH_RE = re.compile(r"(?<!https:)(?<!http:)(?<![A-Za-z0-9])/(?:[^\s\"']+/)+[^\s\"']*")
_URL_USERINFO_RE = re.compile(r"(?i)\A(https?://)[^/?#\s@]+@")
_INLINE_SECRET_RE = re.compile(
    r"\b(?:authorization|api[-_]?key|access[-_]?key|token|secret|password)"
    r"\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^\s,;]+"
    r"|\bbearer\s+[A-Za-z0-9._~+/=-]+"
    r"|\b(?:cookie|set-cookie)\s*[:=]\s*[^\r\n,]+",
    re.IGNORECASE,
)
_CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(?:authorization|api[-_]?key|apikey|access[-_]?key|password|secret|"
    r"cookie|set-cookie|bearer|token)"
)
_IDENTITY_KEYS = {
    "ioc",
    "original_ioc",
    "key",
    "host",
    "hostname",
    "domain",
    "ip",
    "ipv4",
    "ipv6",
    "ip_address",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "url",
    "uri",
    "response_url",
    "reference",
    "subject_common_name",
    "registrantname",
    "registrantemail",
    "submitter",
    "iocprocessor",
    "fail_user",
    "username",
    "user_name",
    "user",
    "user_id",
    "id",
    "uuid",
    "record_id",
    "case_id",
    "task_id",
    "event_id",
    "incident_id",
    "upload_id",
    "submission_id",
    "account",
    "account_name",
    "employee_id",
    "staff_id",
    "name",
    "full_name",
    "display_name",
    "real_name",
    "nickname",
    "author",
    "analyst",
    "reviewer",
    "owner",
    "operator",
    "creator",
    "created_by",
    "updated_by",
    "uploaded_by",
    "uploader",
    "contact",
    "contact_name",
    "registrant",
    "person",
    "submit_user",
    "submitted_by",
    "upload_user",
    "analyst_name",
    "reviewer_name",
    "operator_name",
    "contact_email",
    "email",
    "phone",
    "mobile",
    "organization",
    "organisation",
    "company",
    "path",
    "file_path",
    "filepath",
    "filename",
    "processpath",
    "cmdline",
    "commandline",
    "source",
    "feed",
    "campaign",
    "area_city",
    "area_province",
    "province",
    "city",
    "industry",
    "department",
    "team",
    "tenant",
    "tenant_id",
    "address",
    "postal_code",
    "zip_code",
    "上传人",
    "上传人员",
    "提交人",
    "研判人",
    "分析员",
    "姓名",
    "联系人",
    "手机号",
    "邮箱",
    "身份证",
    "身份证号",
    "工号",
    "部门",
    "单位",
    "公司",
    "地址",
}
_HASH_KEYS = {"hash", "md5", "sha1", "sha256", "ioc_hash"}
_MANIFEST_ID_RE = re.compile(r"[0-9a-f]{20}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MANIFEST_MAC_FIELD = "manifest_mac"


class ShareError(ValueError):
    """Raised when a share bundle, key, or token is invalid."""


@dataclass
class ShareStats:
    rows: int = 0
    token_occurrences: int = 0
    redacted_occurrences: int = 0
    source_findings: int = 0
    output_findings: int = 0


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ShareError("encoded value must not be empty")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        if _b64encode(decoded) != value:
            raise ValueError("non-canonical base64 value")
        return decoded
    except (ValueError, base64.binascii.Error) as exc:
        raise ShareError("invalid base64 value") from exc


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:20]


def _associated_data(kind: str) -> bytes:
    return f"{SCHEMA}:{kind}".encode("ascii")


def _manifest_mac(key: bytes, value: dict) -> str:
    authenticated = {
        item_key: item
        for item_key, item in value.items()
        if item_key != _MANIFEST_MAC_FIELD
    }
    payload = json.dumps(
        authenticated,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, b"ioc-share-manifest/v1\0" + payload, hashlib.sha256).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _derive_wrap_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ShareError("share key passphrase must not be empty")
    try:
        return hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=KDF_N,
            r=KDF_R,
            p=KDF_P,
            dklen=KEY_BYTES,
        )
    except (TypeError, ValueError) as exc:
        raise ShareError("unable to derive share key wrapping key") from exc


def _load_key(path: str | Path, passphrase: str | None) -> tuple[bytes, str]:
    source = Path(path)
    try:
        data = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except FileNotFoundError as exc:
        raise ShareError(f"key file not found: {source}") from exc
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ShareError(f"key file is not valid JSON: {source}") from exc
    if not isinstance(data, dict) or data.get("schema") != KEY_SCHEMA:
        raise ShareError("key file schema is invalid")
    if (
        data.get("algorithm") != ALGORITHM
        or data.get("kdf") != KDF
        or data.get("kdf_n") != KDF_N
        or data.get("kdf_r") != KDF_R
        or data.get("kdf_p") != KDF_P
    ):
        raise ShareError("unsupported share key algorithm")
    if passphrase is None:
        raise ShareError("share key passphrase is required")
    salt = _b64decode(data.get("salt", ""))
    wrapped = _b64decode(data.get("wrapped_key", ""))
    wrap_key = _derive_wrap_key(passphrase, salt)
    try:
        key = AESSIV(wrap_key).decrypt(wrapped, [_associated_data(KEY_SCHEMA)])
    except Exception as exc:
        raise ShareError("share key passphrase is incorrect or key is corrupt") from exc
    if len(key) != KEY_BYTES:
        raise ShareError("share key has an invalid length")
    expected_id = _key_id(key)
    if data.get("key_id") != expected_id:
        raise ShareError("share key_id does not match key material")
    return key, expected_id


def _write_json_atomic(path: Path, value: dict, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise ShareError(f"output already exists: {path}; use --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    with _atomic_path(path, force=True) as temp:
        temp.write_text(payload, encoding="utf-8")


def _create_key(path: Path, passphrase: str, *, force: bool = False) -> str:
    if path.exists() and not force:
        raise ShareError(f"key file already exists: {path}; use --force to overwrite")
    if len(passphrase) < 12:
        raise ShareError("new share key passphrase must contain at least 12 characters")
    key = secrets.token_bytes(KEY_BYTES)
    key_id = _key_id(key)
    salt = secrets.token_bytes(16)
    wrap_key = _derive_wrap_key(passphrase, salt)
    wrapped_key = AESSIV(wrap_key).encrypt(
        key, [_associated_data(KEY_SCHEMA)]
    )
    _write_json_atomic(
        path,
        {
            "schema": KEY_SCHEMA,
            "algorithm": ALGORITHM,
            "kdf": KDF,
            "kdf_n": KDF_N,
            "kdf_r": KDF_R,
            "kdf_p": KDF_P,
            "key_id": key_id,
            "salt": _b64encode(salt),
            "wrapped_key": _b64encode(wrapped_key),
        },
        force=True,
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key_id


@contextmanager
def _atomic_path(path: Path, *, force: bool = False) -> Iterator[Path]:
    if path.exists() and not force:
        raise ShareError(f"output already exists: {path}; use --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        yield temp
        os.replace(temp, path)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class _Codec:
    def __init__(self, key: bytes, stats: ShareStats | None = None) -> None:
        self._cipher = AESSIV(key)
        self._stats = stats

    def encode(self, kind: str, value: str) -> str:
        if not isinstance(value, str):
            raise ShareError("only strings can be tokenized")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", kind):
            raise ShareError(f"invalid token kind: {kind}")
        ciphertext = self._cipher.encrypt(value.encode("utf-8"), [_associated_data(kind)])
        if self._stats is not None:
            self._stats.token_occurrences += 1
        return f"ss1:{kind}:{_b64encode(ciphertext)}"

    def decode(self, kind: str, payload: str) -> str:
        try:
            ciphertext = _b64decode(payload)
            plaintext = self._cipher.decrypt(ciphertext, [_associated_data(kind)])
            return plaintext.decode("utf-8")
        except Exception as exc:
            raise ShareError("token authentication or encoding failed") from exc


def _key_name(parent_key: str) -> str:
    return str(parent_key).strip().lower().replace("-", "_")


def _is_identity_key(parent_key: str) -> bool:
    key = _key_name(parent_key)
    return key in _IDENTITY_KEYS or key in _HASH_KEYS or key.endswith("_hash")


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _infer_kind(value: str, parent_key: str = "") -> str:
    key = _key_name(parent_key)
    if key in _HASH_KEYS or key.endswith("_hash"):
        return "hash"
    if _URL_RE.fullmatch(value.strip()):
        return "url"
    if _EMAIL_RE.fullmatch(value.strip()):
        return "email"
    if _PHONE_RE.fullmatch(value.strip()):
        return "person"
    if _CN_ID_RE.fullmatch(value.strip()):
        return "id"
    if _is_ipv6(value.strip()):
        return "ip"
    if _IP_RE.fullmatch(value.strip()):
        return "ip"
    if _HASH_RE.fullmatch(value.strip()):
        return "hash"
    if _UUID_RE.fullmatch(value.strip()):
        return "id"
    if _DOMAIN_RE.fullmatch(value.strip()):
        return "domain"
    if key in {"path", "file_path", "filepath", "filename", "processpath", "cmdline", "commandline"}:
        return "path"
    if key in {"submitter", "iocprocessor", "fail_user", "username", "user_name", "user", "email", "phone", "mobile", "registrantname", "registrantemail", "organization", "organisation", "company"}:
        return "person"
    if key in {"host", "hostname"}:
        return "host"
    if key in {"ioc", "original_ioc", "key"}:
        return "ioc"
    return "text"


def _safe_url(
    value: str,
    redact: Callable[[str], str] | None = None,
) -> str:
    """Remove credential query values before encrypting a URL token."""
    def replace_secret(secret_value: str) -> str:
        return redact(secret_value) if redact is not None else REDACTED

    def replace_inline(match: re.Match[str]) -> str:
        return replace_secret(match.group(0))

    try:
        parsed = urlsplit(value)
        pairs = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            if _CREDENTIAL_KEY_RE.search(key):
                pairs.append((key, replace_secret(item)))
            else:
                pairs.append((key, _INLINE_SECRET_RE.sub(replace_inline, item)))
        if "@" in parsed.netloc:
            replace_secret(parsed.netloc.rsplit("@", 1)[0])
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        path = _INLINE_SECRET_RE.sub(replace_inline, parsed.path)
        fragment = _INLINE_SECRET_RE.sub(replace_inline, parsed.fragment)
        return urlunsplit((parsed.scheme, netloc, path, urlencode(pairs), fragment))
    except ValueError:
        sanitized = _URL_USERINFO_RE.sub(r"\1", value)
        return _INLINE_SECRET_RE.sub(replace_inline, sanitized)


def _replace_pattern(value: str, pattern: re.Pattern[str], kind: str, codec: _Codec) -> str:
    return pattern.sub(lambda match: codec.encode(kind, match.group(0)), value)


def _replace_ipv6(value: str, codec: _Codec) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        return codec.encode("ip", candidate) if _is_ipv6(candidate) else candidate

    return _IPV6_CANDIDATE_RE.sub(replace, value)


def _replace_literal_outside_tokens(
    value: str,
    literal: str,
    replacement: Callable[[], str],
) -> str:
    pieces: list[str] = []
    cursor = 0

    def replace_plain(plain: str) -> str:
        return re.sub(re.escape(literal), lambda _: replacement(), plain)

    for match in _TOKEN_RE.finditer(value):
        plain = value[cursor:match.start()]
        pieces.append(replace_plain(plain))
        pieces.append(match.group(0))
        cursor = match.end()
    pieces.append(replace_plain(value[cursor:]))
    return "".join(pieces)


class _Transformer:
    def __init__(self, codec: _Codec, names: list[str]) -> None:
        self._codec = codec
        self._names = sorted((name for name in names if name), key=len, reverse=True)

    def transform_string(self, value: str, parent_key: str = "") -> str:
        if not value:
            return value
        if "ss1:" in value:
            raise ShareError("source data already contains a share token")
        if _CREDENTIAL_KEY_RE.search(_key_name(parent_key)):
            if self._codec._stats is not None:
                self._codec._stats.redacted_occurrences += 1
            return REDACTED

        key = _key_name(parent_key)
        if _is_identity_key(key):
            kind = _infer_kind(value, key)
            if kind == "url":
                source = _safe_url(value, self._redact_inline)
            else:
                source = _INLINE_SECRET_RE.sub(
                    lambda match: self._redact_inline(match.group(0)), value
                )
            return self._codec.encode(kind, source)

        result = _URL_RE.sub(
            lambda match: self._codec.encode(
                "url", _safe_url(match.group(0), self._redact_inline)
            ),
            value,
        )
        result = _INLINE_SECRET_RE.sub(
            lambda match: self._redact_inline(match.group(0)), result
        )
        result = _replace_pattern(result, _WINDOWS_PATH_RE, "path", self._codec)
        result = _replace_pattern(result, _UNIX_PATH_RE, "path", self._codec)
        result = _replace_pattern(result, _EMAIL_RE, "email", self._codec)
        result = _replace_pattern(result, _PHONE_RE, "person", self._codec)
        result = _replace_pattern(result, _CN_ID_RE, "id", self._codec)
        result = _replace_ipv6(result, self._codec)
        result = _replace_pattern(result, _IP_RE, "ip", self._codec)
        result = _replace_pattern(result, _HASH_RE, "hash", self._codec)
        result = _replace_pattern(result, _UUID_RE, "id", self._codec)
        result = _replace_pattern(result, _DOMAIN_RE, "domain", self._codec)
        for name in self._names:
            if name and name in result:
                result = _replace_literal_outside_tokens(
                    result,
                    name,
                    lambda current=name: self._codec.encode("person", current),
                )
        return result

    def _redact_inline(self, value: str) -> str:
        if self._codec._stats is not None:
            self._codec._stats.redacted_occurrences += 1
        return REDACTED

    def transform_value(self, value: Any, parent_key: str = "") -> Any:
        key = _key_name(parent_key)
        if _CREDENTIAL_KEY_RE.search(key):
            if self._codec._stats is not None:
                self._codec._stats.redacted_occurrences += 1
            return REDACTED
        if isinstance(value, str):
            return self.transform_string(value, parent_key)
        if isinstance(value, list):
            return [self.transform_value(item, parent_key) for item in value]
        if isinstance(value, dict):
            return {
                self._transform_dynamic_key(key): self.transform_value(item, str(key))
                for key, item in value.items()
            }
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and _is_identity_key(key)
        ):
            try:
                encoded_number = json.dumps(value, allow_nan=False)
            except ValueError as exc:
                raise ShareError("identity number must be finite") from exc
            return self._codec.encode("number", encoded_number)
        return value

    def _transform_dynamic_key(self, key: Any) -> str:
        text = str(key)
        return self.transform_string(text, "<key>")


def _restore_string(value: str, codec: _Codec, *, strict: bool) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            return codec.decode(match.group(1), match.group(2))
        except ShareError:
            if strict:
                raise
            return match.group(0)

    restored = _TOKEN_RE.sub(replace, value)
    if strict and "ss1:" in restored:
        raise ShareError("invalid or malformed share token")
    return restored


def _restore_value(value: Any, codec: _Codec, *, strict: bool) -> Any:
    if isinstance(value, str):
        match = _TOKEN_RE.fullmatch(value)
        if match and match.group(1) == "number":
            try:
                restored_number = json.loads(codec.decode(match.group(1), match.group(2)))
            except (json.JSONDecodeError, ShareError) as exc:
                if strict:
                    raise ShareError("numeric token authentication or encoding failed") from exc
                return value
            if isinstance(restored_number, bool) or not isinstance(
                restored_number, (int, float)
            ):
                if strict:
                    raise ShareError("numeric token contains an invalid value")
                return value
            return restored_number
        return _restore_string(value, codec, strict=strict)
    if isinstance(value, list):
        return [_restore_value(item, codec, strict=strict) for item in value]
    if isinstance(value, dict):
        restored_dict: dict[str, Any] = {}
        for key, item in value.items():
            restored_key = _restore_string(str(key), codec, strict=strict)
            if strict and restored_key in restored_dict:
                raise ShareError("restored object contains duplicate keys")
            restored_dict[restored_key] = _restore_value(item, codec, strict=strict)
        return restored_dict
    return value


def _iter_jsonl(path: Path) -> Iterator[tuple[int, bytes, dict]]:
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise ShareError(f"cannot read input: {path}") from exc
    with handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                text = raw.decode("utf-8")
                if line_no == 1:
                    text = text.lstrip("\ufeff")
                value = json.loads(
                    text,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, ValueError) as exc:
                raise ShareError(f"invalid JSONL at line {line_no}") from exc
            if not isinstance(value, dict):
                raise ShareError(f"JSONL line {line_no} must be an object")
            yield line_no, raw, value


def _scan_string(value: str, parent_key: str, findings: list[dict]) -> None:
    key = _key_name(parent_key)
    if _CREDENTIAL_KEY_RE.search(key) and value != REDACTED:
        findings.append({"code": "credential_field", "path": key})
    for token in _TOKEN_RE.finditer(value):
        try:
            if len(_b64decode(token.group(2))) < 16:
                raise ShareError("token ciphertext is too short")
        except ShareError:
            findings.append({"code": "malformed_token", "path": key})
    scrubbed = _TOKEN_RE.sub("", value)
    if "ss1:" in scrubbed:
        findings.append({"code": "malformed_token", "path": key})
    if _is_identity_key(key) and scrubbed.strip() and value != REDACTED:
        findings.append({"code": "identity_field", "path": key})
    if _URL_RE.search(scrubbed):
        findings.append({"code": "url", "path": key})
    if _EMAIL_RE.search(scrubbed):
        findings.append({"code": "email", "path": key})
    if _PHONE_RE.search(scrubbed):
        findings.append({"code": "phone", "path": key})
    if _CN_ID_RE.search(scrubbed):
        findings.append({"code": "personal_id", "path": key})
    if _IP_RE.search(scrubbed):
        findings.append({"code": "ip", "path": key})
    if any(_is_ipv6(match.group(0)) for match in _IPV6_CANDIDATE_RE.finditer(scrubbed)):
        findings.append({"code": "ip", "path": key})
    if _HASH_RE.search(scrubbed):
        findings.append({"code": "hash", "path": key})
    if _UUID_RE.search(scrubbed):
        findings.append({"code": "uuid", "path": key})
    if _WINDOWS_PATH_RE.search(scrubbed) or _UNIX_PATH_RE.search(scrubbed):
        findings.append({"code": "path", "path": key})
    if _DOMAIN_RE.search(scrubbed):
        findings.append({"code": "domain", "path": key})
    if _INLINE_SECRET_RE.search(scrubbed):
        findings.append({"code": "inline_secret", "path": key})


def scan_value(value: Any) -> list[dict]:
    findings: list[dict] = []

    def walk(item: Any, key: str = "") -> None:
        if isinstance(item, str):
            _scan_string(item, key, findings)
        elif isinstance(item, list):
            for child in item:
                walk(child, key)
        elif isinstance(item, dict):
            for child_key, child in item.items():
                _scan_string(str(child_key), "<key>", findings)
                walk(child, str(child_key))
        elif (
            isinstance(item, (int, float))
            and not isinstance(item, bool)
            and (_is_identity_key(key) or _CREDENTIAL_KEY_RE.search(_key_name(key)))
        ):
            findings.append({"code": "sensitive_number", "path": _key_name(key)})

    walk(value)
    return findings


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_manifest(path: Path) -> Path:
    return path.with_name(path.name + ".manifest.json")


def create_bundle(
    input_path: str | Path,
    output_path: str | Path,
    key_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    names: list[str] | None = None,
    force: bool = False,
    generate_key: bool = False,
    strict: bool = True,
    passphrase: str | None = None,
) -> dict:
    source = Path(input_path)
    output = Path(output_path)
    key_file = Path(key_path)
    manifest = Path(manifest_path) if manifest_path else _default_manifest(output)
    resolved_paths = {
        source.resolve(),
        output.resolve(),
        key_file.resolve(),
        manifest.resolve(),
    }
    if len(resolved_paths) != 4:
        raise ShareError("input, output, key, and manifest must be different files")
    for target in (output, manifest):
        if target.exists() and not force:
            raise ShareError(f"output already exists: {target}; use --force to overwrite")
    if generate_key:
        if passphrase is None:
            raise ShareError("passphrase is required when generating a key")
        _create_key(key_file, passphrase, force=force)
    key, key_id = _load_key(key_file, passphrase)
    stats = ShareStats()
    transformer = _Transformer(_Codec(key, stats), names or [])
    output.parent.mkdir(parents=True, exist_ok=True)
    with _atomic_path(output, force=force) as temp:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            for _, _, row in _iter_jsonl(source):
                findings = scan_value(row)
                stats.source_findings += len(findings)
                transformed = transformer.transform_value(row)
                output_findings = scan_value(transformed)
                stats.output_findings += len(output_findings)
                stats.rows += 1
                handle.write(json.dumps(transformed, ensure_ascii=False, separators=(",", ":")) + "\n")
            if stats.rows == 0:
                raise ShareError("input JSONL contains no objects")
            handle.flush()
            os.fsync(handle.fileno())
    if strict and stats.output_findings:
        output.unlink(missing_ok=True)
        raise ShareError(f"sanitized output still contains {stats.output_findings} sensitive finding(s)")
    output_digest = _sha256_file(output)
    manifest_data = {
        "schema": SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "bundle_id": output_digest[:20],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "output_sha256": output_digest,
        "rows": stats.rows,
        "token_occurrences": stats.token_occurrences,
        "redacted_occurrences": stats.redacted_occurrences,
        "source_findings": stats.source_findings,
        "output_findings": stats.output_findings,
        "strict": strict,
    }
    manifest_data[_MANIFEST_MAC_FIELD] = _manifest_mac(key, manifest_data)
    _write_json_atomic(manifest, manifest_data, force=force)
    return manifest_data


def _verify_manifest(path: Path, manifest_path: Path, key: bytes) -> tuple[dict, bool]:
    try:
        data = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ShareError(f"manifest is not valid JSON: {manifest_path}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ShareError("manifest schema is invalid")
    if data.get("algorithm") != ALGORITHM:
        raise ShareError("manifest algorithm is invalid")
    key_id = data.get("key_id")
    output_sha256 = data.get("output_sha256")
    bundle_id = data.get("bundle_id")
    if not isinstance(key_id, str) or not _MANIFEST_ID_RE.fullmatch(key_id):
        raise ShareError("manifest key_id is invalid")
    if not isinstance(output_sha256, str) or not _SHA256_RE.fullmatch(output_sha256):
        raise ShareError("manifest output_sha256 is invalid")
    if (
        not isinstance(bundle_id, str)
        or not _MANIFEST_ID_RE.fullmatch(bundle_id)
        or not secrets.compare_digest(bundle_id, output_sha256[:20])
    ):
        raise ShareError("manifest bundle_id is invalid")
    rows = data.get("rows")
    if isinstance(rows, bool) or not isinstance(rows, int) or rows < 1:
        raise ShareError("manifest row count is invalid")
    manifest_mac = data.get(_MANIFEST_MAC_FIELD)
    if (
        not isinstance(manifest_mac, str)
        or not _SHA256_RE.fullmatch(manifest_mac)
        or not hmac.compare_digest(manifest_mac, _manifest_mac(key, data))
    ):
        raise ShareError("manifest authentication failed")
    exact_bundle = secrets.compare_digest(output_sha256, _sha256_file(path))
    return data, exact_bundle


def restore_bundle(
    input_path: str | Path,
    output_path: str | Path,
    key_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    force: bool = False,
    strict: bool = True,
    passphrase: str | None = None,
) -> int:
    source = Path(input_path)
    output = Path(output_path)
    key_file = Path(key_path)
    resolved_paths = {source.resolve(), output.resolve(), key_file.resolve()}
    if manifest_path:
        resolved_paths.add(Path(manifest_path).resolve())
        expected_count = 4
    else:
        expected_count = 3
    if len(resolved_paths) != expected_count:
        raise ShareError("input, output, key, and manifest must be different files")
    key, key_id = _load_key(key_file, passphrase)
    manifest: dict | None = None
    exact_bundle = False
    if manifest_path:
        manifest, exact_bundle = _verify_manifest(source, Path(manifest_path), key)
        if manifest.get("key_id") != key_id:
            raise ShareError("manifest key_id does not match key file")
    codec = _Codec(key)
    rows = 0
    with _atomic_path(output, force=force) as temp:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            for _, _, row in _iter_jsonl(source):
                if (
                    manifest is not None
                    and not exact_bundle
                    and row.get("bundle_id") != manifest.get("bundle_id")
                ):
                    raise ShareError(
                        "modified cloud response must include the manifest bundle_id on every row"
                    )
                restored = _restore_value(row, codec, strict=strict)
                handle.write(json.dumps(restored, ensure_ascii=False, separators=(",", ":")) + "\n")
                rows += 1
            if manifest is not None and not exact_bundle and rows == 0:
                raise ShareError(
                    "modified cloud response must include the manifest bundle_id on every row"
                )
            handle.flush()
            os.fsync(handle.fileno())
    return rows


def scan_bundle(input_path: str | Path) -> dict:
    path = Path(input_path)
    findings: list[dict] = []
    rows = 0
    for _, _, row in _iter_jsonl(path):
        rows += 1
        findings.extend(scan_value(row))
    counts: dict[str, int] = {}
    for item in findings:
        code = str(item.get("code", "unknown"))
        counts[code] = counts.get(code, 0) + 1
    return {"schema": SCHEMA, "rows": rows, "finding_count": len(findings), "finding_counts": counts}


def ensure_key(
    path: str | Path,
    passphrase: str,
    *,
    generate: bool = False,
    force: bool = False,
) -> str:
    """Load the share key at ``path`` and return its key id.

    With ``generate`` the key file is created first; an existing key file is
    only replaced when ``force`` is set.  The passphrase is always validated
    by the final load, so a returned key id is proof of a successful unlock.
    """
    if generate:
        _create_key(Path(path), passphrase, force=force)
    _, key_id = _load_key(path, passphrase)
    return key_id



def _load_names(path: str | None) -> list[str]:
    if not path:
        return []
    try:
        return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        raise ShareError(f"cannot read names file: {path}") from exc


def _resolve_passphrase(env_name: str | None) -> str:
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value
    return getpass.getpass("Share key passphrase: ")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and restore local-only encrypted IOC share bundles.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a sanitized JSONL bundle")
    create.add_argument("-i", "--input", required=True, help="source JSONL snapshot or result")
    create.add_argument("-o", "--output", required=True, help="sanitized JSONL output")
    create.add_argument("--key-file", required=True, help="local key JSON path")
    create.add_argument("--manifest", help="manifest JSON path (default: <output>.manifest.json)")
    create.add_argument("--names-file", help="optional person-name list")
    create.add_argument("--generate-key", action="store_true", help="generate the key file before creating")
    create.add_argument("--passphrase-env", default="IOC_SHARE_PASSPHRASE", help="environment variable for the key passphrase")
    create.add_argument("--force", action="store_true", help="overwrite output, manifest, or generated key")
    create.add_argument("--no-strict", action="store_true", help="allow residual scanner findings")

    restore = subparsers.add_parser("restore", help="restore tokens in a JSONL response")
    restore.add_argument("-i", "--input", required=True, help="sanitized JSONL input")
    restore.add_argument("-o", "--output", required=True, help="restored JSONL output")
    restore.add_argument("--key-file", required=True, help="local key JSON path")
    restore.add_argument("--manifest", help="manifest to verify before restoring")
    restore.add_argument("--passphrase-env", default="IOC_SHARE_PASSPHRASE", help="environment variable for the key passphrase")
    restore.add_argument("--force", action="store_true", help="overwrite output")
    restore.add_argument("--no-strict", action="store_true", help="leave invalid tokens untouched")

    scan = subparsers.add_parser("scan", help="scan a JSONL file for residual sensitive values")
    scan.add_argument("-i", "--input", required=True, help="JSONL input")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            passphrase = _resolve_passphrase(args.passphrase_env)
            manifest = create_bundle(
                args.input,
                args.output,
                args.key_file,
                manifest_path=args.manifest,
                names=_load_names(args.names_file),
                force=args.force,
                generate_key=args.generate_key,
                strict=not args.no_strict,
                passphrase=passphrase,
            )
            print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "restore":
            passphrase = _resolve_passphrase(args.passphrase_env)
            rows = restore_bundle(
                args.input,
                args.output,
                args.key_file,
                manifest_path=args.manifest,
                force=args.force,
                strict=not args.no_strict,
                passphrase=passphrase,
            )
            print(f"Restored {rows} JSONL row(s).")
            return 0
        report = scan_bundle(args.input)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0 if report["finding_count"] == 0 else 1
    except (OSError, ShareError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ALGORITHM",
    "KEY_SCHEMA",
    "SCHEMA",
    "ShareError",
    "create_bundle",
    "restore_bundle",
    "scan_bundle",
]
