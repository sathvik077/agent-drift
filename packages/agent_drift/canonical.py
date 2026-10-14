"""Canonical JSON serialization, digests and secret redaction.

Three jobs, all security-relevant:

1. **Canonical JSON.** An approval grant is bound to the *exact* arguments a reviewer saw.
   "Exact" has to survive key reordering, insignificant whitespace, unicode normalization
   and float formatting, or an attacker could obtain approval for ``{"path": "a"}`` and
   then execute ``{"path":"a"}`` with a different digest -- or worse, get a digest collision
   by reordering keys. :func:`canonical_json` produces one byte string per logical value.

2. **Digests.** :func:`digest` is SHA-256 over canonical bytes. The blueprint is explicit
   that a contract hash is an *integrity and evidence identifier*, not proof of authenticated
   approval -- see :mod:`agent_drift.contracts` for the HMAC variant used when a separately
   held local signing key is configured.

3. **Redaction.** Nothing reaches the event log or the dashboard before passing through
   :func:`redact`. This is a defence against logging a secret that an agent put in a tool
   argument, not a guarantee that no secret can ever be logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from typing import Any, Final

__all__ = [
    "REDACTED",
    "canonical_json",
    "canonical_text",
    "digest",
    "keyed_digest",
    "redact",
]

REDACTED: Final[str] = "[REDACTED]"

#: Maximum characters of any single string value kept in an audit record.
MAX_LOGGED_STRING: Final[int] = 512

#: Argument names whose values are always redacted, matched case-insensitively as substrings.
_SENSITIVE_KEY_PATTERNS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "privatekey",
    "credential",
    "authorization",
    "auth",
    "session",
    "cookie",
    "bearer",
    "signature",
    "client_secret",
    "refresh_token",
    "pin",
    "ssn",
    "social_security",
    "card_number",
    "cvv",
    "security_code",
)

#: Value shapes that look like credentials regardless of the key they appear under.
_SENSITIVE_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),  # generic provider key
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),  # GitHub tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # PEM private key
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack tokens
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email address
)


def _normalize_scalar(value: Any) -> Any:
    """Normalize a scalar for canonical form.

    Strings are NFC-normalized so that visually identical but differently composed
    unicode cannot produce two digests for one logical value. Floats that are integral
    are *not* silently narrowed to int, because that would make ``1.0`` and ``1`` collide
    and an approval for one would authorize the other.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite floats have no canonical form")
        return value
    return value


def _canonicalize(value: Any) -> Any:
    """Recursively normalize a JSON-compatible value into canonical form."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda k: unicodedata.normalize("NFC", str(k))):
            out[unicodedata.normalize("NFC", str(key))] = _canonicalize(value[key])
        return out
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        # Sets have no inherent order; sort their canonical text so the form is stable.
        return sorted((_canonicalize(item) for item in value), key=lambda v: json.dumps(v, sort_keys=True))
    return _normalize_scalar(value)


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` to canonical UTF-8 JSON bytes.

    Properties relied on elsewhere: keys sorted by NFC-normalized code point, no
    insignificant whitespace, ``ensure_ascii=False`` so the NFC normalization is what
    determines the bytes, and no trailing newline.
    """
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_text(value: Any) -> str:
    """Canonical JSON as ``str``, for display and for embedding in records."""
    return canonical_json(value).decode("utf-8")


def canonical_json_raw(value: Any) -> bytes:
    """Serialize ``value`` deterministically **without** unicode normalization.

    Same ordering and whitespace rules as :func:`canonical_json`, but strings and keys are
    left exactly as received. Used alongside the canonical digest so an approval binds the
    literal bytes a reviewer saw: two unicode compositions of one visible filename are two
    different files, and folding them together let one grant authorize both.
    """
    return json.dumps(
        _canonicalize_raw(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonicalize_raw(value: Any) -> Any:
    """Recursive ordering without normalization."""
    if isinstance(value, dict):
        return {str(key): _canonicalize_raw(value[key]) for key in sorted(map(str, value.keys()))}
    if isinstance(value, (list, tuple)):
        return [_canonicalize_raw(item) for item in value]
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise ValueError("non-finite floats have no canonical form")
    return value


def digest_raw(value: Any) -> str:
    """SHA-256 over the un-normalized canonical form of ``value``."""
    return hashlib.sha256(canonical_json_raw(value)).hexdigest()


def digest(value: Any) -> str:
    """SHA-256 hex digest over the canonical form of ``value``.

    This is an integrity and evidence identifier. It proves two records describe the
    same logical value; it does **not** prove who approved anything. Use
    :func:`keyed_digest` when a separately held local key is configured.
    """
    return hashlib.sha256(canonical_json(value)).hexdigest()


def keyed_digest(value: Any, key: bytes) -> str:
    """HMAC-SHA256 over the canonical form of ``value``.

    Used for the optional audit integrity chain. A compromised host or leaked key
    defeats this entirely; that caveat is stated in ``docs/THREAT_MODEL.md`` and in the
    README rather than being implied away by the presence of an HMAC.
    """
    return hmac.new(key, canonical_json(value), hashlib.sha256).hexdigest()


def _redact_string(text: str) -> str:
    """Redact credential-shaped substrings and bound the length of a logged string."""
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        text = pattern.sub(REDACTED, text)
    if len(text) > MAX_LOGGED_STRING:
        text = text[:MAX_LOGGED_STRING] + f"...[truncated {len(text) - MAX_LOGGED_STRING} chars]"
    return text


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a copy of ``value`` safe to persist and display.

    Rules: a key whose name matches a sensitive pattern has its value replaced wholesale;
    every remaining string is scanned for credential-shaped substrings and truncated to
    :data:`MAX_LOGGED_STRING`; recursion is bounded so a hostile deeply nested argument
    cannot exhaust the stack.
    """
    if _depth > 24:
        return "[REDACTED: max depth exceeded]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, inner in value.items():
            key_str = str(key)
            lowered = key_str.lower()
            if any(pattern in lowered for pattern in _SENSITIVE_KEY_PATTERNS):
                out[key_str] = REDACTED
            else:
                out[key_str] = redact(inner, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth=_depth + 1) for item in value[:256]]
    if isinstance(value, str):
        return _redact_string(value)
    return value
