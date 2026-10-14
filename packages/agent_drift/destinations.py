"""Destination (URL) normalization and allowlisting.

The rule is **default deny**: a destination is permitted only when its normalized host
matches an entry in the contract's ``allowed_destinations``. Everything else -- including
every unparseable, ambiguous or private-address destination -- is denied.

Normalization closes the gaps that make naive host allowlists trivially bypassable, each
with a test in ``tests/security/test_destinations.py``:

* **Case.** ``EXAMPLE.COM`` and ``example.com`` are the same host.
* **Trailing dot.** ``example.com.`` is the same host as ``example.com`` to DNS, and a
  different string to a naive comparison.
* **IDNA / homograph.** Unicode hosts are converted to A-labels, so ``exаmple.com`` with
  a Cyrillic ``а`` becomes ``xn--...`` and does not match ``example.com``.
* **Userinfo.** ``https://example.com@evil.test/`` has host ``evil.test``; a human and a
  careless parser disagree about that string, so userinfo is stripped and, when present,
  recorded as evidence.
* **Port.** An allowlist entry may pin a port; an entry without one accepts the scheme's
  default only.
* **IP literals.** IPv4, IPv6 (including bracketed and zone-id forms), and the integer
  and octal forms that resolve to loopback are classified and rejected unless explicitly
  allowlisted as literals.
* **Reserved ranges.** loopback, private, link-local, multicast, reserved,
  unspecified and IPv4-mapped IPv6 are rejected by default: a tool told to POST to
  ``http://169.254.169.254/`` is attacking a metadata service, not doing its job.
* **Scheme.** Only ``http`` and ``https`` are candidates; ``file:``, ``gopher:``,
  ``data:``, ``javascript:`` and schemeless input are rejected.

**Stated limitation.** This is a check on the *argument*. It cannot stop a third-party
tool that ignores the URL it was given, nor does it resolve DNS -- a hostname that
currently resolves to a public address may later resolve to a private one (DNS rebinding).
The fixture ``network.http_post`` performs no socket operations at all, so in this
repository the check is conclusive; for real egress a resolve-time check is required and
is listed as a v2 item in ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import unicodedata
import urllib.parse
from typing import Final, NamedTuple

__all__ = ["DestinationVerdict", "destination_allowed", "normalize_destination"]

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}

#: One component of an ``inet_aton``-style IPv4 literal: decimal, octal (leading zero)
#: or hexadecimal (``0x``). ``inet_aton`` accepts one to four such parts, which is why
#: ``0177.0.0.1``, ``0x7f.1`` and ``2130706433`` all reach 127.0.0.1 and why a
#: single-integer check is not enough. This bypass was found by the security suite.
_ATON_PART: Final[re.Pattern[str]] = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)$")


class DestinationVerdict(NamedTuple):
    """Outcome of normalizing a destination argument."""

    ok: bool
    host: str = ""
    port: int = 0
    scheme: str = ""
    normalized: str = ""
    reason: str | None = None
    detail: str | None = None
    is_ip_literal: bool = False
    had_userinfo: bool = False


def _classify_ip(host: str) -> tuple[bool, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    """Return ``(is_literal, address)`` for a host string.

    Handles bracketed IPv6, zone ids, and integer/octal IPv4 spellings. A host that is
    not an IP literal returns ``(False, None)``.
    """
    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if "%" in candidate:  # IPv6 zone id, e.g. fe80::1%eth0
        candidate = candidate.split("%", 1)[0]

    try:
        return True, ipaddress.ip_address(candidate)
    except ValueError:
        pass

    # ``inet_aton``-style spellings that browsers, curl and most resolvers accept:
    # 1 to 4 dot-separated parts, each decimal, octal or hexadecimal. The last part
    # absorbs the remaining bytes, so ``0177.0.0.1`` and ``0x7f.1`` are both loopback.
    packed = _parse_inet_aton(candidate)
    if packed is not None:
        return True, ipaddress.IPv4Address(packed)
    return False, None


def _parse_inet_aton(host: str) -> int | None:
    """Parse an ``inet_aton``-style IPv4 literal into a 32-bit integer, or ``None``.

    Accepts 1-4 parts; each part may be decimal, octal (leading ``0``) or hex (``0x``).
    With fewer than four parts the final part supplies all remaining low-order bytes,
    which is the behaviour that makes ``0x7f.1`` equal to 127.0.0.1.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values: list[int] = []
    for part in parts:
        if not _ATON_PART.match(part):
            return None
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif part.startswith("0") and len(part) > 1:
                value = int(part, 8)
            else:
                value = int(part, 10)
        except ValueError:
            return None
        values.append(value)

    leading, last = values[:-1], values[-1]
    if any(value > 0xFF for value in leading):
        return None
    remaining_bytes = 4 - len(leading)
    if last >= (1 << (8 * remaining_bytes)):
        return None

    packed = 0
    for value in leading:
        packed = (packed << 8) | value
    return (packed << (8 * remaining_bytes)) | last


def _is_reserved(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address a tool has no business POSTing to from a sandbox."""
    if address.is_loopback or address.is_private or address.is_link_local:
        return True
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        return True
    if isinstance(address, ipaddress.IPv6Address):
        # ::ffff:127.0.0.1 and friends must not slip past the IPv4 checks.
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None and _is_reserved(mapped):
            return True
        sixtofour = getattr(address, "sixtofour", None)
        if sixtofour is not None and _is_reserved(sixtofour):
            return True
    return False


def normalize_destination(raw: str) -> DestinationVerdict:
    """Parse and normalize an untrusted destination URL.

    Returns a verdict whose ``normalized`` field is ``scheme://host:port`` with the host
    lowercased, IDNA-encoded, and the trailing dot removed, and the port made explicit.
    """
    from .reasons import Reason

    if not isinstance(raw, str) or not raw.strip():
        return DestinationVerdict(False, reason=Reason.DESTINATION_MISSING, detail="destination was empty")

    text = unicodedata.normalize("NFC", raw.strip())

    # Reject control characters outright; a CR or LF would be a header-injection attempt.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return DestinationVerdict(
            False,
            reason=Reason.DESTINATION_UNPARSEABLE,
            detail="destination contained a control character",
        )

    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError as exc:
        return DestinationVerdict(False, reason=Reason.DESTINATION_UNPARSEABLE, detail=str(exc))

    scheme = parsed.scheme.lower()
    if not scheme:
        return DestinationVerdict(
            False,
            reason=Reason.DESTINATION_SCHEME_DENIED,
            detail="destination had no scheme; only absolute http(s) URLs are accepted",
        )
    if scheme not in _ALLOWED_SCHEMES:
        return DestinationVerdict(
            False,
            scheme=scheme,
            reason=Reason.DESTINATION_SCHEME_DENIED,
            detail=f"scheme {scheme!r} is not permitted",
        )

    had_userinfo = "@" in (parsed.netloc or "")

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        return DestinationVerdict(
            False,
            scheme=scheme,
            reason=Reason.DESTINATION_UNPARSEABLE,
            detail=f"host could not be parsed: {exc}",
            had_userinfo=had_userinfo,
        )

    if not hostname:
        return DestinationVerdict(
            False,
            scheme=scheme,
            reason=Reason.DESTINATION_UNPARSEABLE,
            detail="destination had no host",
            had_userinfo=had_userinfo,
        )

    host = hostname.lower().rstrip(".")
    if not host:
        return DestinationVerdict(
            False,
            scheme=scheme,
            reason=Reason.DESTINATION_UNPARSEABLE,
            detail="host was only dots",
            had_userinfo=had_userinfo,
        )

    is_literal, address = _classify_ip(host)

    if not is_literal:
        # IDNA-encode so a homograph host cannot compare equal to an ASCII allowlist entry.
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            # A host that cannot be IDNA-encoded is rejected rather than compared raw: an
            # un-normalized unicode host could compare equal to an ASCII allowlist entry
            # under some comparison, which is the homograph bypass this guards against.
            return DestinationVerdict(
                False,
                scheme=scheme,
                host=host,
                reason=Reason.DESTINATION_UNPARSEABLE,
                detail="host could not be IDNA-normalized",
                had_userinfo=had_userinfo,
            )
    else:
        host = str(address)

    try:
        port = parsed.port or _DEFAULT_PORTS[scheme]
    except ValueError as exc:
        return DestinationVerdict(
            False,
            scheme=scheme,
            host=host,
            reason=Reason.DESTINATION_UNPARSEABLE,
            detail=f"invalid port: {exc}",
            had_userinfo=had_userinfo,
        )

    if is_literal and address is not None and _is_reserved(address):
        return DestinationVerdict(
            False,
            host=host,
            port=port,
            scheme=scheme,
            normalized=f"{scheme}://{host}:{port}",
            reason=Reason.DESTINATION_PRIVATE_ADDRESS,
            detail=f"{host} is a loopback, private, link-local or otherwise reserved address",
            is_ip_literal=True,
            had_userinfo=had_userinfo,
        )

    bracket_host = f"[{host}]" if is_literal and ":" in host else host
    return DestinationVerdict(
        True,
        host=host,
        port=port,
        scheme=scheme,
        normalized=f"{scheme}://{bracket_host}:{port}",
        is_ip_literal=is_literal,
        had_userinfo=had_userinfo,
    )


def _entry_matches(host: str, port: int, scheme: str, entry: str) -> bool:
    """Match a normalized host/port against one allowlist entry.

    Accepted entry forms: ``example.com``, ``example.com:8443``,
    ``https://example.com``, ``*.example.com`` (subdomains only, never the apex).
    Entries are themselves normalized, so an allowlist written with a trailing dot,
    mixed case or unicode still behaves.
    """
    entry = entry.strip().lower().rstrip(".")
    if not entry:
        return False

    entry_scheme = ""
    if "://" in entry:
        entry_scheme, entry = entry.split("://", 1)
        entry = entry.strip("/")

    entry_port: int | None = None
    if entry.startswith("[") and "]" in entry:  # bracketed IPv6 with optional port
        host_part, _, rest = entry.partition("]")
        entry_host = host_part[1:]
        if rest.startswith(":"):
            try:
                entry_port = int(rest[1:])
            except ValueError:
                return False
    elif entry.count(":") == 1:
        entry_host, _, port_text = entry.partition(":")
        try:
            entry_port = int(port_text)
        except ValueError:
            return False
    else:
        entry_host = entry

    entry_host = entry_host.rstrip(".")
    if not entry_host:
        return False

    if not _classify_ip(entry_host)[0]:
        with contextlib.suppress(UnicodeError, UnicodeDecodeError):
            # An allowlist entry that will not IDNA-encode is compared as written; it
            # simply will not match a normalized host, which fails closed.
            entry_host = entry_host.encode("idna").decode("ascii")

    if entry_scheme and entry_scheme != scheme:
        return False
    if entry_port is not None and entry_port != port:
        return False
    # An entry with no explicit port authorizes only the scheme's default port, so
    # `example.com` does not admit `example.com:8443`.
    if entry_port is None and port != _DEFAULT_PORTS.get(scheme, -1):
        return False

    if entry_host.startswith("*."):
        suffix = entry_host[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")

    return host == entry_host


def destination_allowed(raw: str, allowed: list[str]) -> DestinationVerdict:
    """Normalize ``raw`` and check it against ``allowed`` (default deny).

    An empty allowlist denies everything, which is the correct behaviour for a contract
    that declared no destinations: silence is not consent.
    """
    from .reasons import Reason

    verdict = normalize_destination(raw)
    if not verdict.ok:
        return verdict

    if not allowed:
        return verdict._replace(
            ok=False,
            reason=Reason.DESTINATION_NOT_ALLOWED,
            detail="contract declares no allowed destinations, so all egress is denied",
        )

    for entry in allowed:
        if _entry_matches(verdict.host, verdict.port, verdict.scheme, entry):
            return verdict

    return verdict._replace(
        ok=False,
        reason=Reason.DESTINATION_NOT_ALLOWED,
        detail=f"host {verdict.host!r} is not in allowed_destinations",
    )
