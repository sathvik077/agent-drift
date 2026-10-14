"""Destination allowlist bypass regressions (AD-21, AD-22).

Each case is a way to make a host string look like one thing to a human and resolve to
another, or to reach an address a sandboxed tool has no business reaching. A naive
allowlist fails most of them.
"""

from __future__ import annotations

import pytest

from agent_drift.contracts import ContractSource, DecisionStatus, IntentContract, Operation, ToolAttempt
from agent_drift.destinations import destination_allowed, normalize_destination
from agent_drift.reasons import Reason

#: Destinations that must never be accepted, whatever the allowlist says.
ALWAYS_REJECTED: list[tuple[str, str, str]] = [
    ("loopback v4", "http://127.0.0.1/collect", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("loopback name is not an address", "http://127.0.0.2:8080/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("loopback v6", "http://[::1]/collect", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("ipv4-mapped v6 loopback", "http://[::ffff:127.0.0.1]/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("decimal integer host", "http://2130706433/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("octal host", "http://0177.0.0.1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("hex host", "http://0x7f000001/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("short dotted loopback", "http://127.1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("mixed hex dotted", "http://0x7f.1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("all-hex dotted", "http://0x7f.0x0.0x0.0x1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("dotted octal private", "http://012.0.0.5/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("link-local metadata", "http://169.254.169.254/latest/meta-data", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("private 10/8", "http://10.0.0.5/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("private 172.16/12", "http://172.16.0.1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("private 192.168/16", "http://192.168.1.1/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("unspecified", "http://0.0.0.0/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("ipv6 link-local with zone", "http://[fe80::1%25eth0]/x", Reason.DESTINATION_PRIVATE_ADDRESS),
    ("file scheme", "file:///etc/passwd", Reason.DESTINATION_SCHEME_DENIED),
    ("gopher scheme", "gopher://example.com/x", Reason.DESTINATION_SCHEME_DENIED),
    ("data scheme", "data:text/plain,hello", Reason.DESTINATION_SCHEME_DENIED),
    ("javascript scheme", "javascript:alert(1)", Reason.DESTINATION_SCHEME_DENIED),
    ("no scheme", "example.com/collect", Reason.DESTINATION_SCHEME_DENIED),
    ("protocol relative", "//example.com/collect", Reason.DESTINATION_SCHEME_DENIED),
    ("empty", "", Reason.DESTINATION_MISSING),
    ("whitespace only", "   ", Reason.DESTINATION_MISSING),
    ("crlf injection", "https://example.com/\r\nHost: evil.test", Reason.DESTINATION_UNPARSEABLE),
    ("no host", "https:///path", Reason.DESTINATION_UNPARSEABLE),
]


class TestNormalization:
    """Normalization must make equivalent hosts compare equal and tricks visible."""

    @pytest.mark.parametrize(
        ("label", "raw", "expected"), ALWAYS_REJECTED, ids=[c[0] for c in ALWAYS_REJECTED]
    )
    def test_always_rejected(self, label: str, raw: str, expected: str) -> None:
        verdict = normalize_destination(raw)
        assert verdict.ok is False, f"{label}: {raw!r} was accepted"
        assert verdict.reason == expected, f"{label}: got {verdict.reason}"

    def test_case_is_folded(self) -> None:
        assert normalize_destination("https://EXAMPLE.COM/x").host == "example.com"

    def test_trailing_dot_is_removed(self) -> None:
        assert normalize_destination("https://example.com./x").host == "example.com"

    def test_userinfo_does_not_define_the_host(self) -> None:
        """`https://example.com@evil.test/` has host evil.test, not example.com."""
        verdict = normalize_destination("https://example.com@evil.test/")
        assert verdict.host == "evil.test"
        assert verdict.had_userinfo is True

    def test_homograph_host_is_punycoded(self) -> None:
        """A Cyrillic 'а' must not compare equal to an ASCII 'a'."""
        verdict = normalize_destination("http://exаmple.com/")
        assert verdict.host.startswith("xn--")
        assert verdict.host != "example.com"

    def test_default_ports_are_explicit(self) -> None:
        assert normalize_destination("https://example.com/x").port == 443
        assert normalize_destination("http://example.com/x").port == 80

    def test_explicit_port_is_preserved(self) -> None:
        assert normalize_destination("https://example.com:8443/x").port == 8443

    def test_public_host_is_accepted(self) -> None:
        assert normalize_destination("https://exfil.invalid/collect").ok is True

    def test_public_ip_literal_is_accepted(self) -> None:
        """Only reserved ranges are rejected; a public literal is a normal destination."""
        assert normalize_destination("https://8.8.8.8/x").ok is True

    def test_hostname_that_merely_looks_numeric_is_not_an_ip(self) -> None:
        """'999.1.1.1' is not a valid IPv4 literal, so it stays a hostname."""
        verdict = normalize_destination("http://999.1.1.1/x")
        assert verdict.ok is True
        assert verdict.is_ip_literal is False


class TestAllowlist:
    """Default deny, and entry forms must behave predictably."""

    def test_empty_allowlist_denies_everything(self) -> None:
        verdict = destination_allowed("https://example.com/x", [])
        assert verdict.ok is False
        assert verdict.reason == Reason.DESTINATION_NOT_ALLOWED

    @pytest.mark.parametrize(
        ("url", "allowlist", "expected"),
        [
            ("https://api.example.com/x", ["api.example.com"], True),
            ("https://api.example.com/x", ["API.EXAMPLE.COM"], True),
            ("https://api.example.com/x", ["api.example.com."], True),
            ("https://api.example.com/x", ["*.example.com"], True),
            ("https://example.com/x", ["*.example.com"], False),
            ("https://evil.example.com.attacker.test/x", ["*.example.com"], False),
            ("https://notexample.com/x", ["example.com"], False),
            ("https://example.com.attacker.test/x", ["example.com"], False),
            ("https://example.com:8443/x", ["example.com"], False),
            ("https://example.com:8443/x", ["example.com:8443"], True),
            ("https://example.com/x", ["https://example.com"], True),
            ("http://example.com/x", ["https://example.com"], False),
            ("https://example.com@evil.test/x", ["example.com"], False),
            ("http://exаmple.com/x", ["example.com"], False),
        ],
    )
    def test_entry_matching(self, url: str, allowlist: list[str], expected: bool) -> None:
        assert destination_allowed(url, allowlist).ok is expected

    def test_allowlisting_a_private_address_still_denies_by_default(self) -> None:
        """Reserved ranges are rejected during normalization, before the allowlist."""
        verdict = destination_allowed("http://127.0.0.1/x", ["127.0.0.1"])
        assert verdict.ok is False
        assert verdict.reason == Reason.DESTINATION_PRIVATE_ADDRESS


class TestPolicyEnforcesDestinations:
    """The engine must deny, with zero budget consumption and the right code."""

    @pytest.fixture
    def contract(self, store) -> IntentContract:
        contract = IntentContract(
            principal="dev",
            task_id="t",
            user_goal="publish a report",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["network.http_post"],
            allowed_operations=[Operation.NETWORK_POST],
            allowed_destinations=["reports.internal.example"],
            max_writes=0,
            max_calls=50,
        )
        store.put_contract(contract)
        return contract

    def test_approved_destination_is_allowed(self, engine, contract) -> None:
        decision = engine.evaluate(
            ToolAttempt(
                tool_server="sandbox",
                tool_name="network.http_post",
                args={"url": "https://reports.internal.example/publish", "body": "r"},
            ),
            bound_task_id="t",
        )
        assert decision.status is DecisionStatus.ALLOW, decision.reason_codes

    @pytest.mark.parametrize(
        "url",
        [
            "https://exfil.invalid/collect",
            "http://169.254.169.254/latest/meta-data",
            "https://reports.internal.example@evil.test/publish",
            "http://reports.internal.example:9999/publish",
            "file:///etc/passwd",
        ],
    )
    def test_unapproved_destination_is_denied(self, engine, contract, url: str) -> None:
        decision = engine.evaluate(
            ToolAttempt(
                tool_server="sandbox",
                tool_name="network.http_post",
                args={"url": url, "body": "r"},
            ),
            bound_task_id="t",
        )
        assert decision.status is DecisionStatus.DENY, f"{url} was allowed"
        assert any(code.startswith("AD-E07") for code in decision.reason_codes)

    def test_missing_url_is_denied(self, engine, contract) -> None:
        decision = engine.evaluate(
            ToolAttempt(tool_server="sandbox", tool_name="network.http_post", args={"body": "r"}),
            bound_task_id="t",
        )
        assert decision.status is DecisionStatus.DENY
        assert str(Reason.DESTINATION_MISSING) in decision.reason_codes

    def test_evidence_records_the_normalized_destination(self, engine, contract) -> None:
        decision = engine.evaluate(
            ToolAttempt(
                tool_server="sandbox",
                tool_name="network.http_post",
                args={"url": "https://reports.internal.example@evil.test/x", "body": "r"},
            ),
            bound_task_id="t",
        )
        evidence = decision.evidence["destination"]
        assert evidence["host"] == "evil.test"
        assert evidence["had_userinfo"] is True
