"""Canonical serialization, digests and redaction.

These are the primitives an approval grant's exactness rests on, so the tests are about
the properties rather than specific byte strings: reordering must not change a digest,
and anything a reviewer would consider a different value must.
"""

from __future__ import annotations

import pytest

from agent_drift.canonical import REDACTED, canonical_json, canonical_text, digest, keyed_digest, redact


class TestCanonicalForm:
    """Canonical JSON must be stable under irrelevant differences only."""

    def test_key_order_does_not_change_the_digest(self) -> None:
        assert digest({"b": 1, "a": 2}) == digest({"a": 2, "b": 1})

    def test_nested_key_order_does_not_change_the_digest(self) -> None:
        left = {"outer": {"z": [1, {"b": 2, "a": 3}], "y": 4}}
        right = {"outer": {"y": 4, "z": [1, {"a": 3, "b": 2}]}}
        assert digest(left) == digest(right)

    def test_list_order_does_change_the_digest(self) -> None:
        """Lists are ordered data; approving [a, b] must not authorize [b, a]."""
        assert digest({"x": [1, 2]}) != digest({"x": [2, 1]})

    def test_unicode_normalization_is_applied(self) -> None:
        """Composed and decomposed forms of one character are one logical value."""
        assert digest({"name": "é"}) == digest({"name": "é"})

    def test_integer_and_float_are_distinct(self) -> None:
        """1 and 1.0 are different values; collapsing them would widen an approval."""
        assert digest({"n": 1}) != digest({"n": 1.0})

    def test_no_insignificant_whitespace(self) -> None:
        assert canonical_json({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'

    def test_non_ascii_is_not_escaped(self) -> None:
        assert "é" in canonical_text({"x": "é"})

    def test_non_finite_floats_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="canonical"):
            canonical_json({"x": float("inf")})

    def test_adding_a_key_changes_the_digest(self) -> None:
        """Approving {"path": p} must not authorize {"path": p, "force": true}."""
        assert digest({"path": "a"}) != digest({"path": "a", "force": True})


class TestKeyedDigest:
    """HMAC digests must depend on the key."""

    def test_different_keys_give_different_digests(self) -> None:
        payload = {"event": 1}
        assert keyed_digest(payload, b"key-a") != keyed_digest(payload, b"key-b")

    def test_same_key_and_payload_is_stable(self) -> None:
        payload = {"event": 1}
        assert keyed_digest(payload, b"k") == keyed_digest(payload, b"k")


class TestRedaction:
    """Redaction must catch both sensitive key names and credential-shaped values."""

    @pytest.mark.parametrize(
        "key",
        ["password", "api_key", "apiKey", "AUTHORIZATION", "session_token", "client_secret", "cvv"],
    )
    def test_sensitive_key_names_are_redacted(self, key: str) -> None:
        assert redact({key: "value"})[key] == REDACTED

    @pytest.mark.parametrize(
        "value",
        [
            "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
            "ghp_ABCDEFGHIJKLMNOPQRSTUV",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN RSA PRIVATE KEY-----",
            "xoxb-1234567890-abcdefghij",
            "someone@example.com",
        ],
    )
    def test_credential_shaped_values_are_redacted(self, value: str) -> None:
        result = redact({"note": value})["note"]
        assert REDACTED in result, f"{value!r} survived redaction as {result!r}"

    def test_nested_structures_are_redacted(self) -> None:
        result = redact({"a": {"b": [{"token": "t"}]}})
        assert result["a"]["b"][0]["token"] == REDACTED

    def test_long_strings_are_truncated(self) -> None:
        result = redact({"blob": "x" * 5000})["blob"]
        assert len(result) < 700
        assert "truncated" in result

    def test_deep_nesting_is_bounded(self) -> None:
        """A hostile deeply nested argument must not exhaust the stack."""
        payload: dict[str, object] = {"v": 1}
        for _ in range(200):
            payload = {"n": payload}
        result = redact(payload)
        assert "REDACTED" in repr(result)

    def test_benign_values_survive(self) -> None:
        assert redact({"path": "sandbox-repo/README.md"})["path"] == "sandbox-repo/README.md"
