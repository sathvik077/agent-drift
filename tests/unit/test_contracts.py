"""Contract, attempt, decision and approval schema behaviour."""

from __future__ import annotations

import datetime as _dt

import pytest
from pydantic import ValidationError

from agent_drift.contracts import (
    ApprovalGrant,
    ApprovalState,
    ContractSource,
    IntentContract,
    Operation,
    ToolAttempt,
    utcnow,
)


def make_contract(**overrides: object) -> IntentContract:
    """A minimal valid contract."""
    defaults: dict[str, object] = {
        "principal": "dev",
        "task_id": "t-1",
        "user_goal": "review",
        "approved_by": "dev",
        "source": ContractSource.TRUSTED_CONFIG,
        "allowed_tools": ["repo.read_file"],
    }
    defaults.update(overrides)
    return IntentContract(**defaults)  # type: ignore[arg-type]


class TestContractIntegrity:
    """The contract hash must behave like an integrity identifier."""

    def test_hash_is_computed_on_construction(self) -> None:
        assert len(make_contract().contract_hash) == 64

    def test_identical_authority_hashes_identically(self) -> None:
        """Two contracts granting the same authority have the same hash, so a reviewer
        can see that an 'updated' contract changed no permission."""
        assert make_contract().contract_hash == make_contract().contract_hash

    def test_changing_a_permission_changes_the_hash(self) -> None:
        base = make_contract()
        wider = make_contract(allowed_tools=["repo.read_file", "repo.write_file"])
        assert base.contract_hash != wider.contract_hash

    def test_list_order_does_not_change_the_hash(self) -> None:
        a = make_contract(allowed_tools=["repo.read_file", "repo.list_files"])
        b = make_contract(allowed_tools=["repo.list_files", "repo.read_file"])
        assert a.contract_hash == b.contract_hash

    def test_inconsistent_supplied_hash_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="contract_hash"):
            make_contract(contract_hash="0" * 64)

    def test_budget_change_changes_the_hash(self) -> None:
        assert make_contract(max_writes=0).contract_hash != make_contract(max_writes=1).contract_hash


class TestContractValidation:
    """Validation must reject anything that could masquerade as approved."""

    def test_untrusted_source_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_contract(source="model_supplied")

    def test_unknown_field_is_rejected(self) -> None:
        """extra='forbid' stops a crafted payload smuggling an authority field."""
        with pytest.raises(ValidationError):
            make_contract(is_admin=True)

    def test_naive_datetime_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            make_contract(expires_at=_dt.datetime(2030, 1, 1))

    def test_blank_list_entry_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            make_contract(allowed_tools=["repo.read_file", "  "])

    def test_task_id_pattern_is_enforced(self) -> None:
        with pytest.raises(ValidationError):
            make_contract(task_id="has spaces")

    def test_operations_default_to_read_shaped(self) -> None:
        contract = make_contract()
        assert contract.allowed_operations == [Operation.READ, Operation.LIST]


class TestExpiry:
    """Expiry arithmetic must be explicit and timezone-aware."""

    def test_no_expiry_never_expires(self) -> None:
        assert make_contract().is_expired() is False

    def test_past_expiry_is_expired(self) -> None:
        contract = make_contract(expires_at=utcnow() - _dt.timedelta(seconds=1))
        assert contract.is_expired() is True

    def test_future_expiry_is_not_expired(self) -> None:
        contract = make_contract(expires_at=utcnow() + _dt.timedelta(hours=1))
        assert contract.is_expired() is False

    def test_expiry_is_evaluated_at_the_boundary(self) -> None:
        moment = utcnow()
        contract = make_contract(expires_at=moment)
        assert contract.is_expired(now=moment) is True

    def test_future_issuance_is_not_yet_valid(self) -> None:
        contract = make_contract(issued_at=utcnow() + _dt.timedelta(hours=1))
        assert contract.is_not_yet_valid() is True


class TestToolAttempt:
    """An attempt's digest is what an approval is bound to."""

    def test_digest_ignores_argument_order(self) -> None:
        left = ToolAttempt(tool_server="s", tool_name="t", args={"a": 1, "b": 2})
        right = ToolAttempt(tool_server="s", tool_name="t", args={"b": 2, "a": 1})
        assert left.canonical_args_digest() == right.canonical_args_digest()

    def test_digest_covers_every_argument(self) -> None:
        base = ToolAttempt(tool_server="s", tool_name="t", args={"path": "a"})
        extra = ToolAttempt(tool_server="s", tool_name="t", args={"path": "a", "force": True})
        assert base.canonical_args_digest() != extra.canonical_args_digest()

    def test_redacted_form_hides_secrets(self) -> None:
        attempt = ToolAttempt(
            tool_server="s", tool_name="t", args={"path": "a", "api_key": "sk-AAAAAAAAAAAAAAAAAA"}
        )
        assert attempt.redacted()["args"]["api_key"] == "[REDACTED]"

    def test_task_id_defaults_to_none(self) -> None:
        """No binding means fail closed, so the default must not invent an identity."""
        assert ToolAttempt(tool_server="s", tool_name="t").task_id is None


class TestApprovalGrant:
    """A grant must match on all five key components."""

    def _grant(self, attempt: ToolAttempt, **overrides: object) -> ApprovalGrant:
        defaults: dict[str, object] = {
            "attempt_id": attempt.attempt_id,
            "task_id": "t-1",
            "tool_name": attempt.tool_name,
            "tool_server": attempt.tool_server,
            "args_digest": attempt.canonical_args_digest(),
            "policy_revision": 1,
            "contract_hash": "h",
            "expires_at": utcnow() + _dt.timedelta(minutes=5),
        }
        defaults.update(overrides)
        return ApprovalGrant(**defaults)  # type: ignore[arg-type]

    def _attempt(self, **args: object) -> ToolAttempt:
        return ToolAttempt(task_id="t-1", tool_server="sandbox", tool_name="repo.delete_file", args=args)

    def test_exact_match_succeeds(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        grant = self._grant(attempt)
        assert grant.matches(attempt, policy_revision=1, contract_hash="h")

    def test_different_args_do_not_match(self) -> None:
        approved = self._attempt(path="tmp/a.txt")
        other = self._attempt(path="tmp/b.txt")
        assert not self._grant(approved).matches(other, policy_revision=1, contract_hash="h")

    def test_different_tool_does_not_match(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        grant = self._grant(attempt, tool_name="repo.write_file")
        assert not grant.matches(attempt, policy_revision=1, contract_hash="h")

    def test_stale_revision_does_not_match(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        assert not self._grant(attempt).matches(attempt, policy_revision=2, contract_hash="h")

    def test_changed_contract_hash_does_not_match(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        assert not self._grant(attempt).matches(attempt, policy_revision=1, contract_hash="other")

    def test_different_task_does_not_match(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        grant = self._grant(attempt, task_id="t-2")
        assert not grant.matches(attempt, policy_revision=1, contract_hash="h")

    def test_expiry_is_reported(self) -> None:
        attempt = self._attempt(path="tmp/a.txt")
        grant = self._grant(attempt, expires_at=utcnow() - _dt.timedelta(seconds=1))
        assert grant.is_expired() is True

    def test_initial_state_is_pending(self) -> None:
        assert self._grant(self._attempt(path="x")).state is ApprovalState.PENDING
