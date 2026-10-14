"""Approval grants must be argument-exact, single-use, revision-bound and TTL-bound (AD-08)."""

from __future__ import annotations

import datetime as _dt
import threading

import pytest

from agent_drift.contracts import (
    ApprovalGrant,
    ApprovalState,
    ContractSource,
    DecisionStatus,
    IntentContract,
    Operation,
    ToolAttempt,
    utcnow,
)
from agent_drift.reasons import Reason


@pytest.fixture
def cleanup_contract(store) -> IntentContract:
    """A delete task where every delete requires approval."""
    contract = IntentContract(
        principal="dev",
        task_id="t",
        user_goal="clean up tmp",
        approved_by="dev",
        source=ContractSource.TRUSTED_CONFIG,
        allowed_tools=["repo.delete_file"],
        allowed_operations=[Operation.DELETE],
        resource_scopes=["sandbox-repo/tmp/**"],
        approval_rules=["repo.delete_file"],
        max_writes=10,
        max_calls=50,
    )
    store.put_contract(contract)
    return contract


def delete_attempt(path: str = "sandbox-repo/tmp/demo.txt") -> ToolAttempt:
    """A delete attempt for a given path."""
    return ToolAttempt(tool_server="sandbox", tool_name="repo.delete_file", args={"path": path})


class TestApprovalRequired:
    """A tool in approval_rules must pause, not proceed."""

    def test_first_attempt_requires_approval(self, engine, cleanup_contract) -> None:
        decision = engine.evaluate(delete_attempt(), bound_task_id="t")
        assert decision.status is DecisionStatus.NEEDS_APPROVAL
        assert str(Reason.NEEDS_APPROVAL) in decision.reason_codes
        assert decision.approval_id is not None

    def test_pending_grant_is_persisted_with_the_args_digest(self, engine, store, cleanup_contract) -> None:
        attempt = delete_attempt()
        decision = engine.evaluate(attempt, bound_task_id="t")
        grant = store.get_approval(decision.approval_id or "")
        assert grant is not None
        assert grant.args_digest == attempt.canonical_args_digest()
        assert grant.state is ApprovalState.PENDING

    def test_no_budget_is_consumed_while_pending(self, engine, store, cleanup_contract) -> None:
        engine.evaluate(delete_attempt(), bound_task_id="t")
        assert store.get_budget("t", cleanup_contract.policy_revision)["writes_used"] == 0

    def test_a_non_gated_tool_does_not_pause(self, engine, store) -> None:
        contract = IntentContract(
            principal="dev",
            task_id="t2",
            user_goal="g",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.read_file"],
            allowed_operations=[Operation.READ],
            resource_scopes=["sandbox-repo/**"],
            max_calls=5,
        )
        store.put_contract(contract)
        decision = engine.evaluate(
            ToolAttempt(
                tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
            ),
            bound_task_id="t2",
        )
        assert decision.status is DecisionStatus.ALLOW


class TestApprovalExactness:
    """A grant authorizes one argument set, nothing adjacent to it."""

    def _approve(self, engine, store, attempt: ToolAttempt) -> str:
        decision = engine.evaluate(attempt, bound_task_id="t")
        approval_id = decision.approval_id or ""
        store.decide_approval(approval_id, approve=True, reviewer="reviewer")
        return approval_id

    def test_approved_exact_args_are_allowed(self, engine, store, cleanup_contract) -> None:
        attempt = delete_attempt()
        self._approve(engine, store, attempt)
        second = engine.evaluate(delete_attempt(), bound_task_id="t")
        assert second.status is DecisionStatus.ALLOW
        assert str(Reason.ALLOWED_AFTER_APPROVAL) in second.reason_codes

    def test_different_path_is_not_authorized(self, engine, store, cleanup_contract) -> None:
        self._approve(engine, store, delete_attempt("sandbox-repo/tmp/demo.txt"))
        other = engine.evaluate(delete_attempt("sandbox-repo/tmp/other.txt"), bound_task_id="t")
        assert other.status is DecisionStatus.NEEDS_APPROVAL, "a grant for one path authorized another"

    def test_extra_argument_is_not_authorized(self, engine, store, cleanup_contract) -> None:
        """Approving {"path": p} must not authorize {"path": p, "force": true}."""
        self._approve(engine, store, delete_attempt())
        forced = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": "sandbox-repo/tmp/demo.txt", "force": True},
        )
        decision = engine.evaluate(forced, bound_task_id="t")
        assert decision.status is DecisionStatus.NEEDS_APPROVAL

    def test_argument_reordering_is_still_the_same_grant(self, engine, store) -> None:
        """Canonicalization means key order does not defeat a legitimate approval."""
        contract = IntentContract(
            principal="dev",
            task_id="t3",
            user_goal="g",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.write_file"],
            allowed_operations=[Operation.WRITE],
            resource_scopes=["sandbox-repo/docs/**"],
            approval_rules=["repo.write_file"],
            max_writes=5,
            max_calls=50,
        )
        store.put_contract(contract)
        first = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"path": "sandbox-repo/docs/a.md", "content": "x"},
        )
        decision = engine.evaluate(first, bound_task_id="t3")
        store.decide_approval(decision.approval_id or "", approve=True, reviewer="r")
        reordered = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"content": "x", "path": "sandbox-repo/docs/a.md"},
        )
        assert engine.evaluate(reordered, bound_task_id="t3").status is DecisionStatus.ALLOW


class TestSingleUse:
    """A grant is consumed exactly once, including under concurrency."""

    def test_second_use_requires_a_new_approval(self, engine, store, cleanup_contract) -> None:
        decision = engine.evaluate(delete_attempt(), bound_task_id="t")
        store.decide_approval(decision.approval_id or "", approve=True, reviewer="r")
        assert engine.evaluate(delete_attempt(), bound_task_id="t").status is DecisionStatus.ALLOW
        assert engine.evaluate(delete_attempt(), bound_task_id="t").status is DecisionStatus.NEEDS_APPROVAL

    def test_consume_is_idempotent_at_the_store(self, store) -> None:
        grant = ApprovalGrant(
            attempt_id="a",
            task_id="t",
            tool_name="repo.delete_file",
            tool_server="sandbox",
            args_digest="d",
            policy_revision=1,
            contract_hash="h",
            expires_at=utcnow() + _dt.timedelta(minutes=5),
        )
        store.create_approval(grant)
        store.decide_approval(grant.approval_id, approve=True, reviewer="r")
        assert store.consume_grant(grant.approval_id) is True
        assert store.consume_grant(grant.approval_id) is False

    def test_concurrent_consumption_yields_one_winner(self, store) -> None:
        """Two threads racing to consume one grant: exactly one must succeed."""
        grant = ApprovalGrant(
            attempt_id="a",
            task_id="t",
            tool_name="repo.delete_file",
            tool_server="sandbox",
            args_digest="d",
            policy_revision=1,
            contract_hash="h",
            expires_at=utcnow() + _dt.timedelta(minutes=5),
        )
        store.create_approval(grant)
        store.decide_approval(grant.approval_id, approve=True, reviewer="r")

        results: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def attempt_consume() -> None:
            barrier.wait()
            outcome = store.consume_grant(grant.approval_id)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt_consume) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert sum(results) == 1, f"expected exactly one consumer, got {sum(results)}"


class TestDeclineAndTimeout:
    """Declining and expiry must both deny, never fall through to allow."""

    def test_declined_grant_denies_the_same_arguments(self, engine, store, cleanup_contract) -> None:
        decision = engine.evaluate(delete_attempt(), bound_task_id="t")
        store.decide_approval(decision.approval_id or "", approve=False, reviewer="r")
        second = engine.evaluate(delete_attempt(), bound_task_id="t")
        assert second.status is DecisionStatus.DENY
        assert str(Reason.APPROVAL_DECLINED) in second.reason_codes

    def test_expired_pending_grant_cannot_be_approved(self, store) -> None:
        grant = ApprovalGrant(
            attempt_id="a",
            task_id="t",
            tool_name="repo.delete_file",
            tool_server="sandbox",
            args_digest="d",
            policy_revision=1,
            contract_hash="h",
            expires_at=utcnow() - _dt.timedelta(seconds=1),
        )
        store.create_approval(grant)
        ok, reason = store.decide_approval(grant.approval_id, approve=True, reviewer="r")
        assert ok is False
        assert reason == str(Reason.APPROVAL_EXPIRED)

    def test_expired_approved_grant_is_not_consumable(self, store) -> None:
        attempt = delete_attempt()
        grant = ApprovalGrant(
            attempt_id=attempt.attempt_id,
            task_id="t",
            tool_name=attempt.tool_name,
            tool_server="sandbox",
            args_digest=attempt.canonical_args_digest(),
            policy_revision=1,
            contract_hash="h",
            state=ApprovalState.APPROVED,
            expires_at=utcnow() + _dt.timedelta(milliseconds=1),
        )
        store.create_approval(grant)
        store.decide_approval(grant.approval_id, approve=True, reviewer="r")
        import time

        time.sleep(0.02)
        attempt.task_id = "t"
        assert store.find_consumable_grant(attempt, policy_revision=1, contract_hash="h") is None

    def test_expire_stale_marks_pending_grants(self, store) -> None:
        grant = ApprovalGrant(
            attempt_id="a",
            task_id="t",
            tool_name="x",
            tool_server="s",
            args_digest="d",
            policy_revision=1,
            contract_hash="h",
            expires_at=utcnow() - _dt.timedelta(seconds=1),
        )
        store.create_approval(grant)
        assert store.expire_stale_approvals() == 1
        refreshed = store.get_approval(grant.approval_id)
        assert refreshed is not None and refreshed.state is ApprovalState.EXPIRED

    def test_decided_grant_cannot_be_decided_again(self, store) -> None:
        grant = ApprovalGrant(
            attempt_id="a",
            task_id="t",
            tool_name="x",
            tool_server="s",
            args_digest="d",
            policy_revision=1,
            contract_hash="h",
            expires_at=utcnow() + _dt.timedelta(minutes=5),
        )
        store.create_approval(grant)
        assert store.decide_approval(grant.approval_id, approve=True, reviewer="r")[0] is True
        ok, reason = store.decide_approval(grant.approval_id, approve=False, reviewer="r")
        assert ok is False
        assert reason == str(Reason.APPROVAL_ALREADY_CONSUMED)

    def test_unknown_approval_is_not_found(self, store) -> None:
        ok, reason = store.decide_approval("apr_missing", approve=True, reviewer="r")
        assert ok is False
        assert reason == str(Reason.APPROVAL_NOT_FOUND)


class TestRevisionBinding:
    """A new contract revision invalidates outstanding grants."""

    def test_new_revision_invalidates_a_grant(self, engine, store, cleanup_contract) -> None:
        decision = engine.evaluate(delete_attempt(), bound_task_id="t")
        store.decide_approval(decision.approval_id or "", approve=True, reviewer="r")

        updated = IntentContract(
            principal="dev",
            task_id="t",
            user_goal="clean up tmp, revised",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.delete_file"],
            allowed_operations=[Operation.DELETE],
            resource_scopes=["sandbox-repo/tmp/**"],
            approval_rules=["repo.delete_file"],
            max_writes=10,
            max_calls=50,
            policy_revision=cleanup_contract.policy_revision + 1,
            version=cleanup_contract.version + 1,
        )
        store.put_contract(updated)

        after = engine.evaluate(delete_attempt(), bound_task_id="t")
        assert after.status is DecisionStatus.NEEDS_APPROVAL, "a stale-revision grant was honoured"
