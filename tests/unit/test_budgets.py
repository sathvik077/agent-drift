"""Budget semantics, including the distinction found by the scenario runs (D-011)."""

from __future__ import annotations

from agent_drift.contracts import (
    MUTATING_OPERATIONS,
    WRITE_BUDGET_OPERATIONS,
    ContractSource,
    DecisionStatus,
    IntentContract,
    Operation,
    ToolAttempt,
)
from agent_drift.reasons import Reason


class TestBudgetOperationSets:
    """The write budget is narrower than the set of state-changing operations."""

    def test_write_budget_covers_file_mutations_only(self) -> None:
        assert {Operation.WRITE, Operation.DELETE} == WRITE_BUDGET_OPERATIONS

    def test_network_post_is_mutating_but_not_write_budgeted(self) -> None:
        """Rationale in docs/DECISIONS.md D-011: a permitted POST must not be denied by
        a file-write budget of zero, which is what the egress scenario caught."""
        assert Operation.NETWORK_POST in MUTATING_OPERATIONS
        assert Operation.NETWORK_POST not in WRITE_BUDGET_OPERATIONS


class TestReservation:
    """Reservation must be atomic and must not leak on denial."""

    def _contract(self, store, **overrides) -> IntentContract:
        defaults = {
            "principal": "dev",
            "task_id": "t",
            "user_goal": "g",
            "approved_by": "dev",
            "source": ContractSource.TRUSTED_CONFIG,
            "allowed_tools": ["repo.write_file", "network.http_post", "repo.read_file"],
            "allowed_operations": [Operation.WRITE, Operation.NETWORK_POST, Operation.READ],
            "resource_scopes": ["sandbox-repo/**"],
            "allowed_destinations": ["reports.internal.example"],
            "max_writes": 2,
            "max_calls": 4,
        }
        defaults.update(overrides)
        contract = IntentContract(**defaults)
        store.put_contract(contract)
        return contract

    def _write(self, engine, path: str = "sandbox-repo/docs/a.md"):
        return engine.evaluate(
            ToolAttempt(
                tool_server="sandbox", tool_name="repo.write_file", args={"path": path, "content": "x"}
            ),
            bound_task_id="t",
        )

    def test_writes_are_counted(self, engine, store) -> None:
        contract = self._contract(store)
        assert self._write(engine).status is DecisionStatus.ALLOW
        assert self._write(engine).status is DecisionStatus.ALLOW
        third = self._write(engine)
        assert third.status is DecisionStatus.DENY
        assert str(Reason.WRITE_BUDGET_EXCEEDED) in third.reason_codes
        assert store.get_budget(contract.task_id, contract.policy_revision)["writes_used"] == 2

    def test_call_budget_is_independent(self, engine, store) -> None:
        self._contract(store, max_writes=10, max_calls=2)
        read = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        assert engine.evaluate(read, bound_task_id="t").status is DecisionStatus.ALLOW
        read2 = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        assert engine.evaluate(read2, bound_task_id="t").status is DecisionStatus.ALLOW
        read3 = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        third = engine.evaluate(read3, bound_task_id="t")
        assert str(Reason.CALL_BUDGET_EXCEEDED) in third.reason_codes

    def test_egress_does_not_consume_the_write_budget(self, engine, store) -> None:
        """The exact false block that D-011 records."""
        contract = self._contract(store, max_writes=0)
        decision = engine.evaluate(
            ToolAttempt(
                tool_server="sandbox",
                tool_name="network.http_post",
                args={"url": "https://reports.internal.example/publish", "body": "report"},
            ),
            bound_task_id="t",
        )
        assert decision.status is DecisionStatus.ALLOW, decision.reason_codes
        assert store.get_budget(contract.task_id, contract.policy_revision)["writes_used"] == 0

    def test_denied_call_consumes_no_budget(self, engine, store) -> None:
        contract = self._contract(store, resource_scopes=["sandbox-repo/docs/**"])
        denied = self._write(engine, path="sandbox-repo/src/payment.py")
        assert denied.status is DecisionStatus.DENY
        usage = store.get_budget(contract.task_id, contract.policy_revision)
        assert usage == {"calls_used": 0, "writes_used": 0}

    def test_zero_call_budget_denies_everything(self, engine, store) -> None:
        self._contract(store, max_calls=0)
        decision = self._write(engine)
        assert decision.status is DecisionStatus.DENY
        assert str(Reason.CALL_BUDGET_EXCEEDED) in decision.reason_codes

    def test_release_returns_a_reservation(self, store) -> None:
        contract = self._contract(store)
        store.reserve_budget("t", contract.policy_revision, max_calls=4, max_writes=2, is_write=True)
        assert store.get_budget("t", contract.policy_revision)["writes_used"] == 1
        store.release_budget("t", contract.policy_revision, is_write=True)
        assert store.get_budget("t", contract.policy_revision) == {"calls_used": 0, "writes_used": 0}

    def test_release_never_goes_negative(self, store) -> None:
        contract = self._contract(store)
        store.release_budget("t", contract.policy_revision, is_write=True)
        usage = store.get_budget("t", contract.policy_revision)
        assert usage["calls_used"] >= 0 and usage["writes_used"] >= 0

    def test_new_revision_resets_the_budget(self, store, engine) -> None:
        """A new revision is a new grant of authority with its own budget."""
        first = self._contract(store, max_writes=1)
        assert self._write(engine).status is DecisionStatus.ALLOW
        assert self._write(engine).status is DecisionStatus.DENY
        self._contract(
            store, max_writes=1, policy_revision=first.policy_revision + 1, version=first.version + 1
        )
        assert self._write(engine).status is DecisionStatus.ALLOW
