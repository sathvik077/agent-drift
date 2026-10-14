"""Task identity is host-owned and cannot be supplied, forged or inferred (AD-07)."""

from __future__ import annotations

import pytest

from agent_drift.contracts import ContractSource, DecisionStatus, IntentContract, Operation, ToolAttempt
from agent_drift.reasons import Reason

#: Argument keys an attacker might try to use to assert authority.
IDENTITY_KEYS = [
    "task_id",
    "taskId",
    "TASK_ID",
    "task",
    "principal",
    "contract",
    "contract_id",
    "contract_hash",
    "policy_revision",
    "approved_by",
    "approval_id",
    "admin_token",
    "ad_task_id",
    "_task_id",
    "trust_tier",
    "trusted",
]


@pytest.fixture
def two_tasks(store) -> tuple[IntentContract, IntentContract]:
    """A read-only task and a write-capable task, both registered."""
    readonly = IntentContract(
        principal="dev",
        task_id="task-readonly",
        user_goal="review only",
        approved_by="dev",
        source=ContractSource.TRUSTED_CONFIG,
        allowed_tools=["repo.read_file"],
        allowed_operations=[Operation.READ],
        resource_scopes=["sandbox-repo/**"],
        denied_actions=[Operation.WRITE, Operation.DELETE, Operation.NETWORK_POST],
        max_writes=0,
        max_calls=50,
    )
    writable = IntentContract(
        principal="dev",
        task_id="task-writable",
        user_goal="edit docs",
        approved_by="dev",
        source=ContractSource.TRUSTED_CONFIG,
        allowed_tools=["repo.read_file", "repo.write_file"],
        allowed_operations=[Operation.READ, Operation.WRITE],
        resource_scopes=["sandbox-repo/docs/**"],
        max_writes=5,
        max_calls=50,
    )
    store.put_contract(readonly)
    store.put_contract(writable)
    return readonly, writable


class TestSpoofedIdentityArguments:
    """An identity-shaped argument is refused and recorded, never honoured."""

    @pytest.mark.parametrize("key", IDENTITY_KEYS)
    def test_identity_argument_is_refused(self, engine, two_tasks, key: str) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"path": "sandbox-repo/docs/a.md", "content": "x", key: "task-writable"},
        )
        decision = engine.evaluate(attempt, bound_task_id="task-readonly")
        assert decision.status is DecisionStatus.DENY
        assert decision.reason_codes == [str(Reason.TASK_SPOOF_ATTEMPT)]
        assert decision.rule_ids == ["R2-task-identity"]

    def test_the_attempt_is_recorded_as_evidence(self, engine, two_tasks) -> None:
        """Seeing a spoof attempt is signal; it is surfaced, not silently dropped."""
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md", "task_id": "task-writable"},
        )
        decision = engine.evaluate(attempt, bound_task_id="task-readonly")
        assert decision.evidence["spoofed_argument_keys"] == ["task_id"]
        assert decision.evidence["bound_task_id"] == "task-readonly"

    def test_spoof_is_caught_before_the_contract_is_consulted(self, engine, two_tasks) -> None:
        """Even a path that the *claimed* task would permit is still refused."""
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"path": "sandbox-repo/docs/a.md", "content": "x", "task_id": "task-writable"},
        )
        decision = engine.evaluate(attempt, bound_task_id="task-writable")
        assert decision.status is DecisionStatus.DENY

    def test_benign_arguments_are_untouched(self, engine, two_tasks) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md"},
        )
        assert engine.evaluate(attempt, bound_task_id="task-readonly").status is DecisionStatus.ALLOW


class TestBindingRequired:
    """No binding means nothing is authorized."""

    def test_missing_binding_denies(self, engine, two_tasks) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        decision = engine.evaluate(attempt, bound_task_id=None)
        assert decision.reason_codes == [str(Reason.MISSING_TASK_BINDING)]

    def test_empty_string_binding_denies(self, engine, two_tasks) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        assert engine.evaluate(attempt, bound_task_id="").status is DecisionStatus.DENY

    def test_attempt_task_mismatching_the_binding_denies(self, engine, two_tasks) -> None:
        """A pre-populated attempt task that disagrees with the binding is a mismatch."""
        attempt = ToolAttempt(
            task_id="task-writable",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md"},
        )
        decision = engine.evaluate(attempt, bound_task_id="task-readonly")
        assert decision.reason_codes == [str(Reason.TASK_MISMATCH)]

    def test_unknown_task_binding_denies(self, engine, two_tasks) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox", tool_name="repo.read_file", args={"path": "sandbox-repo/README.md"}
        )
        decision = engine.evaluate(attempt, bound_task_id="task-does-not-exist")
        assert decision.reason_codes == [str(Reason.NO_CONTRACT)]


class TestTaskIsolation:
    """One task's binding must give no access to another task's policy or budget."""

    def test_readonly_binding_cannot_use_the_other_task_policy(self, engine, two_tasks) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"path": "sandbox-repo/docs/a.md", "content": "x"},
        )
        decision = engine.evaluate(attempt, bound_task_id="task-readonly")
        assert decision.status is DecisionStatus.DENY
        assert str(Reason.TOOL_NOT_ALLOWED) in decision.reason_codes

    def test_budgets_are_per_task(self, engine, two_tasks, store) -> None:
        readonly, writable = two_tasks
        engine.evaluate(
            ToolAttempt(
                tool_server="sandbox",
                tool_name="repo.write_file",
                args={"path": "sandbox-repo/docs/a.md", "content": "x"},
            ),
            bound_task_id="task-writable",
        )
        assert store.get_budget("task-writable", writable.policy_revision)["writes_used"] == 1
        assert store.get_budget("task-readonly", readonly.policy_revision)["writes_used"] == 0

    def test_approvals_are_per_task(self, store) -> None:
        """A grant issued for one task must not be findable from another."""
        import datetime as _dt

        from agent_drift.contracts import ApprovalGrant, ApprovalState, utcnow

        attempt = ToolAttempt(
            task_id="task-other",
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": "sandbox-repo/tmp/demo.txt"},
        )
        grant = ApprovalGrant(
            attempt_id=attempt.attempt_id,
            task_id="task-other",
            tool_name=attempt.tool_name,
            tool_server="sandbox",
            args_digest=attempt.canonical_args_digest(),
            policy_revision=1,
            contract_hash="h",
            state=ApprovalState.APPROVED,
            expires_at=utcnow() + _dt.timedelta(minutes=5),
        )
        store.create_approval(grant)
        store.decide_approval(grant.approval_id, approve=True, reviewer="r")

        other_task_attempt = ToolAttempt(
            task_id="task-readonly",
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": "sandbox-repo/tmp/demo.txt"},
        )
        found = store.find_consumable_grant(other_task_attempt, policy_revision=1, contract_hash="h")
        assert found is None
