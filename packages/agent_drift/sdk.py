"""``DriftGuard``: a Python instrumentation SDK for non-MCP agent frameworks.

**Read this before using it.** ``DriftGuard.evaluate()`` *evaluates*; it does not
*enforce*. It returns a typed :class:`~agent_drift.contracts.Decision` describing what
the approved contract says about a proposed call. Whether the tool then runs is entirely
up to the caller. If your framework ignores a ``deny``, the tool runs.

That distinction is not pedantry. The whole reason the MCP gateway exists is that it sits
*between* the host and the tool, where it can refuse to forward. An SDK called from inside
the agent process is advisory by construction: the same code that asks permission is the
code that would have to honour it. Use the SDK when you cannot put a proxy in the path,
and understand that you are buying auditable decisions and a consistent policy, not
containment.

To make the difference visible rather than merely documented:

* :attr:`~agent_drift.contracts.Decision.is_enforcement` is always ``False``.
* ``evaluate()`` does **not** consume budget by default, because nothing was enforced and
  charging a budget for a call that may never happen would corrupt the budget.
* :meth:`DriftGuard.enforce` exists for callers who want the exception-raising shape, and
  its docstring says plainly that it only protects code that actually calls it.

Example::

    from agent_drift import DriftGuard

    guard = DriftGuard(db_path="var/agent_drift.db")
    decision = guard.evaluate(
        task_id="demo-repo-review",
        tool_name="repo.write_file",
        args={"path": "sandbox-repo/README.md", "content": "..."},
    )
    if decision.status != "allow":
        print(decision.reason_codes, decision.explanations)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import Decision, DecisionStatus, ToolAttempt
from .policy import PolicyEngine, ToolSpec
from .reasons import explain
from .store import Store

__all__ = ["DriftGuard", "PolicyViolation"]


class PolicyViolation(RuntimeError):
    """Raised by :meth:`DriftGuard.enforce` when a call is not permitted."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        codes = ", ".join(decision.reason_codes)
        super().__init__(f"Agent Drift denied {decision.attempt_id}: {codes}")


class DriftGuard:
    """Evaluate proposed tool calls against an approved intent contract.

    Parameters
    ----------
    db_path:
        SQLite database holding contracts and the decision log. Defaults to
        ``var/agent_drift.db``, the same database the control plane and gateway use, so
        SDK decisions appear in the dashboard alongside gateway decisions -- clearly
        labelled, because they are not enforcement.
    sandbox_root:
        Optional path-resolution root. When provided, path arguments are resolved through
        the real filesystem so symlink escapes are detected.
    tool_specs:
        Optional override of the tool specification table, for agents whose tools are not
        the bundled fixture's.
    record:
        When ``True`` (the default) attempts and decisions are persisted, which is what
        makes the audit trail complete. Set ``False`` for a pure dry run.
    """

    def __init__(
        self,
        db_path: str | Path = "var/agent_drift.db",
        *,
        sandbox_root: str | Path | None = None,
        tool_specs: dict[str, ToolSpec] | None = None,
        record: bool = True,
        store: Store | None = None,
    ) -> None:
        self._owns_store = store is None
        self.store = store or Store(db_path)
        self.engine = PolicyEngine(
            self.store,
            sandbox_root=Path(sandbox_root) if sandbox_root else None,
            tool_specs=tool_specs,
        )
        self.record = record

    # ------------------------------------------------------------------ evaluate

    def evaluate(
        self,
        task_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        tool_server: str = "sandbox",
        run_id: str | None = None,
        consume_budget: bool = False,
    ) -> Decision:
        """Evaluate a proposed call and return a typed decision.

        ``task_id`` is supplied by *your* code, which must get it from a trusted source.
        The SDK cannot verify that, which is another reason its result is advisory: in the
        gateway the task binding is a property of the process, here it is an argument.

        ``consume_budget`` defaults to ``False``. Set it ``True`` only if your caller
        reliably honours the decision, so that budgets reflect real usage.
        """
        attempt = (
            ToolAttempt(
                task_id=task_id,
                tool_server=tool_server,
                tool_name=tool_name,
                args=dict(args or {}),
                run_id=run_id,
            )
            if run_id
            else ToolAttempt(
                task_id=task_id,
                tool_server=tool_server,
                tool_name=tool_name,
                args=dict(args or {}),
            )
        )

        if self.record:
            self.store.record_attempt(attempt)

        decision = self.engine.evaluate(
            attempt,
            bound_task_id=task_id,
            observed_manifest=None,
            reserve=consume_budget,
        )
        decision.evidence = {
            **decision.evidence,
            "enforcement": "advisory (SDK evaluation, not interception)",
            "note": (
                "This decision was produced by DriftGuard.evaluate in the caller's own "
                "process. It is not enforcement: the caller decides whether the tool runs. "
                "Route calls through the MCP gateway for containment."
            ),
        }

        if self.record:
            self.store.record_decision(decision, run_id=attempt.run_id)

        return Decision(
            status=decision.status,
            reason_codes=decision.reason_codes,
            rule_ids=decision.rule_ids,
            policy_revision=decision.policy_revision,
            attempt_id=decision.attempt_id,
            resource=attempt.target_resource,
            destination=attempt.destination,
            risk=decision.risk,
            elapsed_ms=decision.elapsed_ms,
            contract_hash=decision.contract_hash,
            explanations=[explain(code) for code in decision.reason_codes],
        )

    def enforce(
        self,
        task_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        tool_server: str = "sandbox",
        allow_pending_approval: bool = False,
    ) -> Decision:
        """Evaluate and raise :class:`PolicyViolation` unless the call is allowed.

        This is a convenience shape, not a stronger guarantee. It protects exactly the
        code path that calls it: a tool invoked anywhere else in your agent is untouched.
        """
        decision = self.evaluate(task_id, tool_name, args, tool_server=tool_server, consume_budget=True)
        if decision.status is DecisionStatus.ALLOW:
            return decision
        if allow_pending_approval and decision.status is DecisionStatus.NEEDS_APPROVAL:
            return decision
        raise PolicyViolation(decision)

    # -------------------------------------------------------------------- context

    def close(self) -> None:
        """Close the underlying store if this guard opened it."""
        if self._owns_store:
            self.store.close()

    def __enter__(self) -> DriftGuard:
        """Enter a context that closes the store on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the store."""
        self.close()
