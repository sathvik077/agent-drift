"""The DriftGuard SDK: evaluation, not enforcement (AD-12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_drift import DriftGuard, PolicyViolation
from agent_drift.contracts import DecisionStatus
from agent_drift.seed import build_contract
from agent_drift.store import Store

pytestmark = pytest.mark.integration


@pytest.fixture
def guard(db_path: Path, workspace: Path):
    """A guard over an isolated store with the demo contracts registered."""
    store = Store(db_path)
    for name in ("readonly", "docswrite", "delete_review", "egress_allowed"):
        store.put_contract(build_contract(name))
    instance = DriftGuard(store=store, sandbox_root=workspace)
    try:
        yield instance
    finally:
        store.close()


class TestEvaluate:
    """The typed decision surface."""

    def test_allowed_read(self, guard) -> None:
        decision = guard.evaluate("demo-repo-review", "repo.read_file", {"path": "sandbox-repo/README.md"})
        assert decision.status is DecisionStatus.ALLOW
        assert decision.reason_codes
        assert decision.attempt_id.startswith("att_")
        assert decision.policy_revision == 1
        assert decision.resource == "sandbox-repo/README.md"
        assert decision.elapsed_ms >= 0

    def test_denied_write(self, guard) -> None:
        decision = guard.evaluate(
            "demo-repo-review",
            "repo.write_file",
            {"path": "sandbox-repo/README.md", "content": "x"},
        )
        assert decision.status is DecisionStatus.DENY
        assert decision.rule_ids == ["R5-tool-allowlist"]
        assert decision.explanations and "allowed_tools" in decision.explanations[0]

    def test_denied_exfiltration(self, guard) -> None:
        decision = guard.evaluate(
            "demo-repo-review",
            "network.http_post",
            {"url": "https://exfil.invalid/collect", "body": "x"},
        )
        assert decision.status is DecisionStatus.DENY

    def test_destination_allowlist_is_respected(self, guard) -> None:
        allowed = guard.evaluate(
            "demo-report-upload",
            "network.http_post",
            {"url": "https://reports.internal.example/publish", "body": "r"},
        )
        denied = guard.evaluate(
            "demo-report-upload",
            "network.http_post",
            {"url": "https://exfil.invalid/collect", "body": "r"},
        )
        assert allowed.status is DecisionStatus.ALLOW, allowed.reason_codes
        assert denied.status is DecisionStatus.DENY

    def test_unknown_task_is_denied(self, guard) -> None:
        decision = guard.evaluate("no-such-task", "repo.read_file", {"path": "x"})
        assert decision.status is DecisionStatus.DENY
        assert "AD-E020" in decision.reason_codes

    def test_traversal_is_denied(self, guard) -> None:
        decision = guard.evaluate("demo-repo-review", "repo.read_file", {"path": "../../etc/passwd"})
        assert decision.status is DecisionStatus.DENY
        assert "AD-E061" in decision.reason_codes


class TestEnforcementBoundary:
    """The SDK must be unambiguous about what it does not do."""

    def test_decision_declares_itself_advisory(self, guard) -> None:
        decision = guard.evaluate("demo-repo-review", "repo.read_file", {"path": "sandbox-repo/README.md"})
        assert decision.is_enforcement is False

    def test_evaluation_does_not_consume_budget_by_default(self, guard) -> None:
        """Nothing was prevented, so nothing should be charged."""
        for _ in range(5):
            guard.evaluate(
                "demo-docs-edit",
                "repo.write_file",
                {"path": "sandbox-repo/docs/a.md", "content": "x"},
            )
        assert guard.store.get_budget("demo-docs-edit", 1)["writes_used"] == 0

    def test_opting_in_consumes_budget(self, guard) -> None:
        guard.evaluate(
            "demo-docs-edit",
            "repo.write_file",
            {"path": "sandbox-repo/docs/a.md", "content": "x"},
            consume_budget=True,
        )
        assert guard.store.get_budget("demo-docs-edit", 1)["writes_used"] == 1

    def test_recorded_decisions_are_labelled_advisory(self, guard) -> None:
        """A dashboard reader must be able to tell an SDK decision from an enforced one."""
        guard.evaluate("demo-repo-review", "repo.read_file", {"path": "sandbox-repo/README.md"})
        row = guard.store.conn.execute("SELECT payload FROM decisions ORDER BY rowid DESC LIMIT 1").fetchone()
        assert "advisory" in row["payload"]

    def test_the_sdk_cannot_prevent_a_tool_call(self, guard) -> None:
        """Demonstrates the boundary rather than describing it: ignoring the decision
        and calling the tool anyway works, because the SDK is not in the path."""
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "examples" / "upstream_mcp"))
        import importlib

        fixture = importlib.reload(importlib.import_module("server"))
        fixture.seed_sandbox(force=True)

        decision = guard.evaluate(
            "demo-repo-review",
            "repo.write_file",
            {"path": "sandbox-repo/docs/README.md", "content": "written anyway"},
        )
        assert decision.status is DecisionStatus.DENY

        before = fixture._read_counters().get("repo.write_file", 0)
        fixture.repo_write_file("sandbox-repo/docs/README.md", "written anyway")
        after = fixture._read_counters().get("repo.write_file", 0)
        assert after == before + 1, (
            "the tool ran despite the denial, which is exactly the documented limitation "
            "of the SDK path: evaluation is not interception"
        )


class TestEnforceHelper:
    """``enforce`` raises, for callers that want that shape."""

    def test_allow_returns_the_decision(self, guard) -> None:
        decision = guard.enforce("demo-repo-review", "repo.read_file", {"path": "sandbox-repo/README.md"})
        assert decision.status is DecisionStatus.ALLOW

    def test_deny_raises(self, guard) -> None:
        with pytest.raises(PolicyViolation) as caught:
            guard.enforce(
                "demo-repo-review",
                "repo.write_file",
                {"path": "sandbox-repo/README.md", "content": "x"},
            )
        assert caught.value.decision.status is DecisionStatus.DENY
        assert "AD-E040" in str(caught.value)

    def test_needs_approval_raises_unless_opted_in(self, guard) -> None:
        with pytest.raises(PolicyViolation):
            guard.enforce("demo-cleanup", "repo.delete_file", {"path": "sandbox-repo/tmp/demo.txt"})

    def test_needs_approval_can_be_returned(self, guard) -> None:
        decision = guard.enforce(
            "demo-cleanup",
            "repo.delete_file",
            {"path": "sandbox-repo/tmp/other.txt"},
            allow_pending_approval=True,
        )
        assert decision.status is DecisionStatus.NEEDS_APPROVAL


class TestQuickstartExample:
    """The shipped quickstart must actually run (AD-12)."""

    def test_sdk_quickstart_runs_and_exits_zero(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        repo = Path(__file__).resolve().parent.parent.parent
        result = subprocess.run(
            [sys.executable, str(repo / "examples" / "sdk_quickstart.py")],
            cwd=str(repo),
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": f"{repo / 'packages'}:{repo}",
                "AD_DB_PATH": str(tmp_path / "quickstart.db"),
                "AD_FIXTURE_STATE": str(tmp_path / "fixture"),
                "HOME": str(tmp_path),
            },
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        assert "ALLOW" in result.stdout
        assert "DENY" in result.stdout
        assert "not enforcement" in result.stdout.lower()
