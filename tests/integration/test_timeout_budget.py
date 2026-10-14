"""RT-01 end to end: a timed-out write must not refund its budget.

The exploit an independent review demonstrated: with a tool slower than the gateway's
timeout, every timed-out write was recorded as "did not execute" and refunded, so a
contract with `max_writes: 2` admitted an unbounded number of writes. The oracle here is
the upstream's own counter file and the files actually on disk.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from agent_drift.seed import build_contract
from agent_drift.store import UPSTREAM_EXECUTION_STATES, Store

from .harness import REPO_ROOT

pytestmark = [pytest.mark.integration, pytest.mark.anyio, pytest.mark.slow]

SLOW_SERVER = Path(__file__).resolve().parent / "fixtures" / "slow_upstream.py"


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


def _counters(state: Path) -> dict[str, int]:
    try:
        return {str(k): int(v) for k, v in json.loads((state / "counters.json").read_text()).items()}
    except (OSError, ValueError):
        return {}


class TestTimeoutDoesNotRefundBudget:
    """The write budget must hold even when the tool outlives the timeout."""

    async def test_slow_writes_cannot_exceed_the_write_budget(self, db_path: Path, tmp_path: Path) -> None:
        state = tmp_path / "slow-state"
        (state / "workspace" / "sandbox-repo" / "docs").mkdir(parents=True, exist_ok=True)

        store = Store(db_path)
        try:
            contract = build_contract("docswrite", max_writes=2, max_calls=50)
            store.put_contract(contract)
        finally:
            store.close()

        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(state),
            "AD_SLOW_UPSTREAM_SLEEP": "3.0",
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
                "demo-docs-edit",
                "--db",
                str(db_path),
                "--sandbox-root",
                str(state / "workspace"),
                "--upstream-command",
                sys.executable,
                "--upstream-arg",
                str(SLOW_SERVER),
                "--upstream-timeout",
                "1.0",
                "--log-level",
                "CRITICAL",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        attempts = 5
        async with Client(params, read_timeout_seconds=60.0) as client:
            await client.list_tools()
            for index in range(attempts):
                # The timeout IS the test: the gateway gives up waiting and raises.
                with contextlib.suppress(Exception):
                    await client.call_tool(
                        "repo.write_file",
                        {"path": f"sandbox-repo/docs/slow-{index}.md", "content": "x"},
                    )

        executed = _counters(state).get("repo.write_file", 0)
        files = sorted(p.name for p in (state / "workspace" / "sandbox-repo" / "docs").glob("*.md"))

        assert executed <= contract.max_writes, (
            f"the upstream executed {executed} writes against a budget of "
            f"{contract.max_writes}; files on disk: {files}"
        )
        assert len(files) <= contract.max_writes, files

    async def test_a_timed_out_call_is_recorded_as_execution_unknown(
        self, db_path: Path, tmp_path: Path
    ) -> None:
        """The receipt must not claim a delivered call did not run."""
        state = tmp_path / "slow-state-2"
        (state / "workspace" / "sandbox-repo" / "docs").mkdir(parents=True, exist_ok=True)

        store = Store(db_path)
        try:
            store.put_contract(build_contract("docswrite", max_writes=5, max_calls=50))
        finally:
            store.close()

        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(state),
            "AD_SLOW_UPSTREAM_SLEEP": "3.0",
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
                "demo-docs-edit",
                "--db",
                str(db_path),
                "--sandbox-root",
                str(state / "workspace"),
                "--upstream-command",
                sys.executable,
                "--upstream-arg",
                str(SLOW_SERVER),
                "--upstream-timeout",
                "1.0",
                "--log-level",
                "CRITICAL",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        async with Client(params, read_timeout_seconds=60.0) as client:
            await client.list_tools()
            with contextlib.suppress(Exception):
                await client.call_tool(
                    "repo.write_file", {"path": "sandbox-repo/docs/once.md", "content": "x"}
                )

        store = Store(db_path)
        try:
            row = store.conn.execute(
                "SELECT upstream_executed, upstream_error FROM decisions "
                "WHERE status = 'allow' ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            assert row is not None, "no allow decision was recorded"
            state_label = UPSTREAM_EXECUTION_STATES[int(row["upstream_executed"])]
            assert state_label == "unknown", (
                f"a timed-out call was recorded as {state_label!r}; the gateway cannot know "
                "whether the tool ran, and must say so"
            )
            assert row["upstream_error"]
            assert store.counts()["execution_unknown"] >= 1
        finally:
            store.close()

    async def test_a_fast_upstream_is_unaffected(self, db_path: Path, tmp_path: Path) -> None:
        """The fix must not make ordinary calls look uncertain."""
        state = tmp_path / "fast-state"
        (state / "workspace" / "sandbox-repo" / "docs").mkdir(parents=True, exist_ok=True)

        store = Store(db_path)
        try:
            store.put_contract(build_contract("docswrite", max_writes=5, max_calls=50))
        finally:
            store.close()

        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(state),
            "AD_SLOW_UPSTREAM_SLEEP": "0",
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
                "demo-docs-edit",
                "--db",
                str(db_path),
                "--sandbox-root",
                str(state / "workspace"),
                "--upstream-command",
                sys.executable,
                "--upstream-arg",
                str(SLOW_SERVER),
                "--upstream-timeout",
                "20",
                "--log-level",
                "CRITICAL",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        async with Client(params, read_timeout_seconds=60.0) as client:
            await client.list_tools()
            result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/docs/fast.md", "content": "x"}
            )
            assert result.is_error is False

        store = Store(db_path)
        try:
            row = store.conn.execute(
                "SELECT upstream_executed FROM decisions WHERE status = 'allow' ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            assert UPSTREAM_EXECUTION_STATES[int(row["upstream_executed"])] == "yes"
            assert store.counts()["execution_unknown"] == 0
        finally:
            store.close()
