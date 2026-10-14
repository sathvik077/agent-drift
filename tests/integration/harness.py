"""Shared harness for integration tests that spawn real MCP processes.

A test using this harness runs three real processes: the test itself acting as the MCP
*host* via ``mcp.Client``, the Agent Drift *gateway*, and the sandbox *upstream*. Nothing
is mocked, and every assertion about whether a tool ran reads the upstream's own counter
file rather than asking the gateway.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_SERVER = REPO_ROOT / "examples" / "upstream_mcp" / "server.py"


@dataclass
class Oracle:
    """Reads the upstream's own state. The gateway cannot influence these files."""

    state: Path

    def counters(self) -> dict[str, int]:
        """Per-tool execution counts, written by the upstream before it does anything."""
        try:
            data = json.loads((self.state / "counters.json").read_text())
        except (OSError, ValueError):
            return {}
        return {str(key): int(value) for key, value in data.items()}

    def count(self, tool: str) -> int:
        """Execution count for one tool."""
        return self.counters().get(tool, 0)

    def sink_events(self) -> int:
        """Simulated egress events recorded by the upstream."""
        try:
            text = (self.state / "egress_sink.jsonl").read_text()
        except OSError:
            return 0
        return sum(1 for line in text.splitlines() if line.strip())

    def workspace(self) -> Path:
        """Path-resolution root for file tools."""
        return self.state / "workspace"

    def sha256(self, relative: str) -> str | None:
        """SHA-256 of a sandbox file, or ``None`` when absent."""
        try:
            return hashlib.sha256((self.workspace() / relative).read_bytes()).hexdigest()
        except OSError:
            return None

    def exists(self, relative: str) -> bool:
        """Does a sandbox file exist?"""
        return (self.workspace() / relative).exists()


@asynccontextmanager
async def gateway_client(
    *,
    task_id: str,
    db_path: Path,
    state: Path,
    approval_timeout_s: float = 2.0,
    mutate_manifest: bool = False,
    extra_env: dict[str, str] | None = None,
) -> AsyncIterator[tuple[Client, Oracle]]:
    """Open a real MCP client connected to a real gateway over stdio.

    The gateway is launched as a subprocess with an explicit ``--task-id``, which is the
    trust anchor: nothing the client sends can change it.
    """
    import os

    env = {
        **os.environ,
        "AD_FIXTURE_STATE": str(state),
        "AD_LOG_LEVEL": "WARNING",
        "PYTHONPATH": f"{REPO_ROOT / 'packages'}:{REPO_ROOT}",
    }
    if mutate_manifest:
        env["AD_FIXTURE_MUTATE_MANIFEST"] = "1"
    if extra_env:
        env.update(extra_env)

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agent_drift.cli",
            "gateway",
            "--task-id",
            task_id,
            "--db",
            str(db_path),
            "--sandbox-root",
            str(state / "workspace"),
            "--approval-timeout",
            str(approval_timeout_s),
            "--log-level",
            "WARNING",
        ],
        env=env,
        cwd=str(REPO_ROOT),
    )

    async with Client(params, read_timeout_seconds=60.0) as client:
        yield client, Oracle(state=state)


@asynccontextmanager
async def direct_upstream(state: Path, *, mutate_manifest: bool = False) -> AsyncIterator[Client]:
    """Connect straight to the upstream, bypassing the gateway.

    Used to establish the *unguarded* baseline: with no gateway in the path, the write
    simply happens. That is how the suite shows the gateway is the thing making the
    difference, rather than the fixture being inert.
    """
    import os

    env = {**os.environ, "AD_FIXTURE_STATE": str(state)}
    if mutate_manifest:
        env["AD_FIXTURE_MUTATE_MANIFEST"] = "1"
    params = StdioServerParameters(
        command=sys.executable, args=[str(FIXTURE_SERVER)], env=env, cwd=str(REPO_ROOT)
    )
    async with Client(params, read_timeout_seconds=30.0) as client:
        yield client


def decision_of(result: Any) -> str:
    """Agent Drift's decision for a tool result: ``allow``, ``deny`` or ``error``."""
    if not getattr(result, "is_error", False):
        return "allow"
    payload = _agent_drift_payload(result)
    return str(payload.get("decision", "deny")) if payload else "error"


def reason_codes(result: Any) -> list[str]:
    """Reason codes carried by a denial result."""
    payload = _agent_drift_payload(result)
    return [str(code) for code in payload.get("reason_codes", [])] if payload else []


def rule_ids(result: Any) -> list[str]:
    """Rule identifiers carried by a denial result."""
    payload = _agent_drift_payload(result)
    return [str(rule) for rule in payload.get("rule_ids", [])] if payload else []


def result_text(result: Any) -> str:
    """Concatenated text content of a tool result."""
    return "".join(getattr(block, "text", "") for block in (getattr(result, "content", None) or []))


def _agent_drift_payload(result: Any) -> dict[str, Any] | None:
    """Extract the structured Agent Drift denial record from a result."""
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and "agent_drift" in structured:
        inner = structured["agent_drift"]
        return inner if isinstance(inner, dict) else None
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", "")
        if "agent_drift" in text:
            try:
                parsed = json.loads(text)
            except ValueError:
                return None
            inner = parsed.get("agent_drift")
            return inner if isinstance(inner, dict) else None
    return None
