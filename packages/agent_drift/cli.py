"""``agent-drift`` command line interface.

Subcommands:

* ``gateway`` -- run the MCP stdio gateway bound to one task. This is what an MCP host's
  server configuration points at.
* ``api`` -- run the local control plane (Starlette + uvicorn) on ``127.0.0.1``.
* ``seed`` -- create the demo contracts and the sandbox fixture tree.
* ``smoke`` -- drive a real MCP client through a real gateway to a real upstream and
  assert the allow/deny/counter outcomes, printing normalized counters.
* ``verify-audit`` -- recompute the audit HMAC chain.
* ``reset`` -- clear local demo state.

``gateway`` is the only subcommand that speaks stdio JSON-RPC, so it is also the only one
that must never write to stdout. Its logging is configured to stderr before any protocol
traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _default_upstream() -> tuple[str, list[str]]:
    """The bundled fixture server, as a (command, args) pair."""
    return sys.executable, [str(REPO_ROOT / "examples" / "upstream_mcp" / "server.py")]


def _cmd_gateway(args: argparse.Namespace) -> int:
    """Run the stdio gateway."""
    import anyio

    from .gateway import GatewayConfig, run_gateway

    command, upstream_args = _default_upstream()
    if args.upstream_command:
        command = args.upstream_command
        upstream_args = list(args.upstream_arg or [])

    sandbox_root = Path(args.sandbox_root) if args.sandbox_root else _fixture_workspace()

    tool_specs = None
    if args.tool_specs:
        from .policy import load_tool_specs

        tool_specs = load_tool_specs(args.tool_specs)
        print(
            f"loaded {len(tool_specs)} tool specs from {args.tool_specs}",
            file=sys.stderr,
        )

    config = GatewayConfig(
        task_id=args.task_id,
        upstream_command=command,
        upstream_args=upstream_args,
        upstream_server_name=args.upstream_name,
        db_path=args.db,
        sandbox_root=sandbox_root,
        tool_specs=tool_specs,
        approval_timeout_s=args.approval_timeout,
        upstream_call_timeout_s=args.upstream_timeout,
        log_level=args.log_level,
    )
    anyio.run(run_gateway, config)
    return 0


def _cmd_api(args: argparse.Namespace) -> int:
    """Run the control plane."""
    import uvicorn

    os.environ.setdefault("AD_DB_PATH", args.db)
    uvicorn.run(
        "apps.api.main:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
        reload=args.reload,
    )
    return 0


def _cmd_seed(args: argparse.Namespace) -> int:
    """Create demo contracts and the sandbox fixture tree."""
    from .seed import all_contracts
    from .store import Store

    _ensure_fixture_state()
    sys.path.insert(0, str(REPO_ROOT / "examples" / "upstream_mcp"))
    import server as fixture  # type: ignore[import-not-found]

    fixture.state_dir().mkdir(parents=True, exist_ok=True)
    if args.reset:
        fixture.reset_state()
    else:
        fixture.seed_sandbox()

    store = Store(args.db)
    try:
        for contract in all_contracts():
            store.put_contract(contract)
            print(
                f"registered {contract.task_id:<22} revision={contract.policy_revision} "
                f"hash={contract.contract_hash[:16]} tools={len(contract.allowed_tools)}"
            )
        print(f"\nsandbox:   {fixture.repo_root()}")
        print(f"workspace: {fixture.workspace_root()}")
        print(f"database:  {Path(args.db).resolve()}")
    finally:
        store.close()
    return 0


def _cmd_smoke(args: argparse.Namespace) -> int:
    """Run the end-to-end allow/deny smoke test."""
    import anyio

    from .smoke import run_smoke

    return int(anyio.run(run_smoke, args.db, args.json))


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    """Recompute the audit HMAC chain."""
    from .store import Store

    key = os.environ.get("AD_AUDIT_HMAC_KEY")
    store = Store(args.db, hmac_key=key.encode("utf-8") if key else None)
    try:
        ok, problem = store.verify_chain()
        if ok is None:
            print(f"not configured: {problem}")
            print("This is reported honestly rather than as a pass.")
            return 0
        if ok:
            print(f"audit chain verified over {store.latest_seq()} events")
            return 0
        print(f"AUDIT CHAIN BROKEN: {problem}", file=sys.stderr)
        print(
            "\nIf this database was written by a process that did not hold the signing "
            "key, its events are unsigned and will not verify. That is a configuration "
            "problem, not necessarily tampering: check that every writer (gateway, "
            "control plane) has AD_AUDIT_HMAC_KEY set.",
            file=sys.stderr,
        )
        return 1
    finally:
        store.close()


def _cmd_reset(args: argparse.Namespace) -> int:
    """Remove local demo state."""
    import shutil

    _ensure_fixture_state()
    sys.path.insert(0, str(REPO_ROOT / "examples" / "upstream_mcp"))
    import server as fixture  # type: ignore[import-not-found]

    fixture.reset_state()
    db = Path(args.db)
    for path in (db, db.with_suffix(db.suffix + "-wal"), db.with_suffix(db.suffix + "-shm")):
        if path.exists():
            path.unlink()
    for directory in (REPO_ROOT / "var" / "screenshots",):
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
    print("local demo state cleared")
    return 0


def _cmd_contracts(args: argparse.Namespace) -> int:  # noqa: ARG001 - argparse callback signature
    """Print the seed contracts as canonical JSON."""
    from .seed import all_contracts

    payload = [
        {"task_id": c.task_id, "contract_hash": c.contract_hash, "semantic": c.semantic_fields()}
        for c in all_contracts()
    ]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _fixture_workspace() -> Path:
    """Path-resolution root used by the bundled fixture."""
    state = os.environ.get("AD_FIXTURE_STATE")
    base = Path(state) if state else REPO_ROOT / "var" / "fixture"
    return base / "workspace"


def _ensure_fixture_state() -> None:
    """Default the fixture state directory to ``var/fixture`` inside the repo."""
    os.environ.setdefault("AD_FIXTURE_STATE", str(REPO_ROOT / "var" / "fixture"))


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="agent-drift",
        description="Runtime intent-integrity gateway for MCP agents.",
    )
    parser.add_argument("--version", action="version", version="agent-drift 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    default_db = os.environ.get("AD_DB_PATH", str(REPO_ROOT / "var" / "agent_drift.db"))

    gateway = sub.add_parser("gateway", help="run the MCP stdio gateway for one task")
    gateway.add_argument("--task-id", required=True, help="trusted task binding (host-owned)")
    gateway.add_argument("--db", default=default_db)
    gateway.add_argument("--upstream-command", default=None, help="upstream server command")
    gateway.add_argument("--upstream-arg", action="append", help="argument for the upstream command")
    gateway.add_argument("--upstream-name", default="sandbox", help="logical upstream server name")
    gateway.add_argument("--sandbox-root", default=None, help="path-resolution root for file tools")
    gateway.add_argument(
        "--tool-specs",
        default=os.environ.get("AD_TOOL_SPECS"),
        help=(
            "JSON file mapping your upstream's tool names to operations and argument "
            "names. Required to guard a server other than the bundled fixture: a tool "
            "with no mapping has operation 'unknown' and is denied."
        ),
    )
    gateway.add_argument(
        "--approval-timeout",
        type=float,
        default=60.0,
        help="seconds to wait for a human decision before denying (never auto-approves)",
    )
    gateway.add_argument(
        "--upstream-timeout",
        type=float,
        default=float(os.environ.get("AD_UPSTREAM_TIMEOUT_S", "30")),
        help=(
            "seconds to wait for an upstream tool. On a timeout the call is recorded as "
            "execution-unknown and its budget reservation is NOT returned, because the "
            "tool may have run."
        ),
    )
    gateway.add_argument("--log-level", default="INFO")
    gateway.set_defaults(func=_cmd_gateway)

    api = sub.add_parser("api", help="run the local control plane")
    api.add_argument("--host", default=os.environ.get("AD_API_HOST", "127.0.0.1"))
    api.add_argument("--port", type=int, default=int(os.environ.get("AD_API_PORT", "8001")))
    api.add_argument("--db", default=default_db)
    api.add_argument("--log-level", default="info")
    api.add_argument("--reload", action="store_true")
    api.set_defaults(func=_cmd_api)

    seed = sub.add_parser("seed", help="create demo contracts and sandbox fixture")
    seed.add_argument("--db", default=default_db)
    seed.add_argument("--reset", action="store_true", help="recreate the sandbox from scratch")
    seed.set_defaults(func=_cmd_seed)

    smoke = sub.add_parser("smoke", help="real client -> gateway -> upstream allow/deny check")
    smoke.add_argument("--db", default=str(REPO_ROOT / "var" / "smoke.db"))
    smoke.add_argument("--json", action="store_true", help="emit machine-readable results")
    smoke.set_defaults(func=_cmd_smoke)

    audit = sub.add_parser("verify-audit", help="recompute the audit HMAC chain")
    audit.add_argument("--db", default=default_db)
    audit.set_defaults(func=_cmd_verify_audit)

    reset = sub.add_parser("reset", help="clear local demo state")
    reset.add_argument("--db", default=default_db)
    reset.set_defaults(func=_cmd_reset)

    contracts = sub.add_parser("contracts", help="print seed contracts as canonical JSON")
    contracts.set_defaults(func=_cmd_contracts)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _ensure_fixture_state()
    result: Any = args.func(args)
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
