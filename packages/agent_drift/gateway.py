"""MCP stdio gateway: a server to the host, a client to one upstream server.

This is where enforcement actually happens. Everything else in the package evaluates or
records; only this module stands between a host's ``tools/call`` and a tool that runs.

The shape of the process:

```
agent/host  --stdio-->  [ gateway: Server ]  --evaluate-->  PolicyEngine
                              |                                  |
                              |  ALLOW  (budget reserved)        | DENY / NEEDS_APPROVAL
                              v                                  v
                        [ gateway: Client ] --stdio--> upstream   no upstream call at all
```

Invariants this module is responsible for, each with a test:

* **Decide before forwarding.** The decision row is committed to SQLite *before* the
  upstream client is touched. ``tests/integration/test_deny_before_execute.py`` proves the
  converse by reading the fixture's own counter file after a denial.
* **Exactly one forward per allowed call.** ``_forward_once`` is called from a single
  place and the attempt id is recorded, so a host retry produces a new attempt and a new
  decision rather than a second execution of the same authorized one.
* **No privilege from metadata.** ``tools/list`` is relayed with schemas intact, but the
  descriptions and annotations it carries are fingerprinted as *data* and never consulted
  to decide whether a call is permitted.
* **stdout is sacred.** Every diagnostic goes to stderr. A single stray ``print`` to
  stdout would corrupt the JSON-RPC stream, so this module installs a logging handler
  bound to ``sys.stderr`` and never uses ``print`` without ``file=``.
* **Fail closed on everything.** Upstream death, policy exception, store failure and
  approval timeout all produce a denial, never a pass-through.

Protocol notes for revision ``2026-07-28`` (see ``docs/DECISIONS.md`` D-001, D-006, D-009,
D-010): a denial is returned as ``CallToolResult(is_error=True)`` -- the tool-execution
error channel, which the specification says clients SHOULD feed back to the model --
rather than as a JSON-RPC error, which is reserved for protocol-level failures. Exactly
one upstream server is proxied, so tool names and pagination cursors are forwarded
unchanged; a ``cacheScope: "private"`` list result is never reused across task bindings.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import anyio
import mcp.types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from .contracts import DecisionStatus, ToolAttempt, utcnow
from .manifest import ManifestFingerprint, fingerprint_tools
from .policy import PolicyEngine, ToolSpec
from .reasons import Reason, explain
from .store import Store, StoreUnavailable

__all__ = ["Gateway", "GatewayConfig", "run_gateway"]

GATEWAY_NAME = "agent-drift-gateway"
GATEWAY_VERSION = "0.1.0"

logger = logging.getLogger("agent_drift.gateway")


def _configure_stderr_logging(level: str = "INFO") -> None:
    """Send all logging to stderr.

    An MCP stdio server owns stdout. Any library that logs to stdout corrupts the
    protocol stream, so the root handler is replaced rather than added to.
    """
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


@dataclass(slots=True)
class GatewayConfig:
    """Everything the gateway needs, resolved before any protocol traffic.

    ``task_id`` is the trust anchor: it is supplied when the gateway is *launched*, by
    whoever launched it, and is never derived from anything the agent sends.
    """

    task_id: str
    upstream_command: str
    upstream_args: list[str] = field(default_factory=list)
    upstream_env: dict[str, str] = field(default_factory=dict)
    upstream_server_name: str = "sandbox"
    db_path: str = "var/agent_drift.db"
    sandbox_root: Path | None = None
    approval_timeout_s: float = 60.0
    approval_poll_interval_s: float = 0.25
    approval_ttl_s: int = 300
    upstream_call_timeout_s: float = 30.0
    pin_manifest_on_start: bool = True
    log_level: str = "INFO"
    #: Local tool-to-operation map. ``None`` uses the bundled fixture's specs. This is the
    #: only way to guard a non-fixture server: an unmapped tool has operation ``unknown``
    #: and is denied, so integrating a real server means supplying this. It was previously
    #: unreachable from the gateway, which made the documented integration path inert.
    tool_specs: dict[str, ToolSpec] | None = None

    @classmethod
    def from_env(cls, **overrides: Any) -> GatewayConfig:
        """Build a config from ``AD_*`` environment variables plus explicit overrides."""
        base: dict[str, Any] = {
            "task_id": os.environ.get("AD_TASK_ID", ""),
            "upstream_command": os.environ.get("AD_UPSTREAM_COMMAND", sys.executable),
            "upstream_args": json.loads(os.environ.get("AD_UPSTREAM_ARGS", "[]")),
            "upstream_server_name": os.environ.get("AD_UPSTREAM_NAME", "sandbox"),
            "db_path": os.environ.get("AD_DB_PATH", "var/agent_drift.db"),
            "approval_timeout_s": float(os.environ.get("AD_APPROVAL_TIMEOUT_S", "60")),
            "approval_ttl_s": int(os.environ.get("AD_APPROVAL_TTL_S", "300")),
            "log_level": os.environ.get("AD_LOG_LEVEL", "INFO"),
        }
        sandbox = os.environ.get("AD_SANDBOX_ROOT")
        if sandbox:
            base["sandbox_root"] = Path(sandbox)
        base.update(overrides)
        return cls(**base)


class Gateway:
    """Task-bound MCP proxy that enforces an intent contract on every ``tools/call``."""

    def __init__(self, config: GatewayConfig, *, store: Store | None = None) -> None:
        self.config = config
        self._owns_store = store is None
        self.store = store or Store(config.db_path, hmac_key=_hmac_key_from_env())
        self.engine = PolicyEngine(
            self.store,
            sandbox_root=config.sandbox_root,
            tool_specs=config.tool_specs,
            approval_ttl_s=config.approval_ttl_s,
        )
        self.client: Client | None = None
        self.manifest: ManifestFingerprint | None = None
        self._upstream_tools: dict[str, types.Tool] = {}
        self._list_result: types.ListToolsResult | None = None
        self.run_id = f"run_{utcnow().strftime('%Y%m%d%H%M%S')}_{os.getpid()}"

    # ------------------------------------------------------------------ lifecycle

    async def connect_upstream(self) -> None:
        """Open the stdio connection to the upstream server and discover its tools."""
        env = {**os.environ, **self.config.upstream_env}
        params = StdioServerParameters(
            command=self.config.upstream_command,
            args=list(self.config.upstream_args),
            env=env,
        )
        self.client = Client(params, read_timeout_seconds=self.config.upstream_call_timeout_s)
        await self.client.__aenter__()
        logger.info(
            "connected to upstream %r (protocol %s)",
            self.config.upstream_server_name,
            getattr(self.client, "protocol_version", "unknown"),
        )
        await self.refresh_manifest(pin=self.config.pin_manifest_on_start)

    async def close_upstream(self) -> None:
        """Close the upstream connection cleanly."""
        if self.client is not None:
            try:
                await self.client.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("upstream close raised: %s", exc)
            self.client = None

    async def refresh_manifest(self, *, pin: bool) -> ManifestFingerprint:
        """Call upstream ``tools/list``, fingerprint the manifest, optionally pin it.

        Pinning happens only when the task has no pin yet. Re-pinning after drift is a
        deliberate reviewer action through the control plane, never an automatic
        consequence of the upstream changing -- that would defeat the whole check.
        """
        if self.client is None:
            raise RuntimeError("upstream is not connected")

        result = await self.client.list_tools()
        self._list_result = result
        self._upstream_tools = {tool.name: tool for tool in result.tools}
        self.manifest = fingerprint_tools(
            self.config.upstream_server_name,
            list(result.tools),
            cache_scope=getattr(result, "cache_scope", None),
            ttl_ms=getattr(result, "ttl_ms", None),
        )
        logger.info(
            "upstream manifest: %d tools, digest=%s, cache_scope=%s",
            len(self._upstream_tools),
            self.manifest.manifest_digest[:16],
            self.manifest.cache_scope,
        )

        if pin:
            existing = self.store.get_manifest_pin(self.config.task_id)
            if existing is None and self.store.get_contract(self.config.task_id) is not None:
                self.store.set_manifest_pin(self.config.task_id, self.manifest.to_dict())
                logger.info("pinned manifest for task %s", self.config.task_id)

        self.store.append_event(
            "MANIFEST_OBSERVED",
            task_id=self.config.task_id,
            run_id=self.run_id,
            payload={
                "server": self.config.upstream_server_name,
                "manifest_digest": self.manifest.manifest_digest,
                "tools": sorted(self._upstream_tools),
                "cache_scope": self.manifest.cache_scope,
                "ttl_ms": self.manifest.ttl_ms,
                "cacheable_across_tasks": self.manifest.is_cacheable_across_tasks(),
            },
        )
        return self.manifest

    # ------------------------------------------------------------------- handlers

    async def handle_list_tools(
        self, _ctx: Any, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        """Relay upstream ``tools/list``, preserving schemas, names and cursors.

        The tool set is not filtered. Hiding tools a contract disallows would be a
        usability choice that *weakens* the audit story: the host would never attempt the
        call, so there would be no recorded attempt showing what the agent wanted to do.
        Agent Drift prefers to let the attempt happen and deny it visibly.

        Because exactly one upstream is proxied (decision D-009), the opaque cursor is
        forwarded unchanged; a proxy that filtered or merged tool sets would have to
        synthesize its own cursors instead.
        """
        if self.client is None:
            raise MCPError(code=types.INTERNAL_ERROR, message="upstream unavailable")

        cursor = getattr(params, "cursor", None) if params is not None else None
        try:
            result = await self.client.list_tools(cursor=cursor)
        except Exception as exc:
            logger.error("upstream tools/list failed: %s", exc)
            raise MCPError(code=types.INTERNAL_ERROR, message=f"upstream tools/list failed: {exc}") from exc

        if cursor is None:
            self._list_result = result
            self._upstream_tools = {tool.name: tool for tool in result.tools}
            self.manifest = fingerprint_tools(
                self.config.upstream_server_name,
                list(result.tools),
                cache_scope=getattr(result, "cache_scope", None),
                ttl_ms=getattr(result, "ttl_ms", None),
            )

        logger.info("relayed tools/list: %d tools", len(result.tools))
        return result

    async def handle_call_tool(self, _ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        """Evaluate, record, then either forward exactly once or deny without forwarding."""
        started = time.perf_counter()
        arguments: dict[str, Any] = dict(params.arguments or {})

        attempt = ToolAttempt(
            task_id=None,  # filled by the policy engine from the launch-time binding
            tool_server=self.config.upstream_server_name,
            tool_name=params.name,
            args=arguments,
            run_id=self.run_id,
        )

        upstream_schema: dict[str, Any] | None = None
        tool = self._upstream_tools.get(params.name)
        if tool is not None and isinstance(getattr(tool, "input_schema", None), dict):
            upstream_schema = tool.input_schema

        try:
            self.store.record_attempt(attempt)
        except StoreUnavailable as exc:
            logger.error("could not record attempt, failing closed: %s", exc)
            return _denial_result(
                attempt, [str(Reason.STORE_UNAVAILABLE)], ["R0-fail-closed"], detail=str(exc)
            )

        decision = self.engine.evaluate(
            attempt,
            bound_task_id=self.config.task_id or None,
            observed_manifest=self.manifest,
            upstream_schema=upstream_schema,
        )

        # Committed before anything is forwarded. This ordering is the point.
        try:
            self.store.record_decision(decision, run_id=self.run_id)
        except StoreUnavailable as exc:
            logger.error("could not record decision, failing closed: %s", exc)
            return _denial_result(
                attempt, [str(Reason.STORE_UNAVAILABLE)], ["R0-fail-closed"], detail=str(exc)
            )

        if decision.status is DecisionStatus.NEEDS_APPROVAL:
            decision = await self._await_approval(attempt, decision)
            try:
                self.store.record_decision(decision, run_id=self.run_id)
            except StoreUnavailable as exc:
                logger.error("could not record post-approval decision: %s", exc)
                return _denial_result(
                    attempt, [str(Reason.STORE_UNAVAILABLE)], ["R0-fail-closed"], detail=str(exc)
                )

        if decision.status is not DecisionStatus.ALLOW:
            logger.warning(
                "DENY %s task=%s reasons=%s rules=%s (%.2f ms) -- upstream not called",
                attempt.tool_name,
                self.config.task_id,
                ",".join(decision.reason_codes),
                ",".join(decision.rule_ids),
                decision.elapsed_ms,
            )
            return _denial_result(
                attempt,
                decision.reason_codes,
                decision.rule_ids,
                policy_revision=decision.policy_revision,
                contract_hash=decision.contract_hash,
                evidence=decision.evidence,
            )

        logger.info(
            "ALLOW %s task=%s reasons=%s (%.2f ms) -- forwarding once",
            attempt.tool_name,
            self.config.task_id,
            ",".join(decision.reason_codes),
            decision.elapsed_ms,
        )
        result = await self._forward_once(attempt, decision)
        total_ms = (time.perf_counter() - started) * 1000.0
        logger.info("completed %s in %.2f ms total", attempt.tool_name, total_ms)
        return result

    # -------------------------------------------------------------------- helpers

    async def _await_approval(self, attempt: ToolAttempt, decision: Any) -> Any:
        """Poll for a reviewer decision until the bounded timeout, then deny.

        Polls the database rather than holding an in-memory future, so a reviewer acting
        through the control-plane process (a different process) is seen. On approval the
        contract is re-evaluated from scratch: expiry, revision and manifest are all
        rechecked, because time passed while a human was thinking.
        """
        deadline = time.monotonic() + self.config.approval_timeout_s
        approval_id = decision.approval_id
        logger.info(
            "NEEDS_APPROVAL %s approval_id=%s -- waiting up to %.0fs",
            attempt.tool_name,
            approval_id,
            self.config.approval_timeout_s,
        )

        while time.monotonic() < deadline:
            await anyio.sleep(self.config.approval_poll_interval_s)
            grant = self.store.get_approval(approval_id) if approval_id else None
            if grant is None:
                continue
            if grant.state.value in ("declined", "expired"):
                reason = (
                    Reason.APPROVAL_DECLINED if grant.state.value == "declined" else Reason.APPROVAL_EXPIRED
                )
                decision.status = DecisionStatus.DENY
                decision.reason_codes = [str(reason)]
                decision.rule_ids = ["R10-approval"]
                decision.reviewer = {"decided_by": grant.decided_by, "decided_at": _iso(grant.decided_at)}
                decision.evidence = {
                    **decision.evidence,
                    "approval_outcome": grant.state.value,
                    "explanations": [explain(str(reason))],
                }
                return decision
            if grant.state.value == "approved":
                # Re-evaluate from scratch: this consumes the grant and rechecks everything.
                fresh = self.engine.evaluate(
                    attempt,
                    bound_task_id=self.config.task_id or None,
                    observed_manifest=self.manifest,
                )
                fresh.reviewer = {"decided_by": grant.decided_by, "decided_at": _iso(grant.decided_at)}
                fresh.approval_id = grant.approval_id
                return fresh

        self.store.expire_stale_approvals()
        decision.status = DecisionStatus.DENY
        decision.reason_codes = [str(Reason.APPROVAL_TIMEOUT)]
        decision.rule_ids = ["R10-approval"]
        decision.evidence = {
            **decision.evidence,
            "approval_outcome": "timeout",
            "timeout_s": self.config.approval_timeout_s,
            "explanations": [explain(str(Reason.APPROVAL_TIMEOUT))],
        }
        logger.warning("approval timed out for %s -- denying", attempt.tool_name)
        return decision

    async def _forward_once(self, attempt: ToolAttempt, decision: Any) -> types.CallToolResult:
        """Forward an authorized call to the upstream server exactly once.

        Called from a single site. A failure to *reach* the upstream releases the budget
        reservation, because nothing can have happened; an error *returned by* the tool
        does not, because an errored tool may still have had an effect.
        """
        if self.client is None:
            self.store.mark_upstream_executed(
                attempt.attempt_id, executed=False, error="upstream not connected"
            )
            return _denial_result(
                attempt,
                [str(Reason.EVALUATOR_ERROR)],
                ["R0-fail-closed"],
                detail="upstream connection unavailable",
            )

        try:
            result = await self.client.call_tool(
                attempt.tool_name,
                attempt.args,
                read_timeout_seconds=self.config.upstream_call_timeout_s,
            )
        except Exception as exc:
            delivered = _request_may_have_been_delivered(exc)
            logger.error(
                "upstream call_tool failed for %s: %s (may have executed: %s)",
                attempt.tool_name,
                exc,
                delivered,
            )
            # A timeout or cancellation is *unknown*, not *did not happen*: the request was
            # delivered and the tool may be mid-execution. Recording it as "did not execute"
            # and refunding the budget was a real defect found by an independent review --
            # a tool slower than the timeout could exceed its write budget indefinitely,
            # each timed-out write refunding itself, while the receipt denied it happened.
            self.store.mark_upstream_executed(
                attempt.attempt_id,
                executed=None if delivered else False,
                error=str(exc),
            )
            if not delivered and decision.policy_revision is not None and self.config.task_id:
                from .contracts import WRITE_BUDGET_OPERATIONS

                self.store.release_budget(
                    self.config.task_id,
                    decision.policy_revision,
                    is_write=attempt.operation in WRITE_BUDGET_OPERATIONS,
                )
            suffix = (
                " (the request was delivered; whether the tool ran is unknown, so its "
                "budget reservation is retained)"
                if delivered
                else ""
            )
            raise MCPError(
                code=types.INTERNAL_ERROR,
                message=f"upstream tool call failed: {exc}{suffix}",
            ) from exc

        self.store.mark_upstream_executed(
            attempt.attempt_id,
            executed=True,
            error="tool reported an error" if result.is_error else None,
        )
        return result

    # ---------------------------------------------------------------------- serve

    def build_server(self) -> Server[Any]:
        """Construct the MCP server that faces the host."""
        return Server(
            name=GATEWAY_NAME,
            version=GATEWAY_VERSION,
            title="Agent Drift gateway",
            instructions=(
                "Tool calls through this gateway are evaluated against an approved intent "
                "contract for a specific task. Denied calls are not forwarded upstream."
            ),
            on_list_tools=self.handle_list_tools,
            on_call_tool=self.handle_call_tool,
        )

    async def serve_stdio(self) -> None:
        """Run the gateway on stdio until the host disconnects."""
        server = self.build_server()
        await self.connect_upstream()
        self.store.set_run_metadata(self.run_id, task_id=self.config.task_id, label="gateway session")
        try:
            async with stdio_server() as (read_stream, write_stream):
                logger.info(
                    "gateway serving on stdio; task=%s upstream=%s",
                    self.config.task_id,
                    self.config.upstream_command,
                )
                await server.run(read_stream, write_stream, server.create_initialization_options())
        finally:
            await self.close_upstream()
            if self._owns_store:
                self.store.close()


#: Message fragments that mean the request reached the upstream and its fate is unknown.
_DELIVERED_MARKERS: Final[tuple[str, ...]] = (
    "timed out",
    "timeout",
    "cancelled",
    "canceled",
    "deadline",
)


def _request_may_have_been_delivered(exc: BaseException) -> bool:
    """Could the upstream have received -- and run -- this call despite the failure?

    Errs toward ``True``. Guessing "delivered" when it was not costs one unit of budget;
    guessing "not delivered" when it was lets a slow tool exceed its budget and produces a
    receipt that denies something that happened. That asymmetry sets the default.
    """
    if isinstance(exc, (TimeoutError, asyncio.CancelledError)):
        return True
    if isinstance(exc, (ConnectionRefusedError, FileNotFoundError, BrokenPipeError)):
        return False
    message = str(exc).lower()
    if any(marker in message for marker in _DELIVERED_MARKERS):
        return True
    # Unknown transport failure: assume the request may have landed.
    return True


def _iso(value: Any) -> str | None:
    """ISO-format a datetime that may already be a string or ``None``."""
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return str(value)


def _hmac_key_from_env() -> bytes | None:
    """Audit HMAC key, when one is configured."""
    key = os.environ.get("AD_AUDIT_HMAC_KEY")
    return key.encode("utf-8") if key else None


def _denial_result(
    attempt: ToolAttempt,
    reason_codes: list[str],
    rule_ids: list[str],
    *,
    detail: str | None = None,
    policy_revision: int | None = None,
    contract_hash: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> types.CallToolResult:
    """Build the structured denial returned to the host.

    Returned as a tool-execution error (``is_error=True``) rather than a JSON-RPC error,
    per decision D-006: the 2026-07-28 specification says clients SHOULD feed tool
    execution errors back to the model, which is the behaviour we want -- the agent
    should learn "that is outside the approved task" and adapt, not retry blindly.

    The payload is redacted before it leaves the process.
    """
    from .canonical import redact

    body: dict[str, Any] = {
        "agent_drift": {
            "decision": "deny",
            "attempt_id": attempt.attempt_id,
            "trace_id": attempt.trace_id,
            "tool": attempt.tool_name,
            "task_id": attempt.task_id,
            "reason_codes": reason_codes,
            "rule_ids": rule_ids,
            "explanations": [explain(code) for code in reason_codes],
            "policy_revision": policy_revision,
            "contract_hash": contract_hash,
            "upstream_called": False,
            "message": (
                "This tool call was not performed. It is outside the task contract that the "
                "user approved for this session. The call was blocked before the tool ran."
            ),
        }
    }
    if detail:
        body["agent_drift"]["detail"] = detail
    if evidence:
        body["agent_drift"]["evidence"] = redact({k: v for k, v in evidence.items() if k != "explanations"})

    text = json.dumps(body, indent=2, sort_keys=True)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structured_content=body,
        is_error=True,
    )


async def run_gateway(config: GatewayConfig) -> None:
    """Configure logging and serve one gateway session."""
    _configure_stderr_logging(config.log_level)
    gateway = Gateway(config)
    await gateway.serve_stdio()
