"""Pydantic request and response models for the control plane.

These are the typed boundary. Every mutating route validates its body through one of
these models before anything is written, so a malformed or hostile payload is rejected at
the edge with a structured error rather than part-way through a handler.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_drift.contracts import ContractSource, Operation


class _Strict(BaseModel):
    """Reject unknown fields: a payload cannot smuggle an extra authority field."""

    model_config = ConfigDict(extra="forbid")


class CreateTaskRequest(_Strict):
    """Register a trusted, user-approved intent contract for a task."""

    task_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    user_goal: str = Field(min_length=1, max_length=4096)
    principal: str = Field(default="local-developer", min_length=1, max_length=256)
    approved_by: str = Field(default="local-developer", min_length=1, max_length=256)
    source: ContractSource = ContractSource.TRUSTED_UI
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_servers: list[str] = Field(default_factory=lambda: ["sandbox"])
    allowed_operations: list[Operation] = Field(default_factory=list)
    resource_scopes: list[str] = Field(default_factory=list)
    allowed_destinations: list[str] = Field(default_factory=list)
    denied_actions: list[Operation] = Field(default_factory=list)
    max_writes: int = Field(default=0, ge=0, le=10_000)
    max_calls: int = Field(default=100, ge=0, le=1_000_000)
    approval_rules: list[str] = Field(default_factory=list)
    expires_in_s: int | None = Field(default=None, ge=1, le=86_400 * 30)
    manifest_drift_policy: Literal["deny_risky", "deny_all", "warn"] = "deny_risky"


class EvaluateAttemptRequest(_Strict):
    """Evaluate a proposed tool call.

    This endpoint is **advisory**, exactly like the SDK: it tells you what the contract
    says, and nothing is prevented by calling it. Only calls that traverse the MCP
    gateway are enforced. The response repeats this in ``enforcement``.
    """

    task_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    tool_server: str = Field(default="sandbox", min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    run_id: str | None = None


class ApprovalActionRequest(_Strict):
    """Approve or decline a pending approval."""

    reviewer: str = Field(default="local-reviewer", min_length=1, max_length=256)
    note: str | None = Field(default=None, max_length=1024)


class DecisionResponse(_Strict):
    """A policy decision as returned by the API."""

    attempt_id: str
    status: str
    reason_codes: list[str]
    rule_ids: list[str]
    explanations: list[str]
    risk: str
    policy_revision: int | None
    contract_hash: str | None
    resource: str | None = None
    destination: str | None = None
    elapsed_ms: float
    enforcement: str = (
        "advisory: this endpoint evaluates and records, it does not intercept. "
        "Route tool calls through the Agent Drift MCP gateway for enforcement."
    )


class HealthResponse(_Strict):
    """Health and build information."""

    status: Literal["ok", "degraded"]
    version: str
    mcp_sdk_version: str
    mcp_protocol_revision: str
    database: str
    schema_version: str
    events: int
    tasks: int
    time: _dt.datetime


class ErrorResponse(_Strict):
    """Structured error body returned by every failing route."""

    error: str
    detail: str | None = None
    code: str | None = None
