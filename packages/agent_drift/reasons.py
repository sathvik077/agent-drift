"""Reason codes and rule identifiers for policy decisions.

Every decision Agent Drift emits carries one or more of these codes. They are the
contract between the policy engine, the audit log, the dashboard and the test suite:
tests assert on codes, never on human-readable strings, and the dashboard renders the
rule ID so a reviewer can trace a decision to the clause that produced it.

Stability: these identifiers are part of the public interface. Codes are never
renumbered; retired codes are tombstoned rather than reused.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Reason(StrEnum):
    """Canonical reason codes, grouped by the enforcement stage that emits them."""

    # --- stage 1: input schema validation -------------------------------------
    BAD_ARGUMENTS = "AD-E001"
    ARGUMENTS_NOT_OBJECT = "AD-E002"
    ARGUMENT_TOO_LARGE = "AD-E003"
    SCHEMA_MISMATCH = "AD-E004"
    UNDECLARED_ARGUMENT = "AD-E005"

    # --- stage 2: task identity ----------------------------------------------
    MISSING_TASK_BINDING = "AD-E010"
    TASK_SPOOF_ATTEMPT = "AD-E011"
    TASK_MISMATCH = "AD-E012"

    # --- stage 3: contract validity ------------------------------------------
    NO_CONTRACT = "AD-E020"
    CONTRACT_EXPIRED = "AD-E021"
    CONTRACT_NOT_YET_VALID = "AD-E022"
    CONTRACT_UNTRUSTED_SOURCE = "AD-E023"
    CONTRACT_REVISION_CHANGED = "AD-E024"
    CONTRACT_INTEGRITY_FAILED = "AD-E025"

    # --- stage 4: tool manifest integrity ------------------------------------
    MANIFEST_DRIFT = "AD-E030"
    MANIFEST_UNKNOWN_TOOL = "AD-E031"
    MANIFEST_NOT_PINNED = "AD-E032"

    # --- stage 5: server / tool allowlist ------------------------------------
    TOOL_NOT_ALLOWED = "AD-E040"
    SERVER_NOT_ALLOWED = "AD-E041"
    TOOL_NAME_INVALID = "AD-E042"

    # --- stage 6: operation allow / deny -------------------------------------
    OPERATION_DENIED = "AD-E050"
    OPERATION_NOT_ALLOWED = "AD-E051"

    # --- stage 7: resource scope ---------------------------------------------
    RESOURCE_OUT_OF_SCOPE = "AD-E060"
    PATH_TRAVERSAL = "AD-E061"
    PATH_ABSOLUTE = "AD-E062"
    PATH_SYMLINK_ESCAPE = "AD-E063"
    PATH_UNSAFE_ENCODING = "AD-E064"
    RESOURCE_MISSING = "AD-E065"

    # --- stage 8: destination scope ------------------------------------------
    DESTINATION_NOT_ALLOWED = "AD-E070"
    DESTINATION_UNPARSEABLE = "AD-E071"
    DESTINATION_PRIVATE_ADDRESS = "AD-E072"
    DESTINATION_SCHEME_DENIED = "AD-E073"
    DESTINATION_MISSING = "AD-E074"

    # --- stage 9: budgets -----------------------------------------------------
    CALL_BUDGET_EXCEEDED = "AD-E080"
    WRITE_BUDGET_EXCEEDED = "AD-E081"

    # --- stage 10: approval ---------------------------------------------------
    NEEDS_APPROVAL = "AD-A001"
    APPROVAL_GRANTED = "AD-A002"
    APPROVAL_DECLINED = "AD-A003"
    APPROVAL_NOT_FOUND = "AD-A004"
    APPROVAL_TIMEOUT = "AD-A005"
    APPROVAL_ALREADY_CONSUMED = "AD-A006"
    APPROVAL_ARGS_MISMATCH = "AD-A007"
    APPROVAL_REVISION_STALE = "AD-A008"
    APPROVAL_EXPIRED = "AD-A009"

    # --- stage 11: advisory heuristics (escalate only) -----------------------
    HEURISTIC_ESCALATED = "AD-H001"
    HEURISTIC_SUSPICIOUS_CONTENT = "AD-H002"

    # --- allow ----------------------------------------------------------------
    ALLOWED_BY_CONTRACT = "AD-OK01"
    ALLOWED_READ_ONLY = "AD-OK02"
    ALLOWED_AFTER_APPROVAL = "AD-OK03"

    # --- fail-closed ----------------------------------------------------------
    EVALUATOR_ERROR = "AD-E999"
    STORE_UNAVAILABLE = "AD-E998"


#: Human-readable explanation per code. Rendered by the dashboard; never parsed.
EXPLANATIONS: Final[dict[str, str]] = {
    Reason.BAD_ARGUMENTS: "Tool arguments failed validation against the upstream tool's input schema.",
    Reason.ARGUMENTS_NOT_OBJECT: "Tool arguments were not a JSON object.",
    Reason.ARGUMENT_TOO_LARGE: "Tool arguments exceeded the configured size bound.",
    Reason.SCHEMA_MISMATCH: "Argument types did not match the declared input schema.",
    Reason.UNDECLARED_ARGUMENT: (
        "An argument was supplied that the upstream tool does not declare. Agent Drift "
        "forwards only declared arguments, so an undeclared one is refused rather than "
        "passed through to a tool whose handling of it is unknown."
    ),
    Reason.MISSING_TASK_BINDING: "The gateway process has no trusted task binding, so no call can be authorized.",
    Reason.TASK_SPOOF_ATTEMPT: "Tool arguments attempted to supply or override a task identity; task identity is host-owned and is never read from arguments.",
    Reason.TASK_MISMATCH: "The attempt referenced a different task than the one bound to this gateway.",
    Reason.NO_CONTRACT: "No approved intent contract exists for the bound task.",
    Reason.CONTRACT_EXPIRED: "The approved intent contract has expired.",
    Reason.CONTRACT_NOT_YET_VALID: "The approved intent contract is not yet valid.",
    Reason.CONTRACT_UNTRUSTED_SOURCE: "The contract did not originate from a trusted source (trusted_ui or trusted_config).",
    Reason.CONTRACT_REVISION_CHANGED: "The contract revision changed between evaluation and execution.",
    Reason.CONTRACT_INTEGRITY_FAILED: (
        "The stored contract failed an integrity check: it is unsigned, or its signature "
        "does not match its permissions. It was not written by something holding the "
        "signing key, so it is not treated as approved."
    ),
    Reason.MANIFEST_DRIFT: "The upstream tool manifest changed after the contract was approved; risky calls require review.",
    Reason.MANIFEST_UNKNOWN_TOOL: "The requested tool is not present in the pinned upstream manifest.",
    Reason.MANIFEST_NOT_PINNED: "No manifest fingerprint was pinned for this task, so manifest integrity cannot be checked.",
    Reason.TOOL_NOT_ALLOWED: "The tool is not in the contract's allowed_tools.",
    Reason.SERVER_NOT_ALLOWED: "The upstream tool server is not permitted for this task.",
    Reason.TOOL_NAME_INVALID: "The tool name violates the MCP tool-name character constraints.",
    Reason.OPERATION_DENIED: "The derived operation appears in the contract's denied_actions.",
    Reason.OPERATION_NOT_ALLOWED: "The derived operation is not in the contract's allowed_operations.",
    Reason.RESOURCE_OUT_OF_SCOPE: "The target resource is outside every declared resource scope.",
    Reason.PATH_TRAVERSAL: "The target path attempted to traverse outside the sandbox root.",
    Reason.PATH_ABSOLUTE: "The target path was absolute; only sandbox-relative paths are accepted.",
    Reason.PATH_SYMLINK_ESCAPE: "The target path resolved through a symlink to a location outside the sandbox root.",
    Reason.PATH_UNSAFE_ENCODING: "The target path contained an unsafe encoding (null byte, control character, or ambiguous separator).",
    Reason.RESOURCE_MISSING: "The tool requires a target resource argument and none was supplied.",
    Reason.DESTINATION_NOT_ALLOWED: "The destination host is not in the contract's allowed_destinations.",
    Reason.DESTINATION_UNPARSEABLE: "The destination could not be parsed as an absolute URL.",
    Reason.DESTINATION_PRIVATE_ADDRESS: "The destination resolves to a loopback, private, link-local or otherwise reserved address.",
    Reason.DESTINATION_SCHEME_DENIED: "The destination URL scheme is not permitted.",
    Reason.DESTINATION_MISSING: "The tool requires a destination argument and none was supplied.",
    Reason.CALL_BUDGET_EXCEEDED: "The task's max_calls budget is exhausted.",
    Reason.WRITE_BUDGET_EXCEEDED: "The task's max_writes budget is exhausted.",
    Reason.NEEDS_APPROVAL: "The contract requires human approval for this tool before it may execute.",
    Reason.APPROVAL_GRANTED: "A matching single-use approval grant was consumed.",
    Reason.APPROVAL_DECLINED: "A reviewer declined this action.",
    Reason.APPROVAL_NOT_FOUND: "No approval grant matched this exact tool, arguments, task and contract revision.",
    Reason.APPROVAL_TIMEOUT: "No reviewer decision arrived within the approval timeout; the action was denied.",
    Reason.APPROVAL_ALREADY_CONSUMED: "The approval grant was already used once and cannot be reused.",
    Reason.APPROVAL_ARGS_MISMATCH: "The approval grant was issued for different canonical arguments.",
    Reason.APPROVAL_REVISION_STALE: "The approval grant was issued against an earlier contract revision.",
    Reason.APPROVAL_EXPIRED: "The approval grant's time to live elapsed before execution.",
    Reason.HEURISTIC_ESCALATED: "An advisory heuristic escalated this call to human review. Heuristics can escalate but never override a deterministic deny.",
    Reason.HEURISTIC_SUSPICIOUS_CONTENT: "Advisory only: argument content resembled injected instructions. This is not an access-control decision.",
    Reason.ALLOWED_BY_CONTRACT: "The call matched the approved contract on tool, operation, resource and budget.",
    Reason.ALLOWED_READ_ONLY: "The call is a read permitted by an explicitly read-only contract.",
    Reason.ALLOWED_AFTER_APPROVAL: "The call was allowed after a reviewer approved these exact arguments.",
    Reason.EVALUATOR_ERROR: "The policy evaluator raised an unexpected error. Agent Drift fails closed: the call was denied.",
    Reason.STORE_UNAVAILABLE: "The decision store was unavailable. Agent Drift fails closed: the call was denied.",
}

#: Rule identifiers, one per enforcement stage, in the frozen evaluation order.
RULE_IDS: Final[tuple[str, ...]] = (
    "R1-input-validation",
    "R2-task-identity",
    "R3-contract-validity",
    "R4-manifest-integrity",
    "R5-tool-allowlist",
    "R6-operation-policy",
    "R7-resource-scope",
    "R8-destination-scope",
    "R9-budgets",
    "R10-approval",
    "R11-advisory-heuristics",
)

#: Which rule emits which codes. Used by tests to assert ordering invariants.
RULE_FOR_REASON: Final[dict[str, str]] = {
    Reason.BAD_ARGUMENTS: "R1-input-validation",
    Reason.ARGUMENTS_NOT_OBJECT: "R1-input-validation",
    Reason.ARGUMENT_TOO_LARGE: "R1-input-validation",
    Reason.SCHEMA_MISMATCH: "R1-input-validation",
    Reason.UNDECLARED_ARGUMENT: "R1-input-validation",
    Reason.MISSING_TASK_BINDING: "R2-task-identity",
    Reason.TASK_SPOOF_ATTEMPT: "R2-task-identity",
    Reason.TASK_MISMATCH: "R2-task-identity",
    Reason.NO_CONTRACT: "R3-contract-validity",
    Reason.CONTRACT_EXPIRED: "R3-contract-validity",
    Reason.CONTRACT_NOT_YET_VALID: "R3-contract-validity",
    Reason.CONTRACT_UNTRUSTED_SOURCE: "R3-contract-validity",
    Reason.CONTRACT_REVISION_CHANGED: "R3-contract-validity",
    Reason.CONTRACT_INTEGRITY_FAILED: "R3-contract-validity",
    Reason.MANIFEST_DRIFT: "R4-manifest-integrity",
    Reason.MANIFEST_UNKNOWN_TOOL: "R4-manifest-integrity",
    Reason.MANIFEST_NOT_PINNED: "R4-manifest-integrity",
    Reason.TOOL_NOT_ALLOWED: "R5-tool-allowlist",
    Reason.SERVER_NOT_ALLOWED: "R5-tool-allowlist",
    Reason.TOOL_NAME_INVALID: "R5-tool-allowlist",
    Reason.OPERATION_DENIED: "R6-operation-policy",
    Reason.OPERATION_NOT_ALLOWED: "R6-operation-policy",
    Reason.RESOURCE_OUT_OF_SCOPE: "R7-resource-scope",
    Reason.PATH_TRAVERSAL: "R7-resource-scope",
    Reason.PATH_ABSOLUTE: "R7-resource-scope",
    Reason.PATH_SYMLINK_ESCAPE: "R7-resource-scope",
    Reason.PATH_UNSAFE_ENCODING: "R7-resource-scope",
    Reason.RESOURCE_MISSING: "R7-resource-scope",
    Reason.DESTINATION_NOT_ALLOWED: "R8-destination-scope",
    Reason.DESTINATION_UNPARSEABLE: "R8-destination-scope",
    Reason.DESTINATION_PRIVATE_ADDRESS: "R8-destination-scope",
    Reason.DESTINATION_SCHEME_DENIED: "R8-destination-scope",
    Reason.DESTINATION_MISSING: "R8-destination-scope",
    Reason.CALL_BUDGET_EXCEEDED: "R9-budgets",
    Reason.WRITE_BUDGET_EXCEEDED: "R9-budgets",
    Reason.NEEDS_APPROVAL: "R10-approval",
    Reason.APPROVAL_GRANTED: "R10-approval",
    Reason.APPROVAL_DECLINED: "R10-approval",
    Reason.APPROVAL_NOT_FOUND: "R10-approval",
    Reason.APPROVAL_TIMEOUT: "R10-approval",
    Reason.APPROVAL_ALREADY_CONSUMED: "R10-approval",
    Reason.APPROVAL_ARGS_MISMATCH: "R10-approval",
    Reason.APPROVAL_REVISION_STALE: "R10-approval",
    Reason.APPROVAL_EXPIRED: "R10-approval",
    Reason.HEURISTIC_ESCALATED: "R11-advisory-heuristics",
    Reason.HEURISTIC_SUSPICIOUS_CONTENT: "R11-advisory-heuristics",
    Reason.ALLOWED_BY_CONTRACT: "R6-operation-policy",
    Reason.ALLOWED_READ_ONLY: "R6-operation-policy",
    Reason.ALLOWED_AFTER_APPROVAL: "R10-approval",
    Reason.EVALUATOR_ERROR: "R0-fail-closed",
    Reason.STORE_UNAVAILABLE: "R0-fail-closed",
}


def explain(code: str) -> str:
    """Return the human-readable explanation for a reason code."""
    return EXPLANATIONS.get(code, f"Unknown reason code: {code}")


def rule_for(code: str) -> str:
    """Return the rule ID that emits a reason code."""
    return RULE_FOR_REASON.get(code, "R0-fail-closed")
