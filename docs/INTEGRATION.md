# INTEGRATION.md — wiring Agent Drift into a host, and what it can and cannot see

---

## 1. The integration contract, in one paragraph

Agent Drift is an **MCP stdio proxy**. Your host speaks MCP to the gateway; the gateway
speaks MCP to one upstream server. Two things must be true before anything is enforced:

1. Your host's server configuration points at `agent-drift gateway`, not at the upstream
   server directly.
2. The gateway is launched with `--task-id`, and a contract for that task has been
   registered through the control plane.

If either is missing, the honest outcome differs: a host that bypasses the gateway gets **no
protection and no indication that it is unprotected**, while a gateway with an unregistered
task **denies everything** with `AD-E020`. Fail-closed applies to the second case only. The
first is a configuration property Agent Drift cannot observe.

---

## 2. Quick start against the bundled sandbox

```bash
make setup                                   # venv, pinned deps, .env with a fresh token, seeded demo
make demo                                    # run all 8 scenarios through a real gateway
make dev                                     # control plane + dashboard on http://127.0.0.1:8001
```

Then point your MCP host at the gateway. Copy `examples/mcp_client_config.json` and replace
`/ABSOLUTE/PATH/TO/agent-drift` with your checkout path:

```json
{
  "mcpServers": {
    "agent-drift": {
      "command": "/ABSOLUTE/PATH/TO/agent-drift/.venv/bin/python",
      "args": ["-m", "agent_drift.cli", "gateway",
               "--task-id", "demo-repo-review",
               "--db", "/ABSOLUTE/PATH/TO/agent-drift/var/agent_drift.db",
               "--sandbox-root", "/ABSOLUTE/PATH/TO/agent-drift/var/fixture/workspace"],
      "env": { "PYTHONPATH": "/ABSOLUTE/PATH/TO/agent-drift/packages:/ABSOLUTE/PATH/TO/agent-drift" }
    }
  }
}
```

The host now sees five tools. Reads succeed; a write, a delete or a post is denied before
the tool runs, and appears in the dashboard within about a second.

---

## 3. Registering a contract

Through the API (the token is in `.env`):

```bash
source .env
curl -sS -X POST http://127.0.0.1:${AD_API_PORT}/api/tasks \
  -H "authorization: Bearer ${AD_ADMIN_TOKEN}" \
  -H 'content-type: application/json' \
  -d '{
    "task_id": "demo-repo-review",
    "user_goal": "Review the repository and produce a bug-fix plan without changes or external network transmission",
    "allowed_tools": ["repo.read_file", "repo.list_files"],
    "allowed_operations": ["read", "list"],
    "resource_scopes": ["sandbox-repo/**"],
    "allowed_destinations": [],
    "denied_actions": ["write", "delete", "network_post"],
    "max_writes": 0,
    "max_calls": 50
  }'
```

Field notes that matter:

- `allowed_destinations: []` means **all egress is denied**. Silence is not consent.
- `resource_scopes` uses globs where a trailing `/**` matches a whole subtree and a single
  `*` does not cross a directory separator.
- `approval_rules` lists tools that always pause for human review, even when otherwise
  allowed.
- `expires_in_s` sets an expiry; after it, every call fails closed with `AD-E021`.
- Re-registering the same `task_id` creates a **new revision**, which invalidates every
  outstanding approval grant.

---

## 4. Verifying with the MCP Inspector

The official Inspector is an npm package. Check the current invocation in the version you
install rather than trusting a snippet — the CLI has changed across releases:

```bash
npx @modelcontextprotocol/inspector --help
```

Then run it against the gateway, substituting your absolute paths:

```bash
npx @modelcontextprotocol/inspector \
  /ABSOLUTE/PATH/TO/agent-drift/.venv/bin/python \
  -m agent_drift.cli gateway \
  --task-id demo-repo-review \
  --db /ABSOLUTE/PATH/TO/agent-drift/var/agent_drift.db \
  --sandbox-root /ABSOLUTE/PATH/TO/agent-drift/var/fixture/workspace
```

In the Inspector: list tools (five appear with intact schemas), call
`repo.read_file` with `{"path": "sandbox-repo/README.md"}` (succeeds), then call
`repo.write_file` with `{"path": "sandbox-repo/README.md", "content": "x"}` — it returns
`isError: true` with a structured `agent_drift` record naming the reason codes.

> **Not verified in this build.** The npm registry is blocked by egress policy in the
> environment where Agent Drift was built, so the Inspector could not be installed or run.
> These instructions are written from the documented CLI shape and are marked
> **NOT VERIFIED** in `docs/ACCEPTANCE_STATUS.md` rather than claimed as tested. The
> equivalent round trip *is* verified by `make smoke` and by
> `tests/integration/test_mcp_roundtrip.py`, which drive a real `mcp.Client` through the
> same gateway.

---

## 5. Guarding your own MCP server

```bash
agent-drift gateway \
  --task-id my-task \
  --upstream-command /usr/bin/node \
  --upstream-arg /path/to/your-server/dist/index.js \
  --upstream-name my-server
```

You must also tell the policy engine what your tools *do*. Write a JSON map and pass it with
`--tool-specs` (or set `AD_TOOL_SPECS`); `examples/tool_specs.example.json` is a working
starting point:

```json
{
  "files.read":  { "operation": "read",  "resource_arg": "path", "requires_resource": true },
  "files.write": { "operation": "write", "resource_arg": "path", "requires_resource": true },
  "http.post":   { "operation": "network_post", "destination_arg": "url", "requires_destination": true }
}
```

```bash
agent-drift gateway \
  --task-id my-task \
  --upstream-command /usr/bin/node \
  --upstream-arg /path/to/your-server/dist/index.js \
  --upstream-name my-server \
  --tool-specs ./my-tool-specs.json
```

A tool absent from the map has operation `unknown` and is **denied**, so an incomplete map
fails closed rather than open. (An earlier version of this guide told you to edit a constant
in `policy.py` that the gateway never read, which meant following it produced `AD-E051` on
every call. An independent review caught that; `--tool-specs` is the fix.)

**This mapping is deliberately local configuration.** It is never derived from a tool's own
description or annotations, because those come from the server and the server may be the
adversary (MCP 2026-07-28 says annotations are untrusted hints; Microsoft's MCP guidance
names tool poisoning and rug pulls explicitly). A tool with no mapping has operation
`unknown` and is denied — fail closed, not fail open.

Two more things to know before pointing this at a real server:

- **Undeclared arguments are refused** (`AD-E005`). If your tools accept arguments they do
  not declare in `inputSchema`, either declare them or set `additionalProperties: true`.
- **Argument-level checks do not bind your tool's behaviour.** See §7.

---

## 6. The Python SDK, and what it is not

```python
from agent_drift import DriftGuard

guard = DriftGuard(db_path="var/agent_drift.db")
decision = guard.evaluate(
    task_id="demo-repo-review",
    tool_name="repo.write_file",
    args={"path": "sandbox-repo/README.md", "content": "..."},
)
if decision.status != "allow":
    print(decision.reason_codes, decision.explanations)
```

Run `python examples/sdk_quickstart.py` for a complete working example.

**`evaluate()` evaluates; it does not enforce.** It returns what the approved contract says
and records the decision for audit. Whether the tool then runs is entirely up to your code.
`Decision.is_enforcement` is always `False`, and
`tests/integration/test_sdk.py::TestEnforcementBoundary::test_the_sdk_cannot_prevent_a_tool_call`
demonstrates the gap rather than describing it: it ignores a denial, calls the tool anyway,
and asserts the tool ran.

Use the SDK when you cannot put a proxy in the path, and understand you are buying auditable,
consistent decisions — not containment. Containment requires the gateway.

---

## 7. Exactly what is and is not covered

**Covered** — every `tools/call` that traverses the gateway:

- The tool name, the full argument object, the derived operation
- The target resource, canonicalized and checked against the declared scopes
- The destination, normalized and checked against the allowlist
- Call and write budgets, reserved atomically
- Approval requirements, bound to exact canonical arguments
- Upstream tool manifest drift since approval

**Not covered**

| Not covered | Why |
|---|---|
| Calls to servers your host talks to **directly** | They never reach the gateway. There is no way for Agent Drift to detect this configuration. |
| Non-MCP tool use — shell, built-in host capabilities, direct file access | Outside the protocol. |
| What a third-party tool actually does with its arguments | Agent Drift checks the argument; it cannot bind the behaviour. The bundled fixture re-validates at the moment of use, which closes the gap for *those* tools only. |
| MCP surfaces other than `tools/list` and `tools/call` | Resources, prompts, completion and sampling are not proxied in v1. |
| Streamable HTTP transport | stdio only in v1. See `docs/THREAT_MODEL.md` §5.6 for why this is not a flag flip. |
| Multiple upstream servers | One per gateway process in v1. |
| Harm visible only across a sequence of in-contract calls | Each call is evaluated alone. |

**Do not** read "Agent Drift is configured" as "this agent is safe". Read it as "tool calls
through this gateway are checked against a contract, and there is a receipt for each one".

---

## 8. Operating notes

- **Logging.** The gateway writes to **stderr only**; stdout carries the JSON-RPC stream. A
  single stray `print()` to stdout would corrupt the protocol.
- **Approval timeout.** `--approval-timeout` (default 60s) bounds how long a gated call
  waits. A timeout **denies**; it never auto-approves. A long timeout is a liveness risk for
  the agent, not a security risk.
- **One gateway process per task.** The task binding is per process. Two concurrent tasks
  means two gateway processes, each with its own `--task-id`.
- **Database sharing.** Gateway, control plane and SDK can share one SQLite file; writes are
  serialized and budget reservation is atomic under `BEGIN IMMEDIATE`.
- **Audit integrity.** Set `AD_AUDIT_HMAC_KEY` to enable the HMAC chain and
  `make verify-audit` to check it. Unset, `/api/audit/verify` reports `configured: false` —
  which means "nothing to verify", not "verified".
- **Resetting.** `make clean-demo` clears the database, sandbox and screenshots.
