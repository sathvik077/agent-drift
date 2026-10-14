# Architecture

![Agent Drift architecture](assets/architecture.svg)

Source: [`architecture.mmd`](architecture.mmd). Regenerate with
`npx @mermaid-js/mermaid-cli -i docs/architecture.mmd -o docs/assets/architecture.svg`.

## Four processes

| # | Process | Module | Address |
|---|---|---|---|
| 1 | **Gateway** — MCP server to the host, MCP client to the upstream | `packages/agent_drift/gateway.py` | stdio |
| 2 | **Control plane** — contracts, decisions, events, approvals, SSE | `apps/api/main.py` | `127.0.0.1:8001` |
| 3 | **Dashboard** — React 19 + TypeScript, served by the control plane | `apps/dashboard/` | `127.0.0.1:8001/` |
| 4 | **Upstream fixture** — sandbox-only MCP tools with execution counters | `examples/upstream_mcp/server.py` | stdio |

## The ordering that matters

A decision row is committed to SQLite **before** the gateway touches the upstream client. If
the process dies between the commit and the forward, the record says `allow` with
`upstream_executed = 0` — an honest "we authorized it and do not know whether it ran" rather
than a lost authorization. A denial never reaches the forward path at all, which is why the
fixture's own execution counters can serve as an external oracle in the tests.

## Enforcement order

Evaluated top to bottom; the first stage to object decides. Any exception anywhere becomes
`deny / AD-E999`.

| # | Rule | Checks | Example codes |
|---|---|---|---|
| 1 | `R1-input-validation` | argument object, size bound, declared schema, no undeclared arguments | `AD-E001`, `AD-E004`, `AD-E005` |
| 2 | `R2-task-identity` | gateway has a binding; arguments assert no identity | `AD-E010`, `AD-E011` |
| 3 | `R3-contract-validity` | exists, trusted source, in its validity window, hash consistent | `AD-E020`, `AD-E021` |
| 4 | `R4-manifest-integrity` | upstream manifest matches the approval-time pin | `AD-E030`, `AD-E032` |
| 5 | `R5-tool-allowlist` | server and tool permitted; tool name conformant | `AD-E040`, `AD-E041` |
| 6 | `R6-operation-policy` | operation allowed and not denied | `AD-E050`, `AD-E051` |
| 7 | `R7-resource-scope` | path canonicalizes inside a declared scope | `AD-E060`, `AD-E061`, `AD-E063` |
| 8 | `R8-destination-scope` | destination normalizes to an allowlisted host | `AD-E070`, `AD-E072` |
| 9 | `R9-budgets` | call and write budgets reserved atomically | `AD-E080`, `AD-E081` |
| 10 | `R10-approval` | grant required, exact, single use, unexpired | `AD-A001`, `AD-A005` |
| 11 | `R11-advisory-heuristics` | may escalate an allow to review; **never** overrides a deny | `AD-H002` |

Stage 11 is only reached when the running status is `ALLOW`, which is the structural
guarantee that a probabilistic signal cannot weaken a deterministic decision.

## Data model

```
contracts   (task_id, policy_revision) -> semantic fields + contract_hash + manifest_pin
budgets     (task_id, policy_revision) -> calls_used, writes_used      [BEGIN IMMEDIATE]
attempts    attempt_id -> redacted args + args_digest + run_id
decisions   attempt_id -> status, reason_codes, rule_ids, evidence, upstream_executed
approvals   approval_id -> (task, revision, tool, args_digest, nonce), state, TTL
events      seq AUTOINCREMENT -> kind, payload, prev_hmac, hmac
runs        run_id -> task, scenario, label
```

SQLite in WAL mode with a single serialized writer. Budget reservation and approval
consumption run inside `BEGIN IMMEDIATE` transactions, which is what makes
"two concurrent writes against a budget of one yield exactly one allow" true rather than
usually true (`tests/security/test_budget_race.py`).
