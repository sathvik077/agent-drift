# THREAT_MODEL.md — Agent Drift

**Status:** v1, 2026-10-14. This document is written to be useful to someone trying to break
the system, not to reassure someone evaluating it. Where a control is weak, it says so.

---

## 1. Trust boundary

**Trusted**

- The **approved intent contract**, created through the control plane with the local admin
  token, or from trusted local configuration.
- The **task binding**, supplied as `--task-id` when the gateway process is launched.
- Locally configured **tool-to-operation mappings** (`DEFAULT_TOOL_SPECS`) and
  **resource/destination scopes**.
- The **review UI**, when operated by the person holding the admin token.
- The host, OS and filesystem.

**Untrusted — data, never authority**

- Everything the model proposes: tool names, argument objects, every value inside them.
- Everything an upstream server says: tool **descriptions**, **annotations**, **titles**,
  input and output schemas, and tool results.
- Retrieved documents, issue comments, web page text, file contents.
- MCP transport and connection identity.

The single most important consequence: **no untrusted input can change the task, the
contract, the trust tier, a budget or an approval.** A tool argument named `task_id` is
refused and recorded (`AD-E011`); a tool description claiming `read_only_hint: true` does not
make a write tool safe, because operations are mapped by local configuration.

### Why transport identity is not task identity

MCP revision 2026-07-28 removed protocol-level sessions entirely: there is no
`Mcp-Session-Id` and no `initialize` handshake, and every request is self-contained. A proxy
therefore has **no connection-scoped identity to borrow even if it wanted to**. Agent Drift
binds a task when the gateway process starts. This was a threat-model decision before it was
a protocol one, and the protocol now agrees.

---

## 2. Adversaries

| Adversary | Capability | Addressed? |
|---|---|---|
| **A1 — Content author** | Plants instructions in a document, issue or tool result the agent will read | Yes. Untrusted content cannot alter the contract; a resulting tool call is evaluated on its own merits. |
| **A2 — Drifting planner** | Proposes off-task calls through honest error or model failure | Yes, to the extent the drift is visible in the tool name, arguments or budget. |
| **A3 — Malicious upstream server** | Changes tool metadata after approval; advertises reassuring annotations; returns injected text | Partly. Manifest drift is detected and risky calls denied (`AD-E030`). The server can still lie *inside a tool result*; that content is treated as untrusted data. |
| **A4 — Malicious tool implementation** | Ignores its own declared arguments and acts on something else | **No.** See §5.1. This is the hardest honest limitation. |
| **A5 — Local process without the admin token** | Tries to register a permissive contract or approve a pending action | **Through the HTTP surface, yes** — mutations require a bearer token and fail closed when none is configured. **Through the database file, only when a signing key is set.** See §5.11. |
| **A6 — Agent that does not use the gateway** | Calls tools directly, or uses non-MCP tools | **No.** Out of coverage by construction. See §5.2. |
| **A7 — Host or OS compromise** | Reads the database, the admin token and the HMAC key | **No.** Out of scope. An integrity chain is tamper-evidence under a separately held key; whoever can write the database can usually read the key too. |

---

## 3. In scope

- Indirect prompt injection through untrusted content
- Mistaken or off-target tool use
- Unauthorized scope or destination changes
- Excessive file mutation (write budgets)
- Goal change across a multi-step tool sequence, where each step is individually checkable
- Missing, expired or untrusted contracts
- Tool description, schema and annotation changes after approval
- Replay of recorded calls through the dashboard, export or retries
- Approval lifecycle: issuance, exactness, single use, TTL, decline, timeout, revision change

## 4. Explicitly out of scope for v1

- Introspecting hidden model reasoning
- Intercepting tools that bypass the gateway
- Defending a compromised host, OS or administrator
- Any global proof that all semantic deviation is detected
- Protecting arbitrary commercial agent clients with no user configuration
- Distributed or multi-tenant IAM
- Remote OAuth production security
- Network transports (Streamable HTTP). v1 is stdio only — see §5.6

---

## 5. Known weaknesses, stated plainly

### 5.1 Argument-level enforcement cannot bind a third-party tool's behaviour

Agent Drift decides whether to **forward** a call. It cannot make a tool honour the arguments
it was given. A third-party `repo.write_file` could ignore its `path` argument, construct its
own, follow a symlink the gateway never saw, or act on something else entirely. Checking an
argument is not the same as constraining an effect.

For the **controlled fixture tools in this repository** the gap is closed: each tool
re-validates its path with `resolve_in_root` inside the process that touches the filesystem,
at the moment it touches it (`tests/security/test_path_traversal.py::TestFixtureRejectsTraversalAtUse`).
That is an argument about *these* tools, not about tools in general.

**Consequence:** for untrusted third-party tools, resource restrictions based only on
arguments are advisory. Real containment needs OS-level sandboxing (namespaces, seccomp, a
restricted filesystem view) underneath the gateway. That is a v2 item and is not implemented.

### 5.2 Only what traverses the gateway is seen

An agent that talks to a tool server directly is invisible. So is any non-MCP tool call, any
shell the agent spawns, and any capability the host exposes without going through MCP. The
integration is explicit by design: a host must point its server configuration at the gateway
and the gateway must be launched with a task binding. **A host that is not configured this
way receives no protection at all**, and there is no way for Agent Drift to detect that.

### 5.3 Sequence and aggregate harm

Every call is evaluated on its own. A sequence of individually in-contract calls that is
jointly harmful — reading 500 files one at a time, or writing many small authorized changes
that together break something — is not detected beyond the blunt instrument of `max_calls`
and `max_writes`. This is hypothesis H2's failure mode in `docs/RESEARCH.md`, and it is
stated here before a reviewer finds it.

### 5.4 Destination checks do not resolve DNS

`destinations.py` normalizes and allowlists a URL's host, rejecting reserved address ranges
in literal form. It does **not** resolve DNS, so a hostname that resolves to a public address
at check time and a private one at use time (DNS rebinding) is not caught. The fixture
`network.http_post` opens no sockets at all, so within this repository the check is
conclusive; for real egress a resolve-time check and a pinned-address connection are
required. Not implemented.

### 5.5 The audit chain is tamper-evidence, not tamper-proofing

With `AD_AUDIT_HMAC_KEY` set, events are HMAC-chained and `make verify-audit` recomputes the
chain. Without it, `/api/audit/verify` reports `configured: false` and **does not report
"verified"**. Even with a key, an attacker who can write the database can usually also read
the key, and then the chain can be forged wholesale. Real tamper-evidence needs the key held
outside the trust boundary of the thing being audited — an HSM, a remote signing service, or
append-only external storage.

### 5.6 Single transport, single upstream

v1 implements stdio with exactly one upstream server. Streamable HTTP is not implemented, so
the header-mirroring rules (`Mcp-Method`, `Mcp-Name`, `x-mcp-header` /`Mcp-Param-*`) do not
apply — and that is deliberate, because the spec's own guidance for policy-enforcing
intermediaries there is subtle: an intermediary must verify that `MCP-Protocol-Version`
indicates a revision requiring header–body validation, and reject the request otherwise,
rather than trusting a mirrored header value. Getting that wrong would be a header-versus-body
confusion vulnerability. Supporting the transport correctly is v2 work, not a flag flip.

Multi-upstream aggregation is also unimplemented; it would require tool-name disambiguation
and synthesized pagination cursors (decision D-009).

### 5.7 Approval is a bounded wait, not an in-band protocol exchange

`needs_approval` suspends the call and polls for a grant up to a timeout, then denies. The
spec's own mechanism (MRTR) would be more idiomatic but requires host cooperation and binds
to a *different* request id on retry. The current grant key deliberately excludes the request
id — the 2026-07-28 removal of SSE resumability means request ids are not stable across a
reconnect, so a grant keyed on one would be wrong. A denial on timeout is the fail-closed
outcome; a long timeout is a denial-of-service surface against the agent, not against
security.

### 5.8 Single-user development control plane

Bearer-token auth over loopback with a CORS allowlist. There is no multi-user identity, no
role separation, no TLS, no rate limiting, no CSRF token (not needed for a header-auth API,
but relevant if cookie auth were ever added), and no audit of *who* holds the token. This is
adequate for local development and is not production authentication. Claiming otherwise would
be the exact kind of overstatement this document exists to prevent.

### 5.9 Fail-closed has a liveness cost

Every failure path denies: evaluator exception (`AD-E999`), store unavailable (`AD-E998`),
approval timeout (`AD-A005`), unknown tool, unmapped operation. A corrupted database or a
policy bug therefore stops the agent completely. That is the right trade for a security
control and the wrong trade for availability; an operator who needs the agent to keep working
has to fix the control plane, not bypass it. There is deliberately no bypass flag.

### 5.11 Filesystem write access to the database

An independent review demonstrated this: a local process that can write
`var/agent_drift.db` replaced a read-only contract with a fully permissive one, without
the admin token and without any HTTP request. The `contract_hash` did not stop it, because
that hash is an **unkeyed** SHA-256 whose algorithm ships in this repository — anyone who
can write the row can recompute it.

**What was changed in response.** When `AD_AUDIT_HMAC_KEY` is set, each contract is stored
with an HMAC over its semantic fields and that MAC is verified on every read. A contract
written by something that did not hold the key is refused with `AD-E025` and the call is
denied. The stored `source` field is also checked against the trusted values *before*
validation, so a tampered row cannot reach the policy engine at all.

**What remains true.** With **no** signing key configured, filesystem write access to the
database is equivalent to holding the admin token. Run with `AD_AUDIT_HMAC_KEY` set — which
`make setup` does by default — and keep the key readable only by the account running the
gateway. If an adversary can read that key as well, this control is defeated, which is the
same caveat as §5.5 and is not a reason to omit the control.

### 5.12 Advisory escalation is off by default

`risk_thresholds = {"advisory": "escalate"}` routes a call whose argument content resembles
injected instructions to human review. The default is `"annotate"`: the observation is
recorded and nothing changes. A probabilistic signal turning working tasks into approval
prompts is a real cost, and an operator should choose it deliberately rather than inherit
it. Earlier revisions of this document described escalation as implemented when only the
annotation half existed; an independent review caught that, and the escalation path now
exists and is tested.

### 5.13 At-most-once is best-effort, and a retry is a new call

The gateway forwards each **authorized attempt** exactly once. It does not and cannot make a
non-idempotent upstream tool idempotent, and it does not deduplicate: a host that re-issues a
call creates a new attempt, a new decision and a second execution. This is visible rather than
silent — each execution has its own recorded decision — but "at most once" applies per
attempt, not per logical operation.

When a forward times out, the outcome is recorded as **`unknown`**, not as `no`, and the
budget reservation is **not** returned. An earlier revision refunded on timeout, which let a
tool slower than the gateway's timeout exceed its write budget indefinitely while the receipt
denied the writes had happened. Both halves of that defect are fixed and regression-tested
(`tests/integration/test_timeout_budget.py`).

### 5.10 The benchmark measures the authors' own understanding

`evals/` reports 100% precision and recall on 192 cases. Those cases were written by the same
author as the rules, so a high score demonstrates internal consistency and the absence of the
failure modes somebody thought to write down. Five families are held out to make overfitting
visible, but a held-out family is still an author-chosen family. The published benchmarks that
would test this properly (AgentDojo, ASB) have **not** been run.

---

## 6. Controls and where they are tested

| Control | Implementation | Test |
|---|---|---|
| Host-owned task identity | `policy.py` stage 2 | `tests/security/test_task_identity.py` |
| Fail-closed on any exception | `policy.evaluate` | `tests/unit/test_enforcement_order.py::TestFailClosed` |
| Deny before upstream execution | `gateway.handle_call_tool` | `tests/integration/test_deny_before_execute.py` |
| Path canonicalization + symlink | `paths.py` | `tests/security/test_path_traversal.py` |
| Destination allowlist, default deny | `destinations.py` | `tests/security/test_destinations.py` |
| Undeclared-argument rejection | `policy._schema_mismatch` | `tests/integration/test_schema_gate.py` |
| Atomic budget reservation | `store.reserve_budget` | `tests/security/test_budget_race.py` |
| Single-use argument-exact approvals | `store.consume_grant`, `contracts.ApprovalGrant.matches` | `tests/security/test_approvals.py` |
| Manifest fingerprint / rug pull | `manifest.py`, `policy.py` stage 4 | `tests/unit/test_manifest.py`, scenario F |
| Secret redaction before logging | `canonical.redact` | `tests/security/test_redaction_and_api_auth.py` |
| Bearer auth on mutations | `apps/api/main.auth_middleware` | `tests/security/test_redaction_and_api_auth.py` |
| No outbound network from tests | `tests/conftest.py` socket guard | enforced on every test |
| Heuristics escalate (opt-in), never override | `policy._stage_advisory` | `tests/unit/test_enforcement_order.py::TestAdvisoryHeuristics`, `tests/security/test_review_findings.py::TestRT09AdvisoryEscalation` |
| Contract integrity under a signing key | `store.get_contract`, `store.contract_mac` | `tests/security/test_review_findings.py::TestRT04ContractIntegrity` |
| Timeout does not refund budget | `gateway._forward_once` | `tests/integration/test_timeout_budget.py` |
| Approval exactness across unicode spellings | `contracts.ToolAttempt.raw_args_digest`, `paths` NFC rule | `tests/security/test_review_findings.py::TestRT03UnicodeApprovalAliasing` |
| Audit verification is three-state | `store.verify_chain` | `tests/security/test_review_findings.py::TestRT02AuditChainIsThreeState` |

---

## 7. Red-team questions (from `ACCEPTANCE_EVIDENCE_MATRIX.md`)

Answered in `docs/SECURITY_REVIEW.md` with the evidence from an independent review pass.

1. Can untrusted user or model content forge an authority field or cross a trust boundary?
2. Does any policy, auth or database exception result in permissive behaviour?
3. Can an unauthorized side effect or poisoned context exposure occur while the dashboard
   says BLOCKED?
4. Is any required test skipped by default, or does an evaluation chart use fabricated data?
5. Can a clean user follow the README without secret keys and reproduce the screenshots or
   the causal demo?
6. Are limitations, bypass cases and exact coverage clearly documented?
