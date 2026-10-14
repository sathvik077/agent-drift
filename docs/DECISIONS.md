# DECISIONS.md — dated architecture decisions and tradeoffs

Each entry records what was decided, why, what was given up, and how the consequence is
tested or disclosed. Entries are append-only.

---

## D-001 — 2026-10-14 — Pin MCP SDK `mcp==2.2.0`, protocol revision `2026-07-28`

**Decision.** Use the installed official Python SDK `mcp` 2.2.0 and target protocol
revision `2026-07-28`, which the SDK reports as `LATEST_PROTOCOL_VERSION` and as the sole
member of `MODERN_PROTOCOL_VERSIONS`.

**Why.** The blueprint forbids mixing protocol examples from incompatible revisions and
requires verifying compatibility rather than assuming. Before committing to any
architecture a scratch round trip was executed: a fixture `MCPServer` over stdio, an
`mcp.Client` connecting to it, `list_tools()` returning two dotted-name tools with intact
JSON Schemas, and `call_tool()` returning content. The client reported
`protocol_version == "2026-07-28"`.

**Given up.** Backward compatibility with 2024/2025 handshake-based revisions is not
claimed or tested. The SDK still lists them in `SUPPORTED_PROTOCOL_VERSIONS`; Agent Drift
does not assert conformance for them.

**Tested by.** `tests/integration/test_mcp_roundtrip.py` asserts the negotiated protocol
version and that tool schemas survive the proxy unmodified.

---

## D-002 — 2026-10-14 — Starlette instead of FastAPI for the control plane

**Decision.** Build the control plane directly on `starlette==1.6.0` with `pydantic==2.13.5`
for request/response validation, and hand-generate the OpenAPI 3.1 document plus a `/docs`
page.

**Why.** `pypi.org` is blocked by egress policy in this environment (HTTP 403 at the proxy
on CONNECT), so FastAPI cannot be installed. Starlette, Pydantic v2, sse-starlette and
uvicorn *are* present. CLAUDE.md §3 expresses a preference ("Prefer … FastAPI"), not a
hard gate; AD-11 requires typed routes and a usable `/docs`, which this satisfies.

**Given up.** FastAPI's automatic OpenAPI generation and dependency-injection ergonomics.
The OpenAPI document is therefore hand-maintained and is itself asserted by a test, so it
cannot silently drift from the routes.

**Tested by.** `tests/unit/test_openapi.py` (every registered route appears in the
document, with request/response schemas) and `tests/integration/test_api_smoke.py`
(`/docs` returns 200 and the sample payloads it advertises are accepted by the real routes).

---

## D-003 — 2026-10-14 — stdlib `sqlite3` with WAL instead of SQLAlchemy

**Decision.** Use Python's `sqlite3` module directly, WAL journal mode, a single
serialized writer connection guarded by an in-process lock, and `BEGIN IMMEDIATE`
transactions for budget reservation and approval consumption.

**Why.** CLAUDE.md §3 permits "SQLAlchemy or sqlite3/SQLModel". SQLAlchemy is not
installable here. More importantly, the blueprint requires that budget reservation and
approval consumption be atomic under a single serialized writer — which is clearer and
more auditable written as explicit `BEGIN IMMEDIATE` statements than through an ORM
session abstraction.

**Given up.** ORM conveniences and migrations. Schema is created idempotently by
`store.py` with a `schema_version` row; migration strategy is documented as a v2 concern.

**Tested by.** `tests/security/test_budget_race.py` (N concurrent identical attempts against
a budget of 1 yield exactly one allow) and `tests/security/test_approvals.py`.

---

## D-004 — 2026-10-14 — React 19 + TypeScript + esbuild instead of Vite + Tailwind

**Decision.** The dashboard is a React 19.2.8 + TypeScript 6.0.3 application bundled by
esbuild 0.28.2, with hand-authored CSS (custom properties, dark mode, responsive grid).
`npm ci` is the documented path for users with network access; when the registry is
unreachable, `scripts/offline_bootstrap.py --node` links the pinned packages from the
local store.

**Why.** `registry.npmjs.org` is blocked by egress policy (HTTP 403), so Vite, the Tailwind
CLI and ESLint cannot be installed. React, react-dom, TypeScript and esbuild are available
locally at pinned versions. The governing requirement (AD-13, AD-17, AD-18, and the
blueprint's priority order) is a dashboard that **actually runs and can be screenshotted**,
not a specific bundler.

**Given up.** Vite's dev server and HMR; Tailwind's utility classes; ESLint. Replaced by an
esbuild watch mode, ~700 lines of reviewed CSS, and `tsc --noEmit` + `ruff` for static
checking. A real production bundle is produced and its existence and size are asserted.

**Tested by.** `make build` (esbuild production bundle + `tsc --noEmit`), `tests/e2e/`
(Playwright drives the built bundle), `make screenshots`.

---

## D-005 — 2026-10-14 — Playwright via the Python SDK instead of `@playwright/test`

**Decision.** E2E tests and screenshot capture use `playwright` 1.56.0 for Python with the
Chromium build at `/opt/pw-browsers`, written as pytest tests in `tests/e2e/`.

**Why.** `@playwright/test` is an npm package and the registry is blocked. The Python SDK is
installed and its browser is present. The acceptance criteria require a real headless
browser run against the real backend (AD-14, AD-17, AD-18); they do not require TypeScript
spec files. `ACCEPTANCE_EVIDENCE_MATRIX.md` names `tests/e2e/*.spec.ts` under "evidence
naming conventions" — this is a naming convention, and the deviation is recorded here and
in `docs/VERIFICATION.md`.

**Given up.** `@playwright/test` fixtures, trace viewer, and the `.spec.ts` naming.

**Tested by.** `make e2e` / `make verify`.

---

## D-006 — 2026-10-14 — Deterministic denial is returned as an MCP tool-execution error

**Decision.** A policy denial is returned to the host as a successful JSON-RPC response
carrying `CallToolResult(is_error=True, result_type="complete")` whose content is a
structured, redacted denial record (decision, reason codes, rule IDs, attempt ID,
contract revision). Protocol-level failures (unknown tool, malformed arguments at the
transport layer, upstream transport death) remain JSON-RPC errors.

**Why.** The 2026-07-28 tools specification keeps two distinct error channels and states
that clients SHOULD feed *tool execution* errors back to the model for self-correction
while they MAY feed protocol errors. A denial is information the agent should see and adapt
to — "you may not do that, here is why" — so it belongs in the execution-error channel. It
also means a denial is a first-class, loggable result rather than an exception.

**Given up.** The ability to make a denial invisible to the model. Documented: a denial is
visible to the agent by design, and the denial record is redacted before it is returned.

**Tested by.** `tests/integration/test_deny_before_execute.py::TestReadOnlyTaskCannotMutate` asserts a
denied call produces `is_error=True` with reason codes present and that the upstream
execution counter is unchanged.

---

## D-007 — 2026-10-14 — Approval uses a bounded in-process wait; MRTR documented as the spec-aligned alternative

**Decision.** `needs_approval` suspends the gateway's handling of that one call and polls
the control-plane database for a matching grant up to `AD_APPROVAL_TIMEOUT_S` (default 60),
then denies on timeout. The grant is keyed to
`(task_id, policy_revision, tool_name, canonical_args_digest, nonce)` and is single-use.

**Why.** The blueprint specifies exactly this behaviour ("Async wait up to bounded timeout
(suggest 60 seconds)"). The 2026-07-28 revision additionally provides Multi Round-Trip
Requests (`resultType: "input_required"` + `inputRequests`/`inputResponses`/`requestState`)
as the protocol's own in-band confirmation channel, which would be the more spec-idiomatic
mechanism. MRTR is **not** used in v1 because the host must cooperate with the retry, and
the retry carries a *different* JSON-RPC request id — which the gateway would have to bind
to the pending decision.

**Given up.** In-band host-rendered confirmation. Mitigated by the grant key deliberately
excluding the request id: because 2026-07-28 removed SSE resumability and requires a new
request id after a stream break, any approval keyed on request id would be incorrect by
construction. Our key survives retries and reconnects.

**Tested by.** `tests/security/test_approvals.py` and
`tests/integration/test_release_vectors.py` (AD-SEED-07, 08, 09).

---

## D-008 — 2026-10-14 — Docker images are specified and statically checked, not built

**Decision.** `Dockerfile.api`, `Dockerfile.dashboard` and `compose.yaml` are written and a
`make docker-build` target is provided, but no image is built in this environment.

**Why.** `registry-1.docker.io` does not resolve from the build host, so `FROM` cannot be
satisfied. The Docker daemon itself does start (29.8.2).

**Given up.** Direct evidence for the "Docker images build" half of AD-23. It is recorded
as **NOT VERIFIED (BLOCKED: container registry unreachable)** in
`docs/ACCEPTANCE_STATUS.md`, with the exact retry command, rather than asserted.

---

## D-009 — 2026-10-14 — Tool-name disambiguation deferred; one upstream in v1

**Decision.** v1 proxies exactly one upstream stdio server and forwards tool names and
pagination cursors unchanged.

**Why.** The 2026-07-28 tools page scopes name uniqueness to a single server and says
clients or proxies aggregating *multiple* servers SHOULD implement a disambiguation
strategy such as server-id prefixing, and that `serverInfo.name` must not be relied on for
disambiguation. With one upstream there are no collisions, and forwarding opaque cursors
unchanged is correct because the tool set is not filtered or rewritten.

**Given up.** Multi-upstream aggregation. If the tool set were ever filtered, the proxy
would have to synthesize its own cursors; this is noted in `docs/INTEGRATION.md` as a
precondition for multi-upstream support.

---

## D-010 — 2026-10-14 — `cacheScope: "private"` is honored; no cross-task manifest cache

**Decision.** The gateway caches an upstream `tools/list` result only for the lifetime of
the bound gateway process, and never reuses a result whose `cache_scope` is `"private"`
across tasks.

**Why.** 2026-07-28 adds `ttlMs` and `cacheScope` to list results, where `"private"`
controls whether shared intermediaries may cache. A gateway is a shared intermediary.

**Tested by.** `tests/unit/test_manifest.py`.

---

## D-011 — 2026-10-14 — The write budget covers file mutations, not network egress

**Decision.** ``max_writes`` is consumed by ``write`` and ``delete`` only
(:data:`agent_drift.contracts.WRITE_BUDGET_OPERATIONS`). ``network_post`` is bounded by
the destination allowlist, which is default-deny, and by ``max_calls``.

**Why.** This was found by running the scenarios, not by reasoning about them. The
``benign-approved-egress`` scenario registers a task whose entire purpose is to post a
report to one approved internal host, with ``max_writes: 0`` because it touches no files.
With ``network_post`` charged against the write budget, the task's own approved action was
denied ``AD-E081`` on its first call. That is a false block of the worst kind: the policy
refusing the thing the user explicitly authorized.

CLAUDE.md §2 lists "excessive file mutations" as the in-scope threat for budgets, which is
what ``max_writes`` now means. Egress is already constrained by a stricter mechanism.

**Given up.** A single counter covering every state-changing operation. A contract that
wants to bound the *number* of permitted posts uses ``max_calls``; a per-operation budget
table is a v2 item.

**Tested by.** ``examples/scenarios/07-benign-approved-egress.json`` (first post allowed,
sink gains exactly one event; second post to a different host denied ``AD-E070``) and
``tests/unit/test_budgets.py``.

---

## D-012 — 2026-10-14 — Scenario and vector isolation is an explicit budget reset

**Decision.** Each scenario and each release vector gets a fresh temporary fixture state
directory, and an explicit reset of the task's budget counters, while sharing one decision
database.

**Why.** Also found by running it: writes performed by the ``attack-b-scope-drift``
scenario leaked into ``attack-c-budget-drift``'s budget, so attack C's second legitimate
write was denied and the scenario reported a failure that was an artifact of the harness.
The blueprint anticipates exactly this and permits either a fresh database per case or "an
explicit deterministic reset"; a shared database is worth keeping because it lets the
dashboard and the screenshots show every scenario's runs together.

**Given up.** Complete per-case database isolation in the *demo* runner. The *test* runner
(``tests/integration/test_release_vectors.py``) uses a fresh database per vector as well,
so the stricter isolation is what the assertions run under.

---

## D-013 — 2026-10-14 — Two defects found by running the evaluation, and the fixes

The first full benchmark run reported 97.3% recall and one false block. Both numbers were
real defects, not noise, and both are worth recording because they shaped the design.

**Bypass: undeclared arguments were forwarded.** Cases `AD-EVAL-0116` and `AD-EVAL-0117`
sent `repo.write_file` with a legitimate in-scope path *plus* `force: true` or
`overwrite_scope: "**"`. The call was allowed, because JSON Schema defaults
``additionalProperties`` to permissive and the fixture does not set it to ``false``.

*Fix.* :func:`agent_drift.policy._schema_mismatch` now rejects **any** argument the
upstream tool does not declare, emitting the new code ``AD-E005``. This is stricter than
JSON Schema on purpose: a policy gateway decides whether to forward a call, and an
argument the tool never declared is one whose effect on that tool the policy cannot
reason about. A server that genuinely accepts open arguments can say so with
``additionalProperties: true`` and they are allowed through again.

*Second-order fix.* The benchmark was not passing upstream schemas to the engine at all,
so it was measuring a weaker configuration than the gateway actually runs. The arm now
uses the fixture's real advertised schemas, and
``tests/integration/test_schema_gate.py`` asserts that copy stays current — otherwise the
benchmark could silently drift from the product.

**False block: a legitimate path was read as traversal.** Case `AD-EVAL-0008` sent
`sandbox-repo/docs/../docs/README.md`, which is a redundant but entirely legitimate
spelling of `sandbox-repo/docs/README.md`. The old rule rejected any path containing a
``..`` segment, so it was denied `AD-E061`.

*Fix.* :func:`agent_drift.paths.normalize_relative_path` now collapses ``.`` and ``..``
segments and rejects only a path that actually climbs **above** the sandbox root.
Containment is the rule, not the presence of a character sequence. Lexical collapsing
alone would be unsound when a component is a symlink, so :func:`resolve_in_root` still
re-resolves through the real filesystem whenever a sandbox root is configured, and the
fixture tools still re-validate at the moment of use.

*Consequence for reason codes.* A path that collapses to somewhere inside the root but
outside the granted scope is now denied by the scope rule (`AD-E060`) rather than the
traversal rule (`AD-E061`). The outcome is unchanged — both are denials — and the new
code is the more accurate one for a reviewer. `tests/security/test_path_traversal.py` was
restructured into two explicit groups to reflect this: paths that escape the root, and
paths that stay inside it but leave the scope.

**What this says about the score.** After both fixes the suite reports 100% precision and
recall with zero false blocks. That is reported as measured, with the standing caveat in
`evals/RESULTS.md`: a perfect score on an author-constructed set demonstrates internal
consistency and the absence of the failure modes somebody thought to write down. It is
not evidence about the ones nobody did.
