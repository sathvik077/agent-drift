# IMPLEMENTATION_PLAN.md — Agent Drift

**Owner:** single autonomous engineering agent (Claude) acting sequentially in all roles from
`IMPLEMENTATION_BLUEPRINT.md` §4, with independent subagents used for Research (P0) and
Independent Security Review (P6). Delegation actually used is recorded in `docs/DECISIONS.md`.

**Created:** 2026-10-14. **Status source of truth:** `docs/ACCEPTANCE_STATUS.md` + `make verify`.

---

## 0. Environment reality check (performed before any code)

Measured on the build host, 2026-10-14:

| Tool | Version | Notes |
|---|---|---|
| python3 | 3.13.16 | meets "3.12+" |
| node | 22.22.0 | meets "22+" |
| npm | 10.9.4 | registry unreachable (see below) |
| uv | 0.11.32 | PyPI unreachable (see below) |
| make | 4.3 | |
| git | 2.43.0 | |
| docker | 29.8.2 | daemon starts; **registry unreachable** |

**Hard environmental constraints discovered (these shape every decision below):**

1. `pypi.org` returns HTTP 403 at the egress proxy (`connect_rejected`, organization policy).
   No arbitrary Python package can be installed from the network.
2. `registry.npmjs.org` returns HTTP 403 at the egress proxy. `npm install` cannot resolve
   anything, so **Vite, Tailwind CLI, `@playwright/test` and ESLint are not installable here.**
3. `registry-1.docker.io` does not resolve. Base images cannot be pulled, so `docker build`
   cannot execute even though the daemon runs.
4. A usable offline toolchain *does* exist on the host and is reconstructable:
   - A local `uv` archive cache yields a wheelhouse of 85 wheels including
     **pytest 9.1.1, ruff 0.16.8, mypy 2.3.1, httpx 0.28.1, starlette 1.6.0,
     sse-starlette 3.4.11, uvicorn 0.53.0, pydantic 2.13.5, mcp 2.2.0**.
     `scripts/offline_bootstrap.py` rebuilds this wheelhouse deterministically.
   - `/opt/npm-tools/node_modules` provides **react 19.2.8, react-dom 19.2.8,
     typescript 6.0.3, esbuild 0.28.2**.
   - `playwright` 1.56.0 (Python) with Chromium at `/opt/pw-browsers`.
5. **MCP SDK: `mcp` 2.2.0**, whose `LATEST_PROTOCOL_VERSION` is `2026-07-28`
   (`MODERN_PROTOCOL_VERSIONS == ('2026-07-28',)`). A real stdio `tools/list` +
   `tools/call` round trip was executed against a scratch fixture server before any
   architecture was committed. Protocol version observed on the wire: `2026-07-28`.

Consequences are recorded as dated decisions D-001 … D-008 in `docs/DECISIONS.md`.
Every one of them is a *substitution that still runs and is still measured*, never a
substitution of a claim for a test.

---

## 1. Version lock

Python runtime deps (pinned exactly; see `pyproject.toml`):

```
mcp==2.2.0            # MCP SDK v2; protocol 2026-07-28
pydantic==2.13.5
starlette==1.6.0
sse-starlette==3.4.11
uvicorn==0.53.0
python-multipart==0.0.32
```

Dev/test deps: `pytest==9.1.1`, `httpx==0.28.1`, `ruff==0.16.8`, `mypy==2.3.1`,
`playwright==1.56.0`.

Frontend: `react@19.2.8`, `react-dom@19.2.8`, `typescript@6.0.3`, `esbuild@0.28.2`.
Pinned in `apps/dashboard/package.json`; resolved from the local store when the registry
is unreachable (`scripts/offline_bootstrap.py --node`).

---

## 2. Architecture interfaces (frozen before implementation)

Four processes, exactly as the blueprint requires:

```
P1  gateway   packages/agent_drift/gateway.py     MCP stdio server  <-> MCP stdio client
P2  api       apps/api/main.py                    Starlette control plane  127.0.0.1:8001
P3  dashboard apps/dashboard                      static bundle served by P2, dev on :5173
P4  upstream  examples/upstream_mcp/server.py     MCP stdio fixture ("sandbox")
```

### Module ownership (one owner per file; no shared-file concurrent edits)

| Path | Role | Contents |
|---|---|---|
| `packages/agent_drift/contracts.py` | Backend | `IntentContract`, `ToolAttempt`, `PolicyDecision`, `ApprovalGrant`, `Decision`, reason codes, canonical JSON + digests |
| `packages/agent_drift/store.py` | Backend | SQLite WAL event/decision store, single serialized writer, atomic budget reservation, approval lifecycle, redaction |
| `packages/agent_drift/policy.py` | Security | deterministic evaluator; fixed enforcement order; path and destination normalizers |
| `packages/agent_drift/paths.py` | Security | sandbox path canonicalization (traversal, absolute, symlink, unicode, null byte) |
| `packages/agent_drift/destinations.py` | Security | URL parsing, IDNA, loopback/private/link-local/IPv6, port, trailing dot |
| `packages/agent_drift/manifest.py` | MCP | tool manifest fingerprinting + drift classification |
| `packages/agent_drift/gateway.py` | MCP | stdio proxy: `tools/list` + `tools/call`, deny-before-forward |
| `packages/agent_drift/sdk.py` | Backend | `DriftGuard.evaluate()` — evaluation only, not enforcement |
| `packages/agent_drift/cli.py` | MCP | `agent-drift gateway|api|seed|smoke` |
| `apps/api/main.py` | Backend | routes, bearer auth, SSE, OpenAPI + `/docs` |
| `apps/dashboard/src/*` | UI | React 19 + TS, no runtime deps beyond react/react-dom |
| `examples/upstream_mcp/server.py` | MCP | 5 sandbox tools, execution counters, simulated sink |
| `evals/*` | Eval | label schema, 3 baselines, metrics |
| `tests/**` | QA | unit / integration / security / e2e |

### Enforcement order (frozen — `policy.py` implements exactly this sequence)

```
 1 input schema validation        -> AD-E001 bad_arguments
 2 task identity binding          -> AD-E010 missing_task_binding / AD-E011 task_spoof_attempt
 3 contract validity (exists/exp) -> AD-E020 no_contract / AD-E021 contract_expired
 4 manifest fingerprint check     -> AD-E030 manifest_drift
 5 server/tool allowlist          -> AD-E040 tool_not_allowed / AD-E041 server_not_allowed
 6 operation allowlist + denylist -> AD-E050 operation_denied
 7 resource scope                 -> AD-E060 resource_out_of_scope / AD-E061 path_traversal
 8 destination scope              -> AD-E070 destination_not_allowed
 9 call + write budgets           -> AD-E080 call_budget_exceeded / AD-E081 write_budget_exceeded
10 approval requirement           -> AD-A001 needs_approval ... AD-A005 approval_timeout
11 advisory heuristic annotation  -> may ESCALATE allow->needs_approval, never override a deny
```

Any exception raised anywhere in 1–11 is caught and converted to
`deny / AD-E999 evaluator_error`. There is no pass-through path.

---

## 3. Stage checklist

- [ ] **S0 Research + plan + threat model.** `docs/RESEARCH.md` (>=5 verified primary
      sources, comparison matrix, >=2 falsifiable hypotheses), `docs/THREAT_MODEL.md`,
      this file, `docs/DECISIONS.md`. Protocol feasibility proven by executed round trip.
- [ ] **S1 Offline green slice.** contracts -> policy -> sqlite -> API -> one allowed and
      one denied decision visible over HTTP. Executed, not just written.
- [ ] **S2 Real MCP interception.** fixture server with execution counters; gateway proxying
      `tools/list` and `tools/call`; integration test proving a denied call leaves the
      upstream counter at 0. `DriftGuard` SDK + runnable quickstart.
- [ ] **S3 Enforcement hardening.** path/destination normalizers, atomic budgets under
      concurrency, manifest drift, expiry, task spoofing, one-use approval grants bound to
      `(task, revision, tool, canonical_args_digest, nonce)`, redaction, idempotency.
- [ ] **S4 Dashboard.** intent vs action, run timeline, rule-ID risk explanation, approval
      inbox, Replay Lab with explicit `observed` vs `simulated` labels, JSON export,
      empty/loading/error states, responsive + keyboard accessible.
- [ ] **S5 Tests.** seed-vector runner over all 16 vectors with fresh state per vector;
      unit + security + integration suites covering AD-21; Playwright E2E including an
      SSE-latency assertion; `make smoke` printing normalized counters.
- [ ] **S5b Evaluation.** >=120 labeled cases, balanced, with held-out families; baselines
      (unguarded passthrough / keyword-only / contract policy); confusion matrix, TPR/FPR,
      benign completion, p50/p95 decision overhead -> `evals/RESULTS.{json,md}`.
- [ ] **S6 Docs + packaging.** README per CLAUDE.md §11, architecture `.mmd` + rendered SVG,
      real screenshots from the running system, `INTEGRATION.md`, CI workflow, Dockerfiles,
      compose, changelog.
- [ ] **S7 Independent review.** adversarial subagent answers the six red-team questions
      from `ACCEPTANCE_EVIDENCE_MATRIX.md`; critical/high findings fixed and recorded.
- [ ] **S8 Evidence.** `make verify` run end-to-end; `docs/ACCEPTANCE_STATUS.md` and
      `docs/VERIFICATION.md` completed from observed output only.

A stage is not "done" because its files exist. It is done when the command listed in
`docs/VERIFICATION.md` for that stage has been run and its exit code recorded.

---

## 4. Test approach

**Four layers, all offline, all deterministic.**

1. **Unit** (`tests/unit/`) — pure functions: canonical JSON and digests, path
   canonicalization, URL/destination rules, contract expiry arithmetic, manifest
   fingerprinting, reason-code mapping, redaction.
2. **Security regression** (`tests/security/`) — one test per adversarial behaviour named in
   AD-21: path traversal (`..`, absolute, symlink, unicode dot variants, null byte, backslash,
   percent-encoded), URL variants (IDNA, trailing dot, case, port, userinfo, IP literal,
   loopback, link-local, IPv6, scheme confusion), JSON argument mutation, missing task ID,
   forged `task_id` in arguments, stale/replayed approval, schema mismatch, concurrent budget
   race, cancellation mid-call, malicious tool description/annotation, duplicate execution.
3. **Integration** (`tests/integration/`) — a **real** `mcp.Client` speaking stdio to the
   **real** gateway process, which speaks stdio to the **real** fixture server. Asserts on
   the fixture's own on-disk execution counters and on SHA-256 of sandbox files, not on
   gateway self-reports. Includes `test_release_vectors.py`, which loads all 16 cases from
   `tests/fixtures/release_vectors.json` and resets fixture state and database per case.
4. **E2E** (`tests/e2e/`) — Python Playwright against the running API + built dashboard:
   intent/action juxtaposition, a decision appearing via SSE within the 2 s local target,
   approval changing an outcome, Replay Lab labels, empty/error states, screenshots.

**Oracles are external to the component under test.** A decision is only "deny before
execution" if the *fixture* says it never executed. Counters live in a file the fixture
owns; tests read that file.

**Determinism rules.** Every vector and eval case gets a fresh temp sandbox and a fresh
SQLite file. No test depends on wall-clock ordering except the explicit TTL/timeout tests,
which inject a clock. No network egress from any test; the fixture's `network.http_post`
appends to a local JSONL sink and never opens a socket.

---

## 5. Commands (Make contract)

`setup` `dev` `seed` `smoke` `test` `lint` `typecheck` `build` `eval` `verify` `screenshots`
`clean-demo` `docker-build`.

`make verify` = lint + typecheck + test + smoke + eval + dataset-size gate + README asset
existence check, and is the only command whose exit code is treated as release truth.

---

## 6. Known risks carried into implementation

| Risk | Mitigation | If unmitigated |
|---|---|---|
| Docker registry blocked | write + statically check Dockerfiles; `make docker-build` provided | AD-23 image build marked **NOT VERIFIED** with retry command |
| npm registry blocked | React/TS/esbuild from local store; no Vite/Tailwind/ESLint | documented in D-004/D-005; `ruff`+`tsc` cover lint/typecheck |
| `TOCTOU` on third-party tools | argument-level enforcement only; fixture tools re-validate at use | documented limitation, stated in README and THREAT_MODEL |
| Sequence/aggregate harm | out of scope for v1 rule set | stated as open weakness (hypothesis H2) |
| Approval via blocking wait vs MRTR | implement bounded wait; document MRTR as spec-aligned alternative | recorded in D-007 |
