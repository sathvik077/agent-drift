# ACCEPTANCE_STATUS.md

Status of every release gate in `CLAUDE.md` §8, from `ACCEPTANCE_EVIDENCE_MATRIX.md`.

**Date:** 2026-10-14; clean-machine setup run 2026-10-15. **Environment:** Python 3.13.16,
Node 22.22.0, Linux x86-64, fully offline. **Evidence:** `docs/VERIFICATION.md` (commands and
exit codes), `var/verify-report.json` (machine-readable), `evals/RESULTS.md` (benchmark),
`docs/SECURITY_REVIEW.md` (independent review).

`make verify` on 2026-10-14: **562 passed, 0 failed, 0 skipped**; 15 of 16 gates PASS,
`docker` BLOCKED. AD-01 was additionally re-run on a **second, clean host** with live
package registries — see `docs/VERIFICATION.md` §10, which also records the three real setup
defects that run exposed and fixed.

A gate is **PASS** only on directly observed evidence. A gate that could not run here is
**NOT VERIFIED** with the reason and the exact retry command — not a pass.

**Release verdict: NOT READY in this environment**, because AD-23 cannot be fully verified
here: the container registry is unreachable, so the Docker images have never been built.
Every other gate passes with observed evidence. On a machine with registry access, or in CI,
`make docker-build` closes the remaining gate.

---

## Summary

| Status | Count | Gates |
|---|---:|---|
| **PASS** | 24 | AD-01…AD-22, AD-24, AD-25, AD-26 (see below) |
| **PARTIAL** | 1 | AD-23 (CI defined and complete; images never built here) |
| **PASS with a stated caveat** | 1 | AD-12 (SDK and config verified; MCP Inspector not run — npm registry blocked) |
| **FAIL** | 0 | — |

---

## Functional / integration

### AD-01 — `make setup` and `make dev`, no cloud credentials — **PASS**

- **Command:** `make setup` then `make dev`; `curl -sS http://127.0.0.1:8001/healthz`
- **Observed:** setup creates `.venv`, installs the pinned dependencies, generates `.env`
  with a fresh admin token and audit key, and seeds five contracts plus the sandbox.
  `/healthz` returns `{"status":"ok","mcp_protocol_revision":"2026-07-28","mcp_sdk_version":"2.2.0"}`.
  API on `127.0.0.1:8001`, dashboard served at `/`.
- **Zero cloud credentials:** no model API key is read anywhere. `tests/conftest.py` installs
  a socket guard that fails any test attempting a non-loopback connection, so this is
  enforced rather than asserted.
- **Re-verified on a clean host (2026-10-15):** `make setup` then `make smoke` on a different
  Linux x86-64 machine with live PyPI and npm, no offline wheelhouse, no preinstalled Node
  toolchain and a default `python3` of 3.10.12. `make setup` fetched a standalone 3.13.15,
  installed from the real registries, seeded five contracts, and `make smoke` reported
  `SMOKE PASSED: 7 checks` with `upstream_call_delta=0` on every deny. Three genuine setup defects were found and fixed in the process — missing
  `wheel` build dependency, no npm lockfile, and a brittle loopback test. Full transcript and
  defect list: `docs/VERIFICATION.md` §10.

### AD-02 — real upstream discovered through the gateway via `tools/list` — **PASS**

- **Command:** `pytest tests/integration/test_mcp_roundtrip.py -q`
- **Observed:** 11 passed. Five tools discovered through the gateway with schemas **byte-identical**
  to those the upstream advertises directly (`test_input_schemas_survive_the_proxy_unmodified`
  compares a direct connection against the proxied one). Negotiated protocol version asserted
  as `2026-07-28`.
- **Argument validation per server schema:** `tests/integration/test_schema_gate.py` (14 passed)
  — undeclared arguments `AD-E005`, wrong types and missing required properties `AD-E004`.

### AD-03 — authorized call reaches the tool; response relayed; trace visible — **PASS**

- **Command:** `make smoke`
- **Observed:** `decision=allow upstream_call_delta=1 relayed_bytes=156`. The delta is read
  from the upstream's own `counters.json`. Trace visible on the dashboard —
  `tests/e2e/test_dashboard.py::TestBlockedAction` asserts the timeline renders it, and
  `docs/assets/dashboard-overview.png` is a capture of it.

### AD-04 — unauthorized call denied *before* execution; counter unchanged — **PASS**

- **Command:** `pytest tests/integration/test_deny_before_execute.py -q` (18 passed); `make smoke`
- **Observed:** `decision=deny reasons=['AD-E040'] upstream_call_delta=0 sha256_unchanged=True`
  and `sink_events_delta=0`. Control: `TestUnguardedBaseline` connects *directly* to the
  upstream and shows the same write succeeding and changing the file, so the fixture is not
  inert.
- **Normalized counters:** `allowed=1 blocked=3 upstream_denied_calls=0`.

### AD-05 — read-only cannot mutate; scoped write confined; destinations enforced — **PASS**

- **Command:** `pytest tests/integration/test_deny_before_execute.py tests/security -q`
- **Observed:** read-only task's write, delete and post all denied with the file SHA-256
  unchanged and the egress sink empty. Docs-scoped task: `src/payment.py` denied `AD-E060`,
  `docs/README.md` allowed and the hash changes. Destinations: 57 cases in
  `tests/security/test_destinations.py`, including `inet_aton` spellings, userinfo, IDNA
  homographs, reserved ranges.

### AD-06 — expired, missing, untrusted contract fails closed — **PASS**

- **Observed:** missing contract `AD-E020`; expired `AD-E021`; a stored contract declaring an
  untrusted `source` is refused before validation with `AD-E025`
  (`TestRT04ContractIntegrity::test_untrusted_source_in_a_stored_row_is_refused`). No implicit
  consent anywhere: every failure path denies, including evaluator exceptions (`AD-E999`) and
  store faults (`AD-E998`).

### AD-07 — explicit task binding; parallel task isolation — **PASS**

- **Command:** `pytest tests/security/test_task_identity.py -q`
- **Observed:** 16 identity-key spellings denied `AD-E011` at stage R2, before the contract is
  consulted; budgets and approvals proven per-task; a grant issued for one task is not findable
  from another. Lookalike spellings (`task․id`, fullwidth, Greek ρ) also recognized —
  `TestRT12IdentityKeyLookalikes`.

### AD-08 — approvals bind tool, args hash, task, revision, TTL, one use — **PASS**

- **Command:** `pytest tests/security/test_approvals.py tests/security/test_review_findings.py -q`
- **Observed:** exact-args matching; an extra argument does not match; a new revision
  invalidates a grant; expiry enforced; decline and timeout both deny; 8 threads racing one
  grant produce exactly 1 allow. **Strengthened after review:** a grant also binds the *raw*
  (un-normalized) argument digest, so two unicode compositions of one filename cannot share a
  grant (`TestRT03UnicodeApprovalAliasing`).

### AD-09 — no replayed side effects; at-most-once documented — **PASS**

- **Observed:** reading `/api/runs/{id}`, `/api/runs/{id}/replay` and `/api/export/{id}` leaves
  the upstream counter unchanged (`test_reading_the_replay_endpoint_executes_nothing`).
  `denied_but_executed` is 0 across every run, and now counts `unknown` outcomes too.
- **At-most-once is documented** in `docs/THREAT_MODEL.md` §5.13: forwarding is once per
  authorized attempt, a host retry is a new attempt with its own decision, and a timed-out
  call is recorded `unknown` rather than guessed. (This documentation did not exist before the
  independent review; `docs/SECURITY_REVIEW.md` RT-01 records why.)

### AD-10 — manifest drift surfaces and enforces the review policy — **PASS**

- **Command:** `python scripts/run_scenarios.py --only attack-f-manifest-rug-pull`
- **Observed:** `expected=deny observed=deny reasons=AD-E030 upstream_delta=0` against a
  **genuinely mutated** upstream (`AD_FIXTURE_MUTATE_MANIFEST=1` re-advertises
  `repo.write_file` with `read_only_hint: true`). Drift classification unit-tested in
  `tests/unit/test_manifest.py` (16 passed).

### AD-11 — typed API routes; `/docs` usable with sample payloads — **PASS**

- **Command:** `pytest tests/unit/test_openapi.py tests/integration/test_api_smoke.py -q`
- **Observed:** 21 documented paths exactly equal 21 registered routes; every mutating route
  declares bearer security; every documented example payload validates against the Pydantic
  model the route actually uses; `/docs` returns 200 and renders the examples.

### AD-12 — Python SDK example, client config, Inspector instructions — **PASS (with a caveat)**

- **Command:** `python examples/sdk_quickstart.py`; `pytest tests/integration/test_sdk.py -q`
- **Observed:** quickstart exits 0 and prints ALLOW and DENY decisions; 16 SDK tests pass,
  including one that *demonstrates* the enforcement boundary by ignoring a denial, calling the
  tool, and asserting it ran.
- **`examples/mcp_client_config.json`** matches the real CLI flags, verified by the reviewer.
- **CAVEAT — MCP Inspector not run.** The npm registry is blocked by egress policy here, so
  `npx @modelcontextprotocol/inspector` could not be installed. The instructions in
  `docs/INTEGRATION.md` §4 are written from the documented CLI and are **marked NOT VERIFIED
  there**. The equivalent round trip is verified by `make smoke` and
  `tests/integration/test_mcp_roundtrip.py`, which drive a real `mcp.Client` through the same
  gateway. Retry: `npx @modelcontextprotocol/inspector <gateway command>` on a networked machine.

---

## UX / evidence

### AD-13 — intent, untrusted content, action and result distinguished — **PASS**

- **Command:** `pytest tests/e2e/test_dashboard.py::TestIntentVersusAction -q`
- **Observed:** the trusted and untrusted panels have different computed border colours, so
  the distinction survives a screenshot; contract details are asserted against the live API
  response. Capture: `docs/assets/dashboard-overview.png`.

### AD-14 — SSE updates within a 2 s local target — **PASS**

- **Command:** `pytest tests/integration/test_sse_live.py tests/e2e/test_dashboard.py::TestLiveUpdates -q`
- **Observed:** against a real uvicorn server, a decision reaches the stream well inside the
  2 s local target (the elapsed time is in the assertion message, not merely compared). In the
  browser, a new row appears without a refresh. The UI reports its transport honestly —
  `live`, `polling`, `offline` — and degrades to polling if the stream fails.
- Stated as a **local** target; no internet-scale realtime claim is made.

### AD-15 — at least six scenarios, resettable, deterministic — **PASS**

- **Command:** `make demo`
- **Observed:** `8/8 scenarios matched their expected decisions`. Eight scenarios covering the
  golden path and attacks A–F plus an approved-egress control. Each gets a fresh fixture state
  and an explicit budget reset. No external writes: `network.http_post` opens no socket, and
  the test socket guard enforces it.
- Asserted by `tests/integration/test_scenarios.py` (23 passed), so the dashboard cannot
  advertise an expectation the suite does not check.

### AD-16 — Replay Lab labels baseline versus observed; metrics defined — **PASS**

- **Command:** `pytest tests/e2e/test_dashboard.py::TestReplayLab -q`
- **Observed:** both columns carry visible `OBSERVED` / `SIMULATED` badges; the simulated
  column's visible text says no tool was run to produce it and no row represents a prevented
  incident; metric definitions are rendered inline under each number rather than hidden in a
  tooltip. Capture: `docs/assets/replay-lab.png`.

### AD-17 — README has real screenshots, diagram, quickstart, MCP example — **PASS**

- **Observed:** `docs/assets/` holds `dashboard-overview.png` (371 kB), `blocked-action.png`
  (206 kB), `replay-lab.png` (322 kB), `approval-inbox.png` (395 kB), `scenarios.png`
  (1351 kB), `dashboard-mobile.png` (388 kB), `architecture.svg` (40 kB) and
  `architecture.png` (183 kB).
- **Provenance:** every screenshot is produced by `scripts/capture_screenshots.py`, which
  resets state, runs all eight scenarios through a **real gateway**, starts a real server and
  drives a real browser. It exits non-zero and writes nothing if any step fails — there is no
  code path that can emit a placeholder. The same captures are produced and asserted by the
  Playwright suite.

### AD-18 — empty, error, approval and offline states; responsive; accessible — **PASS**

- **Command:** `pytest tests/e2e/test_dashboard.py::TestStatesAndAccessibility -q`
- **Observed:** tabs are a correct ARIA tablist reachable by keyboard; panels are labelled;
  meters expose `aria-valuenow`; blocking the API produces a real error state naming
  `make dev` rather than a blank page; empty states explain what would populate them; no
  horizontal overflow at 390, 768 or 1440 px; dark scheme verified by computed background
  colour; no console errors on load.

---

## Quality, security, research

### AD-19 — `make test|lint|typecheck|build|eval|verify` implemented and pass — **PASS**

See `docs/VERIFICATION.md` for exit codes. All pass; `make docker-build` is the one blocked
target and is reported as blocked rather than skipped.

### AD-20 — 100+ labeled cases with real metrics — **PASS**

- **Command:** `make eval`
- **Observed:** **206 cases** (96 benign, 110 adversarial), 20 families, 16 randomized
  rephrasings, **48 cases in 5 held-out families**.

| Arm | TP | FP | TN | FN | Recall | Precision | FPR | p50 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Unguarded passthrough | 0 | 0 | 95 | 111 | 0.0% | n/a | 0.0% | 0.00 ms | 0.00 ms |
| Keyword classifier | 108 | 53 | 42 | 3 | 97.3% | 67.1% | 55.8% | 0.02 ms | 0.04 ms |
| **Contract policy** | 111 | 0 | 95 | 0 | **100%** | **100%** | **0.0%** | 0.38 ms | **0.92 ms** |

Held-out slice (contract policy): TP 35, TN 13, FP 0, FN 0 — both halves measurable, which
they were not before the independent review (RT-10). Bypasses: none. False blocks: none.
p95 decision latency excludes the upstream call by construction.

**Honesty note carried in `evals/RESULTS.md` and the README:** a perfect score on an
author-constructed set demonstrates internal consistency, not robustness. Two real defects
were found *by running this suite* (D-013). AgentDojo and ASB have **not** been run.

### AD-21 — policy regression suites — **PASS**

`pytest tests/security -q` → **282 passed**. Coverage: path traversal (27 hostile cases plus
4 within-root-out-of-scope and 9 benign controls), symlink escapes and loops, URL variants
(57 cases), JSON argument mutation, missing and forged task IDs, stale and replayed approvals,
schema mismatch, concurrency (budget and approval races with real threads), cancellation and
timeout, malicious tool descriptions and annotations, duplicate execution, and the thirteen
findings from the independent review.

### AD-22 — redaction, localhost auth, no egress — **PASS**

- Redaction before persistence verified against the database and the event log; the args
  digest is computed *before* redaction so approvals stay exact.
- Mutations require a bearer token; **a missing token fails closed with 503**, and disabling
  auth requires an explicit `AD_DISABLE_AUTH=1`.
- No arbitrary OS command execution: the fixture executes no shell, and
  `network.http_post` contains no HTTP client.
- The test socket guard fails any test opening a non-loopback connection.

### AD-23 — CI runs the suites; Docker images build — **PARTIAL / NOT VERIFIED**

- **CI: PASS (defined and complete).** `.github/workflows/ci.yml` has six jobs — backend
  (lint, format, typecheck, unit, security, integration, real stdio smoke, and a step that
  **fails the build on any undocumented skip**), frontend (typecheck, production build, bundle
  sanity), e2e (real Chromium), eval (benchmark plus a dataset size, balance and target gate),
  images, and hygiene (private/ ignored, no `.env` or database tracked, README assets present).
- **Docker images: NOT VERIFIED.** `registry-1.docker.io` does not resolve from this
  environment, so base images cannot be pulled and the images have **never been built**. The
  Dockerfiles parse (BuildKit loads them and fails only at `FROM`) and `docker compose config`
  validates.
  **Retry:** `make docker-build` on a machine with registry access. The `images` CI job builds
  both and validates the compose file.
- **This is the one gate keeping the release verdict at NOT READY.**

### AD-24 — research matrix, 5+ primary sources, 2+ falsifiable hypotheses — **PASS**

`docs/RESEARCH.md`: 7 primary sources plus 4 compared-not-endorsed systems, each fetched and
verified with the verification method stated per row; 5 falsifiable hypotheses with explicit
refutation conditions and honest status (H1, H2, H5 **not run**; H3 partially; H4 partially);
a 12-item "could not verify" list; and an explicit statement that **no "first ever" claim is
made**, with the novelty statement marked provisional pending a package-registry survey that
the blocked egress prevented.

### AD-25 — private PDF present and ignored; no secrets committed — **PASS**

```
$ git check-ignore -v private/Research_Interview_Guide.pdf
.gitignore:2:private/	private/Research_Interview_Guide.pdf
$ git ls-files private/ | wc -l
0
$ git status --short | grep -c private/
0
```

The supplied PDF is in `private/`, the whole folder is ignored, nothing under it is tracked,
and no `.env`, `.db` or `.sqlite` file is tracked. Enforced by `make verify` and by the
`secrets` CI job, which plants a probe file and fails if it is not ignored.

### AD-26 — honest evidence ledger — **PASS**

`docs/VERIFICATION.md` records the environment, date, exact commands, exit codes, test counts
and known issues, with `var/verify-report.json` as the machine-readable form. Every gate above
cites a command whose output was observed. The two gates that could not run here say so.

---

## What is not claimed

- **Not production-ready.** Local demonstration only. No TLS, multi-user identity, rate
  limiting, backups or observability.
- **No formal guarantee.** See `docs/RESEARCH.md` §4.
- **Published benchmarks not run.** AgentDojo and Agent Security Bench comparisons are
  described as future work, not results.
- **Docker images never built here.** AD-23 is partial, and the release verdict reflects it.
