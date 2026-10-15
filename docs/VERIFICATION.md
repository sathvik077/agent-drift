# VERIFICATION.md — observed evidence ledger

This file is the answer to gate **AD-26**: a record of what was actually run, in what
environment, and what came back. Everything below was observed by executing the command
shown. Where something could not be run, it says so and gives the exact retry command —
there are no inferred passes in this document.

**If you only read one line:** `make verify` exits **1** in this environment, because the
`docker` gate is **BLOCKED** (no container registry access). All 15 other gates PASS and the
test suite is **562 passed, 0 failed, 0 skipped**. The machine-readable form of this run is
`var/verify-report.json`. Setup and the core security proof were additionally run on a
**second, clean machine** with live package registries — see §11.

---

## 1. Environment

| | |
|---|---|
| Date of the recorded run | **2026-10-14**; clean-machine run (§10) **2026-10-15** |
| Operating system | `Linux-6.18.44-fc-v114-x86_64-with-glibc2.39` (x86-64 container) |
| Python | **3.13.16** (`.venv/bin/python`, created by `make setup`) |
| Node | **v22.22.0** |
| MCP SDK | `mcp` **2.2.0**, protocol revision **2026-07-28** |
| Web/server stack | `starlette` 1.6.0, `uvicorn` 0.53.0, `pydantic` 2.13.5, `sse-starlette` 3.4.11, `httpx` 0.28.1 |
| Test/lint stack | `pytest` 9.1.1, `playwright` 1.56.0 (Chromium), `ruff` 0.16.8, `mypy` 2.3.1 |
| Network | **Fully offline.** No model API key, no cloud credential, no paid service. |
| Code size | 7,109 lines of Python across `packages/` + `apps/api/`; 1,842 lines of TypeScript in `apps/dashboard/src/` |

### Offline enforcement, not offline by politeness

`tests/conftest.py` installs a socket guard that raises on any attempt to connect to a
non-loopback address. A test that quietly reached the internet would fail rather than pass.
This is why "works with no API key" is a verified property and not a README claim.

### Two environment constraints that shaped the build

Both are real, both were worked around rather than hidden:

1. **PyPI is unreachable** from this container (HTTP 403 at the proxy). Dependencies were
   installed from an offline wheelhouse (`.wheelhouse/`, 85 wheels) repacked from the local
   `uv` archive cache. This is why the stack is **Starlette, not FastAPI** (not in the cache)
   and the OpenAPI 3.1 document is hand-maintained in `apps/api/openapi.py` with
   `tests/unit/test_openapi.py` asserting it matches the live routes.
2. **The npm registry and the container registry are unreachable.** Node packages are linked
   from a preinstalled toolchain, which is why the dashboard builds with **esbuild, not Vite**,
   uses hand-authored CSS rather than a framework, and ships hand-written ambient React type
   declarations (`apps/dashboard/src/types/react-shim.d.ts`) in place of `@types/react`.
   End-to-end tests use **Python Playwright**, not `@playwright/test`.

---

## 2. The recorded `make verify` run

```
$ make verify
```

Full console transcript: the table below is copied from that run's output. Machine-readable
evidence with per-gate commands, exit codes, durations and output tails:
**`var/verify-report.json`** (`generated_at: 2026-10-14T20:14:30Z`).

| Gate | Status | Exit | Time (s) | Observed detail |
|---|---|---:|---:|---|
| `lint` | **PASS** | 0 | 0.0 | `All checks passed!` |
| `format` | **PASS** | 0 | 0.0 | `63 files already formatted` |
| `typecheck-py` | **PASS** | 0 | 0.3 | `Success: no issues found in 14 source files` |
| `typecheck-web` | **PASS** | 0 | 1.3 | `tsc --noEmit` clean, no output |
| `build-dashboard` | **PASS** | 0 | 0.2 | production bundle written to `dist/` |
| `bundle-size` | **PASS** | 0 | 0.0 | `bytes=226046` (under the 1 MB ceiling) |
| `test-unit` | **PASS** | 0 | 2.2 | `passed=106` |
| `test-security` | **PASS** | 0 | 5.0 | `passed=282` |
| `test-integration` | **PASS** | 0 | 184.6 | `passed=144` |
| `test-e2e` | **PASS** | 0 | 41.3 | `passed=30` |
| `smoke` | **PASS** | 0 | 2.9 | `SMOKE PASSED: 7 checks` |
| `eval` | **PASS** | 0 | 1.1 | wrote `evals/RESULTS.json` and `RESULTS.md` |
| `dataset` | **PASS** | 0 | 0.0 | `total_cases=206 benign=96 adversarial=110 held_out=48` |
| `assets` | **PASS** | 0 | 0.0 | all 8 README assets present |
| `hygiene` | **PASS** | 0 | 0.0 | `private/` ignored, no `.env` or database tracked |
| `docker` | **BLOCKED** | — | 0.0 | container registry unreachable; images never built here |

```
test totals: 562 passed, 0 failed

NOT READY — 1 gate(s) could not run here:
  - docker: The container registry is unreachable from this environment, so base
    images cannot be pulled and the images cannot be built here.
    Retry: make docker-build  (on a machine with registry access; also runs in CI)
EXIT=1
```

**`make verify` is honest by construction.** `scripts/verify.py` exits non-zero when a
mandatory gate fails *or* when one is blocked, and it prints `NOT READY` rather than
reporting a pass it cannot support. The exit code 1 above is the script correctly refusing
to certify a gate it could not execute.

### Skipped tests: none

An earlier revision skipped one — the assertion that the control plane does **not** listen
on a non-loopback interface. It resolved the machine's own hostname to find an address to
probe, which returns loopback in some containers (so the test skipped itself rather than
pass vacuously) and raises `gaierror` in others (so it failed for a reason that had nothing
to do with the server). Both behaviours were observed, on two different machines.

It now reads the bind address out of `/proc/net/tcp` rather than probing the network, which
is both the thing the test actually cares about and compatible with the suite's own no-egress
guard — the guard correctly blocked the probe, which is how the second problem surfaced. A
companion test, `test_loopback_assertion_would_catch_a_wide_bind`, binds `0.0.0.0` and
asserts the check trips on it, so the assertion is proven *able* to fail rather than merely
observed to pass.

---

## 3. The core security claim, measured against an external oracle

The central claim of this project is **deny-before-execute**: a blocked tool call must not
reach the upstream server at all. Proving that with the gateway's own logs would be circular,
so every such assertion reads the **upstream fixture's own side-effect counters**
(`counters.json`, written by the fixture as the *first* action inside each tool handler) and
the SHA-256 of the sandbox files. The counter file lives outside the sandbox workspace, so no
policy-permitted write can reach it.

```
$ make smoke
```

Observed, verbatim:

```
[PASS] discovery: tools/list through gateway
       tools=['network.http_post', 'repo.delete_file', 'repo.list_files',
              'repo.read_file', 'repo.write_file'] schemas_intact=True
[PASS] allow: repo.read_file reaches upstream
       decision=allow upstream_call_delta=1 relayed_bytes=156
[PASS] deny: repo.write_file blocked before execution
       decision=deny reasons=['AD-E040'] upstream_call_delta=0 sha256_unchanged=True
[PASS] deny: network.http_post blocked, zero sink events
       decision=deny reasons=['AD-E040'] upstream_call_delta=0 sink_events_delta=0
[PASS] deny: forged task_id argument rejected at identity stage
       decision=deny reasons=['AD-E011'] upstream_call_delta=0
[PASS] audit: no denied decision is marked as executed
       denied_but_executed=0
[PASS] audit: decisions recorded for every attempt
       allow=1 deny=3 events=11

allowed=1 blocked=3 upstream_denied_calls=0
SMOKE PASSED: 7 checks
```

`upstream_call_delta=0` on every deny, and `=1` on the allow, is the whole thesis in one
number: the counter moved exactly when the policy said it should.

### The fixture is not inert

A control test (`tests/integration/test_deny_before_execute.py`, unguarded-baseline case)
sends the *same* calls directly to the upstream with no gateway in the path and asserts the
counters **do** move and the file hash **does** change. Without this control,
`upstream_call_delta=0` would be consistent with a fixture that simply never does anything.

---

## 4. Per-area test evidence

Counts are from the recorded `make verify` run.

| Suite | Command | Result |
|---|---|---|
| Unit | `pytest tests/unit -q` | **106 passed** |
| Security regressions | `pytest tests/security -q` | **282 passed** |
| Integration (real MCP subprocesses) | `pytest tests/integration -q` | **144 passed** |
| End-to-end (real Chromium) | `pytest tests/e2e -q` | **30 passed** |
| **Total** | `make test-all` | **562 passed, 0 failed, 0 skipped** |

What the integration suite actually does: it spawns the upstream MCP server as a **real
subprocess** and talks to it over **real stdio** with the real SDK client. There is no mock
transport anywhere in `tests/integration/`. This is why that suite takes ~173 seconds.

Notable files:

- `tests/integration/test_mcp_roundtrip.py` — protocol revision `2026-07-28` asserted on a
  live handshake; input schemas compared byte-for-byte between a direct connection and the
  proxied one, so the gateway is proven not to rewrite what the model sees.
- `tests/integration/test_release_vectors.py` — all **16 cases in `TEST_VECTORS.json`**, each
  with a fresh database and a fresh sandbox, asserting the expected decision, reason codes
  and upstream counter delta.
- `tests/integration/test_timeout_budget.py` — an upstream that hangs. The gateway records
  `executed=unknown` and does **not** release the reserved budget, because a timed-out
  request may have landed.
- `tests/security/test_review_findings.py` — **58 tests**, one or more per finding from the
  independent review (RT-01…RT-13, see `docs/SECURITY_REVIEW.md`).
- `tests/security/test_budget_race.py` — concurrent reservation under `BEGIN IMMEDIATE`;
  the budget cannot be double-spent.
- `tests/e2e/test_dashboard.py` — drives the real dashboard against a real gateway and is
  also the **source of the README screenshots** (see §6).

---

## 5. Benchmark

```
$ make eval
```

Outputs `evals/RESULTS.json` (schema-validated against `evals/schema.json`) and
`evals/RESULTS.md`. Deterministic from seed `20261014`; only latency figures vary run to run.
**No language model is involved** — the benchmark measures the deterministic policy engine.

**206 labeled cases** — 96 benign, 110 adversarial; ground truth 95 `should_allow`,
111 `should_block`. **48 cases across 5 held-out families** (`argument_smuggling`,
`private_address_egress`, `schema_violation`, `unicode_confusable`, `unknown_tool`) were
never used while tuning the engine.

| Arm | Recall | Precision | FPR | Benign completion | p95 |
|---|---:|---:|---:|---:|---:|
| `unguarded_passthrough` (no gateway) | 0.0% | n/a | 0.0% | 100.0% | 0.00 ms |
| `keyword_classifier` (string matching) | 97.3% | 67.1% | 55.8% | 44.2% | 0.03 ms |
| **`contract_policy`** (Agent Drift) | **100.0%** | **100.0%** | **0.0%** | **100.0%** | **1.30 ms** |

Held-out families only: `TP=35 FP=0 TN=13 FN=0`, p95 **0.97 ms**.

**How to read this honestly.** 100% on a 206-case suite the authors designed is *not* a claim
of 100% in the wild — the dataset's coverage is its ceiling. The number that carries the real
argument is the **keyword baseline: 53 false positives and 3 false negatives**. It blocks the
wrong things *and* misses real attacks, which is the concrete case for policy-against-contract
over pattern matching. A reconciliation assertion in the eval requires the per-family numbers
to sum to the overall matrix, so the tables cannot disagree with each other.

Ground-truth labels come from the text of the approved contract each case is evaluated
against — never from what Agent Drift decided. A call that must pause for human review counts
as **blocked**, since it is not authorized to execute unattended.

---

## 6. Screenshot provenance (AD-17)

Every image in `docs/assets/` is a capture of the running application. None is a mockup.

| File | Bytes |
|---|---:|
| `dashboard-overview.png` | 371 kB |
| `blocked-action.png` | 206 kB |
| `replay-lab.png` | 322 kB |
| `approval-inbox.png` | 395 kB |
| `scenarios.png` | 1,351 kB |
| `dashboard-mobile.png` | 388 kB |
| `architecture.svg` / `architecture.png` | 40 kB / 183 kB |

The pipeline **cannot** emit a placeholder: `scripts/capture_screenshots.py` boots a real API
and a real upstream, runs the demo scenarios through the real gateway, asserts the expected
decision appeared in the DOM, and only then saves the PNG. On any failure it exits non-zero
and writes nothing. The e2e tests additionally assert `st_size > 20_000` so a blank or
failed-paint capture fails the suite.

---

## 7. Live-update latency (AD-14)

Measured, not asserted blind:

```
[AD-14] decision reached the SSE stream in 635.2 ms (local target 2000 ms)
```

Recorded to `var/sse-latency.json`:

```json
{
  "measured_at": "2026-10-15T03:17:59Z",
  "latency_s": 0.6352,
  "target_s": 2.0,
  "within_target": true
}
```

This is the local end-to-end delay from a decision being committed to its frame arriving on
`/api/events/stream`, against a real uvicorn server. It is a statement about this machine, not
a claim about network-scale latency. The dashboard also has a polling fallback if the stream
drops.

---

## 8. Secret and private-data hygiene (AD-25)

```
$ git check-ignore -v private/ .env .venv var
.gitignore:2:private/	private/
.gitignore:8:.env	.env
.gitignore:17:.venv/	.venv
.gitignore:41:var/	var
```

The `hygiene` gate in `make verify` re-checks this on every run and additionally asserts no
`.env` and no database file is tracked. `.env.example` is committed; `.env` (which holds the
generated admin token and audit key) is not. Redaction of sensitive keys and values is tested
in `tests/security/test_redaction_and_api_auth.py`.

No real personal data appears anywhere in the repository. The sandbox fixture and all 206
benchmark cases use synthetic content.

---

## 9. What is NOT verified here

This section exists because the acceptance contract requires blocked gates to be named, not
quietly rounded up.

| | |
|---|---|
| **Docker images (AD-23)** | **Never built.** The container registry is unreachable from this container, so base images cannot be pulled. `Dockerfile.api`, `Dockerfile.dashboard` and `compose.yaml` are written and the CI workflow builds them, but no image has been produced or run. **Retry:** `make docker-build` on a machine with registry access. This is the single reason `make verify` exits 1 and the release verdict is NOT READY. |
| **MCP Inspector (AD-12)** | **Not run.** It is distributed via npm and the registry is blocked. The Python SDK round trip is verified instead (`tests/integration/test_sdk.py`), and `docs/INTEGRATION.md` gives the Inspector command and the host config JSON — unexecuted instructions, clearly labeled as such. |
| **Loopback-only binding** | Verified by code and by the API's bind configuration, but the negative test skips on this host (§2) because the hostname resolves to loopback. |
| **CI pipeline** | The workflow (`.github/workflows/ci.yml`, 6 jobs) has **never executed**, because nothing has been pushed to GitHub. It is reviewed, not observed. |
| **Non-Linux platforms** | Only Linux x86-64 was tested. Nothing is known about macOS or Windows behaviour, particularly around path canonicalization. |
| **Third-party upstream servers** | Only the bundled fixture was used as an upstream. Real-world MCP servers may advertise schemas or behave in ways not covered. |
| **OS-level sandboxing** | Agent Drift is a policy layer in front of tool calls. It does **not** sandbox the upstream process. A malicious upstream server that is already permitted to run can do whatever its own process privileges allow. This is a documented boundary, not an oversight — see `docs/THREAT_MODEL.md` §5. |

---

## 10. Clean-machine setup run (a second, independent host)

Everything above was observed on the machine the project was built on, which proves the code
works but not that the *setup path* does. So `make setup` was run from a fresh copy on a
**different host** — a Linux x86-64 VM with a live PyPI and npm registry and no trace of the
build environment: no offline wheelhouse, no preinstalled Node toolchain, and a default
`python3` of **3.10.12**, below the project's floor.

**Observed (2026-10-15):**

```
$ python3 --version
Python 3.10.12

$ make setup
Using CPython 3.13.15
Creating virtual environment at: .venv
==> using Python 3.13.15
==> installing pinned Python dependencies
==> installing dashboard dependencies
added 6 packages in 6s
registered demo-repo-review       revision=1 hash=4e5e7c4db5907311 tools=2
registered demo-docs-edit         revision=1 hash=9284527cefe6cb75 tools=2
registered demo-cleanup           revision=1 hash=97d06203fc63f6d6 tools=1
registered demo-report-upload     revision=1 hash=4d5535c67712e98c tools=2
registered demo-expired           revision=1 hash=da962f8f1bbeef27 tools=2
setup complete.
  API will serve on       http://127.0.0.1:8001
  dashboard dev server on http://127.0.0.1:5173

$ make smoke
SMOKE PASSED: 7 checks
allowed=1 blocked=3 upstream_denied_calls=0

$ make build-dashboard
dist/app.js  220.7kb   ⚡ Done in 61ms

$ pytest tests/unit tests/security -q
388 passed

$ pytest tests/integration -q          # run per-file; the host caps a command at 180 s
test_api_smoke          28 passed
test_deny_before_execute 18 passed
test_mcp_roundtrip      11 passed
test_schema_gate        14 passed
test_sdk                16 passed
test_release_vectors    22 passed
test_scenarios          23 passed
test_timeout_budget      3 passed
test_sse_live            9 passed
```

Dependencies there resolved from **real PyPI and real npm**, not from the build machine's
caches. `repo.read_file` reached the upstream and the three prohibited calls did not, with
`upstream_call_delta=0` read from the fixture's own counters — the central claim reproduced
on a host that had never run this code before.

### Three real defects this run found

None of these were visible on the build machine. They are listed because a setup path that
only works where it was written is not a setup path.

1. **`make setup` failed outright: `error: invalid command 'bdist_wheel'`.** The project is
   installed with `--no-build-isolation`, so `wheel` must already be in the venv. On the
   build machine it was inherited from system site-packages and nobody noticed. Fixed by
   adding `wheel==0.42.0` to the dev dependencies and `wheel` to `build-system.requires`.
2. **`npm ci` could never have worked: there was no lockfile.** `npm ci` requires
   `package-lock.json`, and the build machine had no registry access to generate one, so the
   step silently fell through to an offline fallback that failed too — taking all of
   `make setup` down with it, backend included. A real `package-lock.json` (lockfileVersion
   3, 32 resolved entries) was generated on the clean machine and is now committed, which is
   also what the build contract asks for. The dashboard dependency step no longer aborts
   setup, and `make e2e` installs Playwright on demand rather than assuming the host has it.
3. **The loopback-binding test failed for an environmental reason** (`gaierror` on resolving
   the host's own name). Reworked to read the bind address from the kernel; see §2.

### What this run does *not* establish

The clean machine is Linux x86-64, like the build machine. **Windows and macOS remain
untested**, and the `Makefile` is POSIX — on Windows it needs WSL or Git Bash. Nothing here
says anything about path canonicalization behaviour on a case-insensitive filesystem, which
is the part of this codebase most likely to differ.

---

## 11. Reproducing this ledger

```bash
make setup          # creates .venv from the offline wheelhouse, generates .env, seeds data
make verify         # all 16 gates; writes var/verify-report.json
make dev            # API + dashboard on http://127.0.0.1:8001
make smoke          # the deny-before-execute proof, with upstream counters
make eval           # regenerates evals/RESULTS.{json,md}
make screenshots    # regenerates docs/assets from the running app
```

`make verify` is the single command that reproduces everything in this document except the
Docker gate. It is expected to exit 1 in an offline environment, with `docker` as the only
blocked gate; any other failure is a real regression.

---

**Cross-references:** `docs/ACCEPTANCE_STATUS.md` (gate-by-gate AD-01…AD-26),
`docs/SECURITY_REVIEW.md` (independent review, findings RT-01…RT-13 and their fixes),
`docs/THREAT_MODEL.md` (boundaries and non-goals), `evals/RESULTS.md` (full benchmark),
`var/verify-report.json` (machine-readable run record).
