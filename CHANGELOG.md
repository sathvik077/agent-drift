# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — found by running `make setup` on a clean machine (2026-10-15)

- `make setup` failed with `error: invalid command 'bdist_wheel'` on any host without
  `wheel` in system site-packages. The project installs itself with `--no-build-isolation`,
  so `wheel` is now a declared dev dependency and a `build-system.requires` entry.
- Added `apps/dashboard/package-lock.json` (lockfileVersion 3, 32 resolved entries). Without
  it `npm ci` could never succeed, and its failure took the whole of `make setup` down —
  backend included. The dashboard step now falls back to `npm install`, then to the offline
  store, and finally warns and continues rather than aborting: the gateway, the API and the
  entire security argument are Python and do not need Node.
- `make setup` now asks `uv` for a Python `>=3.12` interpreter instead of inheriting the
  host's `python3`, which produced a confusing failure several steps later on a host whose
  default was 3.10.
- `make e2e` installs Playwright on demand instead of assuming the host provides it, and
  explains what still works if the registry is unreachable.
- The loopback-binding assertion no longer resolves the machine's own hostname to find an
  address to probe — it reads the bind address from `/proc/net/tcp`. The old form skipped
  itself on one host and raised `gaierror` on another; neither outcome said anything about
  the server. A companion test binds `0.0.0.0` and proves the assertion can fail.
  This removes the suite's only skipped test: **562 passed, 0 skipped**.
- The AD-14 latency figure is now written to `var/sse-latency.json` as a measurement rather
  than only asserted against its target.
- `make verify`'s `assets` gate now also requires every evidence document the project cites
  to exist and be non-trivial, so a ledger can no longer reference a missing file.

## [0.1.0] — 2026-10-14

First working release. Local demonstration only; see the deployment warning in `README.md`.

### Added

**Enforcement**

- MCP stdio gateway acting as a server to the host and a client to one upstream server,
  proxying `tools/list` and `tools/call` against MCP protocol revision **2026-07-28**
  (SDK `mcp==2.2.0`).
- Deterministic policy engine with eleven ordered enforcement stages, failing closed on any
  exception. A probabilistic heuristic may escalate an allow to human review and can never
  override a deterministic deny.
- Host-owned task binding supplied at gateway launch. Identity-shaped tool arguments
  (`task_id`, `approved_by`, `admin_token`, …) are refused and recorded as `AD-E011`.
- Versioned, hashed intent contracts with tool, operation, resource, destination and budget
  constraints, expiry, and per-tool approval rules.
- Path canonicalization resistant to traversal, absolute and UNC paths, backslash and
  percent-encoded separators, null bytes, unicode confusables, invisible characters and
  symlink escapes (including loops).
- Destination allowlisting with default deny: IDNA normalization, userinfo stripping,
  trailing-dot and case folding, explicit ports, and rejection of loopback, private,
  link-local, multicast and IPv4-mapped-IPv6 addresses — including `inet_aton` spellings
  such as `0177.0.0.1` and `0x7f.1`.
- Strict input-schema gate: arguments the upstream tool does not declare are refused
  (`AD-E005`), which is stricter than JSON Schema's permissive default.
- Tool manifest fingerprinting with drift classification, so a tool that changes its
  description, schema or annotations after approval cannot acquire new privilege.
- Single-use approval grants bound to `(task, policy revision, tool, canonical args digest,
  nonce)` with a TTL, deliberately excluding the JSON-RPC request id.
- Atomic call and write budget reservation under `BEGIN IMMEDIATE`, correct under
  concurrency.
- SQLite WAL event store with monotonic sequencing, secret redaction before persistence, and
  an optional HMAC integrity chain.

**Surfaces**

- Starlette control plane on `127.0.0.1:8001`: tasks, attempts, events, SSE stream,
  decisions, runs, replay, approvals, scenarios, reason catalogue, audit verification and a
  redacted audit export. Bearer token required for every mutation; fails closed when no
  token is configured.
- Hand-maintained OpenAPI 3.1 document and a dependency-free `/docs` reference, both asserted
  against the registered routes by a test.
- React 19 + TypeScript dashboard: intent-versus-action view, live SSE trace with a polling
  fallback, approval inbox, Replay Lab with explicit observed-versus-simulated labelling,
  scenario catalogue, redacted JSON export, and empty, loading and error states.
- `DriftGuard` Python SDK for non-MCP frameworks, documented and tested as **advisory, not
  enforcement**.
- `agent-drift` CLI: `gateway`, `api`, `seed`, `smoke`, `verify-audit`, `reset`, `contracts`.

**Evidence**

- Sandbox-only upstream MCP fixture with execution counters and a simulated egress sink that
  opens no sockets. The counters are the external oracle the tests assert against.
- Eight bundled scenarios covering the golden path and attacks A–F, each with deterministic
  expected decisions asserted by the test suite.
- 499 automated tests: unit, security regression, integration against real MCP processes, and
  Playwright end-to-end against a real browser and a real backend.
- Offline benchmark of 192 labeled cases across 20 families, 34 of them in five held-out
  families, with three arms (unguarded passthrough, keyword classifier, contract policy).
- `make verify` release gate that records every gate's exit code and reports blocked gates as
  blocked rather than passed.
- Screenshots captured from a running system by a script that cannot produce a placeholder.

### Known limitations

Stated in full in `docs/THREAT_MODEL.md` §5. The short version: only calls that traverse the
gateway are enforced; argument checks cannot bind a third-party tool's behaviour; sequence
and aggregate harm is not detected; destination checks do not resolve DNS; the audit chain is
tamper-evidence, not tamper-proofing; the control plane is single-user development
authentication; v1 is stdio, one upstream, `tools/list` and `tools/call` only.

### Not verified in the authoring environment

- Docker image builds — the container registry was unreachable; the images build in CI.
- MCP Inspector instructions — the npm registry was unreachable.
See `docs/ACCEPTANCE_STATUS.md` for the exact status of every acceptance gate.
